#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mozunitor 自更新：从远端取最新标签，比对本地版本，按清单同步文件。

用法::

    python tools\\update.py --status              # 只看：远端到哪了、这次会改哪些文件
    python tools\\update.py --apply               # 落盘（先备份，后写），不重启面板
    python tools\\update.py --rollback            # 回滚最近一次
    python tools\\update.py --rollback 20261012-1930

三条设计取舍，每条都是踩过之后才定下来的：

1. **只同步代码，绝不动配置。** `services.json` 与启动器是**端本地的**：本机那份用
   `where: remote` + 隧道，M1K 那份必须翻译成 `where: local` + 本机回环。让更新顺手覆盖它，
   等于每次升级都炸一次配置 —— 而这种错误看起来像「面板突然全红」，离错因很远。
2. **按清单复制，不用 `git checkout`。** M1K 的安装目录不是 git 工作副本（`D:\\Mozunitor`
   是部署产物），而且 checkout 会与端本地的 `services.json` 打架。
3. **版本以 git tag 为准**（AGENTS：tag 是唯一权威记录）。本地版本从 `monitor_server.py`
   的 `server_version` 解出来，两边对不上就**如实报**，不假装一致。

写入前一律先备份到 `logs/update-backup-<stamp>/` 并落 `manifest.json`；`--rollback`
按那份清单精确还原「这次改了哪些文件」，而不是整目录覆盖。

**它不重启面板。** 重启要分平台、要处理「从面板里跑更新会把自己杀掉」这件事
（面板的 Job 会带走子进程），所以单独一步做，工具只把该敲的命令打出来。
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime
from io import BytesIO
from pathlib import Path

HERE = Path(__file__).resolve().parent
INSTALL_DEFAULT = HERE.parent                     # 安装目录 = 仓库根 / D:\Mozunitor
MIRROR_NAME = ".update"                           # 自己的镜像仓与状态都放这里
DEFAULT_REMOTE = "https://github.com/M1zukiri/Mozunitor.git"  # 公开仓库即更新源

# 端本地：永不被更新覆盖。每条都要写清「为什么不能盖」。
PROTECTED = {
    "services.json": "端本地配置：一端 where: remote + 隧道，一端必须翻译成 where: local + 回环",
}
PROTECTED_PREFIXES = (".state/", "logs/", "__pycache__/", ".update/")
# 树里有、但任何一份运行中的安装都不需要的：明确跳过，并在 --status 里列出来
SKIP_PREFIXES: dict[str, str] = {}

TAG_RE = re.compile(r"^v(\d+(?:\.\d+)*)$")
VER_RE = re.compile(r'(?i)server_version\s*=\s*"Mozunitor/([0-9]+(?:\.[0-9]+)*)"')
TEXT_EXT = {".py", ".js", ".css", ".html", ".json", ".md", ".txt", ".yml", ".yaml",
            ".ps1", ".cmd", ".bat", ".vbs", ".dart", ".kts", ".gradle", ".properties"}


# ------------------------------------------------------------------ git 与基础取值
def run_git(*args, cwd=None, check=True):
    """跑一条 git。stdout 按 bytes 拿（`git show` 要二进制安全），调用方自己解。"""
    proc = subprocess.run(["git", *args], cwd=str(cwd) if cwd else None,
                          capture_output=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} 失败（{proc.returncode}）："
                           + proc.stderr.decode("utf-8", "replace").strip())
    return proc


def mirror_dir(install):
    return install / MIRROR_NAME / "src.git"


def resolve_remote(install, override):
    """远端来源要能被看见：--remote > 环境变量 > 端上的 .update/remote.txt > 内置默认。"""
    if override:
        return override, "--remote"
    import os
    env = os.environ.get("MOZU_UPDATE_REMOTE")
    if env:
        return env, "环境变量 MOZU_UPDATE_REMOTE"
    cfg = install / MIRROR_NAME / "remote.txt"
    if cfg.exists():
        return cfg.read_text(encoding="utf-8").strip(), str(cfg)
    return DEFAULT_REMOTE, "内置默认（公开仓库）"


def ensure_mirror(install, remote):
    """镜像仓：一次 clone --mirror，之后只 fetch。放在安装目录里，跟着这台机器走。

    镜像已存在时**必须核对 origin**：`--remote` 与端上的 `.update/remote.txt` 都可能被改
    （换机器、换镜像位置、裸仓库搬家）。不核对的话新地址只在第一次生效，之后静默继续
    fetch 旧地址 —— 这正是「改了配置没反应」的形状，而报错信息会指向完全不相关的地方。
    """
    m = mirror_dir(install)
    m.parent.mkdir(parents=True, exist_ok=True)
    if not (m / "HEAD").exists():
        proc = run_git("clone", "--mirror", str(remote), str(m), check=False)
        if proc.returncode != 0:
            raise RuntimeError("无法建立镜像仓：" + proc.stderr.decode("utf-8", "replace").strip())
        return "clone"

    cur = run_git("--git-dir", str(m), "config", "--get", "remote.origin.url",
                  check=False).stdout.decode("utf-8", "replace").strip()
    how = "fetch"
    if cur != str(remote):
        run_git("--git-dir", str(m), "remote", "set-url", "origin", str(remote))
        how = f"改指向后 fetch（原为 {cur}）"
    # 标签的 refspec **必须带 `+`**。git 默认拒绝覆盖已存在的标签，所以只要远端有过一次
    # 「打错标签再重打」（发布事故里最常见的一种），镜像里那份旧标签就会让此后每次 fetch
    # 都失败 —— 表现是「更新工具突然永远取不到远端」，而唯一的出路是人工删掉镜像仓。
    # 不用 `--tags`：它走的是不带 force 的隐式 refspec，正是会卡住的那条路。
    proc = run_git("--git-dir", str(m), "fetch", "--prune", "origin",
                   "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*", check=False)
    if proc.returncode != 0:
        raise RuntimeError("取不到远端：" + proc.stderr.decode("utf-8", "replace").strip())
    return how


def newest_tag(install):
    out = run_git("--git-dir", str(mirror_dir(install)), "tag", "--list").stdout
    tags = [t.strip() for t in out.decode("utf-8", "replace").splitlines() if TAG_RE.match(t.strip())]
    if not tags:
        raise RuntimeError("镜像仓里没有任何 vX.Y.Z 标签")
    return max(tags, key=lambda t: tuple(int(x) for x in TAG_RE.match(t).group(1).split(".")))


def ref_version(install, ref):
    """目标 ref 里 `monitor_server.py` 声明的版本。拿不到就返回 None（如实留空）。"""
    proc = run_git("--git-dir", str(mirror_dir(install)), "show", f"{ref}:monitor_server.py",
                   check=False)
    if proc.returncode != 0:
        return None
    m = VER_RE.search(proc.stdout.decode("utf-8", "replace"))
    return m.group(1) if m else None


def local_version(install):
    f = install / "monitor_server.py"
    if not f.exists():
        return None
    m = VER_RE.search(f.read_text(encoding="utf-8", errors="replace"))
    return m.group(1) if m else None


def tree_files(install, ref):
    out = run_git("--git-dir", str(mirror_dir(install)), "ls-tree", "-r", "-z",
                  "--name-only", ref).stdout
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def blob(install, ref, path):
    return run_git("--git-dir", str(mirror_dir(install)), "show", f"{ref}:{path}").stdout


def is_protected(path):
    return path in PROTECTED or path.startswith(PROTECTED_PREFIXES)


def skip_reason(path):
    for pre, why in SKIP_PREFIXES.items():
        if path.startswith(pre):
            return why
    return None


# ------------------------------------------------------------------ 行尾
def text_of(data, path):
    """是文本就返回它，否则 None。用扩展名 + 前 8KB 无 NUL 两个判据。"""
    if Path(path).suffix.lower() not in TEXT_EXT:
        return None
    if b"\0" in data[:8192]:
        return None
    return data


def eol_of(data):
    return b"\r\n" if b"\r\n" in data else b"\n"


def reline(data, style):
    """把文本统一成指定的行尾。行尾不是语义，别让它变成「改动」。"""
    lf = data.replace(b"\r\n", b"\n")
    return lf.replace(b"\n", style) if style != b"\n" else lf


def same_content(old, new, path):
    """判断两个文件是否等价。文本按行尾归一化后再比。

    不这么做的后果很具体：本机 `core.autocrlf=true`，而磁盘上的文件是 LF（写文件的工具
    产出 LF），于是 27 个文件**全被判成「要更新」**，版本明明一致。计划表一旦开始撒谎，
    就再也没人看它了 —— 而这个表是整个工具唯一的价值所在。
    """
    if old is None:
        return False
    if text_of(old, path) is None or text_of(new, path) is None:
        return old == new
    return old.replace(b"\r\n", b"\n") == new.replace(b"\r\n", b"\n")


def fit_eol(new, dest, path):
    """写入时沿用目标文件现有的行尾；文件不存在就用仓库里的那份。

    「保留现状」比「按 core.autocrlf 猜」可靠：猜错了不会报错，只会让整棵树莫名其妙
    全变成已修改，看起来像更新坏了。
    """
    if text_of(new, path) is None or not dest.exists():
        return new
    try:
        old = dest.read_bytes()
    except OSError:
        return new
    if text_of(old, path) is None:
        return new
    return reline(new, eol_of(old))


# ------------------------------------------------------------------ 计划
def previous_manifest(install):
    f = install / MIRROR_NAME / "last.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def checkout_state(install):
    """安装目录如果是 git 工作副本，报出 HEAD 与脏状态。

    在 checkout 型的端上（本机就是），`--apply` 是**错的工具**：它会把未提交的改动按 tag
    覆盖回去。所以必须说清楚，并且默认不让它动手 —— 静默抹掉人的在制品，是这件事里最不
    可接受的失败。M1K 那种部署产物没有 `.git`，不受影响。
    """
    if not (install / ".git").exists():
        return None
    head = run_git("rev-parse", "--short", "HEAD", cwd=install,
                   check=False).stdout.decode("utf-8", "replace").strip()
    out = run_git("status", "--porcelain", cwd=install, check=False).stdout
    dirty = [l for l in out.decode("utf-8", "replace").splitlines() if l.strip()]
    return {"head": head, "dirty": dirty}


def build_plan(install, ref):
    """返回 (actions, protected, skipped)。

    actions 里每项是 (kind, path)，kind：
    - add      树里有、本地没有
    - update   两边都有且**内容确实不同**（文本按行尾归一化后比）
    - remove   上一次更新写过、这次树里已经没有（不删就会让旧代码赖着不走）
    """
    files = tree_files(install, ref)
    actions, protected_hits, skipped = [], [], []

    for path in files:
        if is_protected(path):
            protected_hits.append(path)
            continue
        why = skip_reason(path)
        if why:
            skipped.append((path, why))
            continue
        dest = install / path
        old = dest.read_bytes() if dest.exists() else None
        if not same_content(old, blob(install, ref, path), path):
            actions.append(("add" if old is None else "update", path))

    prev = previous_manifest(install)
    for path in (prev or {}).get("written", []):
        if path in files or is_protected(path) or skip_reason(path):
            continue
        if (install / path).exists():
            actions.append(("remove", path))

    return {"ref": ref, "actions": actions, "protected": protected_hits, "skipped": skipped}


def branch_ahead(install, ref):
    """分支 tip 比目标 ref 多几个提交。0 表示目标就是分支尖。

    默认目标是最新**标签**（AGENTS：tag 是唯一权威记录），于是打完标签后的每笔提交都
    不会被部署。这件事必须说出来 —— 否则使用者看到的是「刚推了一笔，更新却把文件改回
    去」，很像工具坏了或发生了降级，而真相只是「还没打标签」。
    """
    head = run_git("--git-dir", str(mirror_dir(install)), "rev-parse", "main",
                   check=False)
    if head.returncode != 0:
        return 0
    out = run_git("--git-dir", str(mirror_dir(install)), "rev-list", "--count",
                  f"{ref}..main", check=False)
    try:
        return int(out.stdout.decode().strip() or 0)
    except ValueError:
        return 0


def show_plan(install, plan, remote, remote_src, ck=None):
    lv, tv = local_version(install), ref_version(install, plan["ref"])
    # 取 `^{commit}`：注释标签的 rev-parse 给的是**标签对象**的哈希，跟 HEAD 对不上。
    # 使用者拿这一行去核对「取到的是不是那个提交」时会看到不一致，然后合理地怀疑工具解析错了 ref。
    short = run_git("--git-dir", str(mirror_dir(install)), "rev-parse", "--short",
                    f"{plan['ref']}^{{commit}}").stdout.decode().strip()
    print(f"远端      {remote}")
    print(f"来源      {remote_src}")
    print(f"目标      {plan['ref']}  ({short})  声明版本 {tv or '未声明'}")
    print(f"本地      Mozunitor/{lv or '未知'}")
    if lv and tv and lv == tv:
        # 版本一致不等于内容一致：本机就是「刚提交完但还没打标签」的常客。分两种说法，
        # 别让「已是最新」和「有差异」共用一句话 —— 那等于没看清单。
        if plan["actions"]:
            print(f"状态      版本都是 {lv}，但有 {len(plan['actions'])} 处文件差异"
                  f"（在制品，或标签之后又改过）")
        else:
            print(f"状态      已是最新（{lv}，文件清单为空）")
    elif lv and tv:
        print(f"状态      可更新  {lv} → {tv}")
    else:
        print("状态      版本号取不全，按文件清单决定")

    acts = plan["actions"]
    if not acts:
        print("\n文件      无需改动")
    else:
        print(f"\n文件      {len(acts)} 处改动")
        for kind, path in sorted(acts):
            mark = {"add": "新增", "update": "更新", "remove": "删除"}[kind]
            print(f"  [{mark}] {path}")

    print(f"\n不动      {len(plan['protected'])} 个端本地文件"
          f"（{', '.join(sorted(plan['protected'])) or '无'}）")
    for p in sorted(plan["protected"]):
        print(f"          · {p} —— {PROTECTED.get(p, '端本地')}")
    if plan["skipped"]:
        print(f"跳过      {len(plan['skipped'])} 个不属于安装的文件")
        seen = {}
        for p, why in plan["skipped"]:
            seen.setdefault(why, []).append(p)
        for why, ps in seen.items():
            print(f"          · {why}（{len(ps)} 个，如 {ps[0]}）")
    print(f"行尾      沿用每个文件现有的行尾；新文件用仓库里的那份（不按 core.autocrlf 猜）")
    n = branch_ahead(install, plan["ref"])
    if n:
        print(f"注意      分支 main 比 {plan['ref']} 多 {n} 个提交（未打标签）—— "
              f"它们**不会**被部署；要部署就 --ref main，或先给它打标签")
    if ck:
        print(f"工作副本  HEAD {ck['head']}"
              + (f"，**有 {len(ck['dirty'])} 处未提交改动**" if ck["dirty"] else "，工作区干净"))
    return lv, tv


# ------------------------------------------------------------------ 落盘与回滚
def apply_plan(install, plan):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = install / "logs" / f"update-backup-{stamp}"
    written, restored = [], []
    stamp_ref = run_git("--git-dir", str(mirror_dir(install)), "rev-parse",
                        plan["ref"]).stdout.decode().strip()

    for kind, path in sorted(plan["actions"]):
        dest = install / path
        if kind in ("update", "remove"):
            # 备份要保住相对路径：回滚是按同一套路径还原的
            b = backup / "files" / path
            b.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(dest, b)
        if kind == "remove":
            dest.unlink()
            continue
        new = fit_eol(blob(install, plan["ref"], path), dest, path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(new)
        written.append(path)

    (install / MIRROR_NAME).mkdir(parents=True, exist_ok=True)
    manifest = {"stamp": stamp, "ref": plan["ref"], "commit": stamp_ref,
                "written": written, "actions": [list(a) for a in plan["actions"]]}
    backup.mkdir(parents=True, exist_ok=True)
    (backup / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (install / MIRROR_NAME / "last.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    del restored
    return stamp, backup, manifest


def find_manifest(install, stamp):
    root = install / "logs"
    if stamp:
        f = root / f"update-backup-{stamp}" / "manifest.json"
        return f if f.exists() else None
    cands = sorted(root.glob("update-backup-*/manifest.json"))
    return cands[-1] if cands else None


def rollback(install, manifest_file):
    m = json.loads(manifest_file.read_text(encoding="utf-8"))
    backup = manifest_file.parent / "files"
    done = []
    for kind, path in m["actions"]:
        dest = install / path
        if kind == "add":
            if dest.exists():
                dest.unlink()
            done.append(("删掉新增", path))
            continue
        src = backup / path
        if not src.exists():
            done.append(("缺备份，跳过", path))
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        done.append(("还原", path))
    return m, done


# ------------------------------------------------------------------ 入口
def _fix_console() -> None:
    """别让控制台编码把工具自己弄死。

    Windows 上 Python 的 stdout 跟着控制台代码页走：本机那台是 UTF-8，M1K 是 GBK。
    计划里只要出现一个该代码页编不出的字符，print 就抛 UnicodeEncodeError —— 于是工具
    在**报告阶段**崩掉，而它本来正要说明「接下来会改哪些文件」。这个 bug 只在 M1K 上出现，
    因为本机那边调用时顺手设了 PYTHONIOENCODING=utf-8，把它盖住了。

    编码本身不动（GBK 控制台下中文仍然正常显示），只把错误策略改成替换：装不下的字符显示
    成 `?`，而不是让整条命令死掉。**别在输出里放 GBK 装不下的花体符号**（`↔` 就是）。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv=None):
    _fix_console()
    ap = argparse.ArgumentParser(description="Mozunitor 自更新（只同步代码，不动配置）")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--status", action="store_true", help="只报告：远端到哪了、会改哪些文件")
    g.add_argument("--apply", action="store_true", help="落盘（先备份）")
    g.add_argument("--rollback", nargs="?", const="", metavar="STAMP",
                   help="回滚一次更新；不给 STAMP 就回滚最近一次")
    ap.add_argument("--install", default=str(INSTALL_DEFAULT), help="安装目录")
    ap.add_argument("--remote", default=None, help="覆盖远端地址")
    ap.add_argument("--ref", default=None, help="指定标签/分支（缺省用最新的 vX.Y.Z）")
    ap.add_argument("--force", action="store_true",
                    help="安装目录是带未提交改动的 git 工作副本时，仍按 tag 覆盖（默认拒绝）")
    a = ap.parse_args(argv)

    install = Path(a.install).resolve()
    if not install.is_dir():
        print(f"安装目录不存在：{install}")
        return 2

    if a.rollback is not None:
        mf = find_manifest(install, a.rollback or None)
        if not mf:
            print("找不到可回滚的备份（logs/update-backup-*/manifest.json）")
            return 2
        m, done = rollback(install, mf)
        print(f"回滚      {m['ref']}  ({m['commit'][:7]})  备份 {m['stamp']}")
        for what, path in done:
            print(f"  [{what}] {path}")
        print(f"\n本地版本  现在 = Mozunitor/{local_version(install) or '未知'}")
        print("面板仍跑着旧代码 —— 要生效需重启它。")
        return 0

    remote, src = resolve_remote(install, a.remote)
    try:
        how = ensure_mirror(install, remote)
    except RuntimeError as e:
        print(f"取远端失败：{e}")
        return 3
    ref = a.ref or newest_tag(install)
    plan = build_plan(install, ref)
    ck = checkout_state(install)
    print(f"镜像      {mirror_dir(install)}（{how}）")
    lv, tv = show_plan(install, plan, remote, src, ck)

    if a.status:
        print("\n（--status 只报告，什么都没改）")
        return 0

    if ck and ck["dirty"] and not a.force:
        print(f"\n拒绝动手：这是 git 工作副本，且有 {len(ck['dirty'])} 处未提交改动。")
        print("  --apply 会把它们按 tag 覆盖掉 —— 在 checkout 型的端上，正确做法是：")
        print("      git pull --ff-only           # 或 git fetch && git checkout <tag>")
        print("  真要按 tag 抹平未提交改动，再显式加 --force。")
        return 5

    if not plan["actions"]:
        print("\n无需改动，什么都没写。")
        return 0

    stamp, backup, manifest = apply_plan(install, plan)
    print(f"\n写入      {len(manifest['written'])} 个文件")
    print(f"备份      {backup}")
    print(f"回滚      python tools\\update.py --rollback {stamp}")

    now = local_version(install)
    if tv and now != tv:
        print(f"\n自检失败：写完后本地版本是 {now}，目标是 {tv} —— 已备份，可回滚。")
        return 4
    print(f"自检      本地版本现在 = Mozunitor/{now}")
    print("\n面板仍跑着旧代码 —— 要生效需重启它（本工具刻意不动面板）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
