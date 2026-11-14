"""检查/修复 .ps1 的 UTF-8 BOM。

PowerShell 5.1 把无 BOM 的脚本按 ANSI 读，含中文的脚本会被读错 —— 而错法常常**不报错**：
某个多字节字符的尾字节吃掉换行，把下一行并进注释，脚本照跑但少做一件事（2026-10-12 实测：
collect_local.ps1 因此静默返回空进程表）。编辑器保存时很容易把 BOM 抹掉，所以这件事要能被检查。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BOM = b"\xef\xbb\xbf"


def candidates():
    for base in ("tools", "deploy"):
        d = ROOT / base
        if d.is_dir():
            yield from sorted(d.rglob("*.ps1"))


def main() -> int:
    fix = "--fix" in sys.argv
    bad = []
    for p in candidates():
        raw = p.read_bytes()
        nonascii = any(b >= 0x80 for b in raw)
        has_bom = raw.startswith(BOM)
        rel = p.relative_to(ROOT)
        if has_bom:
            print(f"OK    BOM 在  {rel}")
        elif nonascii:
            bad.append(rel)
            if fix:
                p.write_bytes(BOM + raw)
                print(f"修好  补 BOM  {rel}")
            else:
                print(f"!!    缺 BOM  {rel}")
        else:
            print(f"OK    纯 ASCII，不需要 BOM  {rel}")
    if bad and not fix:
        print(f"\n{len(bad)} 个含非 ASCII 的 .ps1 缺 BOM —— 用 --fix 补上")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
