#!/usr/bin/env python3
# 创建时间: 2026-09-17 20:23:23
# 用途: Mozunitor 后端 —— 采集本机与对端节点的常驻服务状态，
#       对外提供状态查询、日志尾部读取与单服务重启。
#       仅用标准库；仅监听回环地址。

from __future__ import annotations

import ast
import base64
import ctypes
import gzip
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mozunitor import tls as mtls
from mozunitor.net.listeners import (NetworkConfig, NetworkConfigError, NetworkServer,
                                     default_bind, ensure_allowed, serve_in_thread)
from mozunitor.net.listeners import stop as stop_network_server
from mozunitor.security.state import AuthError as SecurityAuthError
from mozunitor.security.state import SecurityState
from pathlib import Path

# 便携版（PyInstaller）里代码与静态资源在临时解包目录，可写状态要落在 exe 旁边。
FROZEN = getattr(sys, "frozen", False)
BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
APP_DIR = Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent
ROOT = APP_DIR
TOOLS = BUNDLE_DIR / "tools"
STATIC = BUNDLE_DIR / "static"

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
SSH = r"C:\WINDOWS\System32\OpenSSH\ssh.exe"
REMOTE_HOST = "peer"

# 配置路径可用 MOZU_CONFIG 覆盖：验收脚本要在隔离实例上把整个应用跑起来，
# 不能拿真实 services.json 去改端口、更不能碰真实服务。
CFG_PATH = Path(os.environ.get("MOZU_CONFIG") or (ROOT / "services.json"))
if not CFG_PATH.exists():
    _example = BUNDLE_DIR / "services.example.json"
    if _example.exists():
        try:
            shutil.copyfile(_example, CFG_PATH)
        except OSError:
            pass
CFG = json.loads(CFG_PATH.read_text(encoding="utf-8"))
SERVICES = CFG["services"]
GROUP_DEFS = CFG["groups"]
INTERVALS = CFG["intervals"]
# 标了 ondemand 的组是「按需拉起」的自建项目：不在线是常态，不参与顶栏的在线统计。
# 判据取自配置而不是组名，改名或再开一个按需组都不必动后端。
ONDEMAND_GROUPS = {g["id"] for g in GROUP_DEFS if g.get("ondemand")}

# 监控分级：每个服务在 services.json 里显式声明 tier。旧配置没有这个字段时按分组推导
# （infra -> core，local/remote -> normal，按需组 -> optional），便于两端滚动升级。
TIER_ORDER = ("core", "normal", "optional")
TIER_LEGACY = {"infra": "core", "local": "normal", "remote": "normal"}
UI_DEFAULTS = {
    "card": {"role": False, "detail": True, "metrics": False, "deps": False,
             "note": False, "warn": True, "badges": True, "keepalive": True},
    "collapse": {"core": "auto", "normal": "collapsed", "optional": "collapsed"},
    "mobile_hide_optional": True,
}


def svc_tier(svc: dict) -> str:
    """一条服务的监控级别；缺省按旧 group 推导，未知值退回 normal。"""
    tier = str(svc.get("tier") or "")
    if tier in TIER_ORDER:
        return tier
    if svc.get("group") in ONDEMAND_GROUPS:
        return "optional"
    return TIER_LEGACY.get(str(svc.get("group") or ""), "normal")


def ui_config() -> dict:
    """前端显示默认值：全局卡片字段、折叠策略与移动端取舍。"""
    cfg = CFG.get("ui") or {}
    out = json.loads(json.dumps(UI_DEFAULTS))     # 深拷贝，避免调用方改到默认值
    for key in ("card", "collapse"):
        if isinstance(cfg.get(key), dict):
            out[key].update(cfg[key])
    if isinstance(cfg.get("mobile_hide_optional"), bool):
        out["mobile_hide_optional"] = cfg["mobile_hide_optional"]
    return out


# 本机在 mesh 里的身份：对等节点靠这个 id 区分状态来自哪一台
NODE = CFG.get("node") or {}
NODE_ID = str(NODE.get("id") or "local")
NODE_NAME = str(NODE.get("name") or "本机")

# 对等节点：mesh 下每端各跑一份面板，互相拉对方的原子快照（/api/node）。
# token 不写进 services.json —— 那个文件进 git，凭据只能落在 .state 下。
PEERS = [p for p in ((CFG.get("peers") or {}).get("list") or [])
         if isinstance(p, dict) and p.get("url")]
PEER_POLL_S = max(2.0, INTERVALS.get("peer_poll_ms", 5000) / 1000.0)
PEER_TIMEOUT_S = 8.0
# 对端快照超过这么久没更新，就不再拿它当存活判据，退回本机探测并标明这是降级判断。
# 取 12 个轮询周期：偶发一两轮拉取失败不该让卡片上的判据来回横跳。
PEER_SNAPSHOT_STALE_S = 60.0
# 远端采集（整段脚本经 SSH 送过去）会**间歇性卡死**：2026-10-13 实测同一段 bootstrap 有时
# 2.4 秒返回、有时 20 秒不返回（那时 tailnet 只能走 DERP 中继，本机与对端已不在同一路由器下）。
# 所以单次超时不能当结论：短超时 + 重试，且**连续失败到 REMOTE_DOWN_STREAK 才翻成离线** ——
# 与保活的 KEEPALIVE_DOWN_STREAK 同一个道理。存活判据本身已经不依赖这条通道（见 resolve_status）。
REMOTE_ATTEMPT_TIMEOUT_S = 25.0
REMOTE_ATTEMPTS = 2
REMOTE_RETRY_GAP_S = 3.0
REMOTE_DOWN_STREAK = 2
# 转发的动作超时给得比本机宽：对端的重启同样要等到端口真的起来才返回
FORWARD_TIMEOUT_S = 180.0
# 同一个 peer 两次「经 SSH 拉起」之间至少隔这么久：面板每几秒轮询一轮，不节流会把
# SSH 打爆；而对端根本没装面板这种情形，也不是拉一把能解决的。
PEER_REVIVE_S = 300.0

# 保活：被标 keepalive 的服务由面板自己拉起。三个数都是安全阀 ——
# 去抖避免抖动误判（探测本身有 3 秒一轮的粒度），退避避免打爆对端，
# 上限避免对着一个根本起不来的服务无限重试。
KEEPALIVE_DOWN_STREAK = 3
KEEPALIVE_BACKOFF_S = (60.0, 120.0, 300.0)
KEEPALIVE_MAX_FAILS = 5
# 拉起命令执行完后仍要在对端多留一会儿。启动器多是 GUI/无控制台程序（wscript、start），
# PowerShell 不会等它们跑完就返回，SSH 会话随即关闭并把它们回收 —— 表现出来就是
# 「指令已下发，端口却始终没起来」。实测 wscript 走完 WMI Create 需要数秒。
PEER_START_GRACE_S = 5.0

# 自动发现：扫 tailnet 找同类节点。发现来的 peer 与手工配的走完全相同的鉴权 ——
# 对方不认这个用户名就什么都不返回，所以「同类」不是靠扫描本身保证的。
TAILSCALE = shutil.which("tailscale") or r"C:\Program Files\Tailscale\tailscale.exe"
DISCOVER_CFG = (CFG.get("peers") or {}).get("discover") or {}
DISCOVER_ON = bool(DISCOVER_CFG.get("tailscale", True))
DISCOVER_EVERY_S = max(15.0, float(DISCOVER_CFG.get("every_s", 60)))
DISCOVER_TIMEOUT_S = 2.5

# ---------------------------------------------------------------- 监听面
# 1.1.0 起配置允许 `listen.local` / `listen.network`；旧配置只有 host/port，
# 这里折算成本地 listener；旧的「非回环 host」迁移成网络模式（强制 HTTPS）。
_LISTEN_CFG = CFG.get("listen") if isinstance(CFG.get("listen"), dict) else {}
_LEGACY_LISTEN = _LISTEN_CFG.get("local") is None
_LOCAL_LISTEN = (_LISTEN_CFG.get("local")
                 if isinstance(_LISTEN_CFG.get("local"), dict) else _LISTEN_CFG)
LOCAL_HOST = str(_LOCAL_LISTEN.get("host") or "127.0.0.1")
LOCAL_PORT = int(_LOCAL_LISTEN.get("port") or 8090)
MIGRATION_NOTE = ""
if _LEGACY_LISTEN and LOCAL_HOST not in ("127.0.0.1", "localhost", "::1"):
    _legacy_bind = "" if LOCAL_HOST in ("0.0.0.0", "::", "*") else LOCAL_HOST
    try:
        _legacy_bind = _legacy_bind or default_bind("lan")
    except NetworkConfigError:
        _legacy_bind = ""
    LOCAL_HOST = "127.0.0.1"
    NETWORK_CFG = NetworkConfig(enabled=True, mode="lan", bind=_legacy_bind,
                                port=NetworkConfig().port)
    MIGRATION_NOTE = ("原配置 listen.host 为非回环地址，已迁移为 HTTPS 网络入口；"
                      "请按提示确认证书指纹")
else:
    try:
        NETWORK_CFG = NetworkConfig.from_dict(
            (_LISTEN_CFG.get("network") or {}) if not _LEGACY_LISTEN else {})
    except NetworkConfigError as _exc:
        print(f"[网络] listen.network 配置无效，按关闭处理：{_exc}")
        NETWORK_CFG = NetworkConfig()
NET_SERVER = None                     # 运行中的网络 listener（HTTPS）
TLS_FINGERPRINT = ""                  # 自签证书指纹（网络入口未开启时为空）

# 安全状态：管理员口令、会话、launch/local token、限流与审计。
# 1.1.0 起 Handler 不再自己判“回环免鉴权”，一切经 SecurityState.authorize()。
_SECURITY_CFG = CFG.get("security") or {}
SECURITY = SecurityState(
    ROOT, port=LOCAL_PORT, net_host=LOCAL_HOST, net_port=NETWORK_CFG.port,
    network=NETWORK_CFG,
    ttl_s=int(_SECURITY_CFG.get("session_ttl_s", 1800)),
    max_age_s=int(_SECURITY_CFG.get("session_max_age_s", 2592000)),
    login_window_s=int(_SECURITY_CFG.get("login_window_s", 300)),
    login_max_failures=int(_SECURITY_CFG.get("login_max_failures", 5)),
    lockout_s=int(_SECURITY_CFG.get("lockout_s", 300)),
)
SERVER_VERSION = "Mozunitor/1.0.3"


# 远端 Ollama 的模型状态：直接走 HTTP，不经 SSH。expires_at 是绝对时间戳、倒计时由前端算，
# 故 5 秒采样已够；可用模型清单几乎不变，每 MODELS_TAGS_EVERY 轮才拉一次。
MODELS_POLL_S = 5.0
MODELS_TAGS_EVERY = 12
# 上下文档位。Ollama 不指定时用「模型默认」：qwen35-9b:latest 是 262144（实测 9.85 GB 显存
# + 1.87 GB 溢出、加载 19 s），qwen3-embedding 是 4096。16384 / 131072 对应远程的
# qwen35-9b:16k / :131k 变体（实测 5.27 / 7.60 GB，零溢出）。
# CTX_MODEL_DEFAULT 表示不下发 options.num_ctx —— 变体之间的区别正是靠模型自带值生效。
CTX_CHOICES = (4096, 8192, 16384, 32768, 131072, 262144)
CTX_MODEL_DEFAULT = 0
KEEP_CHOICES = ("5m", "30m", "1h", -1)   # -1 表示永久，直到手动卸载

# RAG 检索层的参数展示与验证链（可选功能；未配置相关服务时不会启用）。
# 项目约定不改动 RAG 的既有代码，所以不向 RAG 加配置端点：参数改为只读解析
# rag_server.py 的模块级常量，验证则复用它已有的三个脚本。
# 注意 calibrate_thresholds.py 默认会写 <LLMdeploy>\calibration.json —— 用 --out 改写到
# 本面板的 logs 下，否则验证链会改动被监控项目的文件（实测踩到过）。
LLMDEPLOY = Path(os.environ.get("MOZU_LLMDEPLOY") or r"C:\LLMdeploy")
RAG_SRC = LLMDEPLOY / "rag_server.py"
RAG_URL = os.environ.get("MOZU_RAG_URL") or "http://127.0.0.1:8000"
CALIB_OUT = ROOT / "logs" / "calibration.json"
RAG_STEPS = (
    ("阈值标定", r"tools\calibrate_thresholds.py", ("--url", RAG_URL, "--out", str(CALIB_OUT))),
    ("路由 check B", r"tools\route_check.py", ("--url", RAG_URL)),
    ("回归 check A", r"tools\regression_check.py",
     ("--baseline", "baseline_optical.json", "--url", RAG_URL)),
)
RAG_STEP_TIMEOUT = 1800      # 单步上限(秒)。GPU 忙时 check B 可达数分钟
RAG_TAIL_LINES = 60          # 每步只留输出尾部
RAG_PARAM_GROUPS = (
    ("端点与模型", ("OLLAMA_URL", "LLM_MODEL", "REWRITE_MODEL", "EMBED_MODEL",
                    "RAG_MODEL_ID", "BIND_HOST", "PUBLIC_BASE", "PORT", "KEEP_ALIVE")),
    ("检索", ("TOP_K_DEFAULT", "PER_SOURCE_CAP", "PROMPT_CHUNK_CHARS",
              "EDGE_PATCH_CHARS", "PROMPT_TOTAL_CHARS", "FORMULA_BONUS")),
    ("路由阈值", ("ROUTE_MARGIN", "OUT_OF_LIB_FLOOR", "LOW_CONF_FLOOR")),
    ("词法通道", ("KW_ENABLED", "KW_WEIGHT", "KW_SAT", "KW_MIN_HITS", "KW_B", "KW_K1")),
    ("多轮历史并入", ("HIST_MAX_MSGS", "HIST_MAX_CHARS", "HIST_MIN_SIM",
                      "HIST_KEEP", "HIST_USER_CHARS", "HIST_ASSIST_CHARS")),
)

# SillyTavern 的只读采集。三处来源各管一段：config.yaml 是服务端策略、
# data\default-user\settings.json 是客户端连什么、data\access.log 是运行痕迹。
# config.yaml 里 basicAuthUser.password 是明文口令 —— 只按白名单取标量，
# 且值要再过一遍 _safe_cfg_value，解析错位也带不出口令。
ST_DIR = Path(os.environ.get("MOZU_SILLYTAVERN") or r"C:\SillyTavern")
ST_CONFIG = ST_DIR / "config.yaml"
ST_SETTINGS = ST_DIR / "data" / "default-user" / "settings.json"
ST_ACCESS = ST_DIR / "data" / "access.log"
ST_ACCESS_TAIL = 400        # access.log 只读尾部
ST_ACCESS_KEEP = 10         # 视图里保留的最近访问条数
ST_UA_NOISE = "Python-urllib"   # 本面板自己的探测，混在真实访问里会淹掉信号

# DSH 的 provider 声明。它和酒馆一样走 OpenAI 兼容端点、一样不传 num_ctx，
# 并排才看得出「声明值根本不约束 Ollama」是系统性的，不是酒馆配错了。
DSH_SETTINGS = Path.home() / ".dsh" / "settings.yaml"

# YAML 取值白名单：(路径, 展示名)。不在此列的键永不进入返回值。
ST_CFG_KEYS = (
    (("port",), "监听端口"),
    (("listenAddress", "ipv4"), "监听地址"),
    (("heartbeatInterval",), "心跳间隔"),
    (("whitelistMode",), "IP 白名单"),
    (("basicAuthMode",), "basicAuth"),
    (("sessionTimeout",), "会话超时"),
    (("enableUserAccounts",), "多用户模式"),
    (("enableServerPlugins",), "服务端插件"),
    (("ssl", "enabled"), "SSL"),
    (("logging", "enableAccessLog"), "访问日志"),
    (("logging", "minLogLevel"), "终端日志级别"),
    (("rateLimiting", "basicAuthMaxAttempts"), "认证失败上限"),
)
DSH_PROVIDER = os.environ.get("MOZU_DSH_PROVIDER") or "peer"
DSH_CTX_PATH = ("providers", DSH_PROVIDER, "contextWindow")

# 酒馆的创作资产：角色卡（PNG 内嵌 base64 JSON）与世界书（独立 JSON）。
# 角色卡 PNG 单张可达 500 KB，3 秒轮询不能反复读，故按「文件清单指纹」缓存整轮扫描结果。
ST_CHARS_DIR = ST_DIR / "data" / "default-user" / "characters"
ST_WORLDS_DIR = ST_DIR / "data" / "default-user" / "worlds"
ST_PREVIEW_CHARS = 58       # 预览截断长度
# 角色卡里值得报字数的正文字段（顺序即展示顺序）
ST_CARD_FIELDS = ("description", "personality", "scenario", "first_mes", "mes_example",
                  "system_prompt", "post_history_instructions", "creator_notes")
ST_FIELD_LABEL = {"description": "描述", "personality": "性格", "scenario": "场景",
                  "first_mes": "开场白", "mes_example": "对话示例", "system_prompt": "系统提示",
                  "post_history_instructions": "历史后指令", "creator_notes": "创作者注记"}
# token 系数：用 qwen35-9b 的 prompt_eval_count 实测标定 —— 444 个 CJK 字符 344.5 tokens、
# 1416 个非 CJK 字符 347 tokens，回代中英混合样本误差 2%。启动基线 11 tokens 不计入，
# 因为世界书与角色卡是拼进已有 prompt 的一部分，不单独承担模板开销。
_TOK_CJK = 0.776
_TOK_OTHER = 0.245


def _is_cjk(ch: str) -> bool:
    o = ord(ch)
    return (0x4E00 <= o <= 0x9FFF or 0x3400 <= o <= 0x4DBF or 0x3040 <= o <= 0x30FF
            or 0xF900 <= o <= 0xFAFF)


def est_tokens(s: str) -> int:
    """按标定系数估算 token 数。中文一字约 0.78 token，英文一字符约 0.245。"""
    if not s:
        return 0
    cjk = sum(1 for ch in s if _is_cjk(ch))
    return round(cjk * _TOK_CJK + (len(s) - cjk) * _TOK_OTHER)

# 本机开着系统代理（FlClash 7890）且环境变量里也有 HTTP_PROXY。被监控的服务全在
# 回环或 Tailscale 内网，绕代理既没必要也会把 FlClash 的存亡变成探测结果的一部分，
# 所以探测一律走直连 opener。
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _strip_comment(raw: str) -> str:
    """YAML 的注释要求 # 前是空白或行首；值里的 # 不能当注释切掉。"""
    for i, ch in enumerate(raw):
        if ch == "#" and (i == 0 or raw[i - 1] in " \t"):
            return raw[:i]
    return raw


def _safe_cfg_value(v: str) -> str | None:
    """只放行布尔、整数与监听地址。

    这是口令不外流的第二道闸：即使 _yaml_scalars 的路径判断出岔子，
    含 @ 或字母的值也走不到视图里。
    """
    if v in ("true", "false", "0.0.0.0", "[::]", "::1", "127.0.0.1", "localhost"):
        return v
    body = v[1:] if v.startswith("-") else v
    return v if body.isdigit() and len(body) <= 7 else None


def _yaml_scalars(text: str, want) -> dict[tuple[str, ...], str]:
    """缩进感知的极简 YAML 标量提取，只回 want 里的路径。

    不处理列表与流式集合、不做类型推断 —— 面板只要几个已知标量，而完整 YAML
    解析要引第三方依赖（SPEC 第 4 节禁）。只有能通向 want 路径的块才压栈，
    所以 ssl.keyPassphrase 这类空值块不会被误当成下一层的父级。
    """
    want = set(want)
    found: dict[tuple[str, ...], str] = {}
    stack: list[tuple[int, str]] = []
    for raw in text.splitlines():
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        key, sep, val = line.strip().partition(":")
        if not sep:
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = tuple(k for _, k in stack) + (key,)
        if val.strip():
            if path in want:
                found[path] = val.strip().strip("'\"")
        elif any(w[:len(path)] == path for w in want):
            stack.append((indent, key))
    return found


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def decode_smart(data: bytes) -> str:
    """日志编码不统一：PowerShell 重定向常产出 UTF-16LE，Python 与 Ollama 产出 UTF-8，
    PowerShell 5.1 的 Add-Content 在旧文件里还可能留下 GBK。"""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    head = data[:2048]
    if head.count(0) > len(head) // 4:            # 无 BOM 的 UTF-16LE：ASCII 高位字节恒为 0
        return data.decode("utf-16-le", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("gbk", "replace")


# ---------------------------------------------------------------- 外部进程调用

# 面板以 pythonw 运行，自己没有控制台：子进程若不带这个标志，Windows 会给它**新开一个**
# 控制台窗口。以前面板只在 Session 0（无桌面）跑，看不见；2026-10-12 把它移进用户的
# console 会话后立刻表现为「不停弹出黑框」—— 每轮采集一个。所有 subprocess 调用都要带上。
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def run_ps_inline(script: str, timeout: float = 30) -> tuple[str, str]:
    """用 -EncodedCommand 执行 PowerShell 片段，绕开所有引号与管道转义问题。"""
    blob = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        r = subprocess.run([PS, "-NoProfile", "-NonInteractive", "-EncodedCommand", blob],
                           capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired:
        return "", f"PowerShell 超时（{timeout}s）"
    except OSError as e:
        return "", f"PowerShell 启动失败: {e}"
    return (r.stdout.decode("utf-8-sig", "replace").strip(),
            r.stderr.decode("utf-8-sig", "replace").strip())


def run_ps_file(path: Path, timeout: float = 60, args: list[str] | None = None) -> tuple[str, str]:
    try:
        r = subprocess.run([PS, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                            "-File", str(path), *(args or [])], capture_output=True, timeout=timeout,
                           creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired:
        return "", f"脚本超时（{timeout}s）: {path.name}"
    except OSError as e:
        return "", f"脚本启动失败: {e}"
    return (r.stdout.decode("utf-8-sig", "replace").strip(),
            r.stderr.decode("utf-8-sig", "replace").strip())


def ssh_inline(script: str, timeout: float = 40, host: str | None = None) -> tuple[str, str]:
    """在远端执行 PowerShell 片段；host 缺省仍是 REMOTE_HOST（对端）。

    mesh 下这条通道只干两件事：对端 HTTP 不通时拉起它的面板，以及降级采集。
    它不参与常规状态获取 —— 那是 /api/node 的活。

    **脚本经 stdin 送过去，不进命令行**：远端默认 shell 是 cmd.exe，命令行上限 8191 字符，
    而 `-EncodedCommand` 要的是 UTF-16LE 的 base64（体积是原文的 2.7 倍）。脚本一旦超过约
    3 KB 就被 cmd 截断 —— 现象是 ssh 返回 1、stdout 全空、stderr 只有一行乱码，看起来像
    「远端不可达」（2026-10-12 实测：给 collect_remote.ps1 加命令行采集后正好撞上，
    8652 > 8191）。所以命令行里只有一个定长 bootstrap，gzip+base64 的脚本走 stdin（纯
    ASCII，不受任何编码假设影响，也不再受长度限制）。
    """
    b64 = base64.b64encode(gzip.compress(script.encode("utf-8"), 9)).decode("ascii")
    bootstrap = ("$b=[Console]::In.ReadToEnd();"
                 "$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String($b));"
                 "$z=New-Object IO.Compression.GzipStream($m,[IO.Compression.CompressionMode]::Decompress);"
                 "$r=New-Object IO.StreamReader($z,[Text.Encoding]::UTF8);"
                 "Invoke-Expression $r.ReadToEnd()")
    cmd = [SSH, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host or REMOTE_HOST,
           f'powershell -NoProfile -NonInteractive -Command "{bootstrap}"']
    try:
        r = subprocess.run(cmd, input=b64.encode("ascii"), capture_output=True, timeout=timeout,
                           creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired:
        return "", f"SSH 超时（{timeout}s）"
    except OSError as e:
        return "", f"SSH 启动失败: {e}"
    # 远端 PowerShell 经 SSH 回来的字节是 UTF-16LE（带 BOM），不是 UTF-8 ——
    # 固定按 utf-8 解码会把中文变成 U+FFFD。以前只传 ASCII（端口号、READY）所以没暴露，
    # 2026-09-23 读远端 RAG 的中文日志时才现形。decode_smart 本就认 UTF-16 BOM。
    out = decode_smart(r.stdout).strip()
    err = decode_smart(r.stderr).strip()
    if err.lstrip().startswith("#< CLIXML"):     # PowerShell 经 SSH 复现的进度流，不是错误
        err = ""
    return out, err


# ---------------------------------------------------------------- 探测原语

def probe_tcp(host: str, port: int, timeout: float = 2.5) -> tuple[bool, float]:
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout):
            return True, (time.perf_counter() - t0) * 1000
    except OSError:
        return False, (time.perf_counter() - t0) * 1000


def probe_http(url: str, ok_codes: list[int], timeout: float = 5.0) -> tuple[bool, float, str]:
    t0 = time.perf_counter()
    req = urllib.request.Request(url, headers={"User-Agent": "Mozunitor/1.0"})
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:                                   # noqa: BLE001 —— 网络异常种类繁多
        return False, (time.perf_counter() - t0) * 1000, type(e).__name__
    ms = (time.perf_counter() - t0) * 1000
    return code in ok_codes, ms, f"HTTP {code}"


# ------------------------------------------------------------ 端口声明

def split_hostport(spec) -> tuple[str | None, int]:
    """把配置里的「端口」解析成 (地址, 端口)。

    **端口号本身不是身份**。对端 上 8000 被两个服务分开用：RAG 绑 Tailscale 地址，
    OENexus 绑回环。只按端口号匹配的检查在那台机器上会同时做三件错事 —— 杀错进程、
    等错进程（报出一个假的成功）、按端口取到对方的 pid 把内存显示错。所以
    `kill_port` / `wait_port` / `pid_ref.port` 都接受两种写法：

        8000                  → (None, 8000)         任意地址（旧的裸整数照旧）
        "8000"                → (None, 8000)
        "127.0.0.1:8000"   → ("127.0.0.1", 8000)
        "[::1]:8000"          → ("::1", 8000)

    地址匹配口径与 对端 启动脚本的 `Test-Port -Address` 逐字一致：**通配绑定
    （0.0.0.0 / ::）在任意地址上都算命中，另一个具体地址不算**。两处若不一致，
    同一件事就会在两台机器上有两套判断。
    """
    if spec is None or isinstance(spec, bool):
        raise ValueError(f"端口声明不合法：{spec!r}")
    if isinstance(spec, int):
        return None, spec
    text = str(spec).strip()
    if text.isdigit():
        return None, int(text)
    if text.startswith("["):                       # [::1]:8000
        host, _, rest = text[1:].partition("]")
        if not host or not rest.startswith(":") or not rest[1:].isdigit():
            raise ValueError(f"端口声明不合法：{spec!r}")
        return host, int(rest[1:])
    host, sep, tail = text.rpartition(":")
    if not sep or not host or not tail.isdigit():
        raise ValueError(f"端口声明不合法（要「端口」或「地址:端口」）：{spec!r}")
    return host, int(tail)


def addr_matches(bound: str, want: str | None) -> bool:
    """绑定地址是否满足要求。want=None 表示不管绑在哪；通配绑定服务所有地址。"""
    if want is None:
        return True
    return bound == want or bound in ("0.0.0.0", "::")


def port_label(spec) -> str:
    """给日志与步骤用的一行写法。`*:8000` 读作「任意地址」。"""
    host, port = split_hostport(spec)
    return f"{host or '*'}:{port}"


def _port_addr_filter(host: str | None) -> str:
    """PowerShell 里按地址过滤监听者的片段；host 为空时不过滤（保持旧行为）。"""
    if not host:
        return ""
    return (" | Where-Object { $_.LocalAddress -eq " + _ps_quote(host)
            + " -or $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' }")


def ollama_get(base: str, path: str, timeout: float = 8.0) -> dict:
    req = urllib.request.Request(base + path, headers={"User-Agent": "Mozunitor/1.0"})
    with _OPENER.open(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def ollama_post(base: str, path: str, payload: dict, timeout: float = 240.0) -> dict:
    """带空 prompt 的 /api/generate 是 Ollama 的加载/卸载约定：不产出 token，只改常驻状态。"""
    req = urllib.request.Request(base + path, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "Mozunitor/1.0"})
    with _OPENER.open(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def model_num_ctx(base: str, name: str) -> int | None:
    """模型自带的 num_ctx —— 客户端不传时，Ollama 就按这个值分配 KV cache。

    /api/show 的 parameters 是一段纯文本，每行「键 值」。走 OpenAI 兼容端点的客户端
    （DSH、酒馆）都没法覆盖它，所以这个值决定它们实际付多少显存。
    """
    try:
        blob = ollama_post(base, "/api/show", {"model": name}, timeout=10.0).get("parameters")
    except Exception:                                        # noqa: BLE001
        return None
    for line in (blob or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "num_ctx":
            try:
                return int(parts[1])
            except ValueError:
                return None
    return None


# ---------------------------------------------------------------- 状态容器

class State:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.local: dict = {"ports": [], "procs": [], "cores": os.cpu_count() or 8,
                            "at": 0.0, "error": None}
        self.remote: dict = {"ports": [], "procs": [], "cores": 16, "at": 0.0,
                             "online": False, "error": None, "task": {}, "models": []}
        self.probes: dict[str, dict] = {}
        self.since: dict[str, float] = {}
        self.cpu_prev: dict[tuple, tuple] = {}
        self.cpu_pct: dict[tuple, float] = {}
        self.restart_log: list[dict] = []
        self.models: dict[str, dict] = {}    # 服务 id -> {at, error, loaded, available}
        self.verify: dict | None = None      # RAG 验证链的最近一次运行状态
        self.peers: dict[str, dict] = {}     # 对等节点 id -> {online, at, latency_ms, error, snapshot}
        self.started_at = time.time()

    # -- CPU 需要两次采样求差 -------------------------------------------
    def _update_cpu(self, where: str, procs: list[dict], cores: int) -> None:
        now = time.time()
        for p in procs:
            if p.get("cpu", -1) < 0:
                continue
            key = (where, p["pid"])
            prev = self.cpu_prev.get(key)
            if prev:
                dt = now - prev[1]
                delta = p["cpu"] - prev[0]
                if dt > 0.5 and delta >= 0:
                    self.cpu_pct[key] = round(delta / dt / max(1, cores) * 100, 1)
            self.cpu_prev[key] = (p["cpu"], now)

    def set_local(self, data: dict) -> None:
        with self.lock:
            cores = int(data.get("cores") or os.cpu_count() or 8)
            self.local = {"ports": data.get("ports", []), "procs": data.get("procs", []),
                          "cores": cores, "at": time.time(), "error": None,
                          "tasks": data.get("tasks", []),
                          # 采集侧自报的诊断：点名了哪些进程名、真取到多少条命令行。
                          # 命令行那一列是空的时，这两个数能立刻指出是哪一头的事。
                          "cmd_names": data.get("cmd_names", ""),
                          "cmd_probed": data.get("cmd_probed", 0)}
            self._update_cpu("local", self.local["procs"], cores)

    def set_remote(self, data: dict) -> None:
        with self.lock:
            cores = int(data.get("cores") or 16)
            self.remote = {"ports": data.get("ports", []), "procs": data.get("procs", []),
                           "cores": cores, "at": time.time(), "online": True, "error": None,
                           "task": data.get("task", {}), "models": data.get("models", []),
                           "tasks": data.get("tasks", []),
                           "cmd_names": data.get("cmd_names", ""),
                           "cmd_probed": data.get("cmd_probed", 0)}
            self._update_cpu("remote", self.remote["procs"], cores)

    def remote_failed(self, err: str) -> None:
        with self.lock:
            self.remote["online"] = False
            self.remote["error"] = err
            self.remote["at"] = time.time()

    # -- 对等节点 -------------------------------------------------------
    def set_peer(self, pid: str, snap: dict, latency_ms: float) -> None:
        with self.lock:
            self.peers[pid] = {"online": True, "error": None, "at": time.time(),
                               "latency_ms": latency_ms, "snapshot": snap,
                               # 快照自己的时刻。拉取失败时 at 会变成「失败时刻」，
                               # 拿它算年龄会把一份很旧的快照当成刚更新的。
                               "snap_at": time.time()}

    def peer_failed(self, pid: str, err: str) -> None:
        """拉取失败时保留上一次的快照：面板要能区分「对方离线」与「从没联系上」。"""
        with self.lock:
            prev = self.peers.get(pid) or {}
            self.peers[pid] = {"online": False, "error": err, "at": time.time(),
                               "latency_ms": None, "snapshot": prev.get("snapshot"),
                               "snap_at": prev.get("snap_at")}

    def record_probe(self, sid: str, status: str, latency: float, detail: str) -> None:
        with self.lock:
            prev = self.probes.get(sid)
            if not prev or prev["status"] != status:
                self.since[sid] = time.time()
            self.probes[sid] = {"status": status, "latency_ms": round(latency, 1),
                                "detail": detail, "at": time.time()}

    # -- 查询辅助 -------------------------------------------------------
    def pid_of(self, where: str, port: int, host: str | None = None) -> int | None:
        with self.lock:
            table = self.local if where == "local" else self.remote
            for entry in table["ports"]:
                if entry["port"] == port and addr_matches(entry.get("addr", ""), host):
                    return entry["pid"]
        return None

    def pids_of(self, where: str, port: int, host: str | None = None) -> list[int]:
        """同一端口可能被多个进程持有（IPv4 / IPv6 各一个），统计内存时不能只取第一个。

        给了 host 就只算满足该地址的监听者 —— 否则 对端 上统计 RAG 的内存会把
        OENexus 也算进去（反之亦然）。
        """
        with self.lock:
            table = self.local if where == "local" else self.remote
            return [e["pid"] for e in table["ports"]
                    if e["port"] == port and addr_matches(e.get("addr", ""), host)]

    def pid_of_name(self, where: str, name: str, cmd: str | None = None) -> int | None:
        """端口不固定的服务只能按进程名定位（UU 远程会在多张网卡上随机端口）。

        `cmd` 是命令行子串，用于**名字撞车**的情形：对端 上有六个 python.exe（HUST 自动登录、
        OENexus 的两个 uvicorn、http.server、ollama-proxy、rag），只按名字取必然张冠李戴 ——
        卡片上会显示另一个进程的内存。命令行只有 CIM 拿得到，所以那一列由采集侧按需补。
        """
        want = (cmd or "").lower()
        with self.lock:
            procs = self.local["procs"] if where == "local" else self.remote["procs"]
            hit = next((p for p in procs if p.get("name") == name
                        and (not want or want in (p.get("cmd") or "").lower())), None)
        return hit["pid"] if hit else None

    def proc_info(self, where: str, pid: int | None) -> dict:
        if pid is None:
            return {}
        with self.lock:
            procs = self.local["procs"] if where == "local" else self.remote["procs"]
            info = next((p for p in procs if p["pid"] == pid), None)
            pct = self.cpu_pct.get((where, pid))
        if not info:
            return {"pid": pid}
        out = {"pid": pid, "proc_name": info.get("name"), "mem_mb": info.get("mem"),
               "cpu_pct": pct, "start": info.get("start"), "path": info.get("path")}
        started = info.get("start")
        if started:
            try:
                out["uptime_s"] = int(time.time() - datetime.fromisoformat(started).timestamp())
            except (ValueError, TypeError):
                pass
        return out


STATE = State()
_RESTART_LOCK = threading.Lock()          # 同一时刻只允许一个重启任务
KEEPALIVE: dict[str, dict] = {}           # 各被保活服务的运行状态，见 keepalive_state()

ACTION_LOG = Path(os.environ.get("MOZU_ACTION_LOG") or (ROOT / "logs" / "actions.jsonl"))


class _JobIoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _JobBasicLimit(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _JobExtendedLimit(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobBasicLimit),
        ("IoInfo", _JobIoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


_KILL_ON_JOB_CLOSE = 0x2000
_JobObjectExtendedLimitInformation = 9


def parent_image() -> str:
    """父进程的映像名。这是判断「面板是被谁拉起来的」最直接的一条线索：
    WmiPrvSE.exe 说明经 WMI 创建、已脱离调用方；wscript/node 则可能仍挂在宿主 Job 上。"""
    try:
        from ctypes import wintypes
        k = ctypes.windll.kernel32
        k.OpenProcess.restype = wintypes.HANDLE
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                 wintypes.LPWSTR,
                                                 ctypes.POINTER(wintypes.DWORD)]
        handle = k.OpenProcess(0x1000, False, os.getppid())   # QUERY_LIMITED_INFORMATION
        if not handle:
            return "已退出"
        buf = ctypes.create_unicode_buffer(512)
        size = wintypes.DWORD(512)
        ok = k.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
        k.CloseHandle(handle)
        return buf.value.rsplit("\\", 1)[-1] if ok else "未知"
    except Exception:                                          # noqa: BLE001
        return "未知"


def job_verdict() -> str:
    """一句话说清「宿主退出时本面板会不会被一起回收」。

    Job Object 是单向的：进程一旦落进去就出不来。所以判据不是「在不在 Job 里」——
    WmiPrvSE.exe 自己就带着 Job——而是这个 Job 有没有设 KILL_ON_JOB_CLOSE。
    """
    try:
        k = ctypes.windll.kernel32
        k.GetCurrentProcess.restype = ctypes.c_void_p
        k.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.POINTER(ctypes.c_int)]
        k.IsProcessInJob.restype = ctypes.c_int
        k.QueryInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                                ctypes.c_void_p, ctypes.c_uint32,
                                                ctypes.c_void_p]
        k.QueryInformationJobObject.restype = ctypes.c_int

        flag = ctypes.c_int(0)
        if not k.IsProcessInJob(k.GetCurrentProcess(), None, ctypes.byref(flag)):
            return "无法判定（IsProcessInJob 失败）"
        if not flag.value:
            return "不在任何 Job 内 ✓"

        info = _JobExtendedLimit()
        # QueryInformationJobObject 传 NULL 句柄时查的就是调用进程所在的 Job
        if not k.QueryInformationJobObject(None, _JobObjectExtendedLimitInformation,
                                           ctypes.byref(info), ctypes.sizeof(info), None):
            return "在 Job 内（读不到 Job 属性，无法判定风险）"
        if info.BasicLimitInformation.LimitFlags & _KILL_ON_JOB_CLOSE:
            return "在 Job 内且设了 KILL_ON_JOB_CLOSE ✗ 宿主退出时会被一并回收"
        return "在 Job 内，但未设 KILL_ON_JOB_CLOSE ✓ 宿主退出不受影响"
    except Exception as e:                                     # noqa: BLE001
        return f"无法判定（{type(e).__name__}）"


def remember(entry: dict) -> None:
    """动作记录必须落盘。面板状态是内存态，进程一死就没了——2026-09-17 正是因此
    查不出谁动过 DSH，只能回头翻 PowerShell 操作日志做取证。"""
    with STATE.lock:
        STATE.restart_log.append(entry)
    try:
        ACTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        with ACTION_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def load_history(limit: int = 200) -> list[dict]:
    if not ACTION_LOG.is_file():
        return []
    out: list[dict] = []
    try:
        for line in ACTION_LOG.read_text(encoding="utf-8").splitlines()[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except OSError:
        return []
    return out


def record_startup() -> None:
    parent = parent_image()
    verdict = job_verdict()
    msg = (f"pid={os.getpid()}  父进程={os.getppid()}({parent})  {verdict}")
    if "✗" in verdict or "无法判定" in verdict:
        msg += "  ← 宿主退出时本面板可能被一并回收，检查启动方式"
    remember({"action": "start", "id": "mozunitor", "name": "Mozunitor 面板",
              "ok": "✗" not in verdict, "at": now_iso(), "elapsed_s": 0, "freed_mb": 0,
              "steps": [{"t": "启动", "msg": msg}]})


# ---------------------------------------------------------------- 采集循环

def process_match(procs: list, spec: dict) -> tuple[dict | None, int]:
    """在进程表里挑出这个探针关心的进程，返回 (命中的那条, 同名进程数)。

    两件事一起做，是因为判定与文案要用同一个数：**名字撞车时只说「进程不存在」会把
    「有同名进程但都不是它」藏起来**，而那种红点最难查（对端 上有六个 python.exe）。
    抽成纯函数是为了验收能直接喂一张合成进程表 —— 否则要动正在跑的那个全局 STATE。
    """
    names = spec.get("names") or ([spec["name"]] if spec.get("name") else [])
    want = set(names)
    named = [p for p in procs if p.get("name") in want]
    cmd_want = (spec.get("cmd") or "").lower()
    hit = next((p for p in named
                if not cmd_want or cmd_want in (p.get("cmd") or "").lower()), None)
    return hit, len(named)


def task_match(tasks: list, spec: dict) -> dict | None:
    """按名字在计划任务表里挑一条。纯函数，理由同 process_match。

    **任务状态跨会话可读，而别人会话进程的 CommandLine 读不到** —— 这正是 HUST 自动登录在
    对端 自己的面板上恒红的原因（面板在会话 1，任务拉起的 python 在会话 0）。
    """
    name = spec.get("name", "")
    return next((t for t in tasks if t.get("name") == name), None)


def probe_one(svc: dict) -> None:
    spec = svc["probe"]
    kind = spec["kind"]
    sid = svc["id"]

    if kind == "http":
        ok, ms, detail = probe_http(spec["url"], spec.get("ok", [200]))
        STATE.record_probe(sid, "up" if ok else "down", ms, detail)
    elif kind == "tcp":
        ok, ms = probe_tcp(spec["host"], spec["port"])
        STATE.record_probe(sid, "up" if ok else "down", ms,
                           "端口可达" if ok else "端口无响应")
    elif kind == "remote-port":
        with STATE.lock:
            online = STATE.remote["online"]
            ports = STATE.remote["ports"]
        if not online:
            STATE.record_probe(sid, "down", 0, "远程不可达")
        elif any(p["port"] == spec["port"] for p in ports):
            STATE.record_probe(sid, "up", 0, "远程已监听（仅回环）")
        else:
            STATE.record_probe(sid, "down", 0, "远程未监听")
    elif kind == "process":
        where = spec.get("where", "local")
        # names 给「一套工具由多个进程组成」的情形用：任一在跑即算在跑。
        # MajdataViewAlpha 就是如此——桌宠 Launcher 关掉后它拉起的 View 与 Edit 仍在，
        # 只认 Launcher 会报「未运行」，用户照着点「启动」就会再起一份。
        # cmd 给「名字撞车」的情形用：对端 上有六个 python.exe，只按名字判会把别人家的
        # 算成它在跑。命令行那一列由采集侧按需补（probe_cmd_names），这里只做子串匹配。
        with STATE.lock:
            procs = STATE.local["procs"] if where == "local" else STATE.remote["procs"]
            reachable = True if where == "local" else STATE.remote["online"]
            hit, named = process_match(procs, spec)
        if not reachable:
            STATE.record_probe(sid, "down", 0, "远程不可达")
        else:
            if hit:
                detail = "进程存在" + (f"（命令行含 {spec['cmd']}）" if spec.get("cmd") else "")
            elif named and spec.get("cmd"):
                detail = f"有 {named} 个同名进程，命令行都不含 {spec['cmd']}"
            else:
                detail = "进程不存在"
            STATE.record_probe(sid, "up" if hit else "down", 0, detail)
    elif kind == "task":
        # 计划任务当探针：**任务状态读得到，而别人会话里的命令行读不到**（Windows 只让调用方
        # 读同会话进程的 CommandLine）。HUST 自动登录正是这种情形：它由计划任务拉起、跑在
        # 会话 0，而面板在会话 1 —— 按命令行判会永远报「进程不存在」。
        where = spec.get("where", "local")
        with STATE.lock:
            table = STATE.local if where == "local" else STATE.remote
            tasks = table.get("tasks") or []
            reachable = True if where == "local" else STATE.remote["online"]
            hit = task_match(tasks, spec)
        if not reachable:
            STATE.record_probe(sid, "down", 0, "远程不可达")
        elif hit is None:
            STATE.record_probe(sid, "down", 0, f"没找到计划任务 {spec['name']}")
        else:
            running = hit.get("state") == "Running"
            detail = f"计划任务 {hit.get('state')}"
            if hit.get("last_result"):
                detail += f"（上次结果 {hit['last_result']}）"
            STATE.record_probe(sid, "up" if running else "down", 0, detail)


def probe_loop() -> None:
    pool = ThreadPoolExecutor(max_workers=8)
    interval = INTERVALS["probe_local_ms"] / 1000
    while True:
        t0 = time.time()
        list(pool.map(probe_one, SERVICES))
        time.sleep(max(0.5, interval - (time.time() - t0)))


def probe_cmd_names() -> list[str]:
    """哪些进程名需要在采集时补一列命令行。

    `probe.kind=process` 的 `cmd` 与 `pid_ref.cmd` 都靠它。**只采配置里点了名的那些名字** ——
    命令行只有 CIM 拿得到（`Get-Process` 没有这一列），而把整份进程表换成 CIM 会丢掉现成的
    指标、也明显更慢。没人在配置里写 `cmd` 时，这里返回空，采集行为与以前一模一样。
    """
    names: set[str] = set()
    for svc in SERVICES:
        pr = svc.get("probe") or {}
        if pr.get("kind") == "process" and pr.get("cmd"):
            names.update(pr.get("names") or ([pr["name"]] if pr.get("name") else []))
        ref = svc.get("pid_ref") or {}
        if ref.get("cmd") and ref.get("process"):
            names.add(ref["process"])
    return sorted(n for n in names if n)


def probe_task_names() -> list[str]:
    """哪些计划任务需要采集状态（`probe.kind=task`）。

    和命令行那次采集同一个道理：只查配置点了名的，没点名一个也不查。
    """
    return sorted({(s.get("probe") or {}).get("name", "") for s in SERVICES
                   if (s.get("probe") or {}).get("kind") == "task"} - {""})


def sample_local_loop() -> None:
    script = TOOLS / "collect_local.ps1"
    interval = INTERVALS["sample_local_ms"] / 1000
    while True:
        t0 = time.time()
        names = probe_cmd_names()
        tasks = probe_task_names()
        args = []
        if names:
            args += ["-CmdNames", ",".join(names)]
        if tasks:
            args += ["-TaskNames", ",".join(tasks)]
        out, err = run_ps_file(script, timeout=45, args=args or None)
        if out:
            try:
                STATE.set_local(json.loads(out))
            except json.JSONDecodeError as e:
                with STATE.lock:
                    STATE.local["error"] = f"采集输出无法解析: {e}"
        else:
            with STATE.lock:
                STATE.local["error"] = err or "采集无输出"
        time.sleep(max(1.0, interval - (time.time() - t0)))


def _remote_is_down(fails: int) -> bool:
    """连续失败到阈值才算「远端采集离线」。

    单抽一层是为了能验收：这条通道的失败是**抖动**而不是状态（同一段脚本上一秒超时、下一秒
    2.4 秒返回），一次失败就翻成离线会让 mem/cpu 那几列整轮变空，而卡片上写着「远程不可达」。
    """
    return fails >= REMOTE_DOWN_STREAK


def sample_remote_loop() -> None:
    src = TOOLS / "collect_remote.ps1"
    if not src.is_file():
        # mesh 下每端只采集自己：没有「远端」的节点自然没有这个脚本。以前无条件读它，
        # 于是对端一启动这个线程就抛 FileNotFoundError —— 把单机拓扑当成了通用假设。
        return
    # 按 utf-8-sig 读：**必须去掉 BOM**。这条通道以前用 -EncodedCommand 直接吃整段脚本，
    # 开头的 BOM 被当成空白容忍掉了；改成 Invoke-Expression 之后它变成一个真字符，
    # 于是第一行 `# 注释` 被当成命令执行（stderr 里一行「无法将 ?# 项识别为 cmdlet」）。
    script = src.read_text(encoding="utf-8-sig")
    interval = INTERVALS["sample_remote_ms"] / 1000
    fails = 0
    while True:
        t0 = time.time()
        # 远端脚本是**整段经 SSH 执行的**，没有参数可传 —— 用前置的变量赋值代替，
        # 脚本里按 $MozuCmdNames / $MozuTaskNames 取（未定义时当空串，行为与以前一致）。
        names = probe_cmd_names()
        tasks = probe_task_names()
        head = (f"$MozuCmdNames = '{','.join(names)}'\n" if names else "") \
            + (f"$MozuTaskNames = '{','.join(tasks)}'\n" if tasks else "")
        out, err = "", ""
        for attempt in range(REMOTE_ATTEMPTS):
            out, err = ssh_inline(head + script, timeout=REMOTE_ATTEMPT_TIMEOUT_S)
            if out.startswith("{"):
                break
            if attempt + 1 < REMOTE_ATTEMPTS:
                time.sleep(REMOTE_RETRY_GAP_S)
        if out.startswith("{"):
            try:
                STATE.set_remote(json.loads(out))
                fails = 0
            except json.JSONDecodeError as e:
                STATE.remote_failed(f"远程采集输出无法解析: {e}")
        else:
            fails += 1
            # 没到阈值就保留上一轮的数据：那几列显示的是「上一次采集到的值」，
            # 比清空更诚实（清空会被读成「这些服务没有进程」）。
            if _remote_is_down(fails):
                STATE.remote_failed(f"{err or 'SSH 无输出'}（已连续 {fails} 轮）")
        time.sleep(max(2.0, interval - (time.time() - t0)))


def sample_models_loop() -> None:
    """远端 Ollama 的已加载 / 可用模型。走 HTTP 而非 SSH：延迟从数百毫秒降到几毫秒，
    也不占用 SSH 通道（远程进程采样还要用它）。"""
    targets = [s for s in SERVICES if s.get("models_api")]
    if not targets:
        return
    last_tags = 0.0
    while True:
        t0 = time.time()
        for svc in targets:
            base = svc["models_api"]
            try:
                loaded = [{
                    "name": m.get("name"),
                    "vram": m.get("size_vram") or m.get("size") or 0,
                    "ctx": m.get("context_length"),
                    "expires_at": m.get("expires_at"),
                    "param": (m.get("details") or {}).get("parameter_size"),
                    "quant": (m.get("details") or {}).get("quantization_level"),
                } for m in ollama_get(base, "/api/ps").get("models", [])]
                with STATE.lock:
                    rec = STATE.models.setdefault(svc["id"], {"available": []})
                    rec.update({"at": time.time(), "error": None, "loaded": loaded})
            except Exception as e:                       # noqa: BLE001 —— 网络异常种类繁多
                with STATE.lock:
                    rec = STATE.models.setdefault(svc["id"], {"available": [], "loaded": []})
                    rec.update({"at": time.time(), "error": f"{type(e).__name__}: {e}"})
                continue

            if time.time() - last_tags > MODELS_TAGS_EVERY * MODELS_POLL_S:
                try:
                    rows = [{"name": m.get("name"), "size": m.get("size") or 0,
                             "param": (m.get("details") or {}).get("parameter_size"),
                             "quant": (m.get("details") or {}).get("quantization_level")}
                            for m in ollama_get(base, "/api/tags").get("models", [])]
                    # 顺带问出每个模型自带的 num_ctx：清单几乎不变，跟 tags 同频足够。
                    for row in rows:
                        row["num_ctx"] = model_num_ctx(base, row["name"])
                    with STATE.lock:
                        STATE.models[svc["id"]]["available"] = rows
                    last_tags = time.time()
                except Exception:                        # noqa: BLE001
                    pass
        time.sleep(max(1.0, MODELS_POLL_S - (time.time() - t0)))


DISCOVERED: dict[str, dict] = {}


def tailscale_devices() -> list[tuple[str, str]]:
    """列出 tailnet 内在线的其他设备：(主机名, IPv4)。"""
    out = subprocess.run([TAILSCALE, "status", "--json"],
                         capture_output=True, timeout=10, creationflags=NO_WINDOW)
    data = json.loads(out.stdout.decode("utf-8", "replace"))
    self_ips = set((data.get("Self") or {}).get("TailscaleIPs") or [])
    devs = []
    for peer in (data.get("Peer") or {}).values():
        if not peer.get("Online"):
            continue
        ip4 = next((i for i in (peer.get("TailscaleIPs") or []) if ":" not in i), None)
        if ip4 and ip4 not in self_ips:
            devs.append((str(peer.get("HostName") or ip4), ip4))
    return devs


def probe_node(url: str) -> dict | None:
    """试连一个候选节点的 /api/node。对方不认这个用户名就会 401，即视作不同类。"""
    try:
        req = urllib.request.Request(url.rstrip("/") + "/api/node",
                                     headers=peer_headers("GET", "/api/node"))
        with _OPENER.open(req, timeout=DISCOVER_TIMEOUT_S) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:                                     # noqa: BLE001
        return None


def discover_loop() -> None:
    """定期扫 tailnet 找同类节点，结果与手工配的 peer 合并使用。"""
    while True:
        t0 = time.time()
        found: dict[str, dict] = {}
        if DISCOVER_ON:
            try:
                devs = tailscale_devices()
            except Exception:                             # noqa: BLE001
                devs = []                                 # 没装或没登录就当没有
            for host, ip in devs:
                url = f"http://{ip}:{LOCAL_PORT}"
                snap = probe_node(url)
                if not snap:
                    continue
                node = snap.get("node") or {}
                nid = str(node.get("id") or ip)
                found[nid] = {"id": nid, "url": url,
                              "name": str(node.get("name") or host),
                              "discovered": True}
        with STATE.lock:
            DISCOVERED.clear()
            DISCOVERED.update(found)
        time.sleep(max(5.0, DISCOVER_EVERY_S - (time.time() - t0)))


def effective_peers() -> list[dict]:
    """手工配置优先：同一个 id 同时来自配置与发现时用配置里那份（它可能带 ssh）。"""
    out = [dict(p) for p in PEERS]
    seen = {str(p.get("id")) for p in out}
    with STATE.lock:
        extra = [dict(p) for k, p in DISCOVERED.items() if k not in seen]
    return out + extra


_peer_revive_at: dict[str, float] = {}


def peer_start(peer: dict) -> str:
    """经 SSH 拉起对方面板 —— 对端 HTTP 不通时的运维通道，不参与常规状态获取。

    只有显式配了 ssh（主机别名）与 start_cmd（启动命令）的 peer 才可拉起；
    对端用什么方式启动是它自己的事，这里绝不猜测。
    """
    host = str(peer.get("ssh") or "")
    cmd = str(peer.get("start_cmd") or "")
    if not host or not cmd:
        return ""
    # 用脚本块包住再等待：启动器自身可能带分号，直接拼会改变语义。
    wrapped = f"& {{ {cmd} }}; Start-Sleep -Seconds {int(PEER_START_GRACE_S)}"
    out, err = ssh_inline(wrapped, timeout=int(PEER_START_GRACE_S) + 25, host=host)
    text = (out or err or "已下发").strip()
    return text.splitlines()[-1][:160] if text else "已下发"


def maybe_revive_peer(peer: dict, pid: str) -> None:
    """对端拉不到时，若配了 SSH 通道就试着拉一把，并按 PEER_REVIVE_S 节流。"""
    if not peer.get("ssh") or not peer.get("start_cmd"):
        return
    now = time.time()
    with STATE.lock:
        if now - _peer_revive_at.get(pid, 0.0) < PEER_REVIVE_S:
            return
        _peer_revive_at[pid] = now
    t0 = time.time()
    msg = peer_start(peer)
    if not msg:
        return
    remember({"action": "revive", "id": pid, "name": str(peer.get("name") or pid),
              "ok": "✗" not in msg, "at": now_iso(),
              "elapsed_s": round(time.time() - t0, 1), "freed_mb": 0,
              "steps": [{"t": "拉起", "msg": msg}]})


def peer_poll_loop() -> None:
    """按 peers 清单扇出拉取对等节点的快照。

    一轮之内串行拉取：节点数是个位数，而并发拉取在对端全挂时反而更难看清谁挂了。
    """
    while True:
        t0 = time.time()
        for peer in effective_peers():
            pid = str(peer.get("id") or peer["url"])
            try:
                t1 = time.time()
                snap = fetch_peer(peer)
                STATE.set_peer(pid, snap, round((time.time() - t1) * 1000, 1))
            except Exception as e:                        # noqa: BLE001
                STATE.peer_failed(pid, f"{type(e).__name__}: {e}")
                maybe_revive_peer(peer, pid)
        time.sleep(max(1.0, max(2.0, INTERVALS.get("peer_poll_ms", 5000) / 1000.0)
                       - (time.time() - t0)))


# ---------------------------------------------------------------- 视图组装

def _peer_index(peers_state: dict) -> dict:
    """把各对端快照摊平成 {机器 id: (peer 状态, {条目 id: 条目})}。

    机器 id 同时认 peer 的配置 id 与它自报的 node.id：两端各写一份配置，
    改名时只改一边不该把判据悄悄弄丢。
    """
    out: dict[str, tuple] = {}
    for pid, p in (peers_state or {}).items():
        snap = (p or {}).get("snapshot") or {}
        mid = str((snap.get("node") or {}).get("id") or pid)
        items: dict[str, dict] = {}
        for g in snap.get("groups") or []:
            for it in g.get("items") or []:
                if it.get("id"):
                    items[str(it["id"])] = it
        rec = (p or {}, items)
        out.setdefault(str(pid), rec)
        out.setdefault(mid, rec)
    return out


def resolve_status(svc: dict, pr: dict, machine: str | None, peer_rec: dict) -> dict:
    """一条服务的存活判据，外加「本机可达」这个独立信号。

    远端项的存活**优先取对端自评**（`/api/node` 里它自己那条记录）—— 服务在它自己那台
    机器上活没活，它自己看得最准；本机探测只说明这条通道通不通，不足以判死。判据若跟着
    通道走，面板就会把活着的服务报成红（2026-10-13 实测：RAG 在 对端 上自评 HTTP 200、
    本机 curl 也能拿到完整响应，而本机连它的 8000 直接 RST —— 原因至今未明）。

    取哪一条也由配置说了算：分组带 `machine` 认定机器，条目用 `peer_item` 指对端的 id
    （缺省=同名）。对端快照过期或对端面板离线时退回本机探测，并标明这是降级判断 ——
    静默退回会让「判据换了」这件事谁也看不见。
    """
    base = {"status": pr.get("status", "unknown"), "detail": pr.get("detail") or "",
            "latency_ms": pr.get("latency_ms"), "src": "local"}
    rec = peer_rec.get(machine) if machine else None
    if not rec:
        return base
    p_state, p_items = rec
    ref = str(svc.get("peer_item") or svc["id"])
    pv = p_items.get(ref)
    if pv is None:
        return base
    age = max(0.0, time.time() - float(p_state.get("snap_at") or p_state.get("at") or 0.0))
    if age > PEER_SNAPSHOT_STALE_S:
        base["degraded"] = True
        base["note"] = "对端自评已 %d 秒未更新（%s），本卡片退回本机探测" % (
            int(age), "对端面板离线" if not p_state.get("online") else "快照过期")
        return base
    local_status, local_detail, local_lat = base["status"], base["detail"], base["latency_ms"]
    base.update({
        "status": pv.get("status") or "unknown",
        "detail": pv.get("detail") or "",
        "latency_ms": None,
        "src": "peer",
        "peer": {"id": str(machine), "ref": ref, "age_s": round(age, 1)},
        "reach": {"ok": local_status == "up", "detail": local_detail,
                  "latency_ms": local_lat},
    })
    return base


def build_view() -> dict:
    with STATE.lock:
        probes = dict(STATE.probes)
        since = dict(STATE.since)
        local_at = STATE.local["at"]
        remote_at = STATE.remote["at"]
        remote_online = STATE.remote["online"]
        remote_error = STATE.remote["error"]
        task = dict(STATE.remote.get("task") or {})
        models = list(STATE.remote.get("models") or [])
        verify_state = dict(STATE.verify) if STATE.verify else None
        peers_state = {k: dict(v) for k, v in STATE.peers.items()}

    fwd = forward_map()              # 局域网入口端口，前端据此改写「打开」按钮
    groups: dict[str, list] = {g["id"]: [] for g in GROUP_DEFS}
    summary = {"up": 0, "down": 0, "total": 0, "deps_broken": 0,
               "by_tier": {t: {"up": 0, "down": 0, "total": 0, "deps_broken": 0}
                           for t in TIER_ORDER}}

    # 依赖图：needs 是声明的出边，supports 由它反推，避免两处各写一遍而走样
    by_id = {s["id"]: s for s in SERVICES}
    dependents: dict[str, list[str]] = {s["id"]: [] for s in SERVICES}
    for s in SERVICES:
        for dep in s.get("needs", []):
            if dep in dependents:
                dependents[dep].append(s["id"])

    # 存活判据整表先算好再渲染：远端项取对端自评、本机探测降级为「本机可达」。
    # 依赖徽章与卡片必须读同一份判据，否则会出现「卡片说正常、它的依赖却标 ✗」这种
    # 自相矛盾 —— 两者以前各读一份 status。
    gdef = {g["id"]: g for g in GROUP_DEFS}
    peer_rec = _peer_index(peers_state)
    resolved = {s["id"]: resolve_status(
        s, probes.get(s["id"], {"status": "unknown", "detail": "尚未采样"}),
        (gdef.get(s["group"]) or {}).get("machine"), peer_rec) for s in SERVICES}

    def _chip(sid: str, with_status: bool) -> dict:
        s = by_id[sid]
        chip = {"id": sid, "label": s.get("short") or s["name"]}
        if with_status:
            chip["status"] = resolved.get(sid, {}).get("status", "unknown")
        return chip

    for svc in SERVICES:
        sid = svc["id"]
        rs = resolved.get(sid) or {"status": "unknown", "detail": "尚未采样", "latency_ms": None}
        pr = {"status": rs["status"], "detail": rs.get("detail") or "",
              "latency_ms": rs.get("latency_ms")}
        pid_ref = svc.get("pid_ref") or {}
        where = pid_ref.get("where")
        if where and "port" in pid_ref:
            _pid_host, _pid_port = split_hostport(pid_ref["port"])
            pid = STATE.pid_of(where, _pid_port, _pid_host)
        elif where and "process" in pid_ref:
            pid = STATE.pid_of_name(where, pid_ref["process"], pid_ref.get("cmd"))
        else:
            pid = None
        rst = svc.get("restart") or {}

        item = {
            "id": sid, "name": svc["name"], "group": svc["group"], "tier": svc_tier(svc),
            "card": svc.get("card") or {}, "role": svc.get("role", ""),
            "settings": svc.get("settings") or [],
            "status": pr["status"], "latency_ms": pr["latency_ms"], "detail": pr["detail"],
            "since": since.get(sid), "logs": svc.get("logs", []),
            "flag": svc.get("flag"), "access": svc.get("access"),
            # 前端据此把「打开」按钮指向局域网入口，而不是回环地址（手机上点不开）
            "fwd_port": (fwd.get(sid) or {}).get("port"),
            # 缺 restart 与 kind=none 同义（keepalive_precheck 早就这么认了）。
            # 这里曾经直接取 svc["restart"]：一条写漏了 restart 的配置会让整个 build_view 抛出去，
            # 表现是「面板全白」，而错因离现场很远。
            "restart_kind": rst.get("kind", "none"),
            "restart_why": rst.get("why") or rst.get("note"),
            "warn": rst.get("warn"),
            "stoppable": bool(svc.get("stop")),
            "stop_warn": (svc.get("stop") or {}).get("warn"),
        }
        if svc.get("keepalive"):
            ka = keepalive_state(sid)
            # 保活是自动化，但状态必须可见：一个被保活、起不来、又不说的服务，
            # 比一个没人管的服务更糟。
            item["keepalive"] = {
                "fails": ka["fails"], "paused": ka["paused"], "invalid": ka["invalid"],
                "waiting_on": ka["waiting_on"], "starts": ka["starts"],
                "last_error": ka["last_error"], "last_ok_at": ka["last_ok_at"],
                # 上限由后端给：前端写死 5 会让调 KEEPALIVE_MAX_FAILS 的那天静默失真
                "max_fails": KEEPALIVE_CFG["max_fails"],
            }
        # 判据的来源与「本机可达」分开呈现：远端项活不活由对端说了算，而本机连不通
        # 只是这条通道的事 —— 两者混成一个红点，就会把正常服务报成不可达。
        if rs.get("src") == "peer":
            item["status_src"] = "peer"
            item["peer"] = rs.get("peer")
            item["reach"] = rs.get("reach")
        if rs.get("degraded"):
            item["degraded"] = True
            item["status_note"] = rs.get("note")
        item["needs"] = [_chip(d, True) for d in svc.get("needs", []) if d in by_id]
        item["supports"] = [_chip(d, False) for d in dependents.get(sid, [])]
        item["deps_broken"] = [c["label"] for c in item["needs"] if c["status"] != "up"]
        # 归属：声明了 under 的条目不在概览上占卡片，改为在宿主的详情里列出来。
        # 指向不存在的 id、或指向自己时**不当下属处理** —— 静默吞掉会让「设了却没反应」
        # 变成最难查的那类问题；这种情况由 nesting_precheck() 在启动时打印出来。
        if svc.get("under") in by_id and svc["under"] != sid:
            item["under"] = svc["under"]
        item.update(STATE.proc_info(where, pid) if where else {})
        # 服务自己声明的操作面，原样透传；卡片上的摘要徽章由适配器按需给出。
        # 这里不再认服务是谁 —— 原先的 models_api / "rag" / "sillytavern" 三处特判已删除。
        item["ops"] = svc.get("ops") or []
        badges = op_badges(svc)
        if badges:
            item["badges"] = badges
        groups[svc["group"]].append(item)
        # 按需层不运行是常态；计进总数会让顶栏永远挂着「N 个不可达」。判据是 tier，
        # 不再看分组（分组轴与级别轴已经分开）。下属同理：它的状态由宿主代表，
        # 概览上看不见它，就不该让它进「N/N 在线」。
        tier_count = summary["by_tier"][item["tier"]]
        if not item.get("under"):
            tier_count["total"] += 1
            tier_count["up" if pr["status"] == "up" else "down"] += 1
            if item["tier"] != "optional":
                summary["total"] += 1
                summary["up" if pr["status"] == "up" else "down"] += 1
        if item["deps_broken"]:
            summary["deps_broken"] += 1
            tier_count["deps_broken"] += 1


    with STATE.lock:
        restarts = list(STATE.restart_log[-8:])

    return {
        "server_time": now_iso(),
        "uptime_s": int(time.time() - STATE.started_at),
        # 本节点身份：前端据此把「本机」这块与各 peer 并列排版（/api/node 里也有，供对端用）
        "node": {"id": NODE_ID, "name": NODE_NAME},
        "groups": [dict(g, items=groups[g["id"]]) for g in GROUP_DEFS],
        "summary": summary,
        "ui": ui_config(),
        "tiers": list(TIER_ORDER),
        "relay": relay_status(),
        "remote_meta": {"online": remote_online, "at": remote_at, "error": remote_error,
                        "task": task, "models": models,
                        "cmd_names": STATE.remote.get("cmd_names", ""),
                        "cmd_probed": STATE.remote.get("cmd_probed", 0)},
        "local_meta": {"at": local_at, "error": STATE.local["error"],
                       "cmd_names": STATE.local.get("cmd_names", ""),
                       "cmd_probed": STATE.local.get("cmd_probed", 0)},
        "peers": peers_state,
        "restarts": restarts,
        "rag_verify": verify_state,
    }


def build_node_snapshot() -> dict:
    """本节点自视角的原子快照，供对等节点经 /api/node 拉取。

    与 build_view() 的差别是不含任何对等聚合：对端拿到的就是「这台机器自己看到了什么」，
    聚合由各端自行完成 —— 平权的含义正在于此，没有哪一端是权威。
    """
    view = build_view()
    return {
        "node": {"id": NODE_ID, "name": NODE_NAME},
        "server_time": view["server_time"],
        "uptime_s": view["uptime_s"],
        "groups": view["groups"],
        "summary": view["summary"],
        "meta": view["local_meta"],
        "restarts": view["restarts"],
        "rag_verify": view["rag_verify"],
        "relay": relay_status(),
    }


def fetch_peer(peer: dict) -> dict:
    """拉取一个对等节点的原子快照。

    走 _OPENER 直连，与探测同一口径 —— 本机代理挂没挂不该混进「对方在不在」的判断。
    """
    url = str(peer["url"]).rstrip("/") + "/api/node"
    req = urllib.request.Request(url, headers={
        **peer_headers("GET", "/api/node"), "Accept": "application/json",
    })
    with _OPENER.open(req, timeout=PEER_TIMEOUT_S) as r:
        return json.loads(r.read().decode("utf-8"))


def forward_action(peer: dict, path: str, payload: dict) -> tuple[int, dict]:
    """把一次重启/终止转发给对等节点，由它用自己的锁与 services.json 执行。

    只转发动作本身并剥掉 node 字段 —— 对端不必知道这次请求是替谁发的。
    返回 (状态码, 正文)：对端的业务答复原样带回，本机不替它改写结论。
    """
    url = str(peer["url"]).rstrip("/") + path
    body = json.dumps({k: v for k, v in payload.items() if k != "node"}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={
        **peer_headers("POST", path), "Content-Type": "application/json",
    })
    try:
        with _OPENER.open(req, timeout=FORWARD_TIMEOUT_S) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # 对端答复了（例如「未知服务 id」）——那是它的业务判断，状态码与正文原样透传；
        # 只有连不上或超时才算本机的转发失败，由调用方报 502。
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"error": f"对端返回 HTTP {e.code}"}


# ---------------------------------------------------------------- 重启

def wait_port(host: str, port: int, seconds: float) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), 1.0):
                return True
        except OSError:
            time.sleep(0.6)
    return False


def _remote_port_probe(spec, seconds: float, cmd: str, probe: str,
                       settle_s: int = 12) -> tuple[str, str]:
    """一次远程轮询：等端口，顺带读启动脚本自己写下的结果文件。

    返回 (状态, 说明)，状态取 ready / failed / pending。端口是异步启动脚本的唯一硬事实，
    结果文件只用来把「没起来」拆成具体原因。settle_s 是端口监听后、等结果文件落盘的余量。

    结果文件的「新鲜度」不看绝对时间戳（两台机器时钟未必一致），只看文件的
    LastWriteTime 距现在多久——启动脚本的判定只在启动后几十秒内产生。

    cmd 是**命令文本**，直接内联执行。不能用 _ps_quote 包成字符串再 & 调用：脚本
    自己就带单引号（Get-Content 'D:...'），包一层会变成字符串字面量，PowerShell 报
    「表达式或语句中包含意外的标记」。
    """
    want_host, want_port = split_hostport(spec)
    why_cmd = f"$why = (({cmd} 2>&1) | Out-String).Trim() -replace '\\s+', ' '; " if cmd else ""
    # 端口一监听就跳出等待循环，可此刻启动脚本往往还没写结果文件（它有自己的轮询周期）。
    # 所以只要端口起来了而结果文件还没成形，就再等它一段，然后重新判定一次状态 —— $state
    # 是在这之前算的，不重算就会把「已监听」退回成信息量为零的兜底文案。
    settle = (f"if ($hit -and $state -eq 'NONE') {{ Start-Sleep -Seconds {settle_s}; {why_cmd}"
              f"if (-not $why) {{ $t2 = ((Get-Content $f -Raw -EA SilentlyContinue) -replace '\\s+', ' ').Trim(); $why = $t2 }}; "
              f"if ($why -match 'ERROR') {{ $state = 'ERROR' }} "
              f"elseif ($why -match 'ALREADY') {{ $state = 'ALREADY' }} "
              f"elseif ($why -match 'READY') {{ $state = 'READY' }} }} ") if cmd else ""
    script = (f"$ProgressPreference='SilentlyContinue'; "
              f"$deadline = (Get-Date).AddSeconds({int(seconds)}); $hit = $false; "
              f"do {{ if (Get-NetTCPConnection -State Listen -LocalPort {want_port} "
              f"-EA SilentlyContinue{_port_addr_filter(want_host)}) "
              f"{{ $hit = $true; break }}; Start-Sleep -Milliseconds 800 }} "
              f"while ((Get-Date) -lt $deadline); "
              f"$state = 'NONE'; $msg = ''; "
              f"$f = {_ps_quote(probe)}; "
              f"if (Test-Path $f) {{ "
              f"  $i = Get-Item $f; "
              f"  if (((Get-Date) - $i.LastWriteTime).TotalSeconds -lt 600) {{ "
              f"    $t = ((Get-Content $f -Raw) -replace '\\s+', ' ').Trim(); "
              f"    if ($t -match 'READY') {{ $state = 'READY' }} "
              f"elseif ($t -match 'ERROR') {{ $state = 'ERROR' }} "
              f"elseif ($t -match 'ALREADY') {{ $state = 'ALREADY' }} "
              f"    $msg = $t }} }}; "
              f"$why = ''; "
              f"if ($state -eq 'READY') {{ {why_cmd} }}; "
              f"{settle}"
              f"'##RESULT|' + $hit + '|' + $state + '|' + $why + '|' + $msg")
    out, err = ssh_inline(script, timeout=seconds + 30)

    fields = None
    for line in out.splitlines():
        if line.startswith("##RESULT|"):
            fields = line.split("|", 4)
            break
    if not fields or len(fields) < 5:
        return "pending", (err.strip()[:200] or "远程未返回结果")

    _, hit, state, why, msg = fields
    if err.strip() and not out.strip():
        return "pending", err.strip()[:200]

    if hit == "True" and state == "READY" and why:
        return "ready", why[:300]
    if hit == "True":
        return "ready", f"远程 {port_label(spec)} 已监听"
    if state in ("ERROR", "ALREADY"):
        return "failed", msg[:300] or state
    return "pending", msg[:300]


def wait_remote_port(spec, seconds: float, cmd: str = "",
                     probe: str = "") -> tuple[str, str]:
    """远程端口只绑在它自己的回环上，本机连不到，只能让远程自己轮询。

    启动脚本是异步点火的（计划任务实例秒退），所以「已下发」不等于「已拉起」——判据只能
    是端口监听。分三次短轮询而不是一次长轮询：脚本判定失败时提前返回，端口起来时立即
    返回，都不必把 wait_s 等满。
    """
    last = ""
    for _ in range(3):
        try:
            state, why = _remote_port_probe(spec, seconds, cmd, probe)
        except Exception as e:                                     # noqa: BLE001
            state, why = "pending", f"{type(e).__name__}: {e}"
        if state in ("ready", "failed"):
            return state, why
        last = why
    return "pending", last or f"等待 {int(seconds) * 3} 秒仍未监听"


def wait_local_process(name: str, seconds: float) -> bool:
    script = (f"$deadline = (Get-Date).AddSeconds({int(seconds)}); $hit = $false; "
              f"do {{ if (Get-Process -Name '{name}' -EA SilentlyContinue) {{ $hit = $true; break }}; "
              f"Start-Sleep -Milliseconds 700 }} while ((Get-Date) -lt $deadline); "
              f"if ($hit) {{ 'UP' }} else {{ 'DOWN' }}")
    out, _ = run_ps_inline(script, timeout=seconds + 20)
    return "UP" in out


def wait_remote_process(name: str, seconds: float) -> bool:
    script = (f"$ProgressPreference='SilentlyContinue'; "
              f"$deadline = (Get-Date).AddSeconds({int(seconds)}); $hit = $false; "
              f"do {{ if (Get-Process -Name '{name}' -EA SilentlyContinue) {{ $hit = $true; break }}; "
              f"Start-Sleep -Milliseconds 700 }} while ((Get-Date) -lt $deadline); "
              f"if ($hit) {{ 'UP' }} else {{ 'DOWN' }}")
    out, _ = ssh_inline(script, timeout=seconds + 30)
    return "UP" in out


def kill_local_port(spec) -> str:
    host, port = split_hostport(spec)
    script = (f"$p = Get-NetTCPConnection -State Listen -LocalPort {port} -EA SilentlyContinue"
              f"{_port_addr_filter(host)} | "
              f"Select-Object -ExpandProperty OwningProcess -Unique; "
              f"foreach ($i in $p) {{ Stop-Process -Id $i -Force -EA SilentlyContinue }}; "
              f"if ($p) {{ 'killed ' + ($p -join ',') }} else {{ 'no listener' }}")
    out, err = run_ps_inline(script, timeout=25)
    return out or err or "无输出"


def kill_remote_port(spec) -> str:
    host, port = split_hostport(spec)
    script = (f"$p = Get-NetTCPConnection -State Listen -LocalPort {port} -EA SilentlyContinue"
              f"{_port_addr_filter(host)} | "
              f"Select-Object -ExpandProperty OwningProcess -Unique; "
              f"foreach ($i in $p) {{ Stop-Process -Id $i -Force -EA SilentlyContinue }}; "
              f"if ($p) {{ 'killed ' + ($p -join ',') }} else {{ 'no listener' }}")
    out, err = ssh_inline(script, timeout=30)
    return out or err or "无输出"


def _ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def wmi_create(command: str, cwd: str | None = None, hide: bool = True) -> str:
    """用 WMI 创建常驻进程，返回一行结果描述。

    WMI 创建出来的进程挂在 WmiPrvSE.exe 下，既不是本面板的子进程，也不进入本面板的
    Job Object —— 面板无论崩溃、被杀还是被宿主回收，都不会把服务带走。

    实测确认：这样起的进程 UserProfile 仍是当前用户、SessionId 仍是交互会话（GUI 程序
    可见），所以对无头服务和桌面程序都成立。hide 只在需要时置位——ShowWindow=0 是
    STARTUPINFO 级别的，会让 GUI 程序的第一个窗口也隐藏。
    """
    args = f"CommandLine = {_ps_quote(command)}"
    if cwd:
        args += f"; CurrentDirectory = {_ps_quote(cwd)}"
    if hide:
        args += ("; ProcessStartupInformation = "
                 "(New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly "
                 "-Property @{ ShowWindow = [uint16]0 })")
    script = (f"$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
              f"-Arguments @{{ {args} }}; "
              f"if ($r.ReturnValue -eq 0) {{ 'pid ' + $r.ProcessId }} "
              f"else {{ 'WMI ReturnValue=' + $r.ReturnValue }}")
    out, err = run_ps_inline(script, timeout=40)
    return out or err or "无输出"


def start_local(r: dict, steps: list) -> None:
    kind = r["kind"]
    if kind == "ps1":
        wmi_create(f'"{PS}" -NoProfile -ExecutionPolicy Bypass -File "{r["path"]}"')
        steps.append({"t": "启动", "msg": f"powershell -File {Path(r['path']).name}"})
    elif kind == "vbs":
        wmi_create(f'wscript.exe "{r["path"]}"')
        steps.append({"t": "启动", "msg": f"wscript {Path(r['path']).name}"})
    elif kind == "exe":
        line = " ".join(f'"{p}"' for p in [r["exe"], *r.get("args", [])])
        needs_cmd = bool(r.get("cwd") or r.get("env") or r.get("log"))
        if needs_cmd:
            # 只有要切目录、注入环境变量或重定向输出时才套一层 cmd；裸 exe 直接交给
            # WMI，避开 cmd 对首字符引号的剥离规则。
            pieces = []
            if r.get("cwd"):
                pieces.append(f'cd /d "{r["cwd"]}"')
            for key, value in (r.get("env") or {}).items():
                pieces.append(f'set "{key}={value}"')
            pieces.append(line)
            command = "cmd.exe /c " + " && ".join(pieces)
            if r.get("log"):
                log_path = Path(r["log"])
                log_path.parent.mkdir(parents=True, exist_ok=True)
                command += f' >> "{log_path}" 2>&1'
        else:
            command = line
        wmi_create(command, hide=bool(r.get("hidden")))
        desc = Path(r["exe"]).name + " " + " ".join(r.get("args", []))
        if r.get("cwd"):
            desc += f"   (cwd={r['cwd']})"
        steps.append({"t": "启动", "msg": desc})
    elif kind == "service":
        out, err = run_ps_inline(f"Restart-Service -Name '{r['name']}' -Force; "
                                 f"(Get-Service -Name '{r['name']}').Status", timeout=45)
        steps.append({"t": "启动", "msg": f"Restart-Service {r['name']} → {out or err}"})
    elif kind == "task":
        # 计划任务，与 remote-task 对称。任务默认「已在运行就不开新实例」，所以重复 Start 是
        # 安全的空操作 —— 正是保活需要的幂等（HUST 自动登录就靠这条）。
        out, err = run_ps_inline(f"Start-ScheduledTask -TaskName '{r['name']}'; "
                                 f"Start-Sleep -Seconds 2; "
                                 f"(Get-ScheduledTask -TaskName '{r['name']}').State", timeout=60)
        steps.append({"t": "启动", "msg": f"Start-ScheduledTask {r['name']} → {out or err}"})


def start_remote(r: dict, steps: list) -> None:
    kind = r["kind"]
    if kind == "remote-ps1":
        script = f"$ProgressPreference='SilentlyContinue'; & '{r['path']}' | Out-Null"
        if r.get("log_after"):                       # 脚本本身不产出 stdout，取它自己的日志回执
            script += f"; Get-Content -Path '{r['log_after']}' -Tail 4 -Encoding UTF8"
        out, err = ssh_inline(script, timeout=180)
        msg = f"已执行 {Path(r['path']).name}"
        if out.strip():
            msg += " → " + " ｜ ".join(ln.strip() for ln in out.strip().splitlines()[-4:] if ln.strip())
        elif err:
            msg += f"（stderr: {err[:180]}）"
        steps.append({"t": "启动", "msg": msg})
    elif kind == "remote-service":
        out, err = ssh_inline(f"$ProgressPreference='SilentlyContinue'; "
                              f"Restart-Service -Name '{r['name']}' -Force; "
                              f"Start-Sleep -Seconds 2; "
                              f"(Get-Service -Name '{r['name']}').Status", timeout=70)
        steps.append({"t": "启动", "msg": f"远程 Restart-Service {r['name']} → {out or err}"})
    elif kind == "remote-task":
        out, err = ssh_inline(f"$ProgressPreference='SilentlyContinue'; "
                              f"Start-ScheduledTask -TaskName '{r['name']}'; "
                              f"Start-Sleep -Seconds 2; "
                              f"(Get-ScheduledTask -TaskName '{r['name']}').State", timeout=60)
        steps.append({"t": "启动", "msg": f"Start-ScheduledTask {r['name']} → {out or err}"})


def _name_list(names) -> str:
    return ",".join("'" + str(n) + "'" for n in names)


def _mem_of(where: str, pids) -> int:
    wanted = {p for p in pids if p}
    if not wanted:
        return 0
    with STATE.lock:
        procs = STATE.local["procs"] if where == "local" else STATE.remote["procs"]
    return sum(p.get("mem", 0) for p in procs if p["pid"] in wanted)


def _pids_by_name(where: str, names) -> list[int]:
    if not names:
        return []
    target = set(names)
    with STATE.lock:
        procs = STATE.local["procs"] if where == "local" else STATE.remote["procs"]
    return [p["pid"] for p in procs if p.get("name") in target]


def _local_kill_names(names) -> str:
    out, err = run_ps_inline(
        f"$p = Get-Process -Name {_name_list(names)} -EA SilentlyContinue; "
        f"if ($p) {{ $p | Stop-Process -Force -EA SilentlyContinue; 'killed ' + (($p.Id) -join ',') }} "
        f"else {{ 'no process' }}", timeout=30)
    return out or err


def _remote_kill_names(names) -> str:
    out, err = ssh_inline(
        f"$ProgressPreference='SilentlyContinue'; "
        f"$p = Get-Process -Name {_name_list(names)} -EA SilentlyContinue; "
        f"if ($p) {{ $p | Stop-Process -Force -EA SilentlyContinue; 'killed ' + (($p.Id) -join ',') }} "
        f"else {{ 'no process' }}", timeout=40)
    return out or err


def _remote_port_listening(spec) -> bool:
    host, port = split_hostport(spec)
    out, _ = ssh_inline(f"$ProgressPreference='SilentlyContinue'; "
                        f"if (Get-NetTCPConnection -State Listen -LocalPort {port} -EA SilentlyContinue"
                        f"{_port_addr_filter(host)}) "
                        f"{{ 'UP' }} else {{ 'DOWN' }}", timeout=25)
    return "UP" in out


def do_stop(svc: dict) -> dict:
    """只做「停」，不做「起」。用于腾内存——把服务关掉，需要时再用「重启」拉回来。"""
    st = svc.get("stop")
    steps: list[dict] = []
    t0 = time.time()
    if not st:
        return {"id": svc["id"], "name": svc["name"], "action": "stop", "ok": False,
                "steps": [{"t": "拒绝", "msg": "该服务未配置终止方式"}],
                "elapsed_s": 0, "freed_mb": 0, "at": now_iso()}

    # 内存必须杀之前量，杀完进程表里就没它了。同一端口可能被多个进程持有，按端口统计要取全部
    # —— 但**只取满足声明地址的那些**：对端 上 8000 有两个人，不按地址算就会把对方的内存也算进来。
    freed = 0
    if "kill_port" in st:
        _h, _p = split_hostport(st["kill_port"])
        freed += _mem_of("local", STATE.pids_of("local", _p, _h))
    if st.get("kill_first"):
        freed += _mem_of("local", _pids_by_name("local", st["kill_first"]))
    if "kill_remote_port" in st:
        _h, _p = split_hostport(st["kill_remote_port"])
        freed += _mem_of("remote", STATE.pids_of("remote", _p, _h))
    if st.get("kill_first_remote"):
        freed += _mem_of("remote", _pids_by_name("remote", st["kill_first_remote"]))

    remote = "kill_remote_port" in st
    ok = True

    # 守护进程必须先杀。ollama app.exe 这类托盘程序会在 serve 被杀掉的瞬间把它重新拉起来，
    # 顺序反了就永远停不掉——2026-09-17 实测踩到：杀完两个 serve，1.2 秒后端口又被占。
    if st.get("kill_first"):
        names = st["kill_first"]
        steps.append({"t": "终止", "msg": f"本机守护进程 {'、'.join(names)} → {_local_kill_names(names)}"})
    if st.get("kill_first_remote"):
        names = st["kill_first_remote"]
        steps.append({"t": "终止", "msg": f"远程守护进程 {'、'.join(names)} → {_remote_kill_names(names)}"})

    def _kill_primary() -> str:
        if remote:
            return f"远程 {port_label(st['kill_remote_port'])} → {kill_remote_port(st['kill_remote_port'])}"
        return f"本机 {port_label(st['kill_port'])} → {kill_local_port(st['kill_port'])}"

    def _port_alive() -> bool:
        if remote:
            return _remote_port_listening(st["kill_remote_port"])
        h, p = split_hostport(st["kill_port"])
        return probe_tcp(h or "127.0.0.1", p, 1.5)[0]

    if remote or "kill_port" in st:
        steps.append({"t": "终止", "msg": _kill_primary()})
        time.sleep(1.5 if remote else 1.2)
        if _port_alive():                 # 还有东西在把它拉回来，再补一刀
            steps.append({"t": "重试", "msg": "端口仍被占用，再杀一次"})
            steps.append({"t": "终止", "msg": _kill_primary()})
            time.sleep(1.5)
        gone = not _port_alive()
        label = port_label(st.get("kill_remote_port") or st["kill_port"])
        steps.append({"t": "确认",
                      "msg": f"{'远程' if remote else '本机'} {label} "
                             + ("已释放" if gone else "仍在监听（有守护进程在把它拉回来）")})
        ok = ok and gone
    elif "remote_service" in st:
        nm = st["remote_service"]
        out, err = ssh_inline(f"$ProgressPreference='SilentlyContinue'; "
                              f"Stop-Service -Name '{nm}' -Force -EA SilentlyContinue; "
                              f"Start-Sleep -Seconds 2; (Get-Service -Name '{nm}').Status", timeout=70)
        steps.append({"t": "终止", "msg": f"远程 Stop-Service {nm} → {out or err}"})
        ok = ok and ("Stopped" in out)
    elif "service" in st:
        nm = st["service"]
        out, err = run_ps_inline(f"Stop-Service -Name '{nm}' -Force -EA SilentlyContinue; "
                                 f"Start-Sleep -Seconds 2; (Get-Service -Name '{nm}').Status", timeout=70)
        steps.append({"t": "终止", "msg": f"Stop-Service {nm} → {out or err}"})
        ok = ok and ("Stopped" in out)

    entry = {"id": svc["id"], "name": svc["name"], "action": "stop", "ok": ok, "steps": steps,
             "elapsed_s": round(time.time() - t0, 1), "freed_mb": freed, "at": now_iso()}
    remember(entry)
    return entry


def do_restart(svc: dict) -> dict:
    r = svc.get("restart") or {"kind": "none", "why": "未配重启方式"}
    steps: list[dict] = []
    t0 = time.time()

    if r["kind"] == "none":
        return {"id": svc["id"], "ok": False, "steps": [{"t": "拒绝", "msg": r.get("why", "不支持重启")}],
                "elapsed_s": 0}

    if "kill_remote_port" in r:
        steps.append({"t": "停止",
                      "msg": f"远程 {port_label(r['kill_remote_port'])} → {kill_remote_port(r['kill_remote_port'])}"})
        time.sleep(2.0)
    if "kill_port" in r:
        steps.append({"t": "停止",
                      "msg": f"本机 {port_label(r['kill_port'])} → {kill_local_port(r['kill_port'])}"})
        time.sleep(1.5)

    if r["kind"].startswith("remote-"):
        start_remote(r, steps)
    else:
        start_local(r, steps)

    if "wait_remote_port" in r:
        spec = r["wait_remote_port"]
        label = port_label(spec)
        state, why = wait_remote_port(spec, r.get("wait_s", 30),
                                      cmd=r.get("probe_cmd", ""), probe=r.get("probe_log", ""))
        if state == "ready":
            # 启动脚本的结论形如「2026-09-22 02:27:30 READY dsh web listening on ...」，
            # 时间戳与端口都是读者已知的，只留结论本身。
            note = why.split(" ", 2)[-1].strip() if why else ""
            if note.upper().startswith("READY"):
                note = note[5:].strip()
            msg = f"远程 {label} 已监听"
            if note:
                msg += f"（启动脚本：{note[:160]}）"
        elif state == "failed":
            msg = f"远程 {label} 未拉起 —— {why}"
        elif why and "ALREADY" in why:
            msg = f"远程 {label} 仍被其他进程占用，启动脚本未执行"
        else:
            msg = f"远程 {label} 等待 {int(r.get('wait_s', 30)) * 3} 秒仍未监听"
            if why:
                msg += f"（{why}）"
        steps.append({"t": "确认", "msg": msg})
        result_ok = state == "ready"
    elif "wait_port" in r:
        h, p = split_hostport(r["wait_port"])
        ok = wait_port(h or "127.0.0.1", p, r.get("wait_s", 30))
        steps.append({"t": "确认",
                      "msg": f"本机 {port_label(r['wait_port'])} " + ("已监听" if ok else "仍未监听")})
        result_ok = ok
    elif "wait_remote_process" in r:
        nm = r["wait_remote_process"]
        ok = wait_remote_process(nm, r.get("wait_s", 30))
        steps.append({"t": "确认", "msg": f"远程进程 {nm} " + ("已就绪" if ok else "未出现")})
        result_ok = ok
    elif "wait_process" in r:
        nm = r["wait_process"]
        ok = wait_local_process(nm, r.get("wait_s", 30))
        steps.append({"t": "确认", "msg": f"本机进程 {nm} " + ("已就绪" if ok else "未出现")})
        result_ok = ok
    else:
        steps.append({"t": "确认", "msg": "该服务无固定端口，按启动指令已下发判定"})
        result_ok = True

    entry = {"id": svc["id"], "name": svc["name"], "action": "restart", "ok": result_ok,
             "steps": steps, "elapsed_s": round(time.time() - t0, 1), "at": now_iso()}
    remember(entry)
    return entry


# ---------------------------------------------------------------- 保活
# 有一类服务「本来就该一直活着」：它几乎不占资源，掉了却会断掉别的链路
# （第一个成员是 SSH 隧道 —— 它是本机看远端 DSH 的唯一通道，且断了不自愈）。
# 它们由 services[].keepalive 声明，本模块负责看着并拉起。
#
# 与 restart 的语义差别是这里最容易出错的地方：
#   restart   = 「人按了一次按钮」
#   keepalive = 「机器自己按」
# 被保活服务的 restart 必须是轻量、幂等、无重副作用的拉起 —— 见 AGENTS.md。

def keepalive_state(sid: str) -> dict:
    """取（并按需初始化）某个服务的保活状态。"""
    return KEEPALIVE.setdefault(sid, {
        "down_streak": 0, "fails": 0, "next_at": 0.0, "paused": False,
        "invalid": "", "waiting_on": "", "last_error": "", "starts": 0,
        # 右栏「轻量常驻」要报「上次拉起」，所以成功那一刻留下时间戳；
        # 只数次数的话，一个刚被拉起和一个半小时前被拉起的服务长得一模一样。
        "last_ok_at": "",
    })


def keepalive_services() -> list[dict]:
    return [s for s in SERVICES if s.get("keepalive")]


def nesting_precheck() -> None:
    """归属（services[].under）的启动自检。

    指向不存在的 id、或指向自己时，build_view 会当它是普通条目 —— 于是它就照常在
    概览上占一张卡，配置看起来「写了却没反应」。这种沉默必须打破，所以启动时说一句。
    """
    ids = {s["id"] for s in SERVICES}
    for svc in SERVICES:
        parent = svc.get("under")
        if not parent:
            continue
        if parent == svc["id"]:
            print(f"[归属] {svc['id']} 的 under 指向自己，按普通条目处理")
        elif parent not in ids:
            print(f"[归属] {svc['id']} 的 under={parent} 不存在，按普通条目处理")


def keepalive_precheck() -> None:
    """启动时静态过一遍：配置层就能判定「起不来」的，根本不进保活循环 ——
    对一个不存在的脚本退避重试五次毫无意义。远端路径存不存在要 SSH 才知道，
    留给第一次拉起失败去判，那时同样是立即暂停。
    """
    for svc in keepalive_services():
        r = svc.get("restart") or {}
        kind = r.get("kind", "none")
        why = ""
        if kind == "none":
            why = "未配重启方式"
        elif kind == "exe":
            exe = r.get("exe") or ""
            if exe and not Path(exe).exists():
                why = f"程序不存在：{exe}"
        elif kind == "ps1":
            path = r.get("path") or ""
            if path and not Path(path).exists():
                why = f"脚本不存在：{path}"
        if why:
            keepalive_state(svc["id"])["invalid"] = why
            print(f"[保活] {svc['id']} 不可保活：{why}")


def keepalive_tick() -> None:
    services = keepalive_services()
    if not services:
        return
    with STATE.lock:
        probes = dict(STATE.probes)
    by_id = {s["id"]: s for s in SERVICES}

    for svc in services:
        sid = svc["id"]
        st = keepalive_state(sid)
        if st["invalid"]:
            continue

        # 「已恢复」这一步必须在 paused 之前判：被暂停的服务可能因为使用者手动重启、
        # 或它自己恢复而重新在线，那时保活应当自动接上 —— 否则「暂停」就成了单向门。
        # 中继服务的存活看本地转发端口，不看经中继的 HTTP：对端服务挂了时隧道本身是好的，
        # 重启隧道无济于事，只会把保活自己推到暂停（旧 rag-tunnel 的假红教训）。
        alive = probes.get(sid, {}).get("status") == "up"
        if svc.get("relay"):
            wait_port = int((svc.get("restart") or {}).get("wait_port") or 0)
            if wait_port:
                alive = probe_tcp("127.0.0.1", wait_port, timeout=1.0)[0]
        if alive:
            st.update(down_streak=0, fails=0, next_at=0.0, last_error="",
                      waiting_on="", paused=False)
            continue

        if st["paused"]:
            continue

        st["down_streak"] += 1
        if st["down_streak"] < KEEPALIVE_CFG["down_streak"]:
            continue

        # 依赖没就绪就先别动手：那个依赖很可能正被它自己的保活拉起。
        # 这不算失败 —— 否则一个共同的上游会把所有下游一起推向暂停。
        missing = [d for d in svc.get("needs", [])
                   if d in by_id and probes.get(d, {}).get("status") != "up"]
        if missing:
            st["waiting_on"] = missing[0]
            continue
        st["waiting_on"] = ""

        if time.time() < st["next_at"]:
            continue

        # 与用户的手动操作撞车时跳过本轮，同样不计失败 ——
        # 否则使用者每点一次重启，就把这个服务往暂停推一格。
        if not _RESTART_LOCK.acquire(blocking=False):
            continue
        try:
            entry = do_restart(svc)
        except Exception as e:                            # noqa: BLE001
            entry = {"ok": False, "elapsed_s": 0,
                     "steps": [{"t": "异常", "msg": f"{type(e).__name__}: {e}"}]}
        finally:
            _RESTART_LOCK.release()

        last = ""
        for step in entry.get("steps", []):
            if step.get("t") == "确认":
                last = step.get("msg", "")
        if not last and entry.get("steps"):
            last = entry["steps"][-1].get("msg", "")

        if entry.get("ok"):
            st.update(fails=0, next_at=0.0, down_streak=0, last_error="",
                      starts=st["starts"] + 1, last_ok_at=now_iso())
        else:
            st["fails"] += 1
            st["last_error"] = last
            idx = min(st["fails"] - 1, len(KEEPALIVE_CFG["backoff"]) - 1)
            st["next_at"] = time.time() + KEEPALIVE_CFG["backoff"][idx]
            if st["fails"] >= KEEPALIVE_CFG["max_fails"]:
                st["paused"] = True

        # do_restart 自己已经记过一行 restart；这里补的是「机器自己按的」这个事实，
        # 所以只记结论，不重复 steps。查行为仍然是先看同一个文件。
        remember({"id": sid, "name": svc["name"], "action": "keepalive",
                  "ok": bool(entry.get("ok")), "attempt": max(1, st["fails"]),
                  "starts": st["starts"], "trigger": "probe", "paused": st["paused"],
                  "msg": last, "elapsed_s": entry.get("elapsed_s", 0), "at": now_iso()})


def keepalive_loop() -> None:
    while True:
        interval = max(2.0, INTERVALS.get("keepalive_ms", 5000) / 1000)
        t0 = time.time()
        try:
            keepalive_tick()
        except Exception as e:                            # noqa: BLE001
            print(f"[保活] 巡检异常：{type(e).__name__}: {e}")
        time.sleep(max(1.0, interval - (time.time() - t0)))


def _loaded_vram(base: str) -> dict:
    """当前常驻模型 -> 显存字节数。卸载前后各取一次，才能如实报出释放量。"""
    return {m.get("name"): (m.get("size_vram") or m.get("size") or 0)
            for m in ollama_get(base, "/api/ps").get("models", [])}


def _ollama_keepalive(base: str, model: str, keep, num_ctx: int | None = None) -> None:
    """改模型的常驻状态而不产出 token。

    /api/generate 带空 prompt 是生成模型的加载/卸载约定；**嵌入模型不吃它**——实测
    qwen3-embedding 走 /api/generate 一律 HTTP 400，只能走 /api/embed。故 400 时回退。
    """
    body: dict = {"model": model, "keep_alive": keep}
    if num_ctx is not None:
        body["options"] = {"num_ctx": num_ctx}
    try:
        ollama_post(base, "/api/generate", body)
    except urllib.error.HTTPError as e:
        if e.code != 400:
            raise
        ollama_post(base, "/api/embed", {**body, "input": [""]})


def do_model_action(svc: dict, payload: dict) -> dict:
    """模型加载 / 卸载 / 全部卸载。

    num_ctx 用 CTX_MODEL_DEFAULT 时不下发 options，让模型自带的值生效 —— 远程的 16k / 32k /
    131k 变体就是靠它区分的。显式指定则按白名单校验：模型默认可能是 262144，实测 9.85 GB
    显存 + 1.87 GB 溢出，而 RTX 3060 只有 12 GB，会连带把生产实例挤掉。
    keep_alive 同样按白名单校验，不接受任意值。
    """
    base = svc["models_api"]
    action = str(payload.get("action") or "")
    steps: list[dict] = []
    t0 = time.time()
    freed = 0
    ok = True

    def done() -> dict:
        entry = {"id": svc["id"], "name": svc["name"], "action": f"model:{action}", "ok": ok,
                 "steps": steps, "elapsed_s": round(time.time() - t0, 1),
                 "freed_mb": freed, "at": now_iso()}
        remember(entry)
        return entry

    if action in ("unload", "unload_all"):
        if action == "unload_all":
            targets = list(_loaded_vram(base).items())
        else:
            model = str(payload.get("model") or "")
            if not model:
                steps.append({"t": "拒绝", "msg": "未指定模型"})
                ok = False
                return done()
            targets = [(model, _loaded_vram(base).get(model, 0))]
        if not targets:
            steps.append({"t": "跳过", "msg": "当前没有已加载的模型"})
            return done()
        for model, vram in targets:
            if not vram:
                steps.append({"t": "跳过", "msg": f"{model} 当前未加载"})
                continue
            _ollama_keepalive(base, model, 0)
            freed += round(vram / 1048576)
            steps.append({"t": "卸载", "msg": model})
        left = _loaded_vram(base)
        steps.append({"t": "确认",
                      "msg": f"释放 {freed} MB" + (f"，仍有 {len(left)} 个常驻" if left
                                                   else "，已无模型常驻")})
        ok = not left

    elif action == "load":
        model = str(payload.get("model") or "")
        try:
            num_ctx = int(payload.get("num_ctx"))
        except (TypeError, ValueError):
            num_ctx = 0
        keep = payload.get("keep_alive")
        if isinstance(keep, str) and keep.lstrip("-").isdigit():
            keep = int(keep)
        if not model:
            steps.append({"t": "拒绝", "msg": "未指定模型"})
            ok = False
            return done()
        if num_ctx != CTX_MODEL_DEFAULT and num_ctx not in CTX_CHOICES:
            steps.append({"t": "拒绝", "msg": f"上下文只能是 模型默认 或 "
                                              f"{'/'.join(map(str, CTX_CHOICES))}"})
            ok = False
            return done()
        if keep not in KEEP_CHOICES:
            steps.append({"t": "拒绝", "msg": f"保留时长只能是 {'/'.join(map(str, KEEP_CHOICES))}"})
            ok = False
            return done()
        sent = None if num_ctx == CTX_MODEL_DEFAULT else num_ctx
        steps.append({"t": "加载", "msg": f"{model}  "
                                          f"num_ctx={'模型默认' if sent is None else sent}  "
                                          f"keep_alive={'永久' if keep == -1 else keep}"})
        before = set(_loaded_vram(base))
        _ollama_keepalive(base, model, keep, sent)
        ps = {m.get("name"): m for m in ollama_get(base, "/api/ps").get("models", [])}
        evicted = sorted(before - set(ps))
        if evicted:
            steps.append({"t": "换出", "msg": f"{'、'.join(evicted)} 被一并换出 —— "
                                              f"剩余显存不足以同时容纳"})
        hit = ps.get(model)
        if hit:
            got = hit.get("context_length")
            steps.append({"t": "确认",
                          "msg": f"已常驻  ctx={got}  "
                                 f"显存 {round((hit.get('size_vram') or 0) / 1048576)} MB  "
                                 f"到期 {str(hit.get('expires_at'))[:19]}"})
            want = model_num_ctx(base, model) if sent is None else num_ctx
            ok = want is None or got == want
        else:
            # Ollama 对配置等价的模型复用实例，/api/ps 只报先加载的那个名字。判据取
            # 「同一基础模型 + 相同 num_ctx」—— 不同 tag 的 manifest digest 各不相同，
            # 没法用 digest 认出来。如实说明复用，不报「未常驻」。
            want = model_num_ctx(base, model) if sent is None else num_ctx
            stem = model.split(":")[0]
            twin = next((m for m in ps.values()
                         if want is not None and m.get("context_length") == want
                         and str(m.get("name") or "").split(":")[0] == stem), None)
            if twin is not None:
                steps.append({"t": "复用", "msg": f"与常驻的 {twin.get('name')} 配置等价，"
                                                  f"Ollama 未另起实例（ctx={want}）"})
                ok = True
            else:
                steps.append({"t": "确认", "msg": "加载后未出现在常驻列表"})
                ok = False

    else:
        steps.append({"t": "拒绝", "msg": f"未知操作 {action!r}"})
        ok = False

    return done()


_rag_params_cache: dict = {"mtime": 0.0, "data": None}


# ------------------------------------------------- SillyTavern / DSH 只读采集

_read_cache: dict[str, tuple[float, dict]] = {}


def _cached_read(key: str, path: Path, loader) -> dict:
    """按 mtime 缓存。读坏的文件也缓存住，免得每 3 秒轮询都报一次同样的错。"""
    try:
        mtime = path.stat().st_mtime
    except OSError as e:
        return {"error": f"读不到 {path.name}: {e.strerror or e}"}
    prev = _read_cache.get(key)
    if prev and prev[0] == mtime:
        return prev[1]
    try:
        out = loader(path)
    except Exception as e:                    # noqa: BLE001 —— 文件内容千奇百怪
        out = {"error": f"{type(e).__name__}: {e}"}
    _read_cache[key] = (mtime, out)
    return out


def _st_settings_read(path: Path) -> dict:
    """客户端连什么。custom 源用 custom_url/custom_model，其余 OpenAI 系源走 reverse_proxy。"""
    doc = json.loads(path.read_text(encoding="utf-8"))
    oai = doc.get("oai_settings") or {}
    tc = doc.get("textgenerationwebui_settings") or {}
    api, src = doc.get("main_api"), oai.get("chat_completion_source")
    if src == "custom":
        url, model = oai.get("custom_url"), oai.get("custom_model")
    else:
        url, model = oai.get("reverse_proxy"), oai.get("openai_model")
    stale = None
    if api != "textgenerationwebui" and tc.get("type"):
        stale = {"type": tc.get("type"), "model": tc.get("ollama_model"),
                 "url": (tc.get("server_urls") or {}).get("ollama")}
    return {
        "error": None, "version": doc.get("currentVersion"),
        "api": api, "source": src, "url": url or "", "model": model or "",
        "ctx_declared": doc.get("max_context"), "max_tokens": oai.get("openai_max_tokens"),
        "char": (doc.get("active_character") or "").removesuffix(".png") or None,
        "stale": stale,
    }


def _st_config_read(path: Path) -> dict:
    found = _yaml_scalars(path.read_text(encoding="utf-8", errors="replace"),
                          [p for p, _ in ST_CFG_KEYS])
    rows = []
    for path_key, label in ST_CFG_KEYS:
        safe = _safe_cfg_value(found.get(path_key) or "")
        if safe is not None:                  # 非布尔/整数/地址一律不展示
            rows.append({"label": label, "key": ".".join(path_key), "value": safe})
    return {"error": None, "rows": rows}


def _ua_kind(ua: str) -> str:
    if "Android" in ua or "iPhone" in ua or "Mobile" in ua:
        return "手机"
    if "PowerShell" in ua or "curl" in ua or "urllib" in ua:
        return "脚本"
    return "浏览器" if "Mozilla" in ua else "其他"


def _st_access_read(path: Path) -> dict:
    """access.log 一次连接一行：时间 IP UA。本面板自己的探测要先滤掉。"""
    size = path.stat().st_size
    with path.open("rb") as f:
        f.seek(max(0, size - 262144))
        data = f.read()
    rows, noise = [], 0
    for line in decode_smart(data).splitlines()[-ST_ACCESS_TAIL:]:
        parts = line.split(" ", 2)
        if len(parts) < 3:
            continue
        if ST_UA_NOISE in parts[2]:
            noise += 1
            continue
        rows.append({"ts": parts[0][:19].replace("T", " "), "ip": parts[1],
                     "kind": _ua_kind(parts[2]), "ua": parts[2]})
    return {"error": None, "rows": rows[-ST_ACCESS_KEEP:][::-1],
            "total": len(rows) + noise, "noise": noise, "real": len(rows)}


def _dsh_settings_read(path: Path) -> dict:
    found = _yaml_scalars(path.read_text(encoding="utf-8"), [DSH_CTX_PATH])
    return {"error": None, "ctx": _safe_cfg_value(found.get(DSH_CTX_PATH) or "")}


def _st_findings(st: dict, cfg: dict) -> list[dict]:
    """挑出「配了但不生效」和「开了但没必要」。只陈述事实与后果，不给建议。"""
    got = {r["key"]: r["value"] for r in (cfg.get("rows") or [])}
    out = []
    if got.get("listenAddress.ipv4") == "0.0.0.0" and got.get("whitelistMode") == "false":
        out.append({"level": "warn", "text": "监听全部网卡、IP 白名单关闭，唯一防线是 basicAuth"})
    if st.get("stale"):
        s = st["stale"]
        out.append({"level": "warn",
                    "text": f"Text Completion 通道残留（type={s.get('type')}，"
                            f"模型 {s.get('model')}）；当前 main_api 不是它，不生效"})
    if got.get("heartbeatInterval") == "0":
        out.append({"level": "info", "text": "heartbeatInterval 为 0，外部无从判断它是否卡死"})
    if got.get("logging.minLogLevel") == "0":
        out.append({"level": "info", "text": "终端日志级别 DEBUG(0)，输出量最大"})
    if got.get("sessionTimeout") == "-1":
        out.append({"level": "info", "text": "会话永不过期，认证一次后不再复核"})
    if got.get("ssl.enabled") == "false":
        out.append({"level": "info", "text": "未启用 SSL；经 Tailscale 访问时链路本身已加密"})
    return out


def st_info() -> dict:
    st = _cached_read("st_settings", ST_SETTINGS, _st_settings_read)
    cfg = _cached_read("st_config", ST_CONFIG, _st_config_read)
    acc = _cached_read("st_access", ST_ACCESS, _st_access_read)
    dsh = _cached_read("dsh_settings", DSH_SETTINGS, _dsh_settings_read)
    return {"at": time.time(), "st": st, "cfg": cfg, "access": acc, "dsh": dsh,
            "findings": _st_findings(st, cfg), "assets": st_assets()}


# ------------------------------------------------- 创作资产：角色卡与世界书

_st_assets: dict = {"stamp": None, "chars": [], "worlds": []}


def _png_card(path: Path) -> dict | None:
    """角色卡把 JSON 塞在 PNG 的 tEXt chunk 里：keyword=chara，值是 base64。"""
    try:
        b = path.read_bytes()
    except OSError:
        return None
    if b[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    i = 8
    while i + 12 <= len(b):
        ln = struct.unpack(">I", b[i:i + 4])[0]
        if b[i + 4:i + 8] == b"tEXt":
            kw, _, val = b[i + 8:i + 8 + ln].partition(b"\x00")
            if kw == b"chara":
                try:
                    return json.loads(base64.b64decode(val).decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    return None
        i += 12 + ln
    return None


def _dir_stamp(d: Path) -> tuple:
    """文件清单指纹。目录 mtime 在文件被改写时并不变，得看每个文件的大小与 mtime。"""
    try:
        return tuple(sorted((f.name, f.stat().st_size, int(f.stat().st_mtime))
                            for f in d.glob("*") if f.is_file()))
    except OSError:
        return ()


def _preview(s: str) -> str:
    flat = " ".join(s.split())
    return flat[:ST_PREVIEW_CHARS] + ("…" if len(flat) > ST_PREVIEW_CHARS else "")


def _scan_assets() -> None:
    """整轮扫描并把结果留在缓存里；索引视图在返回时再裁剪掉全文。"""
    chars = []
    for f in sorted(ST_CHARS_DIR.glob("*.png")):
        doc = _png_card(f)
        if not doc:
            chars.append({"file": f.name, "error": "无法解析 PNG 中的角色卡数据"})
            continue
        d = doc.get("data") or doc
        texts = {k: str(d.get(k) or "") for k in ST_CARD_FIELDS}
        side, sync = f.with_suffix(".json"), None
        if side.is_file():
            try:
                same = (json.dumps(json.loads(side.read_text(encoding="utf-8")),
                                   sort_keys=True) == json.dumps(doc, sort_keys=True))
                sync = "一致" if same else "不同"
            except (OSError, ValueError):
                sync = "读失败"
        book = d.get("character_book")
        chars.append({
            "file": f.name, "error": None,
            "name": str(d.get("name") or f.stem),
            "spec": f"{doc.get('spec', '?')} / {doc.get('spec_version', '?')}",
            "creator": str(d.get("creator") or ""),
            "version": str(d.get("character_version") or ""),
            "tags": [str(t) for t in (d.get("tags") or [])],
            "greetings": len(d.get("alternate_greetings") or []),
            "tokens": est_tokens("".join(texts.values())),
            "book": (f"{book.get('name') or '?'}（{len(book.get('entries') or [])} 条）"
                     if isinstance(book, dict) else None),
            "json_sync": sync, "texts": texts,
        })

    worlds = []
    for f in sorted(ST_WORLDS_DIR.glob("*.json")):
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            worlds.append({"file": f.name, "error": f"{type(e).__name__}: {e}"})
            continue
        ent = doc.get("entries")
        items = list(ent.values()) if isinstance(ent, dict) else list(ent or [])
        rows = []
        for e in items:
            body = str(e.get("content") or "")
            rows.append({"uid": e.get("uid"), "comment": str(e.get("comment") or ""),
                         "keys": [str(k) for k in (e.get("key") or [])],
                         "constant": bool(e.get("constant")),
                         "disable": bool(e.get("disable")), "order": e.get("order"),
                         "chars": len(body), "tokens": est_tokens(body), "text": body})
        live = [r for r in rows if not r["disable"]]
        worlds.append({
            "file": f.name, "error": None, "entries": len(rows),
            "disabled": len(rows) - len(live),
            "chars": sum(r["chars"] for r in rows),
            # token 只算未禁用的：禁用的条目不进 prompt
            "tokens": sum(r["tokens"] for r in live),
            "constant_n": sum(1 for r in live if r["constant"]),
            "constant_tokens": sum(r["tokens"] for r in live if r["constant"]),
            "rows": rows,
        })

    _st_assets.update({"stamp": (_dir_stamp(ST_CHARS_DIR), _dir_stamp(ST_WORLDS_DIR)),
                       "chars": chars, "worlds": worlds})


def _assets_findings() -> list[dict]:
    """只陈述事实。这些是创作资产里值得看一眼的地方，不是故障。"""
    out = []
    for c in _st_assets["chars"]:
        if c.get("error"):
            out.append({"level": "warn", "text": f"{c['file']}：{c['error']}"})
            continue
        if c.get("json_sync") == "不同":
            out.append({"level": "warn", "text": f"{c['name']}（{c['file']}）："
                                                  f"PNG 内嵌卡与同名 .json 内容不同"})
    for w in _st_assets["worlds"]:
        if w.get("error"):
            continue
        if w["disabled"]:
            out.append({"level": "info",
                        "text": f"{w['file']}：{w['disabled']} 条被禁用，不进 prompt"})
        if not w["constant_n"]:
            out.append({"level": "info", "text": f"{w['file']}：没有常驻条目，全部靠关键词触发"})
    return out


def st_assets(full: bool = False) -> dict:
    if _st_assets["stamp"] != (_dir_stamp(ST_CHARS_DIR), _dir_stamp(ST_WORLDS_DIR)):
        _scan_assets()

    chars = []
    for c in _st_assets["chars"]:
        if c.get("error"):
            chars.append(c)
            continue
        out = {k: v for k, v in c.items() if k != "texts"}
        out["fields"] = [{"key": k, "label": ST_FIELD_LABEL[k],
                          "chars": len(c["texts"][k]), "tokens": est_tokens(c["texts"][k]),
                          "preview": _preview(c["texts"][k])}
                         for k in ST_CARD_FIELDS if c["texts"][k]]
        chars.append(out)

    worlds = []
    for w in _st_assets["worlds"]:
        if w.get("error"):
            worlds.append(w)
            continue
        out = {k: v for k, v in w.items() if k != "rows"}
        out["rows"] = [dict((k, v) for k, v in r.items() if k != "text") | {"preview": _preview(r["text"])}
                       for r in w["rows"]]
        worlds.append(out)

    ok_c = [c for c in chars if not c.get("error")]
    ok_w = [w for w in worlds if not w.get("error")]
    view = {"at": time.time(), "chars": chars, "worlds": worlds,
            "findings": _assets_findings(),
            "totals": {"cards": len(ok_c), "worlds": len(ok_w),
                       "card_tokens": sum(c["tokens"] for c in ok_c),
                       "world_tokens": sum(w["tokens"] for w in ok_w),
                       "constant_tokens": sum(w["constant_tokens"] for w in ok_w),
                       "constant_n": sum(w["constant_n"] for w in ok_w)}}
    if full:      # 展开全文用；走独立端点，避免 3 秒轮询每次都搬这些正文
        view["texts"] = {c["file"]: c["texts"] for c in _st_assets["chars"] if not c.get("error")}
        view["world_text"] = {w["file"]: {r["uid"]: r["text"] for r in w["rows"]}
                              for w in _st_assets["worlds"] if not w.get("error")}
    return view


def rag_params() -> dict:
    """只读展示 rag_server.py 的模块级常量。

    项目约定不改动 C:\\LLMdeploy 的既有代码, 故不向 RAG 加配置端点, 改为解析源码。
    用 ast 而不是正则: 只有真正是字面量的赋值才取值, 其余(os.path.join、re.compile、
    _state_lock)一律跳过 —— 拿不到就说拿不到, 不猜。
    """
    try:
        mtime = RAG_SRC.stat().st_mtime
    except OSError:
        return {"error": f"找不到 {RAG_SRC}"}
    if _rag_params_cache["data"] is not None and _rag_params_cache["mtime"] == mtime:
        return _rag_params_cache["data"]
    try:
        tree = ast.parse(RAG_SRC.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as e:
        return {"error": f"读取或解析失败: {e}"}

    scalars: dict = {}
    counts: dict = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            # 下划线开头的是运行时状态(_KW_AVG/_KW_DIRTY 等), 不是配置, 不展示
            if not (isinstance(target, ast.Name) and target.id.isupper()
                    and not target.id.startswith("_")):
                continue
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                continue
            if isinstance(value, (dict, list, tuple)):
                counts[target.id] = len(value)
            elif isinstance(value, (str, int, float, bool)):
                scalars[target.id] = value

    listed = {k for _, keys in RAG_PARAM_GROUPS for k in keys}
    groups = []
    for title, keys in RAG_PARAM_GROUPS:
        rows = [{"key": k, "value": scalars[k]} for k in keys if k in scalars]
        if rows:
            groups.append({"title": title, "rows": rows})
    rest = sorted(k for k in scalars if k not in listed)
    if rest:
        groups.append({"title": "其余标量", "rows": [{"key": k, "value": scalars[k]} for k in rest]})

    # num_ctx 是内联在请求体字典里的字面量，不是模块级常量，得单独走一遍 tree。
    # 它是对账表里唯一一个「显式传给 Ollama」的上下文值，必须取到。
    num_ctx = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if (isinstance(k, ast.Constant) and k.value == "num_ctx"
                    and isinstance(v, ast.Constant) and isinstance(v.value, int)):
                num_ctx = v.value
                break
        if num_ctx is not None:
            break

    out = {"error": None, "at": time.time(), "source": str(RAG_SRC), "groups": groups,
           "counts": [{"key": k, "n": counts[k]} for k in sorted(counts)],
           "num_ctx": num_ctx}
    _rag_params_cache.update({"mtime": mtime, "data": out})
    return out


# ---------------------------------------------------------------- 设置写入
#
# 两类设置：
#   1) 面板自身配置（services.json）：显示默认值、采样间隔、保活策略、服务清单与命令；
#   2) 服务参数（services[].settings 声明）：由拥有该服务的面板本地落地，跨机经 peer 转发。
# 两者都要求写级权限；命令字段只允许回环 —— 改命令等于改面板会执行的程序。

_SETTINGS_LOCK = threading.RLock()
KEEPALIVE_CFG = {"down_streak": KEEPALIVE_DOWN_STREAK,
                 "backoff": list(KEEPALIVE_BACKOFF_S),
                 "max_fails": KEEPALIVE_MAX_FAILS}
CARD_PREF_FIELDS = ("role", "detail", "metrics", "deps", "note", "warn", "badges", "keepalive")
INTERVAL_KEYS = ("probe_local_ms", "sample_local_ms", "sample_remote_ms",
                 "peer_poll_ms", "keepalive_ms")
INTERVAL_RANGE = (500, 3600000)
TIER_VALUES = ("core", "normal", "optional")


def _settings_audit(action, sid, name, fields, ok, msg="", via="", elapsed=0.0):
    # 只记字段名与白名单值；命令类（可能含 env 密钥）只记字段名
    remember({"id": sid or "panel", "name": name or "Mozunitor 设置",
              "action": action, "ok": bool(ok), "fields": fields,
              "via": via, "msg": msg, "elapsed_s": round(elapsed, 2), "at": now_iso()})


def _cfg_write() -> None:
    """原子写回 services.json：先序列化并自校验，再临时文件 + os.replace。"""
    text = json.dumps(CFG, indent=2, ensure_ascii=False) + "\n"
    json.loads(text)
    tmp = CFG_PATH.with_name(CFG_PATH.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, CFG_PATH)


def _find_service(sid: str) -> dict | None:
    return next((s for s in SERVICES if s.get("id") == sid), None)


def settings_snapshot(loopback: bool) -> dict:
    services = []
    for svc in SERVICES:
        if svc.get("relay"):
            continue                      # 中继服务由 relay 配置派生，不在设置页编辑
        row = {
            "id": svc["id"], "name": svc["name"], "group": svc.get("group"),
            "tier": svc_tier(svc), "card": svc.get("card") or {},
            "keepalive": bool(svc.get("keepalive")),
            "probe": svc.get("probe"),
            "commands_editable": loopback,
        }
        if loopback:
            row["restart"] = svc.get("restart")
            row["stop"] = svc.get("stop")
        services.append(row)
    return {
        "node": {"id": NODE_ID, "name": NODE_NAME},
        "ui": ui_config(),
        "intervals": dict(INTERVALS),
        "keepalive": {"down_streak": KEEPALIVE_CFG["down_streak"],
                      "backoff": list(KEEPALIVE_CFG["backoff"]),
                      "max_fails": KEEPALIVE_CFG["max_fails"]},
        "tiers": list(TIER_ORDER),
        "card_fields": list(CARD_PREF_FIELDS),
        "services": services,
        "editable": {"commands": loopback},
    }


def _valid_card_patch(patch: dict) -> dict:
    if not isinstance(patch, dict):
        raise ValueError("card 必须是对象")
    out = {}
    for key, val in patch.items():
        if key not in CARD_PREF_FIELDS:
            raise ValueError(f"未知卡片字段 {key!r}")
        out[key] = bool(val)
    return out


def _valid_probe(probe: dict) -> dict:
    if not isinstance(probe, dict):
        raise ValueError("probe 必须是对象")
    kind = str(probe.get("kind") or "")
    if kind not in ("tcp", "http", "process", "task", "remote-port"):
        raise ValueError(f"未知探测方式 {kind!r}")
    out = {"kind": kind}
    for key in ("host", "url", "name"):
        if key in probe:
            val = str(probe[key])[:500]
            if not val:
                raise ValueError(f"probe.{key} 不能为空")
            out[key] = val
    for key in ("port",):
        if key in probe:
            val = int(probe[key])
            if not (1 <= val <= 65535):
                raise ValueError(f"probe.{key} 越界")
            out[key] = val
    if "ok" in probe:
        codes = probe["ok"]
        if not isinstance(codes, list) or not all(isinstance(x, int) for x in codes):
            raise ValueError("probe.ok 必须是整数数组")
        out["ok"] = [int(x) for x in codes]
    return out


def apply_panel_settings(section: str, values: dict, via: str, loopback: bool) -> dict:
    """应用一组面板配置；返回审计用的字段摘要。异常时原文件不变。"""
    if not isinstance(values, dict):
        raise ValueError("values 必须是对象")
    before = json.dumps(CFG, ensure_ascii=False, sort_keys=True)
    changed = {}
    try:
        with _SETTINGS_LOCK:
            if section == "ui":
                ui = CFG.setdefault("ui", {})
                if "card" in values:
                    card = _valid_card_patch(values["card"])
                    ui.setdefault("card", {}).update(card)
                    changed["card"] = sorted(card)
                if "collapse" in values:
                    col = values["collapse"]
                    if not isinstance(col, dict):
                        raise ValueError("collapse 必须是对象")
                    out = {}
                    for tier, mode in col.items():
                        if tier not in TIER_VALUES or mode not in ("auto", "collapsed", "expanded"):
                            raise ValueError(f"非法折叠项 {tier}={mode!r}")
                        out[tier] = mode
                    ui.setdefault("collapse", {}).update(out)
                    changed["collapse"] = sorted(out)
                if "mobile_hide_optional" in values:
                    ui["mobile_hide_optional"] = bool(values["mobile_hide_optional"])
                    changed["mobile_hide_optional"] = ui["mobile_hide_optional"]
            elif section == "intervals":
                for key, raw in values.items():
                    if key not in INTERVAL_KEYS:
                        raise ValueError(f"未知采样间隔 {key!r}")
                    val = int(raw)
                    if not (INTERVAL_RANGE[0] <= val <= INTERVAL_RANGE[1]):
                        raise ValueError(f"{key} 越界（{INTERVAL_RANGE[0]}–{INTERVAL_RANGE[1]}）")
                    INTERVALS[key] = val
                    changed[key] = val
            elif section == "keepalive":
                ka = KEEPALIVE_CFG
                if "down_streak" in values:
                    ka["down_streak"] = int(values["down_streak"])
                    if not (1 <= ka["down_streak"] <= 10):
                        raise ValueError("down_streak 越界（1–10）")
                    changed["down_streak"] = ka["down_streak"]
                if "max_fails" in values:
                    ka["max_fails"] = int(values["max_fails"])
                    if not (1 <= ka["max_fails"] <= 20):
                        raise ValueError("max_fails 越界（1–20）")
                    changed["max_fails"] = ka["max_fails"]
                if "backoff" in values:
                    backoff = values["backoff"]
                    if (not isinstance(backoff, list) or not backoff
                            or not all(isinstance(x, (int, float)) for x in backoff)):
                        raise ValueError("backoff 必须是非空数字数组")
                    ka["backoff"] = [int(x) for x in backoff]
                    if not all(1 <= x <= 3600 for x in ka["backoff"]):
                        raise ValueError("backoff 越界（1–3600 秒）")
                    changed["backoff"] = ka["backoff"]
            elif section == "service":
                sid = str(values.get("id") or "")
                svc = _find_service(sid)
                if not svc:
                    raise ValueError(f"未知服务 id {sid!r}")
                if svc.get("relay"):
                    raise ValueError("中继服务由 relay 配置生成，请在 relay 配置里改")
                patch = values.get("patch") or {}
                if not isinstance(patch, dict):
                    raise ValueError("patch 必须是对象")
                for key in patch:
                    if key in ("restart", "stop"):
                        raise ValueError("命令字段请走 commands 段（仅回环）")
                if "tier" in patch:
                    if patch["tier"] not in TIER_VALUES:
                        raise ValueError(f"未知 tier {patch['tier']!r}")
                    svc["tier"] = patch["tier"]
                    changed["tier"] = patch["tier"]
                if "card" in patch:
                    card = _valid_card_patch(patch["card"])
                    svc.setdefault("card", {}).update(card)
                    changed["card"] = sorted(card)
                if "keepalive" in patch:
                    svc["keepalive"] = bool(patch["keepalive"])
                    changed["keepalive"] = svc["keepalive"]
                if "probe" in patch:
                    svc["probe"] = _valid_probe(patch["probe"])
                    changed["probe"] = svc["probe"].get("kind")
            elif section == "commands":
                if not loopback:
                    raise PermissionError("命令字段只允许在本机回环修改")
                sid = str(values.get("id") or "")
                svc = _find_service(sid)
                if not svc:
                    raise ValueError(f"未知服务 id {sid!r}")
                if svc.get("relay"):
                    raise ValueError("中继服务由 relay 配置生成，请在 relay 配置里改")
                for key in ("restart", "stop"):
                    if key not in values:
                        continue
                    val = values[key]
                    if val is not None and not isinstance(val, dict):
                        raise ValueError(f"{key} 必须是对象或 null")
                    if val is None:
                        svc.pop(key, None)
                    else:
                        svc[key] = val
                    changed[key] = "set" if val else "cleared"
            else:
                raise ValueError(f"未知设置段 {section!r}")
            _cfg_write()
    except Exception:
        CFG.clear()
        CFG.update(json.loads(before))
        raise
    _settings_audit("settings", "panel", f"面板设置 · {section}", changed, True, via=via)
    return changed


# ---------------------------------------------------------------- 服务参数适配器

def _http_json(url: str, payload=None, timeout: float = 10.0) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json",
                                          "Accept": "application/json"})
    with _OPENER.open(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _rag_base(svc: dict) -> str:
    # 中继开启时优先走本机回环端口：RAG 的写请求也收敛到 Mozunitor 通道。
    relay = CFG.get("relay") or {}
    if relay.get("enabled"):
        for c in (relay.get("consumers") or []):
            if c.get("service") == svc.get("id") and c.get("local_port"):
                return f"http://127.0.0.1:{int(c['local_port'])}"
    from urllib.parse import urlsplit
    probe = svc.get("probe") or {}
    url = str(probe.get("url") or "")
    if url:
        p = urlsplit(url)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    return RAG_URL


def _atomic_json(path: Path, doc: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def _adapter_st(svc: dict, values: dict | None = None) -> dict:
    try:
        doc = json.loads(ST_SETTINGS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return {"error": f"读不到酒馆设置：{e}"}
    oai = doc.setdefault("oai_settings", {})
    if values is None:
        return {"values": {"custom_url": oai.get("custom_url") or "",
                           "custom_model": oai.get("custom_model") or "",
                           "openai_max_context": oai.get("openai_max_context")}}
    old = {}
    for key, val in values.items():
        if key == "openai_max_context":
            v = int(val)
            if not (512 <= v <= 1048576):
                raise ValueError("openai_max_context 越界（512–1048576）")
            old[key] = oai.get(key)
            oai[key] = v
        elif key in ("custom_url", "custom_model"):
            v = str(val).strip()
            if not v or len(v) > 500:
                raise ValueError(f"{key} 不能为空且不超过 500 字符")
            old[key] = oai.get(key)
            oai[key] = v
        else:
            raise ValueError(f"未知酒馆参数 {key!r}")
    _atomic_json(ST_SETTINGS, doc)
    _read_cache.pop("st_settings", None)
    return {"values": {k: oai.get(k) for k in values}, "previous": old,
            "notes": ["重开酒馆（或刷新页面）后生效"]}


def _adapter_rag(svc: dict, values: dict | None = None) -> dict:
    base = _rag_base(svc)
    try:
        cur = _http_json(base + "/api/config", {})
    except Exception as e:                                    # noqa: BLE001
        return {"error": f"读 RAG 参数失败：{type(e).__name__}: {e}"}
    if values is None:
        return {"values": {"temperature": cur.get("temperature"),
                           "rewrite_temperature": cur.get("rewrite_temperature")}}
    body = {}
    for key, val in values.items():
        if key not in ("temperature", "rewrite_temperature"):
            raise ValueError(f"未知 RAG 参数 {key!r}")
        v = float(val)
        if not (0.0 <= v <= 2.0):
            raise ValueError(f"{key} 越界（0–2）")
        body[key] = v
    try:
        out = _http_json(base + "/api/config", body)
    except Exception as e:                                    # noqa: BLE001
        return {"error": f"写 RAG 参数失败：{type(e).__name__}: {e}"}
    return {"values": {k: out.get(k) for k in body},
            "notes": ["热生效；重启 RAG 后恢复代码里的默认值"]}


def _ollama_load_defaults(svc: dict) -> dict:
    defaults = svc.get("load_defaults") or {}
    load = next((o for o in (svc.get("ops") or []) if o.get("id") == "load"), {})
    fields = {f.get("name"): f.get("default") for f in (load.get("fields") or [])}
    return {"num_ctx": defaults.get("num_ctx", fields.get("num_ctx")),
            "keep_alive": defaults.get("keep_alive", fields.get("keep_alive"))}


def _adapter_ollama_defaults(svc: dict, values: dict | None = None) -> dict:
    if values is None:
        return {"values": _ollama_load_defaults(svc)}
    cur = _ollama_load_defaults(svc)
    for key, val in values.items():
        if key == "num_ctx":
            v = int(val)
            if v not in CTX_CHOICES:
                raise ValueError(f"num_ctx 必须是 {CTX_CHOICES} 之一")
        elif key == "keep_alive":
            v = str(val)
            if v not in [str(x) for x in KEEP_CHOICES]:
                raise ValueError(f"keep_alive 必须是 {KEEP_CHOICES} 之一")
        else:
            raise ValueError(f"未知 Ollama 加载参数 {key!r}")
        cur[key] = v
    with _SETTINGS_LOCK:
        svc["load_defaults"] = cur
        load = next((o for o in (svc.get("ops") or []) if o.get("id") == "load"), None)
        if load:
            for field in (load.get("fields") or []):
                if field.get("name") in cur:
                    field["default"] = cur[field["name"]]
        _cfg_write()
    return {"values": dict(cur), "notes": ["下次加载模型时生效"]}


OLLAMA_OVERRIDES = LLMDEPLOY / "mozunitor-overrides.json"
OLLAMA_ENV_KEYS = ("OLLAMA_MAX_LOADED_MODELS",)


def _llmdeploy_dir() -> Path:
    """LLMdeploy 目录：先读路径配置，再从服务的启动脚本反推；都没有才用本机默认。"""
    cfg = CFG.get("paths") or {}
    p = cfg.get("llmdeploy")
    if p:
        return Path(str(p))
    for svc in SERVICES:
        r = svc.get("restart") or {}
        path = str(r.get("path") or "")
        if path.replace("/", "\\").endswith("m1k-services.ps1"):
            return Path(path).parent
    return LLMDEPLOY


def _adapter_ollama_env(svc: dict, values: dict | None = None) -> dict:
    base = _llmdeploy_dir()
    overrides = base / "mozunitor-overrides.json"
    if not base.is_dir():
        return {"error": "本机没有 LLMdeploy；Ollama 的持久参数请在 对端 面板上修改"}
    doc = {}
    if overrides.exists():
        try:
            doc = json.loads(overrides.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            doc = {}
    env = dict(doc.get("env") or {})
    if values is None:
        return {"values": {k: env.get(k) for k in OLLAMA_ENV_KEYS},
                "wired": overrides.exists()}
    for key, val in values.items():
        if key not in OLLAMA_ENV_KEYS:
            raise ValueError(f"未知 Ollama 环境参数 {key!r}")
        v = int(val)
        if not (1 <= v <= 8):
            raise ValueError(f"{key} 越界（1–8）")
        env[key] = str(v)
    doc["env"] = env
    with _SETTINGS_LOCK:
        _atomic_json(overrides, doc)
    return {"values": {k: env.get(k) for k in OLLAMA_ENV_KEYS},
            "notes": ["需重启 Ollama 生效；启动脚本是否已接线以启动日志为准"]}


def _safe_ops_path(rel: str) -> Path:
    base = (BUNDLE_DIR / "tools" / "ops").resolve()
    p = (base / rel).resolve()
    if not str(p).startswith(str(base) + os.sep):
        raise ValueError("settings_file 越界")
    return p


def _adapter_file_json(svc: dict, values: dict | None = None) -> dict:
    """通用适配器：读写 tools/ops 下的一个 JSON 对象。验收 fixture 与轻量服务用。"""
    path = _safe_ops_path(str(svc.get("settings_file") or ""))
    doc = {}
    if path.exists():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            return {"error": f"读 {path.name} 失败：{e}"}
    if values is None:
        return {"values": dict(doc)}
    allowed = {f["id"] for f in (svc.get("settings") or [])}
    for key in values:
        if key not in allowed:
            raise ValueError(f"未知参数 {key!r}")
    doc.update(values)
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_json(path, doc)
    return {"values": dict(doc), "notes": []}


SETTINGS_ADAPTERS = {
    "st_settings": _adapter_st,
    "rag_config": _adapter_rag,
    "ollama_load_defaults": _adapter_ollama_defaults,
    "ollama_env": _adapter_ollama_env,
    "file_json": _adapter_file_json,
}


def _coerce_setting(decl: dict, raw):
    typ = decl.get("type", "text")
    if typ == "int":
        val = int(raw)
        if "min" in decl and val < int(decl["min"]):
            raise ValueError(f"{decl['id']} 小于 {decl['min']}")
        if "max" in decl and val > int(decl["max"]):
            raise ValueError(f"{decl['id']} 大于 {decl['max']}")
        return val
    if typ == "float":
        val = float(raw)
        if "min" in decl and val < float(decl["min"]):
            raise ValueError(f"{decl['id']} 小于 {decl['min']}")
        if "max" in decl and val > float(decl["max"]):
            raise ValueError(f"{decl['id']} 大于 {decl['max']}")
        return val
    if typ == "bool":
        return bool(raw)
    if typ == "choice":
        val = str(raw)
        if val not in [str(x) for x in (decl.get("choices") or [])]:
            raise ValueError(f"{decl['id']} 不在可选值内")
        return val
    val = str(raw)
    if len(val) > 2000:
        raise ValueError(f"{decl['id']} 过长")
    return val


def service_settings_view(svc: dict) -> dict:
    decls = svc.get("settings") or []
    groups: dict[str, list] = {}
    for decl in decls:
        groups.setdefault(str(decl.get("adapter") or ""), []).append(decl)
    values, errors, meta = {}, {}, {}
    for name in groups:
        adapter = SETTINGS_ADAPTERS.get(name)
        if not adapter:
            for decl in groups[name]:
                errors[decl["id"]] = f"未知适配器 {name!r}"
            continue
        try:
            out = adapter(svc, None)
        except Exception as e:                                # noqa: BLE001
            out = {"error": f"{type(e).__name__}: {e}"}
        if out.get("error"):
            for decl in groups[name]:
                errors[decl["id"]] = out["error"]
            continue
        values.update(out.get("values") or {})
        if out.get("wired") is not None:
            meta[name] = {"wired": out["wired"]}
    fields = []
    for decl in decls:
        row = {k: decl.get(k) for k in
               ("id", "label", "type", "min", "max", "step", "choices", "apply", "danger", "note")
               if k in decl}
        row["value"] = values.get(decl["id"])
        if decl["id"] in errors:
            row["error"] = errors[decl["id"]]
        if decl.get("note"):
            row["note"] = decl["note"]
        fields.append(row)
    return {"id": svc["id"], "name": svc["name"], "settings": fields, "meta": meta}


def service_settings_write(svc: dict, values: dict, via: str) -> dict:
    if not isinstance(values, dict) or not values:
        raise ValueError("values 必须是非空对象")
    decls = {d["id"]: d for d in (svc.get("settings") or [])}
    unknown = [k for k in values if k not in decls]
    if unknown:
        raise ValueError(f"未声明的参数：{', '.join(unknown)}")
    by_adapter: dict[str, dict] = {}
    for key, raw in values.items():
        decl = decls[key]
        by_adapter.setdefault(str(decl.get("adapter") or ""), {})[key] = \
            _coerce_setting(decl, raw)
    applied, notes, errors = {}, [], []
    for name, subset in by_adapter.items():
        adapter = SETTINGS_ADAPTERS.get(name)
        if not adapter:
            errors.append(f"未知适配器 {name!r}")
            continue
        try:
            out = adapter(svc, subset)
        except Exception as e:                                # noqa: BLE001
            errors.append(f"{type(e).__name__}: {e}")
            continue
        if out.get("error"):
            errors.append(out["error"])
            continue
        applied.update(out.get("values") or {})
        notes.extend(out.get("notes") or [])
    ok = not errors
    _settings_audit("service-settings", svc["id"], svc["name"],
                    {k: values[k] for k in values}, ok, "；".join(errors), via=via)
    if not ok:
        return {"ok": False, "id": svc["id"], "error": "；".join(errors)}
    return {"ok": True, "id": svc["id"], "applied": applied, "notes": notes}


def forward_get(peer: dict, path: str) -> tuple[int, dict]:
    """GET 转发（服务参数读取）。与 forward_action 同一套 peer 证明。"""
    url = str(peer["url"]).rstrip("/") + path
    req = urllib.request.Request(url, headers={
        **peer_headers("GET", path), "Accept": "application/json"})
    try:
        with _OPENER.open(req, timeout=FORWARD_TIMEOUT_S) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"error": f"对端返回 HTTP {e.code}"}


# ---------------------------------------------------------------- 中继
#
# 本机 Mozunitor → SSH → 对端 Mozunitor → 对端服务。远端只听回环，SSH 是唯一入口；
# 本机把每条消费者注册成保活服务（ssh -L 进程），复用既有探测/重启/告警。
_RELAY_LOCK = threading.Lock()
_RELAY_STATE: dict = {}


def relay_status() -> dict:
    with _RELAY_LOCK:
        return {"enabled": bool((CFG.get("relay") or {}).get("enabled")),
                "listeners": [dict(v) for v in _RELAY_STATE.values()]}


def _relay_pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def _relay_handle(conn: socket.socket, item: dict, st: dict) -> None:
    target = str(item.get("target") or "")
    host, port = split_hostport(target)
    try:
        up = socket.create_connection((host or "127.0.0.1", port), timeout=10)
    except OSError as e:
        with _RELAY_LOCK:
            st["last_error"] = f"连不到 {target}：{e}"
        try:
            conn.close()
        except OSError:
            pass
        return
    threading.Thread(target=_relay_pipe, args=(conn, up), daemon=True).start()
    threading.Thread(target=_relay_pipe, args=(up, conn), daemon=True).start()


def _relay_listener(item: dict) -> None:
    from urllib.parse import urlsplit
    cfg = CFG.get("relay") or {}
    port = int(item.get("port") or 0)
    if not (1 <= port <= 65535):
        print(f"[中继] 端口非法：{item.get('port')!r}")
        return
    st = {"id": item.get("id") or f"relay-{port}", "port": port,
          "target": item.get("target"), "service": item.get("service"),
          "listening": False, "connections": 0, "last_error": ""}
    with _RELAY_LOCK:
        _RELAY_STATE[st["id"]] = st
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((str(cfg.get("bind") or "127.0.0.1"), port))
        srv.listen(64)
    except OSError as e:
        with _RELAY_LOCK:
            st["last_error"] = f"监听失败：{e}"
        print(f"[中继] {st['id']} 监听失败：{e}")
        try:
            srv.close()
        except OSError:
            pass
        return
    with _RELAY_LOCK:
        st["listening"] = True
    print(f"[中继] {st['id']} 监听 127.0.0.1:{port} → {item.get('target')}")
    while True:
        try:
            conn, _ = srv.accept()
        except OSError as e:
            with _RELAY_LOCK:
                st["last_error"] = f"accept 失败：{e}"
            time.sleep(1.0)
            continue
        with _RELAY_LOCK:
            st["connections"] += 1
        threading.Thread(target=_relay_handle, args=(conn, item, st), daemon=True).start()


def relay_start_listeners() -> None:
    cfg = CFG.get("relay") or {}
    if not cfg.get("enabled"):
        return
    for item in (cfg.get("listeners") or []):
        threading.Thread(target=_relay_listener, args=(item,), daemon=True,
                         name=f"relay-{item.get('id')}").start()


def build_relay_services() -> list[dict]:
    """把本机的中继消费者注册成保活服务；配置里只有 consumers，服务是派生的。"""
    cfg = CFG.get("relay") or {}
    if not cfg.get("enabled"):
        return []
    ssh = str(cfg.get("ssh") or "")
    out = []
    for c in (cfg.get("consumers") or []):
        local = int(c.get("local_port") or 0)
        remote = int(c.get("remote_port") or 0)
        if not (local and remote and ssh):
            continue
        args = ["-N", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
                "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
                "-L", f"{local}:127.0.0.1:{remote}", ssh]
        out.append({
            "id": str(c.get("id") or f"relay-{local}"),
            "name": str(c.get("name") or f"中继 · {local}"),
            "group": "infra",
            "tier": str(c.get("tier") or "core"),
            "role": str(c.get("role") or f"本机 {local} → {ssh}:{remote}（经对端面板转发）"),
            "probe": c.get("probe") or {"kind": "tcp", "host": "127.0.0.1", "port": local},
            "keepalive": True,
            "relay": True,
            "restart": {"kind": "exe", "exe": SSH, "args": args, "hidden": True,
                        "kill_port": local, "wait_port": local, "wait_s": 15,
                        "note": "中继：SSH 本地转发，由面板保活"},
            "stop": {"kill_port": local},
        })
    return out


SERVICES = list(SERVICES) + build_relay_services()


# ---------------------------------------------------------------- ops 协议
#
# services[].ops 是服务自己声明的操作面。前端不认识任何服务 id，只认 kind 与 sections，
# 于是「给一个服务加前端能力」从「前后端各改一遍」变成「只改一处配置」。
#
# 取数分两层：
#   配置自省层（restart / logs / access）—— 读服务自己已声明的配置，零服务专属代码；
#   服务外挂层（models / rag_params / …）—— 具名适配器，把既有数据源归一成 sections。
# 特判因此从「后端认服务是谁」转移到「服务声明用哪个适配器」。

OP_KINDS = ("link", "view", "run")

# 视图统一契约：一个 sections 容器 + 四种节类型。四种足以覆盖既有全部形状 ——
# 分节标题落成节的 title，键值表 → kv，3–6 列数据表 → table（单元格可带装饰或内嵌动作），
# 徽章行与错误条 → notes，等宽文本 → text。
#
# 表格单元格与键值行的形状：
#   "纯文本"                                        —— 直接渲染
#   {"t": 文本, "hot": 真, "dim": 真, "countdown": ISO 时间}   —— 带装饰的文本
#   {"btn": 标签, "op": 操作 id, "data": {...}, "danger": 真}   —— 内嵌的操作按钮


def _sec(kind: str, title: str = "", **kw) -> dict:
    sec = {"kind": kind, "title": title}
    sec.update(kw)
    return sec


def _kv(title: str, pairs) -> dict:
    rows = [{"label": k, "value": v} for k, v in pairs if v not in (None, "", [], {})]
    return _sec("kv", title, rows=rows)


def _table(title: str, cols, rows) -> dict:
    return _sec("table", title, cols=cols, rows=rows)


def _notes(items) -> dict:
    return _sec("notes", "", items=[{"level": lv, "text": tx} for lv, tx in items if tx])


def _text(title: str, text: str, mono: bool = True) -> dict:
    return _sec("text", title, text=text, mono=mono)


def _gb(n) -> str:
    if not n:
        return "—"
    return f"{n / 1024 ** 3:.1f} GB" if n >= 1024 ** 3 else f"{n / 1024 ** 2:.0f} MB"


def _num(v) -> str:
    return "—" if v in (None, "") else f"{int(v):,}"


def _left(iso) -> str:
    if not iso:
        return "—"
    try:
        left = (datetime.fromisoformat(str(iso)) - datetime.now().astimezone()).total_seconds()
    except (TypeError, ValueError):
        return "—"
    if left <= 0:
        return "已到期"
    return f"{int(left // 60)}m{int(left % 60):02d}s" if left < 3600 else f"{int(left // 3600)}h{int(left % 3600 // 60):02d}m"


_ENV_SECRET = re.compile(r"key|token|secret|pass|pwd|auth", re.I)


def _mask_env(env: dict) -> list:
    """env 是这套配置里唯一能塞进密钥的地方：键名命中敏感词就遮蔽其值。

    今天只有一个服务配了 env（NODE_ENV=production），实测无密钥；但「今天没有」不等于
    「以后没有」，这里预先设防 —— 面板泄漏凭据是这个项目明令禁止的。
    """
    return [(k, "••••" if _ENV_SECRET.search(str(k)) else v) for k, v in (env or {}).items()]


# ---- 配置自省层：读服务自己已声明的配置，与它是谁无关

_RESTART_WAY = {
    "exe": "直接起进程", "vbs": "经 VBS 启动器", "ps1": "经 PowerShell 脚本",
    "service": "Windows 服务", "task": "计划任务",
    "remote-ps1": "远端 PowerShell 脚本",
    "remote-task": "远端计划任务", "remote-service": "远端 Windows 服务",
    "none": "本面板不负责拉起",
}


def _op_restart(svc: dict, op: dict) -> list:
    """启动方式自省：把服务自己声明的 exe/args/cwd/env/端口/等待条件摊开。

    这是「看启动参数」的落点，也是新服务零成本接入的那一半 —— 不认服务是谁。
    """
    r = svc.get("restart") or {}
    secs = [_kv("启动方式", [
        ("方式", _RESTART_WAY.get(r.get("kind"), r.get("kind"))),
        ("程序", r.get("exe") or r.get("path") or r.get("name")),
        ("参数", " ".join(str(a) for a in (r.get("args") or [])) or None),
        ("工作目录", r.get("cwd")),
        ("隐藏窗口", "是" if r.get("hidden") else None),
    ]), _kv("等待与终止", [
        ("终止端口", r.get("kill_port") or r.get("kill_remote_port")),
        ("等待端口", r.get("wait_port") or r.get("wait_remote_port")),
        ("等待进程", r.get("wait_process") or r.get("wait_remote_process")),
        ("等待上限", f"{r.get('wait_s')} 秒" if r.get("wait_s") else None),
        ("日志", r.get("log") or r.get("log_after")),
    ])]
    env = _mask_env(r.get("env"))
    if env:
        secs.append(_kv("环境变量", env))
    notes = [("warn", r.get("warn")), ("info", r.get("why") or r.get("note"))]
    if any(t for _, t in notes):
        secs.append(_notes(notes))
    stop = svc.get("stop") or {}
    if stop:
        secs.append(_kv("终止方式", [
            ("先杀", "、".join(stop.get("kill_first") or stop.get("kill_first_remote") or [])),
            ("终止端口", stop.get("kill_port") or stop.get("kill_remote_port")),
            ("Windows 服务", stop.get("service") or stop.get("remote_service")),
            ("警告", stop.get("warn")),
        ]))
    return secs


def _read_log_tail(target: str, lines: int = 80) -> str:
    """读一个白名单日志文件的尾部。

    这个口径原先只服务于卡片上的「日志」按钮，现在由 ops 的日志视图调用 ——
    抽成一处，避免两条路径读出不同结果。
    """
    if target.startswith("D:"):
        # RAG 迁到 对端 后日志在远端；D: 是 \\peer\D 的映射盘，走 ssh 读。
        # 开头那段的 OutputEncoding 不能省：不设时远端 PowerShell 读出来的中文就是
        # U+FFFD（实测），设了才拿到正确字符（外层仍是 UTF-16LE，由 decode_smart 收尾）。
        out, err = ssh_inline(f"[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
                              f"Get-Content -Path '{target}' -Tail {lines} "
                              f"-Encoding UTF8 -EA SilentlyContinue", timeout=30)
        if err and not out:
            return f"[读取失败] {err}"
        return out or "[空]"
    p = Path(target)
    if not p.is_file():
        return "[文件不存在]"
    size = p.stat().st_size
    with p.open("rb") as f:
        f.seek(max(0, size - 262144))
        data = f.read()
    return "\n".join(decode_smart(data).splitlines()[-lines:]) or "[空]"


def _op_logs(svc: dict, op: dict) -> list:
    paths = svc.get("logs") or []
    if not paths:
        return [_notes([("info", "该服务未配置日志路径")])]
    return [_text(Path(t).name, _read_log_tail(t, int(op.get("lines") or 80))) for t in paths[:4]]


def _op_access(svc: dict, op: dict) -> list:
    a = svc.get("access") or {}
    if not a:
        return [_notes([("info", "该服务未配置访问信息")])]
    secs = []
    if a.get("kind") == "url" and a.get("url"):
        secs.append(_kv("访问", [("地址", a.get("url")), ("标签", a.get("label"))]))
    if a.get("text"):
        secs.append(_text("用法", a["text"], mono=False))
    if a.get("note"):
        secs.append(_notes([("info", a["note"])]))
    return secs or [_notes([("info", "该服务未配置访问信息")])]


# ---- 服务外挂层：一个具名适配器，把既有数据源归一成 sections

def _op_models(svc: dict, op: dict) -> list:
    st = STATE.models.get(svc["id"]) or {}
    if st.get("error"):
        return [_notes([("warn", f"模型列表不可读：{st['error']}")])]
    loaded = st.get("loaded") or []
    rows = [{"cells": [
        m.get("name", ""),
        f"{m.get('param') or ''} {m.get('quant') or ''}".strip(),
        _gb(m.get("vram")),
        {"t": m.get("ctx") or "—"},
        {"t": _left(m.get("expires_at")), "countdown": m.get("expires_at")},
        {"btn": "卸载", "op": "unload", "data": {"model": m.get("name")}},
    ]} for m in loaded]
    secs = [_table(f"已加载 · {len(loaded)}", ["名称", "规模", "显存", "上下文", "卸载倒计时", ""], rows)]
    avail = st.get("available") or []
    arows = [{"cells": [
        m.get("name", ""),
        _gb(m.get("size")),
        {"t": m.get("num_ctx") or "—"},
        {"btn": "加载", "op": "load", "data": {"model": m.get("name")}},
    ]} for m in avail]
    secs.append(_table(f"可用 · {len(avail)}", ["名称", "体积", "上下文", ""], arows))
    if loaded:
        secs.append(_notes([("info", f"合计显存 {_gb(sum(m.get('vram') or 0 for m in loaded))}")]))
    return secs


def _badge_models(svc: dict) -> dict | None:
    st = STATE.models.get(svc["id"]) or {}
    if st.get("error"):
        return {"text": "模型列表不可读", "hot": True}
    loaded = st.get("loaded") or []
    if not loaded:
        return {"text": "未加载模型"}
    soon = sorted(m["expires_at"] for m in loaded if m.get("expires_at"))
    txt = f"已加载 {len(loaded)} 个 · 显存 {_gb(sum(m.get('vram') or 0 for m in loaded))}"
    if soon:
        txt += f" · 最早 {_left(soon[0])} 后卸载"
    return {"text": txt, "hot": True}


def _op_rag_params(svc: dict, op: dict) -> list:
    p = rag_params()
    if p.get("error"):
        return [_notes([("warn", f"参数不可读：{p['error']}")])]
    secs = [_kv(g.get("title", ""), [(r.get("key"), r.get("value")) for r in g.get("rows") or []])
            for g in p.get("groups") or []]
    if p.get("counts"):
        secs.append(_notes([("info", "、".join(f"{c['key']} {c['n']}" for c in p["counts"]))]))
    if p.get("num_ctx") is not None:
        secs.append(_kv("检索上下文", [("num_ctx", p["num_ctx"])]))
    secs.append(_notes([("info", f"来源 {Path(p.get('source') or '').name}；本面板只读展示、不写回")]))
    return secs


def _op_rag_verify(svc: dict, op: dict) -> list:
    with STATE.lock:
        v = dict(STATE.verify) if STATE.verify else None
    if not v:
        return [_notes([("info", "尚未运行过验证链")])]
    steps = v.get("steps") or []
    secs = [_kv("状态", [("运行中", "是" if v.get("running") else "否"),
                         ("当前", v.get("current")),
                         ("已用", f"{v.get('elapsed_s') or 0:.1f} 秒")])]
    rows = [{"cells": [
        s.get("name", ""),
        {"t": s.get("reason") or ("跳过" if s.get("skipped") else "完成"),
         "hot": not s.get("ok") and not s.get("skipped")},
        f"{s.get('seconds') or 0:.1f} 秒",
        {"t": "✗" if (not s.get("ok") and not s.get("skipped")) else "✓"},
    ]} for s in steps]
    secs.append(_table("步骤", ["步骤", "状态", "耗时", ""], rows))
    tail = "\n".join(f"[{s.get('name')}] {s.get('tail')}" for s in steps if s.get("tail"))
    if tail:
        secs.append(_text("输出", tail))
    return secs


def _op_st(svc: dict, op: dict) -> list:
    """酒馆详情。跨服务取数走 op.refs 的具名引用，不在这里写死任何服务 id。"""
    refs = op.get("refs") or {}
    info = st_info()
    st, cfg, acc = info.get("st") or {}, info.get("cfg") or {}, info.get("access") or {}
    secs = []
    if st.get("error"):
        secs.append(_notes([("warn", f"设置不可读：{st['error']}")]))
    else:
        secs.append(_kv("连接", [
            ("接口", st.get("api")), ("来源", st.get("source")), ("地址", st.get("url")),
            ("模型", st.get("model")), ("声明上下文", st.get("ctx_declared")),
            ("最大输出", st.get("max_tokens")), ("当前角色", st.get("char")),
            ("版本", st.get("version")),
        ]))
    if info.get("findings"):
        secs.append(_notes([(f.get("level"), f.get("text")) for f in info["findings"]]))
    # 上下文对账：三个客户端各自声明多少，Ollama 实际为它预留多少。不一致就高亮 ——
    # 这是本项目最容易出错的一处（声明 262144 而模型挂 :131k 时，超出部分被静默丢弃）。
    # 两处引用都走 op.refs 的具名入口，这里不写死任何服务 id。
    ref_models = (STATE.models.get(refs.get("models")) or {}) if refs.get("models") else {}
    rag_ctx = rag_params().get("num_ctx") if refs.get("rag") else None
    mine = next((m for m in (ref_models.get("available") or [])
                 if m.get("name") == st.get("model")), {})
    real = mine.get("num_ctx")
    clients = [
        ("RAG 检索后端", "/api/chat", rag_ctx, None, "显式"),
        ("SillyTavern", "/v1/chat/completions", st.get("ctx_declared"), real, "内置"),
        ("DSH", "/v1/chat/completions", (info.get("dsh") or {}).get("ctx"), real, "内置"),
    ]
    rows = []
    for name, ep, decl, real_v, how in clients:
        bad = decl is not None and real_v is not None and str(decl) != str(real_v)
        rows.append({"cells": [
            name,
            {"t": ep, "dim": True},
            {"t": _num(decl)},
            {"t": _num(real_v) + (f"  {how}" if real_v is not None else ""), "hot": bad},
        ]})
    secs.append(_table("上下文对账", ["客户端", "端点", "自行声明", "Ollama 实际"], rows))
    if st.get("ctx_declared") is not None and real is not None \
            and str(st["ctx_declared"]) != str(real):
        secs.append(_notes([("warn", f"酒馆按 {_num(st['ctx_declared'])} 拼 prompt，Ollama 却为它预留 "
                                    f"{_num(real)} 的 KV cache。多出的部分用不到，只占着显存。")]))
    if mine.get("size"):
        secs.append(_notes([("info", f"{st.get('model') or '模型'} 权重 {_gb(mine['size'])}，"
                                    f"量化 {mine.get('quant') or '—'}")]))
    if cfg.get("error"):
        secs.append(_notes([("warn", f"配置不可读：{cfg['error']}")]))
    elif cfg.get("rows"):
        secs.append(_kv("config.yaml（白名单）", [(r.get("label"), r.get("value")) for r in cfg["rows"]]))
    if acc.get("error"):
        secs.append(_notes([("warn", f"访问日志不可读：{acc['error']}")]))
    else:
        arows = [{"cells": [r.get("ts", ""), r.get("ip", ""), r.get("kind", "")]}
                 for r in (acc.get("rows") or [])[:40]]
        secs.append(_table(f"访问记录 · 共 {acc.get('total') or 0} 条（真实 {acc.get('real') or 0}）",
                           ["时间", "来源", "类型"], arows))
    dsh = info.get("dsh") or {}
    if dsh.get("ctx") is not None:
        secs.append(_kv("DSH 侧", [("peer contextWindow", dsh["ctx"])]))
    secs.append(_notes([("info", "口令不在面板中展示；本视图只读")]))
    return secs


def _st_asset_sections(a: dict) -> list:
    if a.get("error"):
        return [_notes([("warn", f"内容不可读：{a['error']}")])]
    t = a.get("totals") or {}
    secs = [_kv("概览", [
        ("角色卡", t.get("cards")), ("世界书", t.get("worlds")),
        ("角色卡 token", t.get("card_tokens")), ("世界书 token", t.get("world_tokens")),
        ("常驻条目", t.get("constant_n")), ("常驻 token", t.get("constant_tokens")),
    ])]
    if a.get("findings"):
        secs.append(_notes([(f.get("level"), f.get("text")) for f in a["findings"]]))
    crows = [{"cells": [
        {"t": c.get("name") or c.get("file", ""), "dim": not c.get("name")},
        c.get("creator") or "—",
        {"t": "、".join(c.get("tags") or []) or "—", "dim": True},
        {"t": c.get("tokens") or "—"},
        {"t": c.get("json_sync") or "—", "hot": c.get("json_sync") == "不同"},
    ]} for c in a.get("chars") or []]
    secs.append(_table("角色卡", ["名称", "作者", "标签", "token", "JSON 同步"], crows))
    for w in a.get("worlds") or []:
        rows = [{"cells": [
            {"t": r.get("comment") or f"#{r.get('uid')}", "dim": not r.get("comment")},
            {"t": "、".join(r.get("keys") or []) or "—"},
            {"t": "常驻" if r.get("constant") else ("停用" if r.get("disable") else ""),
             "hot": bool(r.get("constant"))},
            {"t": r.get("tokens") or "—"},
            {"t": (r.get("preview") or "")[:58], "dim": True},
        ]} for r in w.get("rows") or []]
        secs.append(_table(f"世界书 · {Path(w.get('file', '')).name} · {w.get('entries') or 0} 条",
                           ["条目", "关键词", "属性", "token", "预览"], rows))
    return secs


def _op_st_assets(svc: dict, op: dict) -> list:
    return _st_asset_sections(st_assets(full=False))


def _op_content(svc: dict, op: dict) -> list:
    return _st_asset_sections(st_assets(full=True))


OP_SOURCES = {
    "restart": {"sections": _op_restart},
    "logs": {"sections": _op_logs},
    "access": {"sections": _op_access},
    "models": {"sections": _op_models, "badge": _badge_models},
    "rag_params": {"sections": _op_rag_params},
    "rag_verify": {"sections": _op_rag_verify},
    "st": {"sections": _op_st},
    "st_assets": {"sections": _op_st_assets},
    "content": {"sections": _op_content},
}

# run 类 op 只能落到这些既有动作端点上 —— 白名单，而不是任意端点：
# 配置里一个字符串不该有本事调用到未预期的代码路径。
OP_RUN_ENDPOINTS = ("/api/model", "/api/rag/verify")


def find_op(sid: str, opid: str):
    svc = next((s for s in SERVICES if s["id"] == sid), None)
    if not svc:
        return None, None
    return svc, next((o for o in (svc.get("ops") or []) if o.get("id") == opid), None)


def op_view(svc: dict, op: dict) -> list:
    src = op.get("source")
    entry = OP_SOURCES.get(src)
    if not entry:
        raise KeyError(f"未知的视图来源 source={src!r}；可选 {'、'.join(sorted(OP_SOURCES))}")
    return entry["sections"](svc, op)


def op_level(op: dict) -> str:
    """视图与跳转默认 read，动作默认 write；服务可在 op 上显式覆盖（如全文与日志要 write）。"""
    if op.get("level") in LEVEL_RANK:
        return op["level"]
    return "write" if op.get("kind") == "run" else "read"


def op_badges(svc: dict) -> list:
    out = []
    for o in svc.get("ops") or []:
        fn = (OP_SOURCES.get(o.get("source")) or {}).get("badge")
        if o.get("kind") == "view" and o.get("badge") and fn:
            b = fn(svc)
            if b:
                out.append(dict(b, op=o.get("id")))
    return out


# ---- 自定义操作脚本：服务自带任意动作，新增操作不改后端代码

OP_SCRIPT_DIR = BUNDLE_DIR / "tools" / "ops"
OP_SCRIPT_TIMEOUT = 30
OP_SCRIPT_TIMEOUT_MAX = 300
OP_SCRIPT_OUT_MAX = 256 * 1024
OP_SCRIPT_EXTS = (".ps1", ".py", ".cmd")


def script_path(svc_id: str, rel: str) -> Path:
    """把 op 声明的脚本名解析成绝对路径，并强制它落在 tools/ops/ 下。

    护栏一（路径）：绝对路径、`..`、以及解析后跑到 tools/ops/ 之外的（含指向外部的符号
    链接 —— resolve() 会先把链接展开，所以越界链接在这一步就露出来）一律拒绝。
    """
    if not rel or Path(rel).is_absolute():
        raise ValueError(f"脚本名必须是指向 tools/ops/ 的相对路径：{rel!r}")
    root = OP_SCRIPT_DIR.resolve()
    target = (OP_SCRIPT_DIR / svc_id / rel).resolve()
    if root != target and root not in target.parents:
        raise ValueError(f"脚本路径越界，必须在 tools/ops/ 下：{rel!r}")
    return target


def script_argv(path: Path) -> list:
    """按扩展名选解释器。

    PowerShell 用 `-Command` 而不是 `-File`：前者能在跑之前把控制台输出编码设成 UTF-8，
    否则中文会按 GBK 落进管道（decode_smart 虽有兜底，但那是一层可能误判的猜测）。
    **脚本路径经环境变量传进去，命令行本身是常量** —— 配置里的值不进命令串。
    """
    ext = path.suffix.lower()
    if ext not in OP_SCRIPT_EXTS:
        raise ValueError(f"不支持的脚本扩展名 {ext!r}，只允许 {'、'.join(OP_SCRIPT_EXTS)}")
    if ext == ".ps1":
        # 三件事必须同时成立，缺一都会出错：
        #   1) 控制台输出编码先设成 UTF-8，否则中文按 GBK 落进管道（decode_smart 有兜底，
        #      但那是一层可能误判的猜测）。
        #   2) 末尾显式 `exit $LASTEXITCODE`：只写 `& $path` 时 PowerShell 会把脚本的退出码
        #      吞成 1（实测），非零退出就再也分不出是"脚本失败"还是"脚本退了个非零码"。
        #   3) 脚本路径经环境变量传进去，命令行本身是常量 —— 配置里的值不进命令串。
        return ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-Command",
                "[Console]::OutputEncoding=[Text.Encoding]::UTF8; & $env:MOZU_SCRIPT_PATH; "
                "exit $LASTEXITCODE"]
    if ext == ".py":
        return [sys.executable, str(path)]
    return ["cmd", "/c", str(path)]


def _cap_out(data: bytes) -> tuple:
    """护栏四（输出上限）：超限截断并告知，避免一个失控脚本把面板撑爆。"""
    if len(data) <= OP_SCRIPT_OUT_MAX:
        return decode_smart(data), False
    return decode_smart(data[:OP_SCRIPT_OUT_MAX]), True


def _script_result_sections(op: dict, stdout: str, stderr: str, code: int,
                           truncated: bool, timed_out: bool, timeout: int) -> tuple:
    """把脚本输出变成 sections。format 必须显式声明，解析失败如实报错、不静默回退。"""
    ok = True
    secs: list = []
    if timed_out:
        ok = False
        secs.append(_notes([("warn", f"脚本超时（{timeout} 秒）已被终止")]))
    if (op.get("format") or "text") == "sections":
        try:
            data = json.loads(stdout or "{}")
            got = data.get("sections")
            if not isinstance(got, list):
                raise ValueError("顶层没有 sections 数组")
            secs.extend(got)
        except Exception as e:                                    # noqa: BLE001
            ok = False
            secs.append(_notes([("warn", f"format 声明为 sections，但 stdout 不是合法的 "
                                        f"sections JSON：{type(e).__name__}: {e}")]))
            secs.append(_text("原始输出", stdout or "(空)"))
    else:
        secs.append(_text("输出", stdout if stdout.strip() else "(空)"))
    if truncated:
        secs.append(_notes([("warn", f"输出超过 {OP_SCRIPT_OUT_MAX // 1024} KB，已截断")]))
    if not timed_out and code != 0:
        ok = False
        secs.append(_notes([("warn", f"脚本退出码 {code}")]))
    if stderr.strip():
        secs.append(_text("stderr", stderr))
    return ok, secs


def run_script_op(svc: dict, op: dict, payload: dict | None = None) -> dict:
    """执行一个 kind=script 的操作，返回与其它 op 同构的结果。"""
    rel = str(op.get("script") or "")
    t0 = time.time()
    try:
        path = script_path(svc["id"], rel)
    except ValueError as e:
        return {"id": svc["id"], "op": op["id"], "ok": False, "elapsed_s": 0,
                "at": now_iso(), "error": str(e),
                "sections": [_notes([("warn", str(e))])]}
    except Exception as e:                                        # noqa: BLE001
        return {"id": svc["id"], "op": op["id"], "ok": False, "elapsed_s": 0,
                "at": now_iso(), "error": f"{type(e).__name__}: {e}",
                "sections": [_notes([("warn", f"{type(e).__name__}: {e}")])]}
    if not path.is_file():
        msg = f"脚本未找到：tools/ops/{svc['id']}/{rel}"
        return {"id": svc["id"], "op": op["id"], "ok": False, "elapsed_s": 0,
                "at": now_iso(), "error": msg, "sections": [_notes([("warn", msg)])]}
    try:
        argv = script_argv(path)
    except ValueError as e:
        return {"id": svc["id"], "op": op["id"], "ok": False, "elapsed_s": 0,
                "at": now_iso(), "error": str(e), "sections": [_notes([("warn", str(e))])]}

    try:
        timeout = int(op.get("timeout") or OP_SCRIPT_TIMEOUT)
    except (TypeError, ValueError):
        timeout = OP_SCRIPT_TIMEOUT
    timeout = max(1, min(timeout, OP_SCRIPT_TIMEOUT_MAX))

    env = dict(os.environ)
    env.update({
        "MOZU_SCRIPT_PATH": str(path),
        "MOZU_ROOT": str(ROOT),
        "MOZU_SERVICE_ID": svc["id"],
        "MOZU_SERVICE_NAME": svc["name"],
        "MOZU_OP_ID": op["id"],
        "MOZU_NODE_ID": NODE_ID,
        "PYTHONIOENCODING": "utf-8",
    })
    # 服务声明的 Ollama 地址下发给脚本：脚本与面板必须看同一个来源，否则改了 services.json
    # 里的 models_api，脚本里还留着一份硬编码的地址，两边各说各话。写成 `in svc` 而不是
    # svc.get(...)：check_ops 的静态断言把后者的形状判为「视图层特判」，这里要的是通用下发。
    if "models_api" in svc:
        env["MOZU_MODELS_API"] = str(svc["models_api"])
    # 护栏五（传参）：字段值只经环境变量，绝不拼进命令行；名字不合法的键直接丢弃。
    for k, v in (payload or {}).items():
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(k)):
            env[f"MOZU_FIELD_{str(k).upper()}"] = str(v)

    timed_out = False
    code = 0
    raw_out = raw_err = b""
    try:
        proc = subprocess.run(argv, cwd=str(path.parent), env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        code, raw_out, raw_err = proc.returncode, proc.stdout or b"", proc.stderr or b""
    except subprocess.TimeoutExpired as e:
        timed_out = True
        code = -1
        raw_out, raw_err = e.stdout or b"", e.stderr or b""
    except Exception as e:                                        # noqa: BLE001
        msg = f"脚本启动失败：{type(e).__name__}: {e}"
        return {"id": svc["id"], "op": op["id"], "ok": False,
                "elapsed_s": round(time.time() - t0, 1), "at": now_iso(),
                "error": msg, "sections": [_notes([("warn", msg)])]}

    stdout, trunc_o = _cap_out(raw_out)
    stderr, trunc_e = _cap_out(raw_err)
    elapsed = round(time.time() - t0, 1)
    ok, secs = _script_result_sections(op, stdout, stderr, code, trunc_o or trunc_e,
                                      timed_out, timeout)
    remember({"id": svc["id"], "name": svc["name"], "action": f"script:{op['id']}", "ok": ok,
              "steps": [{"t": "执行", "msg": f"{rel} · 退出码 {code} · {elapsed}s"
                                              + ("（超时终止）" if timed_out else "")}],
              "elapsed_s": elapsed, "freed_mb": 0, "at": now_iso()})
    return {"id": svc["id"], "op": op["id"], "ok": ok, "elapsed_s": elapsed,
            "at": now_iso(), "exit_code": code, "sections": secs}


def history_sections(sid: str, limit: int = 20) -> list:
    """内建的「动作历史」面板：读 actions.jsonl 里属于该服务的条目。

    这是唯一内建的面板（另一个内建是侧边栏的指标头）—— 每个服务都有历史，
    让每个服务各声明一遍只会重复。返回 sections，于是前端只有一个渲染器。
    """
    rows: list = []
    try:
        if ACTION_LOG.is_file():
            size = ACTION_LOG.stat().st_size
            with ACTION_LOG.open("rb") as f:
                f.seek(max(0, size - 512 * 1024))          # 只读尾部，日志再长也不拖慢
                text = decode_smart(f.read())
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("id") != sid:
                    continue
                rows.append(e)
    except OSError as e:
        return [_notes([("warn", f"动作日志不可读：{e}")])]
    if not rows:
        return [_notes([("info", "还没有记录到任何动作")])]
    rows = rows[-max(1, min(limit, 200)):][::-1]           # 最新在前
    table = _table("最近 %d 次" % len(rows), ["时间", "动作", "结果", "耗时"],
                   [{"cells": [
                       {"t": (r.get("at") or "")[11:19], "dim": True},
                       r.get("action") or "—",
                       {"t": "成功" if r.get("ok") else "失败", "hot": not r.get("ok")},
                       {"t": f"{r.get('elapsed_s') or 0}s"},
                   ]} for r in rows])
    secs = [table]
    last = rows[0]
    steps = "\n".join(f"[{s.get('t')}] {s.get('msg')}" for s in (last.get("steps") or []))
    if steps:
        secs.append(_text(f"最近一次（{last.get('action')}）", steps))
    return secs


def run_rag_verify(svc: dict | None = None) -> None:
    """把「改了检索参数就要手工按序跑三个脚本」收成一次点击。

    目标服务由调用方从请求里解析后传进来 —— 原先这里与前置检查都写死 "rag"，
    是协议层最硬的一处耦合（换服务名就静默失效）。

    regression_check 只在 --write-baseline 时才写基线，calibrate_thresholds 的输出已用
    --out 改写到本面板的 logs 下。所以除 RAG 自身的查询日志外，不改动 C:\\LLMdeploy。
    """
    t_all = time.time()
    steps: list[dict] = []
    CALIB_OUT.parent.mkdir(parents=True, exist_ok=True)

    def publish(current: str) -> None:
        with STATE.lock:
            STATE.verify = {"running": True, "started_at": t_all, "current": current,
                            "elapsed_s": round(time.time() - t_all, 1),
                            "steps": [dict(s) for s in steps]}

    for name, rel, args in RAG_STEPS:
        script = LLMDEPLOY / rel
        row = {"name": name, "ok": False, "skipped": False, "reason": "",
               "seconds": 0.0, "tail": ""}
        steps.append(row)
        publish(name)

        if not script.is_file():
            row.update(skipped=True, reason=f"脚本不存在: {script}")
            continue
        # 只有 --baseline 指向输入文件；--out 是输出路径，不能拿它查存在性
        if "--baseline" in args:
            baseline = LLMDEPLOY / args[args.index("--baseline") + 1]
            if not baseline.is_file():
                row.update(skipped=True, reason=f"基线不存在: {baseline.name}（需先采集）")
                continue

        t0 = time.time()
        out = ""
        try:
            proc = subprocess.run([sys.executable, str(script), *args], cwd=str(LLMDEPLOY),
                                  capture_output=True, timeout=RAG_STEP_TIMEOUT,
                                  creationflags=NO_WINDOW)
            out = decode_smart(proc.stdout or b"") + decode_smart(proc.stderr or b"")
            row["ok"] = proc.returncode == 0
            row["reason"] = f"退出码 {proc.returncode}"
        except subprocess.TimeoutExpired:
            row["reason"] = f"超时（>{RAG_STEP_TIMEOUT}s）"
        except OSError as e:
            row["reason"] = f"启动失败: {e}"
        row["seconds"] = round(time.time() - t0, 1)
        row["tail"] = "\n".join(out.splitlines()[-RAG_TAIL_LINES:])

    ok = all(s["ok"] or s["skipped"] for s in steps)
    total = round(time.time() - t_all, 1)
    with STATE.lock:
        STATE.verify = {"running": False, "started_at": t_all, "current": "",
                        "elapsed_s": total, "steps": [dict(s) for s in steps]}
    remember({"id": (svc or {}).get("id", "rag"), "name": (svc or {}).get("name", "RAG 检索后端"),
              "action": "rag:verify", "ok": ok,
              "steps": [{"t": s["name"],
                         "msg": f"跳过 · {s['reason']}" if s["skipped"]
                                else f"{s['seconds']}s · " + ("通过" if s["ok"] else s["reason"])}
                        for s in steps],
              "elapsed_s": total, "freed_mb": 0, "at": now_iso()})


def _verify_worker(svc: dict | None = None) -> None:
    """后台跑验证链, 结束后释放操作锁。

    锁在整个验证期间持有 —— 运行中重启 RAG 会被 409 拒绝, 否则脚本会打到半死的服务上。
    """
    try:
        run_rag_verify(svc)
    finally:
        _RESTART_LOCK.release()


# ---------------------------------------------------------------- HTTP 层

# ---------------------------------------------------------------- 访问控制

ACCESS = CFG.get("access") or {}
TOKENS_FILE = ROOT / ACCESS.get("tokens_file", ".state/access-tokens.json")
TOKEN_KINDS = ("lan", "tailscale", "mesh")
AUTH_COOKIE = "mozunitor_token"


def load_tokens() -> dict:
    """读取访问 token；文件不存在则生成一份并落盘。

    几种 token 分开是为了能单独作废：手机换了、访客来过，只换 lan 那个即可，
    不必把 tailnet 里的设备一起重新配置。mesh 那种专给对等节点之间互认。
    """
    got: dict = {}
    try:
        raw = json.loads(TOKENS_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            got = {k: v for k, v in raw.items() if isinstance(v, str) and v}
    except (OSError, json.JSONDecodeError):
        pass
    missing = [k for k in TOKEN_KINDS if k not in got]
    if not missing:
        return {k: got[k] for k in TOKEN_KINDS}
    # 只补缺的那一种，不整份重签：多出 token 种类时若一起轮换，手机上已有的
    # 书签与 Cookie 会全部失效。
    for k in missing:
        got[k] = secrets.token_urlsafe(24)
    try:
        TOKENS_FILE.parent.mkdir(parents=True, exist_ok=True)
        TOKENS_FILE.write_text(
            json.dumps({k: got[k] for k in TOKEN_KINDS}, indent=2, ensure_ascii=False),
            encoding="utf-8")
        try:
            TOKENS_FILE.chmod(0o600)
        except OSError:
            pass
    except OSError:
        pass
    return {k: got[k] for k in TOKEN_KINDS}


TOKENS: dict = {}

# ---------------------------------------------------------------- 节点凭据
# 凭据不是「登录账号」，而是一对用于对等匹配的共享秘密：
#   username —— 可见性标识：两端一致才互相发现、才允许查询对方状态
#   password —— 高权限密钥：两端一致才允许跨节点执行控制类操作
#
# 派生刻意不加随机盐。两端必须能从各自的输入算出同一个值，否则「密码相同」永远
# 匹配不上 —— 这是互认的前提，也决定了这个值的强度就等于密码本身。文件按 0600
# 保存，与 access-tokens.json 同一级别。

CRED_FILE = ROOT / ".state" / "credentials.json"
SESSION_SECRET_FILE = ROOT / ".state" / "session-secret"
SESSION_COOKIE = "mozunitor_session"
SESSION_MAX_AGE = 2592000          # 会话有效期(秒)，与旧 cookie 一致
PEER_TIME_WINDOW = 60              # 节点间证明的时间戳容差(秒)

# 端点 → 所需级别。read = 用户名一致即可，write = 还要密码证明。
# 哪些操作要密码可逐项覆盖：改 services.json 的 access.levels 即可。
DEFAULT_LEVELS = {
    "/api/state": "read",
    "/api/node": "read",
    "/api/restart": "write",
    "/api/stop": "write",
    # ops 协议共用一个端点，实际级别由每个 op 自己声明（见 op_level）：视图与跳转默认 read，
    # 动作默认 write；全文与日志在 services.json 里显式标 write。所以这里放 read 即可。
    "/api/op": "read",
    # 内建的动作历史面板。日志尾巴可能带凭据，但这里只回结构化条目（动作名与结果），
    # 不比 /api/state 更敏感，所以跟它同级。
    "/api/history": "read",
    # 设置：GET 是读，写入口在方法里再要求 write（命令字段还要求回环）。
    "/api/settings": "read",
    "/api/service-settings": "read",
}
LEVELS: dict = {**DEFAULT_LEVELS, **((ACCESS.get("levels") or {}))}
LEVEL_RANK = {"": 0, "read": 1, "write": 2, "admin": 3}

CREDS: dict = {}


def shared_key(username: str, password: str) -> str:
    """由 (用户名, 密码) 派生共享密钥 —— 节点间互认与 HMAC 证明都用它。"""
    return hashlib.sha256(f"{username}:{password}".encode("utf-8")).hexdigest()


def save_credentials(creds: dict) -> None:
    global CREDS
    CREDS = creds
    try:
        CRED_FILE.parent.mkdir(parents=True, exist_ok=True)
        CRED_FILE.write_text(json.dumps(creds, indent=2, ensure_ascii=False), encoding="utf-8")
        try:
            CRED_FILE.chmod(0o600)
        except OSError:
            pass
    except OSError:
        pass


def load_credentials() -> dict:
    """读取本机凭据；不存在则生成随机预设。

    preset 为真表示这仍是自动生成的值，前端要一直提醒用户改掉。
    """
    global CREDS
    try:
        got = json.loads(CRED_FILE.read_text(encoding="utf-8"))
        if isinstance(got, dict) and isinstance(got.get("key"), str) and got["key"]:
            CREDS = got
            return CREDS
    except (OSError, json.JSONDecodeError):
        pass
    name = "mozunitor-" + secrets.token_hex(2)
    pwd = secrets.token_urlsafe(12)
    save_credentials({"version": 1, "username": name, "key": shared_key(name, pwd),
                      "preset": True, "preset_password": pwd})
    return CREDS


def load_session_secret() -> bytes:
    """会话 Cookie 的签名密钥；固定保存，轮换它等于让所有会话立即失效。"""
    try:
        raw = SESSION_SECRET_FILE.read_text(encoding="utf-8").strip()
        if raw:
            return bytes.fromhex(raw)
    except (OSError, ValueError):
        pass
    made = secrets.token_bytes(32)
    try:
        SESSION_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        SESSION_SECRET_FILE.write_text(made.hex(), encoding="utf-8")
        try:
            SESSION_SECRET_FILE.chmod(0o600)
        except OSError:
            pass
    except OSError:
        pass
    return made


SESSION_SECRET: bytes = b""


def issue_session(level: str) -> str:
    """签发无状态会话：用户名 + 级别 + 到期时间，外加签名。"""
    exp = int(time.time()) + SESSION_MAX_AGE
    user = str(CREDS.get("username") or "")
    mac = hmac.new(SESSION_SECRET, f"{user}\n{level}\n{exp}".encode("utf-8"),
                   hashlib.sha256).hexdigest()
    raw = f"{user}\n{level}\n{exp}\n{mac}".encode("utf-8")
    # 去掉 base64 的 '=' 填充：会话会经 WebViewCookieManager 下发，那条路会对值做一次
    # URL 编码，'=' 变成 %3D 之后服务端就再也解不出来。urlsafe 字母表本身不需要填充。
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def read_session(value: str) -> str:
    """解出会话级别；签名不对、过期或用户名已变更都返回空串。"""
    try:
        pad = "=" * (-len(value) % 4)       # 签发时省了填充，解码前补回来
        raw = base64.urlsafe_b64decode((value + pad).encode("ascii")).decode("utf-8")
        user, level, exp, mac = raw.split("\n")
        exp_i = int(exp)
    except (ValueError, UnicodeDecodeError):
        return ""
    if exp_i < time.time() or user != str(CREDS.get("username") or ""):
        return ""
    expect = hmac.new(SESSION_SECRET, f"{user}\n{level}\n{exp}".encode("utf-8"),
                      hashlib.sha256).hexdigest()
    return level if hmac.compare_digest(mac, expect) else ""


def peer_headers(method: str, path: str) -> dict:
    """访问对端时带上的身份。

    用户名让对端判断「是不是同类」；HMAC 证明用来换取高权限。两边都只用自己那份
    凭据算，因此本机不需要知道对端的密码，对端也不需要知道本机的。
    """
    ts = str(int(time.time()))
    key = str(CREDS.get("key") or "")
    mac = hmac.new(key.encode("utf-8"), f"{method}\n{path}\n{ts}".encode("utf-8"),
                   hashlib.sha256).hexdigest()
    return {"X-Mozunitor-User": str(CREDS.get("username") or ""),
            "X-Mozunitor-Time": ts, "X-Mozunitor-Mac": mac}


def token_matches(cand: str | None) -> bool:
    if not cand:
        return False
    return any(hmac.compare_digest(cand, v) for v in TOKENS.values())


def remote_access() -> bool:
    """面板是否绑在非回环地址上。1.1.0 起回环也需要登录，这个函数只用于提示。"""
    return LOCAL_HOST not in ("127.0.0.1", "::1", "localhost")


# ---------------------------------------------------------------- 局域网入口
# 只绑回环的服务（DSH、RAG、Gemini、酒馆）要给手机用，就得有个入口。手机上同时只能
# 开一个代理，Tailscale 一开别的代理就用不了，所以入口走局域网而不是 tailnet。
#
# 做法是**转发**而不是改它们的绑定：RAG 把 127.0.0.1 硬编码在 rag_server.py 里、Gemini
# 是二进制、DSH 改绑定要重启（会打断正在跑的 Agent 会话）。转发不动被监控服务一行代码。
#
# 在 TCP 层转发而不是重写一个 HTTP 代理，是因为 DSH 靠 WebSocket 通信：把两个方向
# 的字节原样对拷，协议细节一概不用管。

_PROXY_BUF = 65536
_TOKEN_RE = re.compile(rb"[?&]token=([^&\s]+)")
_COOKIE_TOKEN_RE = re.compile(rb"Cookie:\s*([^\r\n]+)", re.I)
_HEADER_TOKEN_RE = re.compile(rb"X-Mozunitor-Token:\s*([^\r\n]+)", re.I)


def _proxy_authorized(head: bytes) -> tuple[bool, str, str]:
    """校验首个请求里的凭据，返回 (是否放行, 下发的 Cookie 名, 下发的 Cookie 值)。

    两种情况都要把凭据**原样下发成 Cookie**：鉴权只看首个请求的头部，而浏览器随后加载
    /static 与 /api/* 时一概不带它 —— 只放行首个请求，页面能打开、数据全是空的。

    查询参数、Cookie、自定义头这几处 token 都认，与面板同一套 —— 少认一种就会出现
    「面板能进、入口进不去」这种自相矛盾的拒绝。会话这一种是手机改用用户名密码登录后
    必须补上的，否则面板进得去、点开酒馆还是 401。"""
    for rx in (_TOKEN_RE, _HEADER_TOKEN_RE):
        m = rx.search(head)
        if m:
            cand = m.group(1).decode("latin-1").strip()
            if token_matches(cand):
                return True, AUTH_COOKIE, cand
    c = _COOKIE_TOKEN_RE.search(head)
    if c:
        for part in c.group(1).decode("latin-1").split(";"):
            k, _, v = part.strip().partition("=")
            if k == AUTH_COOKIE and token_matches(v):
                return True, AUTH_COOKIE, v
            if k == SESSION_COOKIE and read_session(v):
                return True, SESSION_COOKIE, v
    return False, "", ""


def _proxy_denied(conn) -> None:
    body = ("需要登录：先打开面板 http://<本机局域网IP>:%d/ 用用户名密码登录，"
            "或在本地址后加 ?token=<lan token>。" % int(CFG["listen"]["port"])).encode("utf-8")
    try:
        conn.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain; charset=utf-8\r\n"
                     b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                     b"Connection: close\r\n\r\n" + body)
    except OSError:
        pass


_DSH_LOG_RE = re.compile(r"token=([A-Za-z0-9_-]{8,})")
_dsh_cache: tuple[float, str] = (0.0, "")


def _read_log_text(path: Path) -> str:
    """读日志文本，逐行认编码。

    这个文件是**混合编码**的：启动时 `Set-Content -Encoding UTF8` 写的那行是 UTF-8
    （带 BOM），随后 PowerShell 的 `*>>` 追加的是 UTF-16LE。整体按任一种编码读都会
    UnicodeDecodeError，所以必须按行各认各的。
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    out: list[str] = []
    for line in raw.split(b"\n"):
        if line.count(b"\x00") > len(line) // 8:        # 大量 NUL → 这行是 UTF-16
            for enc in ("utf-16-le", "utf-16-be"):
                try:
                    out.append(line.decode(enc).replace("\x00", ""))
                    break
                except UnicodeDecodeError:
                    continue
            else:
                out.append(line.decode("utf-8", errors="replace"))
        else:
            out.append(line.decode("utf-8", errors="replace"))
    return "\n".join(out)


def dsh_launch_token(log_path: str) -> str:
    """从 DSH 的启动日志里取 launch token。

    它是每进程随机生成、只打印一次、不落盘的值（dsh-client-connection 的
    PROCESS_LAUNCH_TOKENS 只在内存里），所以只能从被重定向的输出里捞。
    按 mtime 缓存，DSH 一重启 token 自然换新。
    """
    global _dsh_cache
    try:
        p = Path(log_path)
        mtime = p.stat().st_mtime
    except OSError:
        return ""
    if mtime != _dsh_cache[0]:
        hits = _DSH_LOG_RE.findall(_read_log_text(p))
        _dsh_cache = (mtime, hits[-1] if hits else "")
    return _dsh_cache[1]


def _proxy_inject_token(head: bytes, target_port: int, token: str) -> bytes:
    """给需要它的目标补上 token。

    DSH 只接受 `GET /?token=<launchToken>` 这一次交换，且不接受 Authorization 头，
    所以必须改请求行。只改根路径：DSH 换完会向干净 `/` 发 302，之后的请求靠它自己
    签发的 Cookie，不能再塞 token，否则会来回重定向。
    """
    lines = head.split(b"\r\n")
    if not lines:
        return head
    parts = lines[0].split(b" ")
    if len(parts) != 3 or parts[0] != b"GET":
        return head
    raw = parts[1].decode("latin-1")
    path, sep, query = raw.partition("?")
    if path != "/":
        return head
    # 面板自己在 URL 上也用 ?token=，而 dsh 只认它自己的 launch token：位置被面板 token
    # 占着时，若不替换，送过去的就永远是错的那个，结果恒为 401。带别的 token 才保留。
    q = query.encode("latin-1")
    m = _TOKEN_RE.search(b"?" + q)
    if m and not token_matches(m.group(1).decode("latin-1")):
        return head
    lines[0] = b"GET " + (path + "?token=" + token).encode("latin-1") + b" " + parts[2]

    host = next((ln for ln in lines[1:] if ln.lower().startswith(b"host:")), None)
    authority = host.split(b":", 1)[1].strip().decode("latin-1") if host else ""
    if authority:
        # Origin 必须与 Host 同源，否则 dsh 的栅栏按跨站拒掉（403）
        for i, ln in enumerate(lines[1:], 1):
            if ln.lower().startswith(b"origin:"):
                lines[i] = b"Origin: http://" + authority.encode("latin-1")
                break
    return b"\r\n".join(lines)


def _read_proxy_head(conn) -> tuple[bytes, bytes] | None:
    """读首个请求的头部，剩下的字节一并带回（不能丢，否则上游收到残缺请求）。"""
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) > _PROXY_BUF:
            return None
        try:
            chunk = conn.recv(_PROXY_BUF)
        except OSError:
            return None
        if not chunk:
            return None
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    return head + b"\r\n\r\n", rest


def _pump(src, dst, done: threading.Event, cookie: str = "") -> None:
    """把一个方向的字节搬到另一个方向。

    读完只**半关闭**对端的写方向（SHUT_WR），绝不 close：HTTP 客户端发完请求常会关掉
    自己的写端（`Connection: close`），若此时把套接字整个关掉，另一个方向就再也读不到
    响应了 —— 这正是第一版把响应吞掉的原因（WinError 10038）。

    `cookie` 非空时是响应方向，往响应头末尾补一条 Set-Cookie。它必须是完整的
    `名=值`：token 与会话的名字不同，两者都要下发，别拿一个变量兼作两用。
    """
    pending, insert = b"", bool(cookie)
    line = (f"\r\nSet-Cookie: {cookie}; Path=/; HttpOnly; "
            f"SameSite=Strict; Max-Age=2592000").encode("latin-1")
    try:
        while True:
            chunk = src.recv(_PROXY_BUF)
            if not chunk:
                break
            if insert:
                # 头部可能被切成好几块送达，没攒到空行就继续攒，不在半截头部里插 Cookie
                pending += chunk
                end = pending.find(b"\r\n\r\n")
                if end < 0:
                    continue
                chunk = pending[:end] + line + pending[end:]
                insert = False
            dst.sendall(chunk)
        if insert and pending:          # 后端连头部都没发完就断了，原样送出
            dst.sendall(pending)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)    # 告诉对端「这边说完了」
        except OSError:
            pass
        done.set()


def _close_quiet(sock) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _proxy_conn(conn, target_port: int, label: str) -> None:
    try:
        head_rest = _read_proxy_head(conn)
        if head_rest is None:
            return
        head, rest = head_rest
        ok, cname, cval = _proxy_authorized(head)
        if not ok:
            _proxy_denied(conn)
            return
        tok_file = forward_token_file(label)
        if tok_file:
            dsh_tok = dsh_launch_token(tok_file)
            if dsh_tok:
                head = _proxy_inject_token(head, target_port, dsh_tok)
        try:
            up = socket.create_connection(("127.0.0.1", target_port), timeout=10)
        except OSError as e:
            # 后端没在跑时，502 的正文要说清是哪个端口连不上，否则用户只会以为是 token 问题
            body = f"目标服务 127.0.0.1:{target_port} 连不上（{type(e).__name__}）。".encode("utf-8")
            try:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n"
                             b"Content-Type: text/plain; charset=utf-8\r\n"
                             b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                             b"Connection: close\r\n\r\n" + body)
            except OSError:
                pass
            return
        up.settimeout(None)
        conn.settimeout(None)
        # head 必须发出去：它是被读出来做鉴权的，正常请求的 rest 是空的，
        # 只发 rest 等于把整个请求头吞掉，后端永远收不到请求。
        up.sendall(head)
        if rest:
            up.sendall(rest)
        both = threading.Event()
        # 鉴权只看首个请求的头部，可只有首个请求带得来 token：浏览器加载页面时 `?token=` 在
        # 主文档上，随后的 `/static`、`/api/*` 一概不带。只放行首个请求的话，页面能打开、
        # 数据全是空的 —— 酒馆正是这样：角色卡与世界书列表空、前端报「API 未配置」（每个
        # /api 都被这里 401）。所以把已验过的 token 下发成 Cookie，之后的请求自动带上来。
        threading.Thread(target=_pump, args=(conn, up, both), daemon=True).start()
        # 返回即表示两个方向都收完了。下发的凭据按进来的那一种原样回给浏览器：
        # token 进就回 token，会话进就回会话，名字不能弄混。
        _pump(up, conn, both, f"{cname}={cval}" if cname else "")
    except OSError as e:
        print(f"[forward {label}] {type(e).__name__}: {e}")
    finally:
        _close_quiet(conn)


def _serve_forward(bind: str, port: int, target_port: int, label: str) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((bind, port))
        srv.listen(64)
    except OSError as e:
        print(f"[forward {label}] 无法监听 {bind}:{port} —— {e}")
        _close_quiet(srv)
        return
    print(f"[forward {label}] {bind}:{port} → 127.0.0.1:{target_port}")
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            time.sleep(0.5)
            continue
        conn.settimeout(15)             # 只在读首个请求头时生效，之后放开
        threading.Thread(target=_proxy_conn, args=(conn, target_port, label),
                         daemon=True).start()


def forward_ports() -> list[dict]:
    """校验配置里的端口映射，跳过无效项并说明原因。"""
    fw = CFG.get("forwards") or {}
    ok = {s["id"] for s in SERVICES}
    out: list[dict] = []
    for item in fw.get("ports") or []:
        sid, port, to = item.get("service"), item.get("port"), item.get("to")
        if sid not in ok or not isinstance(port, int) or not isinstance(to, int):
            print(f"[forward] 跳过无效映射: {item}")
            continue
        out.append({"service": sid, "port": port, "to": to, "note": item.get("note", ""),
                    "inject_token": str(item.get("inject_token") or "")})
    return out


def forward_map() -> dict:
    return {f["service"]: f for f in forward_ports()}


def forward_token_file(sid: str) -> str:
    """某个服务是否需要面板代它注入 token —— 需要则返回 token 文件的路径。"""
    f = forward_map().get(sid) or {}
    spec = f.get("inject_token")
    if not spec:
        return ""
    svc = next((s for s in SERVICES if s["id"] == sid), None)
    return str((svc or {}).get("restart", {}).get(spec) or "")


def open_proxy_listeners() -> None:
    fw = CFG.get("forwards") or {}
    if not remote_access() or not fw.get("ports"):
        return
    bind = str(fw.get("bind") or "0.0.0.0")
    for f in forward_ports():
        threading.Thread(target=_serve_forward,
                         args=(bind, f["port"], f["to"], f["service"]), daemon=True).start()


def safe_join(base: Path, rel: str) -> Path:
    """把静态资源请求拼到 base 之内，越界直接拒绝。

    resolve() 之后 base 本身也被解析过，两边形式一致；再比 str 前缀的话
    「/static/../monitor_server.py」这种就会漏过去。
    """
    base = base.resolve()
    target = (base / str(rel).lstrip("/\\")).resolve()
    if target != base and base not in target.parents:
        raise ValueError("outside static root")
    return target


def lan_addresses() -> list[str]:
    """本机可用于局域网访问的 IPv4 地址（Tailscale 的 100.x 也在其中）。"""
    out: list[str] = []
    for probe in ("10.255.255.255", "192.168.255.255", "172.31.255.255"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((probe, 1))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127.") and ip not in out:
                out.append(ip)
        except OSError:
            pass
        finally:
            s.close()
    return out


def save_listen_config(cfg: NetworkConfig) -> None:
    """把 listen 段写回 services.json（原子替换，保留其它字段）。"""
    data = json.loads(CFG_PATH.read_text(encoding="utf-8"))
    data["listen"] = {"local": {"host": LOCAL_HOST, "port": LOCAL_PORT},
                      "network": cfg.snapshot()}
    tmp = CFG_PATH.with_name(CFG_PATH.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, CFG_PATH)


def start_network_listener(cfg: NetworkConfig, *, rotate_cert: bool = False) -> None:
    global NET_SERVER, TLS_FINGERPRINT
    if NET_SERVER is not None:
        stop_network_listener()
    ctx, fp, _cert = mtls.ensure(SECURITY.state_dir, [socket.gethostname()],
                                 [cfg.bind], rotate=rotate_cert)
    server = NetworkServer((cfg.bind, cfg.port), Handler, ctx)
    NET_SERVER = server
    TLS_FINGERPRINT = fp
    serve_in_thread(server)


def stop_network_listener() -> None:
    global NET_SERVER
    stop_network_server(NET_SERVER)
    NET_SERVER = None


def apply_network_config(cfg: NetworkConfig, *, persist: bool = True,
                         rotate_cert: bool = False) -> NetworkConfig:
    """校验并启停网络入口；persist 时把 listen 段写回配置。"""
    global NETWORK_CFG, TLS_FINGERPRINT
    if cfg.enabled:
        cfg = ensure_allowed(cfg)
    stop_network_listener()
    if cfg.enabled:
        start_network_listener(cfg, rotate_cert=rotate_cert)
    else:
        TLS_FINGERPRINT = ""
    NETWORK_CFG = cfg
    SECURITY.set_network(cfg)
    if persist:
        save_listen_config(cfg)
    return cfg


def print_access_hints(host: str, port: int) -> None:
    print(f"Mozunitor 已启动: http://127.0.0.1:{port}/")
    print("1.1.0 起回环也需要登录（不再有回环免鉴权）：")
    if SECURITY.needs_setup:
        print(f"  首次初始化 setup code: {SECURITY.setup_code}")
        print("  壳内通过 launch token 自动登录；也可用上面的 setup code 完成初始化")
    else:
        print("  用管理员口令登录；本机脚本可用 .state/local-token")
    if NETWORK_CFG.enabled and NET_SERVER is not None:
        print(f"网络入口（HTTPS）: https://{NETWORK_CFG.bind}:{NETWORK_CFG.port}/")
        print(f"  证书指纹 SHA256: {mtls.format_fingerprint(TLS_FINGERPRINT)}")
        print(f"  允许来源: {', '.join(NETWORK_CFG.allowed_cidrs)}")
    if MIGRATION_NOTE:
        print(f"  [迁移] {MIGRATION_NOTE}")


class Handler(BaseHTTPRequestHandler):
    server_version = "Mozunitor/1.0.2"
    protocol_version = "HTTP/1.1"
    _session_cookie: str | None = None       # 本次响应要下发的会话 Cookie

    def log_message(self, fmt, *args):                       # 静音，避免刷屏
        pass

    # -- 工具 ----------------------------------------------------------
    def _listener_kind(self) -> str:
        return getattr(self.server, "listener_kind", "local")

    def _is_loopback(self) -> bool:
        """本地管理面（loopback listener）的请求；网络入口一律按远端处理。"""
        return self._listener_kind() == "local"

    def _token_from_req(self) -> str:
        """首次可用 ?token= 进来（方便做成书签/二维码），之后走 Cookie。"""
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(self.path).query)
        cand = (q.get("token") or [""])[0]
        if cand:
            return cand
        cookie = self.headers.get("Cookie") or ""
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == AUTH_COOKIE:
                return v
        return self.headers.get("X-Mozunitor-Token") or ""

    def _peer_level(self) -> str:
        """按节点间的约定判定级别：用户名一致给 read，另有密码证明才给 write。

        证明是 HMAC(key, 命令+路径+时间戳)，本机用本地密码派生，对端拿自己那份算一遍
        比对 —— 密码明文不上网，本机也不需要知道对端的密码。
        """
        user = self.headers.get("X-Mozunitor-User") or ""
        if not user or not hmac.compare_digest(user, str(CREDS.get("username") or "")):
            return ""
        ts = self.headers.get("X-Mozunitor-Time") or ""
        mac = self.headers.get("X-Mozunitor-Mac") or ""
        if not ts or not mac:
            return "read"
        try:
            if abs(time.time() - int(ts)) > PEER_TIME_WINDOW:
                return ""
        except ValueError:
            return ""
        key = str(CREDS.get("key") or "")
        expect = hmac.new(key.encode("utf-8"),
                          f"{self.command}\n{self.path}\n{ts}".encode("utf-8"),
                          hashlib.sha256).hexdigest()
        return "write" if hmac.compare_digest(mac, expect) else ""

    def _level(self) -> str:
        """本次请求的权限级别；由 SecurityState.authorize() 在 gate 里写入。"""
        auth = getattr(self, "_auth", None)
        return auth.scope if auth is not None else ""

    def _authorized(self, required: str = "write") -> bool:
        auth = getattr(self, "_auth", None)
        if auth is None:
            return False
        return LEVEL_RANK.get(auth.scope, 0) >= LEVEL_RANK.get(required, 2)

    def _run_gate(self, method: str, path: str) -> bool:
        """统一请求管线：回环也要认证；Host/Origin/CSRF/JSON 由 gate 统一判。"""
        res = SECURITY.authorize(
            method=method, path=path, headers=self.headers,
            client_ip=self.client_address[0], loopback=self._is_loopback())
        self._auth = res
        if res.status == 200:
            return True
        extra = []
        if res.status == 429:
            extra.append(("Retry-After", str(max(1, int(res.retry_after or 1)))))
        if res.status == 410:
            extra.append(("X-Mozunitor-Gone", "use /api/session"))
        self._send(res.status, {"error": res.error,
                                "auth_required": res.status in (401, 403),
                                "level": res.route.scope if res.route else ""},
                   extra or None)
        return False

    def _handle_auth(self, payload: dict) -> None:
        """登录：只给用户名换只读会话，用户名 + 密码换完整会话。

        旧 token 仍然认且直接给全权 —— 手机上已有的书签与 Cookie 不必重配。
        """
        tok = str(payload.get("token") or "")
        if tok and token_matches(tok):
            self._set_session("write")
            self._send(200, {"ok": True, "level": "write", "via": "token"})
            return
        user = str(payload.get("user") or "")
        pwd = str(payload.get("password") or "")
        if not user or not hmac.compare_digest(user, str(CREDS.get("username") or "")):
            self._send(401, {"ok": False, "error": "用户名不一致"})
            return
        if not pwd:
            self._set_session("read")
            self._send(200, {"ok": True, "level": "read"})
            return
        if not hmac.compare_digest(shared_key(user, pwd), str(CREDS.get("key") or "")):
            self._send(401, {"ok": False, "error": "密码不一致"})
            return
        self._set_session("write")
        self._send(200, {"ok": True, "level": "write"})

    def _set_session(self, level: str) -> None:
        """记下本次要下发的会话 Cookie，由 _send 统一附到响应头上。"""
        self._session_cookie = (f"{SESSION_COOKIE}={issue_session(level)}; Path=/; "
                                f"HttpOnly; SameSite=Strict; Max-Age={SESSION_MAX_AGE}")

    def _handle_credentials(self, payload: dict | None) -> None:
        """读写本机凭据。只在回环上开 —— 经远端渠道改凭据是明确禁止的。"""
        if not self._is_loopback():
            self._send(403, {"error": "凭据只能在运行面板的这台机器上修改"})
            return
        if payload is None:
            self._send(200, {"username": CREDS.get("username") or "",
                             "preset": bool(CREDS.get("preset")),
                             "preset_password": CREDS.get("preset_password") or ""})
            return
        user = str(payload.get("username") or "").strip()
        pwd = str(payload.get("password") or "")
        if not user or not pwd:
            self._send(400, {"error": "用户名与密码都不能为空"})
            return
        save_credentials({"version": 1, "username": user, "key": shared_key(user, pwd),
                          "preset": False})
        self._set_session("write")
        self._send(200, {"ok": True, "username": user})

    # -- 1.1.0 会话/初始化/安全面 ------------------------------------
    def _client_ip(self) -> str:
        return str(self.client_address[0])

    def _ua(self) -> str:
        return str(self.headers.get("User-Agent") or "")[:200]

    def _auth_error(self, exc: SecurityAuthError) -> None:
        extra = []
        if exc.status == 429:
            extra.append(("Retry-After", str(max(1, int(exc.retry_after or 1)))))
        self._send(exc.status, {"ok": False, "error": exc.message}, extra or None)

    def _handle_setup_complete(self, payload: dict) -> None:
        try:
            session, cookie = SECURITY.complete_setup(
                str(payload.get("password") or ""),
                str(payload.get("proof") or self.headers.get("X-Mozunitor-Launch") or ""),
                client_ip=self._client_ip(), ua=self._ua())
        except SecurityAuthError as exc:
            self._auth_error(exc)
            return
        self._session_cookie = cookie
        self._send(200, {"ok": True, "scope": session.scope, "csrf": session.csrf,
                         "setup_done": True})

    def _handle_session_login(self, payload: dict) -> None:
        try:
            session, cookie = SECURITY.login(
                str(payload.get("password") or ""), client_ip=self._client_ip(),
                ua=self._ua(), loopback=self._is_loopback())
        except SecurityAuthError as exc:
            self._auth_error(exc)
            return
        self._session_cookie = cookie
        self._send(200, {"ok": True, "scope": session.scope, "csrf": session.csrf,
                         "node": {"id": NODE_ID, "name": NODE_NAME},
                         "version": SERVER_VERSION})

    def _handle_session_launch(self, payload: dict) -> None:
        try:
            session, cookie = SECURITY.launch(
                str(payload.get("token") or self.headers.get("X-Mozunitor-Launch") or ""),
                client_ip=self._client_ip(), ua=self._ua())
        except SecurityAuthError as exc:
            self._auth_error(exc)
            return
        self._session_cookie = cookie
        self._send(200, {"ok": True, "scope": session.scope, "csrf": session.csrf})

    def _handle_password_change(self, payload: dict) -> None:
        try:
            SECURITY.change_password(str(payload.get("old") or ""),
                                     str(payload.get("new") or ""),
                                     client_ip=self._client_ip())
        except SecurityAuthError as exc:
            self._auth_error(exc)
            return
        self._session_cookie = SECURITY.clear_cookie_header()
        self._send(200, {"ok": True, "relogin": True})

    def _handle_security_network(self, payload: dict) -> None:
        try:
            cfg = NetworkConfig.from_dict(payload)
        except NetworkConfigError as exc:
            self._send(400, {"error": str(exc)})
            return
        try:
            cfg = apply_network_config(cfg, persist=True,
                                       rotate_cert=bool(payload.get("rotate_cert")))
        except NetworkConfigError as exc:
            SECURITY.audit.write("network_config_failed", ip=self._client_ip(),
                                 reason=str(exc))
            self._send(400, {"error": str(exc)})
            return
        except OSError as exc:
            SECURITY.audit.write("network_config_failed", ip=self._client_ip(),
                                 reason=str(exc))
            self._send(500, {"error": f"启动网络入口失败：{exc}"})
            return
        SECURITY.audit.write("network_config", ip=self._client_ip(), enabled=cfg.enabled,
                             mode=cfg.mode, bind=cfg.bind, port=cfg.port,
                             cidrs=",".join(cfg.allowed_cidrs))
        self._send(200, {"ok": True, "network": dict(
            NETWORK_CFG.snapshot(), tls_fingerprint=TLS_FINGERPRINT,
            tls_fingerprint_pretty=mtls.format_fingerprint(TLS_FINGERPRINT))})

    def _send(self, code: int, body, ctype: str = "application/json; charset=utf-8",
              extra_headers: list | None = None) -> None:
        if isinstance(body, (dict, list)):
            raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            raw = body.encode("utf-8")
        else:
            raw = body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data:; "
                         "style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'; connect-src 'self'")
        if self._session_cookie:
            # 登录或改凭据刚签发的会话，只附在这一次响应上
            self.send_header("Set-Cookie", self._session_cookie)
            self._session_cookie = None
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _serve_static(self, rel: str) -> None:
        try:
            target = safe_join(STATIC, rel)
        except ValueError:
            self._send(404, {"error": "not found"})
            return
        if not target.is_file():
            self._send(404, {"error": "not found"})
            return
        ctype = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                 ".js": "application/javascript; charset=utf-8",
                 ".svg": "image/svg+xml"}.get(target.suffix, "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    # -- 路由 ----------------------------------------------------------
    def do_GET(self) -> None:                                # noqa: N802
        from urllib.parse import parse_qs, urlparse
        u = urlparse(self.path)
        path, query = u.path, parse_qs(u.query)

        # index.html 与 static/ 不设门槛：面板显示一个「请输入 token」的页面本身
        # 不泄露任何状态，而 CSS/JS 要能在登录前加载。真正的数据全在 /api/* 后面。
        if path in ("/", "/index.html"):
            self._serve_static("index.html")
            return
        if path.startswith("/static/"):
            self._serve_static(path[len("/static/"):])
            return
        # 1.1.0：所有 /api/*（含回环）统一过 gate；不再有 loopback 免鉴权。
        if not self._run_gate("GET", path):
            return
        if path == "/api/setup/status":
            self._send(200, {"needs_setup": SECURITY.needs_setup,
                             "node": {"id": NODE_ID, "name": NODE_NAME},
                             "version": SERVER_VERSION})
        elif path == "/api/session":
            auth = self._auth
            self._send(200, {"scope": auth.scope if auth else "",
                             "csrf": auth.session.csrf if auth and auth.session else "",
                             "node": {"id": NODE_ID, "name": NODE_NAME},
                             "version": SERVER_VERSION,
                             "setup_done": not SECURITY.needs_setup})
        elif path == "/api/security":
            snap = SECURITY.snapshot()
            snap["node"] = {"id": NODE_ID, "name": NODE_NAME}
            snap["version"] = SERVER_VERSION
            snap["listener"] = self._listener_kind()
            snap["network"] = dict(
                NETWORK_CFG.snapshot(), tls_fingerprint=TLS_FINGERPRINT,
                tls_fingerprint_pretty=mtls.format_fingerprint(TLS_FINGERPRINT))
            self._send(200, snap)
        elif path == "/api/devices":
            self._send(200, {"devices": []})
        elif path == "/api/state":
            self._send(200, build_view())
        elif path == "/api/node":
            # 对等节点拉本机快照的入口；与 /api/state 分开，聚合各端自行完成
            self._send(200, build_node_snapshot())
        elif path == "/api/op":
            # ops 协议的读入口：视图与跳转都从这里取（写入口见 do_POST）。
            # 级别按 op 声明判，所以这一条在 LEVELS 里是 read。
            self._handle_op()
        elif path == "/api/history":
            self._handle_history()
        elif path == "/api/settings":
            self._handle_settings_get()
        elif path == "/api/service-settings":
            self._handle_service_settings_get()
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:                               # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length > 65536:
            self._send(413, {"error": "请求体过大"})
            return
        path = self.path.split("?", 1)[0]
        if not self._run_gate("POST", path):
            return
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"error": "请求体不是合法 JSON"})
            return
        if not isinstance(payload, dict):
            self._send(400, {"error": "请求体不是 JSON 对象"})
            return

        # ---- 1.1.0 会话/初始化/安全面
        if path == "/api/setup/complete":
            self._handle_setup_complete(payload)
            return
        if path == "/api/session/login":
            self._handle_session_login(payload)
            return
        if path == "/api/session/launch":
            self._handle_session_launch(payload)
            return
        if path == "/api/session/logout":
            SECURITY.logout(self._auth.session if self._auth else None)
            self._session_cookie = SECURITY.clear_cookie_header()
            self._send(200, {"ok": True})
            return
        if path == "/api/security/password":
            self._handle_password_change(payload)
            return
        if path == "/api/security/network":
            self._handle_security_network(payload)
            return
        if path in ("/api/pair/start", "/api/pair/complete", "/api/devices/revoke"):
            self._send(501, {"error": "设备配对在 P4 阶段接入（安全重构进行中）"})
            return

        if path in ("/api/restart", "/api/stop"):
            action = "stop" if self.path == "/api/stop" else "restart"
            node = str(payload.get("node") or "")
            if node and node != NODE_ID:
                # 跨节点动作：转发给对端，由它用自己的 services.json 与锁执行。
                # 这里刻意不取本机的 _RESTART_LOCK —— 那把锁保护的是本机动作，
                # 对端的并发由对端自己挡；否则一处阻塞会连累所有节点排队。
                peer = next((p for p in PEERS if str(p.get("id")) == node), None)
                if not peer:
                    self._send(404, {"error": "未知节点 id"})
                    return
                try:
                    status, body = forward_action(peer, self.path, payload)
                    self._send(status, body)
                except Exception as e:                    # noqa: BLE001
                    self._send(502, {"error": f"转发到 {node} 失败：{e}"})
                return
            svc = next((s for s in SERVICES if s["id"] == payload.get("id")), None)
            if not svc:
                self._send(404, {"error": "未知服务 id"})
                return
            if not _RESTART_LOCK.acquire(blocking=False):
                self._send(409, {"error": f"已有操作在执行，请稍候再{ '终止' if action == 'stop' else '重启' }"})
                return
            try:
                self._send(200, do_stop(svc) if action == "stop" else do_restart(svc))
            except Exception as e:                            # noqa: BLE001
                self._send(500, {"id": svc["id"], "name": svc["name"], "action": action, "ok": False,
                                 "steps": [{"t": "异常", "msg": str(e)}],
                                 "elapsed_s": 0, "freed_mb": 0})
            finally:
                _RESTART_LOCK.release()
        elif self.path.split("?", 1)[0] == "/api/op":
            # 动作类 op 的唯一出口；模型与验证链原先各自的端点块已并入这里
            self._handle_op(payload)
        elif self.path.split("?", 1)[0] == "/api/settings":
            self._handle_settings_post(payload)
        elif self.path.split("?", 1)[0] == "/api/service-settings":
            self._handle_service_settings_post(payload)
        else:
            self._send(404, {"error": "not found"})

    def _handle_op(self, payload: dict | None = None) -> None:
        """ops 协议的统一入口：GET 取视图，POST 执行动作。

        服务专属能力全部声明在 services.json 的 ops 里，这里不认识任何服务 id ——
        只做四件事：解析请求、按 op 声明的级别鉴权、取视图、把动作落到白名单端点上。
        """
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(self.path).query)
        sid = (q.get("id") or [""])[0]
        opid = (q.get("op") or [""])[0]
        svc, op = find_op(sid, opid)
        if not svc:
            self._send(404, {"error": "未知服务 id"})
            return
        if not op:
            self._send(404, {"error": f"{svc['name']} 未声明操作 {opid!r}"})
            return
        # 级别按 op 判，而不是按路径：全套视图共用一个端点，靠声明区分谁能看
        level = op_level(op)
        if not self._authorized(level):
            self._send(401, {"error": "需要更高权限", "auth_required": True, "level": level})
            return

        kind = op.get("kind")
        if kind == "view":
            if payload is not None:
                self._send(400, {"error": "视图类操作只支持 GET"})
                return
            try:
                self._send(200, {"id": sid, "op": opid, "sections": op_view(svc, op)})
            except Exception as e:                                  # noqa: BLE001
                self._send(500, {"id": sid, "op": opid, "error": f"{type(e).__name__}: {e}"})
            return
        if kind == "link":
            self._send(200, {"id": sid, "op": opid, "url": op.get("url")})
            return
        if kind == "script":
            if payload is None:
                self._send(400, {"error": "脚本类操作需要 POST"})
                return
            # 只读脚本不该去抢重启锁：它会挡住一次重启 30 秒，而它自己并不改状态。
            # 声明了 level=write 的脚本才持锁，理由与重启一致（同一时刻只允许一个改状态的操作）。
            lock = level == "write"
            if lock and not _RESTART_LOCK.acquire(blocking=False):
                self._send(409, {"error": "已有操作在执行，请稍候再试"})
                return
            try:
                self._send(200, run_script_op(svc, op,
                                              payload if isinstance(payload, dict) else {}))
            finally:
                if lock:
                    _RESTART_LOCK.release()
            return
        if kind != "run":
            self._send(400, {"error": f"未知的操作类型 kind={kind!r}"})
            return
        if payload is None:
            self._send(400, {"error": "该操作需要 POST"})
            return
        endpoint = op.get("endpoint")
        if endpoint not in OP_RUN_ENDPOINTS:
            self._send(400, {"error": f"动作端点不在白名单内：{endpoint!r}"})
            return
        # op 自己写死的部分优先于表单提交值，id 一律以 URL 为准 ——
        # 表单不该有本事改动作语义（例如把 load 改成 unload）。
        merged = {**(payload or {}), **dict(op.get("body") or {}), "id": sid}

        if endpoint == "/api/rag/verify":
            with STATE.lock:
                if STATE.verify and STATE.verify.get("running"):
                    self._send(409, {"error": "验证链正在运行"})
                    return
            # 目标从请求解析，不再写死查 "rag" 的探测状态
            if (STATE.probes.get(sid) or {}).get("status") != "up":
                self._send(409, {"error": f"{svc['name']} 未在线 —— 验证链依赖它的接口"})
                return
            if not _RESTART_LOCK.acquire(blocking=False):
                self._send(409, {"error": "已有操作在执行，请稍候再试"})
                return
            # 锁交给 worker 释放：验证链在后台跑，这里不能立刻放锁
            threading.Thread(target=_verify_worker, args=(svc,), daemon=True).start()
            self._send(202, {"started": True, "steps": [n for n, _, _ in RAG_STEPS],
                             "at": now_iso()})
            return

        if not _RESTART_LOCK.acquire(blocking=False):
            self._send(409, {"error": "已有操作在执行，请稍候再试"})
            return
        try:
            self._send(200, do_model_action(svc, merged))
        except Exception as e:                                      # noqa: BLE001
            self._send(500, {"id": sid, "name": svc["name"],
                             "action": f"model:{merged.get('action')}", "ok": False,
                             "steps": [{"t": "异常", "msg": str(e)}],
                             "elapsed_s": 0, "freed_mb": 0, "at": now_iso()})
        finally:
            _RESTART_LOCK.release()

    def _handle_history(self) -> None:
        """内建动作历史。返回 sections，与其它视图同构，前端因此只有一个渲染器。"""
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(self.path).query)
        sid = (q.get("id") or [""])[0]
        try:
            limit = int((q.get("limit") or ["20"])[0])
        except ValueError:
            limit = 20
        if not any(s["id"] == sid for s in SERVICES):
            self._send(404, {"error": "未知服务 id"})
            return
        self._send(200, {"id": sid, "sections": history_sections(sid, limit)})

    # -- 设置 ----------------------------------------------------------
    def _handle_settings_get(self) -> None:
        if not self._authorized("read"):
            self._send(401, {"error": "需要更高权限", "auth_required": True, "level": "read"})
            return
        auth = getattr(self, "_auth", None)
        self._send(200, settings_snapshot(bool(auth and auth.scope == "admin")))

    def _handle_settings_post(self, payload: dict) -> None:
        if not self._authorized("write"):
            self._send(401, {"error": "需要更高权限", "auth_required": True, "level": "write"})
            return
        section = str(payload.get("section") or "")
        # commands 段是“把节点变成任意命令执行”的唯一入口：要求 admin 且只允许本机。
        if section == "commands":
            auth = getattr(self, "_auth", None)
            if not auth or auth.scope != "admin" or not self._is_loopback():
                self._send(403, {"error": "命令字段只允许本机管理员修改"})
                return
        values = payload.get("values") or {}
        loopback = self._is_loopback()
        via = "loopback" if loopback else "remote"
        try:
            changed = apply_panel_settings(section, values, via, loopback)
        except PermissionError as e:
            _settings_audit("settings", "panel", f"面板设置 · {section}", {}, False, str(e), via=via)
            self._send(403, {"error": str(e)})
            return
        except (ValueError, KeyError, TypeError) as e:
            _settings_audit("settings", "panel", f"面板设置 · {section}", {}, False, str(e), via=via)
            self._send(400, {"error": str(e)})
            return
        except Exception as e:                                # noqa: BLE001
            _settings_audit("settings", "panel", f"面板设置 · {section}", {}, False, str(e), via=via)
            self._send(500, {"error": f"{type(e).__name__}: {e}"})
            return
        self._send(200, {"ok": True, "section": section, "changed": changed,
                         "settings": settings_snapshot(loopback)})

    def _handle_service_settings_get(self) -> None:
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(self.path).query)
        sid = (q.get("id") or [""])[0]
        node = (q.get("node") or [""])[0]
        if node and node != NODE_ID:
            peer = next((p for p in PEERS if str(p.get("id")) == node), None)
            if not peer:
                self._send(404, {"error": "未知节点 id"})
                return
            try:
                status, body = forward_get(peer, self.path)
                self._send(status, body)
            except Exception as e:                            # noqa: BLE001
                self._send(502, {"error": f"转发到 {node} 失败：{e}"})
            return
        svc = _find_service(sid)
        if not svc:
            self._send(404, {"error": "未知服务 id"})
            return
        if not svc.get("settings"):
            self._send(200, {"id": sid, "name": svc["name"], "settings": [], "meta": {}})
            return
        self._send(200, service_settings_view(svc))

    def _handle_service_settings_post(self, payload: dict) -> None:
        if not self._authorized("write"):
            self._send(401, {"error": "需要更高权限", "auth_required": True, "level": "write"})
            return
        sid = str(payload.get("id") or "")
        node = str(payload.get("node") or "")
        if node and node != NODE_ID:
            peer = next((p for p in PEERS if str(p.get("id")) == node), None)
            if not peer:
                self._send(404, {"error": "未知节点 id"})
                return
            try:
                status, body = forward_action(peer, "/api/service-settings", payload)
                self._send(status, body)
            except Exception as e:                            # noqa: BLE001
                self._send(502, {"error": f"转发到 {node} 失败：{e}"})
            return
        svc = _find_service(sid)
        if not svc:
            self._send(404, {"error": "未知服务 id"})
            return
        values = payload.get("values") or {}
        try:
            out = service_settings_write(svc, values,
                                         "loopback" if self._is_loopback() else "remote")
        except (ValueError, TypeError, KeyError) as e:
            _settings_audit("service-settings", sid, svc["name"], {}, False, str(e))
            self._send(400, {"error": str(e)})
            return
        except Exception as e:                                # noqa: BLE001
            _settings_audit("service-settings", sid, svc["name"], {}, False, str(e))
            self._send(500, {"error": f"{type(e).__name__}: {e}"})
            return
        self._send(200 if out.get("ok") else 500, out)


# ---------------------------------------------------------------- 入口

def main() -> int:
    host = LOCAL_HOST
    port = LOCAL_PORT

    if SECURITY.needs_setup:
        print(f"[初始化] 首次运行，setup code: {SECURITY.setup_code}")
        print("[初始化] 壳内 launch token 可自动登录；外部浏览器需用 setup code 完成初始化")

    with STATE.lock:
        STATE.restart_log.extend(load_history())
    record_startup()

    nesting_precheck()
    keepalive_precheck()
    relay_start_listeners()

    for fn in (probe_loop, sample_local_loop, sample_remote_loop, sample_models_loop,
               discover_loop, peer_poll_loop, keepalive_loop):
        threading.Thread(target=fn, daemon=True).start()

    open_proxy_listeners()

    if NETWORK_CFG.enabled:
        try:
            apply_network_config(NETWORK_CFG, persist=False)
        except (NetworkConfigError, OSError) as exc:
            print(f"[网络] 网络入口启动失败，仅保留本机入口：{exc}")

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    print_access_hints(host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        stop_network_listener()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
