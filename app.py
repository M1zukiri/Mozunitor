#!/usr/bin/env python3
# 创建时间: 2026-10-12 00:49:35
# 用途: Mozunitor 应用入口 —— 托盘常驻 + 内嵌 WebView2 窗口，后端与它同进程。
#       设计依据、取舍与实测数据见 SPEC-app-shell.md §4；四类探针的产物在
#       Desktop\个人\temp\mozunitor-probe\（隔离目录，不进仓库）。
#
# 三条来自实测的硬事实，改动前先看懂：
#
#   1) 托盘与窗口不抢主线程：pystray 走 run_detached() 子线程，webview.start() 占主线程。
#   2) 点 X 要收进托盘，closing 处理函数必须返回 False —— Event.set() 只在返回 False 时
#      才算「取消关闭」（webview/event.py:60-63），返回 True 是放行。
#   3) pythonw 下没有可靠 stdout，所以诊断信息既打印也落 logs/app.out。
#      该文件含 print_access_hints() 打出的访问 token，**绝不能**进 services.json 的 logs 白名单。

from __future__ import annotations

import ctypes
import html
import json
import os
import socket
import sys
import threading
import time
import urllib.request
from ctypes import wintypes
from pathlib import Path

import pystray
import webview

FROZEN = getattr(sys, "frozen", False)
ROOT = Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent
STATE_DIR = ROOT / ".state"
LOG_DIR = ROOT / "logs"
IPC_FILE = STATE_DIR / "app-ipc.json"
APP_LOG = LOG_DIR / "app.out"
ICON_FILE = STATE_DIR / "mozunitor.ico"

# 互斥量名可用 MOZU_MUTEX 覆盖：验收脚本要在真实应用正跑着的时候也能起隔离实例，
# 否则它会撞上那个实例、走「唤起已有窗口」分支然后自己退出（实测就是这样假失败两项）。
MUTEX_NAME = os.environ.get("MOZU_MUTEX") or "Local\\MozunitorApp"
ERROR_ALREADY_EXISTS = 183
TITLE = "Mozunitor"

WIN = None
TRAY = None
API = None
MUTEX_HANDLE = None
QUITTING: list[bool] = []
BACKEND_ERROR: list[str] = []


def log(msg: str) -> None:
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    try:
        print(line, flush=True)
    except Exception:                       # pythonw 下 stdout 可能不可用
        pass
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with APP_LOG.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- 单实例与唤起

def acquire_mutex() -> bool:
    """返回 True 表示已有实例在跑。句柄必须留在模块级，被 GC 回收就等于放锁。"""
    global MUTEX_HANDLE
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
    k32.CreateMutexW.restype = ctypes.c_void_p
    MUTEX_HANDLE = k32.CreateMutexW(None, False, MUTEX_NAME)
    return ctypes.get_last_error() == ERROR_ALREADY_EXISTS


def ipc_send(cmd: str, timeout: float = 3.0) -> str | None:
    """把命令发给已在跑的那个实例。连不上就返回 None —— 陈旧文件与真没实例是一回事。"""
    try:
        info = json.loads(IPC_FILE.read_text(encoding="utf-8"))
        port = int(info["port"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.sendall((cmd + "\n").encode("utf-8"))
            s.settimeout(timeout)
            return s.recv(64).decode("utf-8", "replace").strip()
    except OSError:
        return None


class IpcServer(threading.Thread):
    """唤起通道：窗口收进托盘后，第二次启动要能把它叫出来，而不是再开一个后端。"""

    def __init__(self) -> None:
        super().__init__(name="mozu-ipc", daemon=True)
        self.on_show = None
        self.on_quit = None

    def run(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            srv.bind(("127.0.0.1", 0))       # 端口交给系统挑，避免与别的应用撞车
        except OSError as exc:
            log(f"IPC 绑定失败：{type(exc).__name__}: {exc}")
            return
        srv.listen(4)
        port = srv.getsockname()[1]
        try:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            IPC_FILE.write_text(json.dumps({"port": port, "pid": os.getpid()}),
                                encoding="utf-8")
        except OSError as exc:
            log(f"IPC 端口文件写入失败：{type(exc).__name__}: {exc}")
        log(f"IPC 就绪 127.0.0.1:{port}")
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                try:
                    cmd = conn.recv(64).decode("utf-8", "replace").strip()
                except OSError:
                    continue
                if cmd == "show":
                    conn.sendall(b"ok\n")
                    if self.on_show:
                        self.on_show()
                elif cmd == "ping":
                    conn.sendall(b"ok\n")
                elif cmd == "quit":
                    conn.sendall(b"ok\n")
                    if self.on_quit:
                        self.on_quit()
                    return
                else:
                    conn.sendall(b"unknown\n")


# ---------------------------------------------------------------- 后端（同进程）

def panel_alive(port: int, timeout: float = 1.5) -> bool:
    """端口上跑的是不是 Mozunitor —— 用来把「已有裸后端」与「别的程序占了端口」分开。"""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=timeout) as r:
            body = r.read(4096).decode("utf-8", "replace")
            return r.status == 200 and "Mozunitor" in body
    except Exception:
        return False


def run_backend() -> None:
    import monitor_server
    try:
        monitor_server.main()
    except BaseException as exc:            # noqa: BLE001 —— 端口冲突等都要让用户看见
        BACKEND_ERROR.append(f"{type(exc).__name__}: {exc}")
        log(f"后端启动失败：{BACKEND_ERROR[-1]}")


def wait_panel(port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if BACKEND_ERROR:
            return False
        if panel_alive(port, 1.0):
            return True
        time.sleep(0.3)
    return False


# ---------------------------------------------------------------- 窗口与托盘

def make_icon_image(size: int = 64):
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([2, 2, size - 3, size - 3], radius=13, fill=(18, 21, 27, 255))
    d.rounded_rectangle([15, 15, size - 16, size - 16], radius=7, fill=(64, 200, 172, 255))
    return img


def ensure_icon_file() -> str | None:
    """窗口图标：首次运行时生成到 .state 下，不把二进制塞进仓库。"""
    try:
        if not ICON_FILE.is_file():
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            make_icon_image(256).save(ICON_FILE, sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])
        return str(ICON_FILE)
    except Exception as exc:                # noqa: BLE001 —— 没图标也要能开窗
        log(f"图标生成失败：{type(exc).__name__}: {exc}")
        return None


class Api:
    """暴露给页面：面板里的入口按钮经 openExternal() 调进来，开一个应用内新窗口。

    只认 http/https —— 页面能传任意字符串进来，壳不该成为命令入口。
    """

    def open_child(self, url: str) -> bool:
        if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
            log(f"拒绝开子窗口：{url!r}")
            return False
        try:
            host = url.split("/")[2] if len(url.split("/")) > 2 else url
            webview.create_window(f"{TITLE} · {host}", url, width=1020, height=740)
            log(f"应用内新窗口：{url}")
            return True
        except Exception as exc:            # noqa: BLE001
            log(f"开子窗口失败：{type(exc).__name__}: {exc}")
            return False


def own_main_hwnd() -> int | None:
    """本进程里标题为 TITLE 的可见顶层窗口句柄。"""
    u = ctypes.windll.user32
    u.EnumWindows.argtypes = [ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM),
                              wintypes.LPARAM]
    u.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    u.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    u.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    u.IsWindowVisible.argtypes = [wintypes.HWND]
    pid = os.getpid()
    found: list[int] = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    def cb(hwnd, _lparam):
        wpid = wintypes.DWORD()
        u.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        if wpid.value == pid and u.IsWindowVisible(hwnd):
            n = u.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(n + 1)
            u.GetWindowTextW(hwnd, buf, n + 1)
            if buf.value == TITLE:
                found.append(int(hwnd))
        return True

    u.EnumWindows(cb, 0)
    return found[0] if found else None


def focus_window() -> None:
    """把窗口带到最前。`win.show()` 只做 SW_SHOW，**不抢前台** —— 实测过一次
    「从托盘唤回却看不到窗口」：窗口被别的窗口盖着，看着像点了没反应。
    SetForegroundWindow 对非前台进程经常静默失败，所以再补一手「置顶后立刻取消」。"""
    hwnd = own_main_hwnd()
    if not hwnd:
        return
    u = ctypes.windll.user32
    u.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    u.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                               ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    u.SetForegroundWindow.argtypes = [wintypes.HWND]
    u.ShowWindow(hwnd, 9)                                          # SW_RESTORE
    u.SetWindowPos(hwnd, ctypes.c_void_p(-1), 0, 0, 0, 0, 0x0003)  # TOPMOST（不移动不改尺寸）
    u.SetForegroundWindow(hwnd)
    u.SetWindowPos(hwnd, ctypes.c_void_p(-2), 0, 0, 0, 0, 0x0003)  # 立刻取消置顶


def has_interactive_desktop() -> bool:
    """当前进程有没有可用的交互桌面。

    SSH 会话与 Windows 服务都落在 Session 0，那里的窗口站是 `Service-0x0-3e7$`：
    pywebview 能在其中起进程、后端也照常工作，但 WebView2 初始化会失败
    （对端 实测：进程与 8090 都正常，`panel.err` 里是 InitCoreWebView2Async 的异常）。
    HANDLE 必须显式声明 restype —— 按 c_int 传会被截断，这个判据会静默失效。
    """
    try:
        u = ctypes.windll.user32
        u.GetProcessWindowStation.restype = ctypes.c_void_p
        u.GetUserObjectInformationW.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                                ctypes.c_void_p, ctypes.c_ulong,
                                                ctypes.POINTER(ctypes.c_ulong)]
        u.GetUserObjectInformationW.restype = ctypes.c_bool
        hwinsta = u.GetProcessWindowStation()
        buf = ctypes.create_unicode_buffer(256)
        got = ctypes.c_ulong()
        if not u.GetUserObjectInformationW(hwinsta, 2, buf, ctypes.sizeof(buf),  # UOI_NAME
                                           ctypes.byref(got)):
            return True                     # 问不出来就别拦着，按有桌面处理
        return buf.value.upper() == "WINSTA0"
    except Exception:                       # noqa: BLE001
        return True


def window_geometry(default_w: int = 1180, default_h: int = 780, margin: int = 80):
    """按**逻辑**屏幕尺寸收敛窗口大小，并显式居中。

    实测踩到两件事：2560x1600 @200% 缩放时逻辑屏幕只有 1280x800，1180x780 的窗口右下角会被
    推出屏外；而**只收尺寸还不够** —— 交给系统的默认位置会把窗口放到 (98,98)，
    底边依然越界（实测窗口 (98,98)-(1278,818) 对 1280x800）。所以位置也自己算。"""
    u = ctypes.windll.user32
    sw, sh = u.GetSystemMetrics(0), u.GetSystemMetrics(1)
    w = max(760, min(default_w, sw - margin))
    h = max(520, min(default_h, sh - margin))
    return max(0, (sw - w) // 2), max(0, (sh - h) // 2), w, h


def show_window(*_args) -> None:
    if WIN is None:
        return
    try:
        WIN.show()
        focus_window()
        log("窗口已显示并置前")
    except Exception as exc:                # noqa: BLE001
        log(f"显示窗口失败：{type(exc).__name__}: {exc}")


def hide_window(*_args) -> None:
    if WIN is None:
        return
    try:
        WIN.hide()
        log("窗口已收进托盘")
    except Exception as exc:                # noqa: BLE001
        log(f"隐藏窗口失败：{type(exc).__name__}: {exc}")


def quit_app(*_args) -> None:
    QUITTING.append(True)
    log("退出应用")
    try:
        if TRAY is not None:
            TRAY.stop()
    except Exception:                       # noqa: BLE001
        pass
    try:
        IPC_FILE.unlink(missing_ok=True)
    except OSError:
        pass
    for w in list(webview.windows):
        try:
            w.destroy()
        except Exception:                   # noqa: BLE001
            pass
    time.sleep(0.4)
    os._exit(0)                             # 端口随进程消失而释放，这正是验收要断言的


def on_closing():
    """点标题栏的 X 等价于「关闭窗口」：收进托盘，后端继续服务 mesh 与手机。"""
    if QUITTING:
        return True                         # 放行关闭
    hide_window()
    return False                            # 返回 False 才取消关闭


def build_tray():
    return pystray.Icon(
        "mozunitor", make_icon_image(), TITLE,
        menu=pystray.Menu(
            pystray.MenuItem("打开面板", show_window, default=True),
            pystray.MenuItem("关闭窗口", hide_window),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出应用", quit_app),
        ))


# ---------------------------------------------------------------- 入口

_ERROR_HTML = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<style>
 body{margin:0;padding:30px;background:#12151b;color:#dfe4ec;
      font:14px/1.75 system-ui,"Microsoft YaHei",sans-serif}
 h1{font-size:17px;margin:0 0 14px}
 pre{background:#1b202a;padding:13px;border-radius:8px;overflow:auto;color:#ffb4a8;
     font-size:13px;white-space:pre-wrap}
 p{margin:10px 0;color:#98a2b3}
 code{color:#7fd8c4}
</style></head><body>
<h1>后端没有起来</h1>
<p>Mozunitor 的采集与 HTTP 服务没能在这个进程里启动，窗口因此没有面板可显示。</p>
<pre>__REASON__</pre>
<p>排查：<code>logs/app.out</code> 与 <code>logs/panel.err</code>；
若提示端口被占用，先停掉占用该端口的进程再启动应用。</p>
</body></html>"""


def error_html(reason: str) -> str:
    return _ERROR_HTML.replace("__REASON__", html.escape(reason or "（没有更多信息）"))


def main() -> int:
    global WIN, TRAY, API

    # 验收脚本要经 CDP 在真实页面里调 open_child()，否则「应用内开窗」这条没法自动验。
    # 只在显式给了端口时开，生产路径不带这个环境变量。
    debug_port = os.environ.get("MOZU_DEBUG_PORT")
    if debug_port:
        try:
            webview.settings["REMOTE_DEBUGGING_PORT"] = int(debug_port)
            log(f"CDP 调试端口已开：{debug_port}")
        except (ValueError, KeyError) as exc:
            log(f"调试端口设置失败：{type(exc).__name__}: {exc}")

    if acquire_mutex():
        reply = ipc_send("show")
        if reply == "ok":
            log("已有实例在跑，已请求它显示窗口")
            return 0
        # 不静默退出：否则用户看到的是「点了没反应」，比报错更难查
        msg = "Mozunitor 已在运行，但无法唤起它的窗口（IPC 无响应）。"
        log(msg)
        print(msg, file=sys.stderr)
        return 2

    IPC = IpcServer()
    IPC.start()
    IPC.on_show = show_window
    IPC.on_quit = quit_app

    try:
        import monitor_server
    except Exception as exc:                # noqa: BLE001 —— 配置坏了要看得见
        log(f"载入后端失败：{type(exc).__name__}: {exc}")
        API = Api()
        WIN = webview.create_window(TITLE, html=error_html(f"载入后端失败：{exc}"),
                                    width=760, height=430, js_api=API)
        WIN.events.closing += on_closing
        webview.start(private_mode=False, storage_path=str(STATE_DIR / "webview"),
                      icon=ensure_icon_file())
        return 1

    # 1.1.0 起 listen 可能写成 {local, network}；LOCAL_PORT 已由后端折算过旧格式。
    port = int(monitor_server.LOCAL_PORT)
    external = panel_alive(port)
    if external:
        log(f"端口 {port} 上已有 Mozunitor 后端（外部进程），本应用只负责窗口与托盘")
    else:
        threading.Thread(target=run_backend, name="mozu-backend", daemon=True).start()
        if not wait_panel(port, 20):
            reason = BACKEND_ERROR[-1] if BACKEND_ERROR else f"{port} 端口在 20 秒内没有就绪"
            log(f"后端未就绪：{reason}")
            API = Api()
            WIN = webview.create_window(TITLE, html=error_html(reason),
                                        width=760, height=430, js_api=API)
            WIN.events.closing += on_closing
            TRAY = build_tray()
            TRAY.run_detached()
            webview.start(private_mode=False, storage_path=str(STATE_DIR / "webview"),
                          icon=ensure_icon_file())
            return 1

    monitor_server.remember({
        "action": "app:start", "id": "mozunitor-app", "name": "Mozunitor 应用",
        "ok": True, "at": monitor_server.now_iso(), "elapsed_s": 0, "freed_mb": 0,
        "steps": [{"t": "启动",
                   "msg": f"pid={os.getpid()}  端口={port}  "
                          f"后端={'沿用外部进程' if external else '内置线程'}"}]})

    if not has_interactive_desktop():
        # Session 0（SSH / 服务会话）里没有交互桌面：只做后端与对等互联，不建窗口与托盘。
        # 硬建的话 WebView2 会初始化失败，留下一堆无意义的异常 —— 对端 就是这样。
        log("没有交互桌面（会话 0 / 服务环境）：后端与对等互联照常，跳过窗口与托盘")
        while True:
            time.sleep(3600)

    API = Api()
    x, y, width, height = window_geometry()
    # 1.1.0：回环不再免鉴权。壳把仅存在于本进程内存的 launch token 通过 URL 片段
    # 交给 WebView，前端用它换 HttpOnly 会话后立刻清掉片段；浏览器手动打开仍需口令登录。
    panel_url = f"http://127.0.0.1:{port}/"
    try:
        _sec = getattr(monitor_server, "SECURITY", None)
        _launch = str(getattr(_sec, "launch_token", "") or "")
        if _launch:
            panel_url += "#launch=" + _launch
    except Exception:  # noqa: BLE001 —— launch 注入失败要退化成普通登录，不能拦住窗口
        log("launch token 注入失败，退回口令登录")
    WIN = webview.create_window(TITLE, panel_url,
                                x=x, y=y, width=width, height=height, js_api=API)
    WIN.events.closing += on_closing
    TRAY = build_tray()
    TRAY.run_detached()
    log(f"托盘已起，进入 webview.start()（面板 http://127.0.0.1:{port}/）")
    # 启动后主动置前一次：实测窗口可能被别的窗口盖住，用户会以为「应用没起来」。
    webview.start(private_mode=False, storage_path=str(STATE_DIR / "webview"),
                  icon=ensure_icon_file(), func=focus_window)

    monitor_server.remember({
        "action": "app:quit", "id": "mozunitor-app", "name": "Mozunitor 应用",
        "ok": True, "at": monitor_server.now_iso(), "elapsed_s": 0, "freed_mb": 0,
        "steps": [{"t": "退出", "msg": f"pid={os.getpid()} 窗口全部关闭"}]})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
