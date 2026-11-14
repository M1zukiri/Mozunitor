# 2026-10-12  Mozunitor 面板重启工具（v3.3.0 重写）
#
# 用法：
#   python tools\reload_panel.py                 # 重启本端面板
#   python tools\reload_panel.py --dry-run       # 只打印要做什么
#   python tools\reload_panel.py --node <peer>  # 重启对端面板（走 peers.list 的 ssh + start_cmd）
#   python tools\reload_panel.py --start "schtasks /run /tn Mozunitor"   # 换本端的拉起方式
#
# 流程：py_compile 校验 -> 干净退出 -> 等端口释放 -> 按启动器拉起 -> 轮询到 API 就绪。
#
# **旧版拉的是 `monitor_server.py`（裸后端）**，而 v3.0.0 起人面对的入口是托盘应用 `app.py`：
# 用它会把托盘换成「没有图标的孤儿后端」，现象是「重启之后托盘没了」。所以本端走启动器
# `start-monitor-hidden.vbs`（内部经 WMI，落交互会话），对端走它自己配置里的 `start_cmd`
# —— M1K 上那是计划任务 `/run /tn Mozunitor`：**只有计划任务能落进交互会话**，从 SSH 直接
# 起会进 Session 0，没有托盘（见 AGENTS.md「应用形态」）。
#
# 本端退出走 IPC `quit`（面板自己的干净路径）；对端只能 SSH 杀掉监听 8090 的进程。
# 两条路径都以**端口**为判据，不以「已下发」为判据。
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, "monitor_server.py")
CFG = os.path.join(ROOT, "services.json")
IPC = os.path.join(ROOT, ".state", "app-ipc.json")
VBS = os.path.join(ROOT, "start-monitor-hidden.vbs")
DEFAULT_START = f'wscript.exe "{VBS}"'

# 对端这条命令在 M1K 的 cmd.exe 里执行，所以只用单引号、纯 ASCII。
REMOTE_KILL = ("powershell -NoProfile -Command "
               "\"$p=(Get-NetTCPConnection -LocalPort %(port)d -State Listen -EA SilentlyContinue)"
               ".OwningProcess | Select-Object -Unique; "
               "foreach($i in $p){Stop-Process -Id $i -Force -EA SilentlyContinue}; "
               "if($p){'killed ' + ($p -join ',')}else{'no listener'}\"")


def load_cfg() -> dict:
    with open(CFG, encoding="utf-8") as f:
        return json.load(f)


def compile_check() -> bool:
    r = subprocess.run([sys.executable, "-m", "py_compile", SERVER],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("py_compile 失败：")
        print(r.stderr.strip())
        return False
    print("py_compile OK")
    return True


def port_listening(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), 1.0):
            return True
    except OSError:
        return False


def wait_free(port: int, seconds: float) -> bool:
    t0 = time.time()
    while time.time() - t0 < seconds:
        if not port_listening(port):
            print(f"  端口 {port} 已释放（{int(time.time() - t0)}s）")
            return True
        time.sleep(0.5)
    print(f"  !! 端口 {port} 在 {int(seconds)}s 内没释放")
    return False


def panel_procs() -> list[int]:
    """本端还活着的面板进程（python/pythonw + app.py）。

    **端口释放不等于进程消失**，而启动器 `start-monitor-hidden.vbs` 的守卫看的正是进程：
    「已有 pythonw app.py 就 WScript.Quit」。只等端口就拉起，会撞上那道守卫 —— 它静默退出，
    什么都不做也不报错，现象是「重启之后面板没了」。这条是 2026-10-12 真踩到的。
    """
    ps = ("Get-CimInstance Win32_Process -Filter \"Name like 'python%'\" | "
          "Where-Object { $_.CommandLine -like '*app.py*' } | "
          "Select-Object -ExpandProperty ProcessId; "
          "Get-CimInstance Win32_Process -Filter \"Name='Mozunitor.exe'\" | "
          "Select-Object -ExpandProperty ProcessId")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, text=True, timeout=40)
    return [int(x) for x in r.stdout.split() if x.strip().isdigit()]


def wait_gone(seconds: float) -> bool:
    t0 = time.time()
    while time.time() - t0 < seconds:
        pids = panel_procs()
        if not pids:
            print(f"  旧面板进程已退出（{int(time.time() - t0)}s）")
            return True
        time.sleep(0.4)
    print(f"  !! 面板进程 {panel_procs()} 在 {int(seconds)}s 内没退出")
    return False


def wait_ready(port: int, seconds: float) -> bool:
    t0 = time.time()
    url = f"http://127.0.0.1:{port}/"
    while time.time() - t0 < seconds:
        try:
            with urllib.request.urlopen(url, timeout=4) as r:
                body = r.read()
            print(f"  面板已恢复：{url} HTTP {r.status}  bytes={len(body)}  用时 {int(time.time() - t0)}s")
            return True
        except Exception:                                          # noqa: BLE001
            time.sleep(1)
    print(f"  !! 面板在 {int(seconds)}s 内没起来（查 logs\\panel.err 与进程的 SessionId）")
    return False


def ipc_quit() -> bool:
    """本端干净退出：面板自己的 IPC 只认 quit / show / ping 三个命令。"""
    if not os.path.exists(IPC):
        print("  没有 .state/app-ipc.json —— 端口上可能不是托盘应用（裸后端？），改用杀进程")
        return False
    with open(IPC, encoding="utf-8") as f:
        info = json.load(f)
    try:
        s = socket.create_connection(("127.0.0.1", int(info["port"])), timeout=5)
    except OSError as e:
        print(f"  IPC 连不上（{e}）—— 改用杀进程")
        return False
    with s:
        s.sendall(b"quit\n")
        try:
            reply = s.recv(64).decode("utf-8", "replace").strip()
        except OSError:
            reply = "(无回执)"
    print(f"  IPC quit -> {reply}")
    return True


def kill_local(port: int) -> None:
    """IPC 不可用时的退路：杀掉监听该端口的进程。"""
    ps = (f"$p=(Get-NetTCPConnection -LocalPort {port} -State Listen -EA SilentlyContinue)"
          f".OwningProcess | Select-Object -Unique; "
          f"foreach($i in $p){{Stop-Process -Id $i -Force -EA SilentlyContinue}}; "
          f"if($p){{'killed ' + ($p -join ',')}}else{{'no listener'}}")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, text=True)
    print(f"  杀进程 -> {(r.stdout or r.stderr).strip()}")


def ssh_inline(host: str, cmd: str, timeout: float = 60) -> str:
    r = subprocess.run(["ssh", host, cmd], capture_output=True, text=True, timeout=timeout)
    return (r.stdout or r.stderr).strip()


def listen_port(cfg: dict) -> int:
    """1.1.0 起 listen 可能是 {local: {port}, network: ...}，旧格式才是 {port}。"""
    listen = cfg.get("listen") or {}
    local = listen.get("local") if isinstance(listen.get("local"), dict) else listen
    try:
        return int((local or {}).get("port") or 8090)
    except (TypeError, ValueError):
        return 8090


def restart_local(cfg: dict, start_cmd: str, timeout: float, dry: bool) -> bool:
    port = listen_port(cfg)
    if not port_listening(port):
        print(f"  端口 {port} 上没有面板，直接拉起")
    else:
        if dry:
            print(f"  [dry-run] IPC quit（{IPC}）→ 等 {port} 释放**且**旧进程退出")
        else:
            if not ipc_quit():
                kill_local(port)
            # 两个条件都要满足：端口释放是给人看的，进程消失才是启动器那道守卫看的。
            if not wait_free(port, 20):
                return False
            if not wait_gone(20):
                return False
    if dry:
        print(f"  [dry-run] 拉起：{start_cmd}")
        print(f"  [dry-run] 等 {port} 就绪（最多 {int(timeout)}s）")
        return True
    for attempt in (1, 2):
        print(f"  拉起（第 {attempt} 次）：{start_cmd}")
        r = subprocess.run(start_cmd, shell=True, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  启动器返回 {r.returncode}：{(r.stdout or r.stderr).strip()[:200]}")
        if wait_ready(port, min(timeout, 25)):
            return True
        # 没起来时先分清「启动器没干活」与「起来了又崩了」：前者进程表是空的，后者有进程。
        pids = panel_procs()
        if not pids:
            print("  进程表是空的 —— 启动器的守卫把这次拉起吞掉了（它要求旧进程已消失）")
            time.sleep(2)
            continue
        print(f"  进程在（{pids}）但端口没起 —— 像是启动即崩，去看 logs\\panel.err")
        break
    return False


def restart_remote(cfg: dict, node: str, timeout: float, dry: bool) -> bool:
    peer = next((p for p in (cfg.get("peers", {}).get("list") or []) if p.get("id") == node), None)
    if not peer:
        print(f"  !! peers.list 里没有 id={node}；对端要显式配 ssh 与 start_cmd，不猜")
        return False
    ssh_host = peer.get("ssh")
    start_cmd = peer.get("start_cmd")
    if not ssh_host or not start_cmd:
        print(f"  !! peer {node} 缺 ssh 或 start_cmd（拉起对端面板只能靠这两项，不猜）")
        return False
    port = listen_port(cfg)
    url = peer.get("url") or ""
    if dry:
        print(f"  [dry-run] ssh {ssh_host} 杀掉 {port} 的监听者")
        print(f"  [dry-run] ssh {ssh_host} 执行：{start_cmd}")
        print(f"  [dry-run] 等 {url or f'对端 {port}'} 就绪（最多 {int(timeout)}s）")
        return True
    print(f"  对端退出：ssh {ssh_host} -> {ssh_inline(ssh_host, REMOTE_KILL % {'port': port})}")
    print(f"  对端拉起：ssh {ssh_host} -> {ssh_inline(ssh_host, f'cmd /c {start_cmd}')}")
    # 对端的就绪判据只能从本端探它（peers.url），探不到就如实说没等到。
    if not url:
        print("  peer 没配 url，无法从本端判断是否起来 —— 请看对端日志")
        return False
    m = re.match(r"https?://([^/:]+):(\d+)", url)
    host, rport = (m.group(1), int(m.group(2))) if m else (None, port)
    t0 = time.time()
    while time.time() - t0 < timeout:
        if port_listening(rport, host):
            print(f"  对端面板已恢复：{url}（{int(time.time() - t0)}s）")
            return True
        time.sleep(1.5)
    print(f"  !! 对端面板在 {int(timeout)}s 内没起来：{url}")
    return False


def main() -> int:
    args = sys.argv[1:]
    dry = "--dry-run" in args
    node = None
    start_cmd = None
    timeout = 90.0
    for i, a in enumerate(args):
        if a == "--node" and i + 1 < len(args):
            node = args[i + 1]
        elif a.startswith("--node="):
            node = a.split("=", 1)[1]
        elif a == "--start" and i + 1 < len(args):
            start_cmd = args[i + 1]
        elif a.startswith("--start="):
            start_cmd = a.split("=", 1)[1]
        elif a == "--timeout" and i + 1 < len(args):
            timeout = float(args[i + 1])

    if not compile_check():
        return 1
    cfg = load_cfg()
    self_id = (cfg.get("node") or {}).get("id")
    print(f"本端 node.id = {self_id}，listen = {cfg.get('listen')}")

    if node and node != self_id:
        print(f"=== 重启对端 {node} ===")
        return 0 if restart_remote(cfg, node, timeout, dry) else 1

    print("=== 重启本端面板 ===")
    cmd = start_cmd or DEFAULT_START
    if not start_cmd and not os.path.exists(VBS):
        print(f"!! 找不到 {VBS}，也不知道本端怎么拉起 —— 用 --start 显式给一条命令")
        return 1
    if dry:
        print(f"本端拉起方式：{cmd}")
    return 0 if restart_local(cfg, cmd, timeout, dry) else 1


if __name__ == "__main__":
    sys.exit(main())
