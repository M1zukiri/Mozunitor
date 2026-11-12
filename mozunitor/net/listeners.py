"""网络入口：监听面配置、CIDR 白名单与网络类别判定。

本模块不依赖 `monitor_server`，便于单测；HTTP handler 由调用方传入。
"""
from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
import sys
import threading
from dataclasses import dataclass
from http.server import ThreadingHTTPServer

MODES = ("lan", "tailnet")
DEFAULT_PORT = 8443
DEFAULT_CIDRS = (
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "100.64.0.0/10",
)
CGNAT = ipaddress.ip_network("100.64.0.0/10")


class NetworkConfigError(ValueError):
    pass


def parse_cidrs(values) -> list[ipaddress._BaseNetwork]:
    """把字符串列表解析成网络对象；任何一项非法都报错（不给默认值兜底）。"""
    if values is None:
        return []
    if not isinstance(values, (list, tuple)):
        raise NetworkConfigError("allowed_cidrs 必须是字符串数组")
    out = []
    for idx, raw in enumerate(values):
        try:
            out.append(ipaddress.ip_network(str(raw).strip(), strict=False))
        except ValueError as exc:
            raise NetworkConfigError(f"allowed_cidrs[{idx}] 不是合法 CIDR：{raw}") from exc
    return out


def ip_in_cidrs(ip: str, networks) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return any(addr in net for net in networks)


@dataclass(frozen=True)
class NetworkConfig:
    enabled: bool = False
    mode: str = "lan"
    bind: str = ""
    port: int = DEFAULT_PORT
    allowed_cidrs: tuple[str, ...] = DEFAULT_CIDRS

    @classmethod
    def from_dict(cls, raw) -> "NetworkConfig":
        if not isinstance(raw, dict):
            raw = {}
        mode = str(raw.get("mode") or "lan").strip().lower()
        if mode not in MODES:
            raise NetworkConfigError(f"mode 只能是 {'/'.join(MODES)}")
        bind = str(raw.get("bind") or "").strip()
        if bind:
            try:
                ipaddress.ip_address(bind)
            except ValueError as exc:
                raise NetworkConfigError(f"bind 不是合法 IP：{bind}") from exc
        try:
            port = int(raw.get("port") or DEFAULT_PORT)
        except (TypeError, ValueError) as exc:
            raise NetworkConfigError("port 必须是整数") from exc
        if not 1024 <= port <= 65535:
            raise NetworkConfigError("port 必须在 1024-65535 之间")
        cidrs = raw.get("allowed_cidrs")
        parse_cidrs(cidrs) if cidrs is not None else None
        return cls(enabled=bool(raw.get("enabled")), mode=mode, bind=bind, port=port,
                   allowed_cidrs=tuple(cidrs) if cidrs else DEFAULT_CIDRS)

    @property
    def networks(self) -> list[ipaddress._BaseNetwork]:
        return parse_cidrs(self.allowed_cidrs)

    def snapshot(self) -> dict:
        return {"enabled": self.enabled, "mode": self.mode, "bind": self.bind,
                "port": self.port, "allowed_cidrs": list(self.allowed_cidrs)}


def _is_private_v4(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return isinstance(addr, ipaddress.IPv4Address) and addr.is_private


def lan_ip_candidates() -> list[str]:
    """本机非回环 IPv4，按「RFC1918 优先、CGNAT 兜底」排序。"""
    hosts: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in hosts and not ip.startswith("127.") and not ip.startswith("169.254."):
                hosts.append(ip)
    except OSError:
        pass
    rfc1918 = [ip for ip in hosts if _is_private_v4(ip) and not ip_in_cidrs(ip, [CGNAT])]
    cgnat = [ip for ip in hosts if ip_in_cidrs(ip, [CGNAT])]
    return rfc1918 + cgnat


def default_bind(mode: str) -> str:
    for ip in lan_ip_candidates():
        if mode == "tailnet":
            if ip_in_cidrs(ip, [CGNAT]):
                return ip
        elif not ip_in_cidrs(ip, [CGNAT]):
            return ip
    raise NetworkConfigError("找不到可用的网络接口地址，请手动指定 bind")


def network_category(ip: str) -> str:
    """Windows 网络类别：Public / Private / DomainAuthenticated / Unknown。"""
    override = os.environ.get("MOZU_NET_CATEGORY")
    if override:
        return override.strip() or "Unknown"
    if sys.platform != "win32":
        return "Unknown"
    script = (
        "$ErrorActionPreference='Stop';"
        f"$p=Get-NetIPAddress -IPAddress '{ip}';"
        "(Get-NetConnectionProfile -InterfaceAlias $p.InterfaceAlias).NetworkCategory"
    )
    creation = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=15, creationflags=creation)
    except (OSError, subprocess.TimeoutExpired):
        return "Unknown"
    text = (out.stdout or "").strip()
    for name in ("Public", "Private", "DomainAuthenticated"):
        if name.lower() in text.lower():
            return name
    return "Unknown"


def ensure_allowed(cfg: NetworkConfig) -> NetworkConfig:
    """开启网络入口前的检查；返回补全 bind 后的配置，失败抛 NetworkConfigError。"""
    if not cfg.enabled:
        return cfg
    bind = cfg.bind or default_bind(cfg.mode)
    if cfg.mode == "tailnet" and not ip_in_cidrs(bind, [CGNAT]):
        raise NetworkConfigError("tailnet 模式只能绑定 100.64.0.0/10 内的 Tailscale 地址")
    category = network_category(bind)
    if category == "Public":
        raise NetworkConfigError(f"当前网络 {bind} 属于「公用网络」，拒绝开启网络入口；"
                                 "请先把网络配置文件改为专用网络")
    if category == "Unknown":
        raise NetworkConfigError(f"无法判定网络 {bind} 的类别（Public/Private），拒绝开启；"
                                 "可用 MOZU_NET_CATEGORY 显式指定")
    return NetworkConfig(enabled=True, mode=cfg.mode, bind=bind, port=cfg.port,
                         allowed_cidrs=cfg.allowed_cidrs)


class NetworkServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    listener_kind = "network"

    def __init__(self, addr, handler, ssl_ctx):
        super().__init__(addr, handler)
        self.socket = ssl_ctx.wrap_socket(self.socket, server_side=True)


def serve_in_thread(server: NetworkServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True,
                              name="mozunitor-network")
    thread.start()
    return thread


def stop(server) -> None:
    if server is None:
        return
    try:
        server.shutdown()
    except Exception:  # noqa: BLE001
        pass
    try:
        server.server_close()
    except Exception:  # noqa: BLE001
        pass
