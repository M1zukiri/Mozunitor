"""安全状态：管理员口令、会话、launch token、本地 token、限流与审计。

这里是 P2 起 HTTP 管线唯一的安全事实来源；`monitor_server.Handler` 不再自己判回环。
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import authz, csrf, pairing
from . import nodes as peer_nodes
from .tickets import TicketStore
from .audit import AuditLog
from .identity import LocalToken, NodeIdentity, harden_file, random_token
from .passwords import hash_password, needs_rehash, verify_password
from .ratelimit import AttemptLimiter
from ..net.listeners import NetworkConfig, ip_in_cidrs
from .sessions import Session, SessionStore

ADMIN_USER = "admin"
MIN_PASSWORD_LEN = 8
COOKIE_NAME = "mozunitor_session"


class AuthError(Exception):
    def __init__(self, status: int, message: str, *, retry_after: float = 0.0):
        super().__init__(message)
        self.status = status
        self.message = message
        self.retry_after = retry_after


@dataclass(frozen=True, slots=True)
class AuthResult:
    status: int = 200
    error: str = ""
    scope: str = ""
    session: Session | None = None
    route: authz.Route | None = None
    via: str = ""
    device_id: str = ""
    node_id: str = ""
    retry_after: float = 0.0


@dataclass
class SecurityState:
    root: Path
    port: int = 8090
    net_host: str = "127.0.0.1"
    net_port: int = 8443
    network: NetworkConfig | None = None
    network_enabled: bool = False
    ttl_s: int = 1800
    max_age_s: int = 2592000
    login_window_s: int = 300
    login_max_failures: int = 5
    lockout_s: int = 300
    clock: object = time.time
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)
    _admin: dict | None = field(default=None, init=False)
    _setup_done: bool = field(default=False, init=False)
    launch_token: str = field(default="", init=False)
    identity: NodeIdentity = field(init=False)
    local_token: LocalToken = field(init=False)
    sessions: SessionStore = field(init=False)
    limiter: AttemptLimiter = field(init=False)
    audit: AuditLog = field(init=False)
    devices: pairing.DeviceStore = field(init=False)
    pair_codes: pairing.PairCodes = field(init=False)
    nodes: peer_nodes.NodeStore = field(init=False)
    tickets: TicketStore = field(init=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        env_state = os.environ.get("MOZU_STATE_DIR")
        self.state_dir = Path(env_state) if env_state else (self.root / ".state")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.identity = NodeIdentity(self.state_dir).ensure()
        self.local_token = LocalToken(self.state_dir / "local-token")
        self.local_token.ensure()
        self.devices = pairing.DeviceStore(self.state_dir / "devices.json")
        self.pair_codes = pairing.PairCodes()
        self.nodes = peer_nodes.NodeStore(self.state_dir)
        self.tickets = TicketStore()
        secret = self._load_secret(self.state_dir / "session-secret")
        self.sessions = SessionStore(secret, ttl_s=self.ttl_s, max_age_s=self.max_age_s,
                                     clock=self.clock)
        self.limiter = AttemptLimiter(window_s=self.login_window_s,
                                      max_failures=self.login_max_failures,
                                      lockout_s=self.lockout_s, clock=self.clock)
        self.audit = AuditLog(self.root / "logs" / "security.jsonl")
        self._load_state()
        self.launch_token = os.environ.get("MOZU_LAUNCH_TOKEN") or random_token(32)

    # ---------------------------------------------------------------- 持久化
    @property
    def state_file(self) -> Path:
        return self.state_dir / "security.json"

    def _load_secret(self, path: Path) -> bytes:
        try:
            raw = path.read_text(encoding="utf-8").strip()
            if raw:
                return bytes.fromhex(raw)
        except (OSError, ValueError):
            pass
        made = secrets.token_bytes(32)
        try:
            path.write_text(made.hex(), encoding="utf-8")
            harden_file(path)
        except OSError:
            pass
        return made

    def _load_state(self) -> None:
        try:
            got = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            got = {}
        admin = got.get("admin") if isinstance(got, dict) else None
        if isinstance(admin, dict) and isinstance(admin.get("password"), dict):
            self._admin = admin
            self._setup_done = bool(got.get("setup_done"))
        else:
            self._admin = None
            self._setup_done = False

    def _save_state(self) -> None:
        payload = {"version": 2, "setup_done": bool(self._setup_done),
                   "admin": self._admin,
                   "updated": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        tmp = self.state_file.with_name(self.state_file.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.state_file)
        harden_file(self.state_file)

    # ---------------------------------------------------------------- 状态
    @property
    def needs_setup(self) -> bool:
        return not self._setup_done or not self._admin

    @property
    def admin_user(self) -> str:
        return str((self._admin or {}).get("user") or ADMIN_USER)

    # ---------------------------------------------------------------- 来源
    def allowed_hosts(self, loopback: bool) -> set[str]:
        if loopback:
            port = int(self.port)
            return {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
        port = int(self.net_port)
        hosts = {f"localhost:{port}"}
        net = self.network or NetworkConfig()
        if net.bind:
            hosts.add(f"{net.bind}:{port}")
        for ip in self._local_ips():
            hosts.add(f"{ip}:{port}")
        return hosts

    def allowed_origins(self, loopback: bool) -> set[str]:
        scheme = "http" if loopback else "https"
        return {f"{scheme}://{h}" for h in self.allowed_hosts(loopback)}

    def _local_ips(self) -> set[str]:
        out: set[str] = set()
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                out.add(info[4][0])
        except OSError:
            pass
        return out

    # ---------------------------------------------------------------- 会话
    def cookie_header(self, session: Session, *, secure: bool = False) -> str:
        attrs = ["Path=/", "HttpOnly", "SameSite=Strict",
                 f"Max-Age={int(self.max_age_s)}"]
        if secure:
            attrs.append("Secure")
        return f"{COOKIE_NAME}={self.sessions.cookie_value(session.sid)}; " + "; ".join(attrs)

    @staticmethod
    def clear_cookie_header() -> str:
        return (f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")

    @staticmethod
    def _cookie_from_headers(headers) -> str:
        cookie = headers.get("Cookie") or ""
        for part in cookie.split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE_NAME:
                return value
        return ""

    # ---------------------------------------------------------------- 认证
    def authenticate(self, *, headers, client_ip: str, loopback: bool) -> AuthResult:
        # 本地 token 优先于 Cookie：本机脚本/CLI 用 admin 身份，浏览器不会带这个头。
        if loopback:
            supplied = headers.get("X-Mozunitor-Local-Token") or ""
            if supplied and self.local_token.verify(supplied):
                return AuthResult(scope="admin", via="local-token")
        supplied = pairing.bearer_token(headers)
        if supplied:
            device = self.devices.verify(supplied)
            if device is not None:
                return AuthResult(scope=str(device.get("scope") or "read"),
                                  via="device", device_id=str(device.get("id") or ""))
            node = self.nodes.verify(supplied)
            if node is not None:
                return AuthResult(scope="write", via="node",
                                  node_id=str(node.get("id") or ""))
        session = self.sessions.get(self._cookie_from_headers(headers))
        if session is not None:
            return AuthResult(scope=session.scope, session=session, via="session")
        return AuthResult(scope="", via="")

    def check_csrf(self, *, method: str, headers, session: Session | None,
                   via: str, loopback: bool) -> None:
        """Cookie 会话的写请求必须带 CSRF；同时校验 Origin / Sec-Fetch-Site。"""
        if method.upper() in csrf.SAFE_METHODS:
            return
        allowed = self.allowed_origins(loopback)
        ok, reason = csrf.mutation_allowed(
            method=method,
            origin=headers.get("Origin") or "",
            sec_fetch_site=headers.get("Sec-Fetch-Site") or "",
            csrf_header=headers.get("X-Mozunitor-CSRF") or "",
            session_csrf=session.csrf if session else "",
            allowed_origins=allowed,
            cookie_auth=via == "session",
        )
        if not ok:
            raise AuthError(403, reason)

    def authorize(self, *, method: str, path: str, headers, client_ip: str,
                  loopback: bool) -> AuthResult:
        if path in authz.GONE_PATHS:
            return AuthResult(status=410, error="该接口已下线，请使用 /api/session 与 /api/security")

        if not loopback:
            net = self.network or NetworkConfig()
            if not net.enabled:
                return AuthResult(status=403, error="网络入口未开启")
            if not ip_in_cidrs(client_ip, net.networks):
                return AuthResult(status=403, error="来源地址不在允许的网络范围内")

        route = authz.find_route(method, path)
        if route is None:
            if authz.path_known(path):
                return AuthResult(status=405, error="方法不允许")
            return AuthResult(status=404, error="not found")

        if route.listener == "local" and not loopback:
            return AuthResult(status=403, error="该接口只允许本机访问")
        if route.listener == "network" and loopback:
            return AuthResult(status=403, error="该接口只允许网络入口访问")

        host = headers.get("Host") or ""
        if not csrf.host_allowed(host, self.allowed_hosts(loopback)):
            return AuthResult(status=403, error="Host 不在允许列表")

        auth = self.authenticate(headers=headers, client_ip=client_ip, loopback=loopback)
        if route.scope is not None and not auth.scope:
            return AuthResult(status=401, error="需要登录", route=route,
                              retry_after=0)
        if route.scope is not None:
            need = authz.SCOPE_RANK.get(route.scope, 3)
            have = authz.SCOPE_RANK.get(auth.scope, 0)
            if have < need:
                return AuthResult(status=403, error="权限不足", scope=auth.scope,
                                  route=route, via=auth.via)

        if route.content_type == "json" and method.upper() not in csrf.SAFE_METHODS:
            ctype = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype != "application/json":
                return AuthResult(status=415, error="Content-Type 必须是 application/json",
                                  route=route, scope=auth.scope, via=auth.via)

        try:
            self.check_csrf(method=method, headers=headers, session=auth.session,
                            via=auth.via, loopback=loopback)
        except AuthError as exc:
            return AuthResult(status=exc.status, error=exc.message, route=route,
                              scope=auth.scope, via=auth.via)

        return AuthResult(scope=auth.scope, session=auth.session, route=route,
                          via=auth.via)

    # ---------------------------------------------------------------- 登录/初始化
    def _rate_key(self, client_ip: str) -> str:
        return f"login:{client_ip}"

    def login(self, password: str, *, client_ip: str, ua: str = "",
              loopback: bool = False) -> tuple[Session, str]:
        if self.needs_setup:
            raise AuthError(409, "尚未完成初始化")
        key = self._rate_key(client_ip)
        allowed, wait = self.limiter.allow(key)
        if not allowed:
            raise AuthError(429, "尝试过于频繁，请稍后再试", retry_after=wait)
        record = (self._admin or {}).get("password") or {}
        if not verify_password(password, record):
            self.limiter.fail(key)
            self.audit.write("login_failed", ip=client_ip, ua=ua)
            raise AuthError(401, "口令错误")
        self.limiter.success(key)
        if needs_rehash(record):
            self._admin["password"] = hash_password(password)
            self._save_state()
        session, _ = self.sessions.create(
            "admin", listener="local" if loopback else "network", ua=ua, ip=client_ip)
        self.audit.write("login_ok", ip=client_ip, ua=ua, sid=session.sid[-8:])
        return session, self.cookie_header(session, secure=not loopback)

    def complete_setup(self, password: str, *, client_ip: str,
                       ua: str = "", loopback: bool = True) -> tuple[Session, str]:
        """首次初始化：只设管理员口令，不再要求 setup code。

        初始化只允许发生一次（`needs_setup` 之后即拒绝），口令强度只做长度下限。
        """
        if not self.needs_setup:
            raise AuthError(409, "已经完成初始化")
        if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
            raise AuthError(400, f"口令至少 {MIN_PASSWORD_LEN} 位")
        self._admin = {"user": ADMIN_USER, "password": hash_password(password)}
        self._setup_done = True
        self._save_state()
        session, _ = self.sessions.create("admin", listener="local" if loopback else "network",
                                          ua=ua, ip=client_ip)
        self.audit.write("setup_ok", ip=client_ip)
        return session, self.cookie_header(session, secure=not loopback)

    def launch(self, token: str, *, client_ip: str, ua: str = "") -> tuple[Session, str]:
        """壳的 launch token 换会话；只允许回环，token 仅存在于本进程内存。"""
        if not token or not hmac.compare_digest(str(token), self.launch_token):
            self.audit.write("launch_failed", ip=client_ip)
            raise AuthError(403, "launch token 不正确")
        session, _ = self.sessions.create("admin", listener="local", ua=ua, ip=client_ip)
        self.audit.write("launch_ok", ip=client_ip, sid=session.sid[-8:])
        return session, self.cookie_header(session)

    def change_password(self, old: str, new: str, *, client_ip: str) -> None:
        record = (self._admin or {}).get("password") or {}
        if not verify_password(old, record):
            self.audit.write("password_change_failed", ip=client_ip)
            raise AuthError(401, "原口令错误")
        if not isinstance(new, str) or len(new) < MIN_PASSWORD_LEN:
            raise AuthError(400, f"口令至少 {MIN_PASSWORD_LEN} 位")
        self._admin["password"] = hash_password(new)
        self._save_state()
        self.sessions.revoke_all()
        self.audit.write("password_changed", ip=client_ip)

    def logout(self, session: Session | None) -> None:
        if session:
            self.sessions.revoke(session.sid)
            self.audit.write("logout", sid=session.sid[-8:])

    # ---------------------------------------------------------------- 展示
    def set_network(self, cfg: NetworkConfig) -> None:
        with self._lock:
            self.network = cfg
            self.net_port = int(cfg.port)

    # ---------------------------------------------------------------- 配对
    def start_pairing(self, *, client_ip: str) -> dict:
        code, expires = self.pair_codes.issue()
        self.audit.write("pair_started", ip=client_ip)
        return {"code": code, "expires_at": expires, "ttl_s": self.pair_codes.ttl_s}

    def complete_pairing(self, code: str, name: str, fingerprint: str = "",
                         *, client_ip: str, ua: str = "") -> tuple[dict, str]:
        key = f"pair:{client_ip}"
        allowed, wait = self.limiter.allow(key)
        if not allowed:
            raise AuthError(429, "配对尝试过于频繁，请稍后再试", retry_after=wait)
        if not self.pair_codes.redeem(code):
            self.limiter.fail(key)
            self.audit.write("pair_failed", ip=client_ip, ua=ua)
            raise AuthError(403, "配对码不正确或已过期")
        device, token = self.devices.register(name, fingerprint=fingerprint, scope="write")
        self.limiter.success(key)
        self.audit.write("pair_completed", ip=client_ip, ua=ua, device=device["id"])
        return device, token

    def revoke_device(self, device_id: str, *, client_ip: str) -> None:
        if not self.devices.revoke(device_id):
            raise AuthError(404, "设备不存在或已吊销")
        self.audit.write("device_revoked", ip=client_ip, device=device_id)

    def devices_snapshot(self) -> dict:
        return {"devices": self.devices.list()}

    # ---------------------------------------------------------------- 节点互联
    def start_node_pairing(self, *, client_ip: str) -> dict:
        code, expires = self.pair_codes.issue()
        self.audit.write("node_pair_started", ip=client_ip)
        return {"code": code, "expires_at": expires, "ttl_s": self.pair_codes.ttl_s}

    def complete_node_pairing(self, code: str, node_id: str, name: str, url: str,
                              incoming_token: str, *, client_ip: str,
                              fingerprint: str = "", ua: str = "") -> tuple[dict, str]:
        key = f"pair:{client_ip}"
        allowed, wait = self.limiter.allow(key)
        if not allowed:
            raise AuthError(429, "配对尝试过于频繁，请稍后再试", retry_after=wait)
        if not self.pair_codes.redeem(code):
            self.limiter.fail(key)
            self.audit.write("node_pair_failed", ip=client_ip, ua=ua)
            raise AuthError(403, "配对码不正确或已过期")
        if not incoming_token:
            raise AuthError(400, "缺少节点 token")
        record = self.nodes.register(node_id, name, url, incoming_token,
                                     fingerprint=fingerprint)
        self.limiter.success(key)
        outgoing = peer_nodes.new_token()
        self.nodes.set_outgoing(str(record["id"]), outgoing)
        self.audit.write("node_pair_completed", ip=client_ip, ua=ua, node=record["id"])
        return record, outgoing

    def pair_with_peer(self, url: str, code: str, *, node_id: str, node_name: str,
                       self_url: str, fingerprint: str = "",
                       own_fingerprint: str = "", client_ip: str = "") -> tuple[dict, str]:
        our_token = peer_nodes.new_token()
        body = {"code": code, "node": {"id": node_id, "name": node_name},
                "url": self_url, "token": our_token,
                "fingerprint": own_fingerprint}
        try:
            status, payload, fp = peer_nodes.request(
                url, "POST", "/api/nodes/pair/complete", body=body,
                expected_fingerprint=fingerprint)
        except peer_nodes.NodeError as exc:
            raise AuthError(exc.status, exc.message)
        except OSError as exc:
            raise AuthError(502, f"连接对端失败：{exc}")
        if status != 200 or not payload.get("ok"):
            raise AuthError(status if status in (400, 403, 429) else 502,
                            str(payload.get("error") or f"对端配对失败（HTTP {status}）"))
        remote = payload.get("node") or {}
        remote_id = str(remote.get("id") or "")
        if not remote_id:
            raise AuthError(502, "对端没有返回节点 id")
        if fingerprint and fp != str(fingerprint).upper():
            raise AuthError(400, "对端证书指纹与指定值不一致")
        token = str(payload.get("token") or "")
        if not token:
            raise AuthError(502, "对端没有返回节点 token")
        self.nodes.register(remote_id, str(remote.get("name") or remote_id), url,
                            token, fingerprint=fp)
        self.nodes.set_outgoing(remote_id, our_token)
        self.audit.write("node_paired", ip=client_ip, node=remote_id, url=url)
        return self.nodes.get(remote_id) or {}, token

    def revoke_node(self, node_id: str, *, client_ip: str) -> None:
        if not self.nodes.revoke(node_id):
            raise AuthError(404, "节点不存在")
        self.audit.write("node_revoked", ip=client_ip, node=node_id)

    def nodes_snapshot(self) -> dict:
        return {"nodes": self.nodes.list()}

    # ---------------------------------------------------------------- 转发 ticket
    def issue_forward_ticket(self, service_id: str, target_port: int, *,
                             client_ip: str = "", allowed_cidrs=()) -> dict:
        ticket, expires = self.tickets.issue(service_id, target_port,
                                             client_ip=client_ip,
                                             allowed_cidrs=allowed_cidrs)
        self.audit.write("forward_ticket", ip=client_ip, service=service_id,
                         port=int(target_port))
        return {"ticket": ticket, "expires_at": expires,
                "ttl_s": self.tickets.ttl_s, "service": service_id,
                "target_port": int(target_port)}

    def redeem_forward_ticket(self, ticket: str, client_ip: str) -> dict | None:
        return self.tickets.redeem(ticket, client_ip)

    def snapshot(self) -> dict:
        net = self.network or NetworkConfig()
        return {
            "setup_done": not self.needs_setup,
            "node": {"id": "", "name": ""},       # 由调用方填充
            "sessions": self.sessions.list(),
            "local_token_file": str(self.local_token.path),
            "identity_fingerprint": self.identity.fingerprint(),
            "network": net.snapshot(),
            "net_port": self.net_port,
            "devices": self.devices.list(),
            "nodes": self.nodes.list(),
        }
