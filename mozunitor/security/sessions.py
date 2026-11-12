"""服务端会话：随机 session id + HMAC 签名 Cookie，可吊销、滑动过期。"""
from __future__ import annotations

import hmac
import threading
import time
from dataclasses import dataclass, replace

from .identity import b64u, random_token, unb64u

COOKIE_NAME = "mozunitor_session"


@dataclass(frozen=True, slots=True)
class Session:
    sid: str
    scope: str
    csrf: str
    device_id: str = ""
    listener: str = "local"
    ua: str = ""
    ip: str = ""
    created: float = 0.0
    last_seen: float = 0.0


class SessionStore:
    """进程内会话存储；Cookie 只带签名后的 sid，不携带级别等可变字段。"""

    def __init__(self, secret: bytes, *, ttl_s: int = 1800, max_age_s: int = 2592000,
                 clock=time.time):
        if not secret:
            raise ValueError("session secret 不能为空")
        self._secret = bytes(secret)
        self._ttl = int(ttl_s)
        self._max_age = int(max_age_s)
        self._clock = clock
        self._lock = threading.RLock()
        self._sessions: dict[str, Session] = {}

    # ---- cookie 编解码
    def cookie_value(self, sid: str) -> str:
        # HMAC(key, "session:"+sid) 的 base64url；与 sid 用点分隔
        import hashlib
        mac = hmac.new(self._secret, b"session:" + sid.encode("ascii"),
                       hashlib.sha256).digest()
        return f"{sid}.{b64u(mac)}"

    def parse_cookie(self, value: str) -> str | None:
        import hashlib
        if not value or "." not in value:
            return None
        sid, _, mac = value.partition(".")
        try:
            raw = unb64u(mac)
        except (ValueError, TypeError):
            return None
        expect = hmac.new(self._secret, b"session:" + sid.encode("ascii"),
                          hashlib.sha256).digest()
        return sid if hmac.compare_digest(raw, expect) else None

    # ---- 生命周期
    def create(self, scope: str, *, device_id: str = "", listener: str = "local",
               ua: str = "", ip: str = "") -> tuple[Session, str]:
        now = self._clock()
        session = Session(
            sid=random_token(32), scope=scope, csrf=random_token(32),
            device_id=device_id, listener=listener, ua=ua[:200], ip=ip,
            created=now, last_seen=now,
        )
        with self._lock:
            self._sessions[session.sid] = session
            self._prune_locked(now)
        return session, self.cookie_value(session.sid)

    def get(self, cookie_value: str) -> Session | None:
        sid = self.parse_cookie(cookie_value)
        if not sid:
            return None
        now = self._clock()
        with self._lock:
            session = self._sessions.get(sid)
            if not session:
                return None
            if self._expired(session, now):
                self._sessions.pop(sid, None)
                return None
            session = replace(session, last_seen=now)
            self._sessions[sid] = session
            return session

    def revoke(self, sid: str) -> bool:
        with self._lock:
            return self._sessions.pop(sid, None) is not None

    def revoke_device(self, device_id: str) -> int:
        with self._lock:
            doomed = [sid for sid, s in self._sessions.items()
                      if device_id and s.device_id == device_id]
            for sid in doomed:
                self._sessions.pop(sid, None)
            return len(doomed)

    def revoke_all(self) -> int:
        with self._lock:
            count = len(self._sessions)
            self._sessions.clear()
            return count

    def list(self) -> list[dict]:
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            return [{"sid": s.sid[-8:], "scope": s.scope, "device_id": s.device_id,
                     "listener": s.listener, "ip": s.ip, "ua": s.ua,
                     "created": s.created, "last_seen": s.last_seen}
                    for s in self._sessions.values()]

    def count(self) -> int:
        with self._lock:
            self._prune_locked(self._clock())
            return len(self._sessions)

    # ---- 内部
    def _expired(self, session: Session, now: float) -> bool:
        return (now - session.last_seen > self._ttl
                or now - session.created > self._max_age)

    def _prune_locked(self, now: float) -> None:
        doomed = [sid for sid, s in self._sessions.items()
                  if self._expired(s, now)]
        for sid in doomed:
            self._sessions.pop(sid, None)

    @property
    def ttl_s(self) -> int:
        return self._ttl
