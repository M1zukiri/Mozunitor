"""短 TTL 转发 ticket：绑定服务/目标端口/来源 CIDR，可吊销、限时限次。"""
from __future__ import annotations

import ipaddress
import secrets
import threading
import time

TICKET_TTL_S = 60.0
TICKET_MAX_USES = 256


def new_ticket() -> str:
    return "mozt_" + secrets.token_hex(16)


def _parse_cidrs(cidrs) -> list:
    out = []
    for raw in cidrs or []:
        try:
            out.append(ipaddress.ip_network(str(raw).strip(), strict=False))
        except ValueError:
            continue
    return out


class TicketStore:
    """内存态 ticket 表：面板签发，转发代理核销；重启即失效。"""

    def __init__(self, ttl_s: float = TICKET_TTL_S, clock=time.time):
        self.ttl_s = float(ttl_s)
        self._clock = clock
        self._lock = threading.Lock()
        self._tickets: dict[str, dict] = {}

    def issue(self, service_id: str, target_port: int, client_ip: str = "",
              allowed_cidrs=(), uses: int = TICKET_MAX_USES) -> tuple[str, float]:
        ticket = new_ticket()
        expires_at = self._clock() + self.ttl_s
        with self._lock:
            self._prune_locked()
            self._tickets[ticket] = {
                "service": str(service_id), "target_port": int(target_port),
                "cidrs": _parse_cidrs(allowed_cidrs), "bind": str(client_ip or ""),
                "expires_at": expires_at, "uses": max(1, int(uses)),
                "issued_at": self._clock(),
            }
        return ticket, expires_at

    def redeem(self, ticket: str, client_ip: str) -> dict | None:
        ticket = str(ticket or "").strip()
        if not ticket:
            return None
        with self._lock:
            self._prune_locked()
            rec = self._tickets.get(ticket)
            if rec is None:
                return None
            if rec["expires_at"] < self._clock() or rec["uses"] <= 0:
                self._tickets.pop(ticket, None)
                return None
            if rec["cidrs"]:
                try:
                    addr = ipaddress.ip_address(str(client_ip).strip())
                except ValueError:
                    return None
                if not any(addr in net for net in rec["cidrs"]):
                    return None
            rec["uses"] -= 1
            return {"service": rec["service"], "target_port": rec["target_port"],
                    "expires_at": rec["expires_at"], "uses_left": rec["uses"]}

    def revoke(self, ticket: str) -> bool:
        with self._lock:
            return self._tickets.pop(str(ticket or ""), None) is not None

    def count(self) -> int:
        with self._lock:
            self._prune_locked()
            return len(self._tickets)

    def _prune_locked(self) -> None:
        now = self._clock()
        for key, rec in list(self._tickets.items()):
            if rec["expires_at"] < now or rec["uses"] <= 0:
                del self._tickets[key]
