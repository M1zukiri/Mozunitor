"""设备配对：一次性配对码 + 设备 token（只存哈希）+ 吊销。"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .identity import harden_file

CODE_TTL_S = 300.0
PAIR_CODE_LEN = 8
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"     # 去掉易混淆的 I/O/0/1
DEVICE_SCOPES = ("read", "write")


class PairingError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def hash_token(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def new_token() -> str:
    return "mozd_" + secrets.token_hex(24)


def bearer_token(headers) -> str:
    """设备 token 走 Authorization: Bearer；也接受显式头方便脚本。"""
    supplied = headers.get("X-Mozunitor-Device-Token") or ""
    if supplied:
        return supplied.strip()
    auth = headers.get("Authorization") or ""
    scheme, _, value = auth.partition(" ")
    if scheme.lower() == "bearer":
        return value.strip()
    return ""


@dataclass
class PairCodes:
    """一次性配对码：内存态、TTL、用后即焚。"""
    ttl_s: float = CODE_TTL_S
    clock: object = time.time
    _codes: dict = field(default_factory=dict, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def issue(self) -> tuple[str, float]:
        with self._lock:
            self._prune()
            code = "".join(secrets.choice(ALPHABET) for _ in range(PAIR_CODE_LEN))
            expires = self.clock() + self.ttl_s
            self._codes[code] = expires
            return code, expires

    def redeem(self, code: str) -> bool:
        with self._lock:
            self._prune()
            code = str(code or "").strip().upper()
            for known in list(self._codes):
                if hmac.compare_digest(known, code):
                    expires = self._codes.pop(known)
                    return expires >= self.clock()
            return False

    def _prune(self) -> None:
        now = self.clock()
        for known, expires in list(self._codes.items()):
            if expires < now:
                del self._codes[known]

    def pending(self) -> int:
        with self._lock:
            self._prune()
            return len(self._codes)


class DeviceStore:
    """设备记录：token 只存 SHA256，文件 ACL 收紧。"""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._devices: list[dict] = []
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self._devices = [d for d in raw.get("devices", []) if isinstance(d, dict)]
        except (OSError, json.JSONDecodeError):
            self._devices = []

    def _save(self) -> None:
        payload = {"version": 1, "devices": self._devices}
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
        harden_file(self.path)

    def register(self, name: str, fingerprint: str = "",
                 scope: str = "write") -> tuple[dict, str]:
        scope = scope if scope in DEVICE_SCOPES else "read"
        token = new_token()
        record = {"id": "dev_" + secrets.token_hex(6),
                  "name": str(name or "设备")[:40],
                  "fingerprint": str(fingerprint or "")[:128], "scope": scope,
                  "token_hash": hash_token(token), "created": time.time(),
                  "last_seen": 0.0, "revoked": False}
        with self._lock:
            self._devices.append(record)
            self._save()
        return self._public(record), token

    @staticmethod
    def _public(record: dict) -> dict:
        return {k: v for k, v in record.items() if k != "token_hash"}

    def verify(self, token: str) -> dict | None:
        token = str(token or "")
        if not token:
            return None
        digest = hash_token(token)
        with self._lock:
            for record in self._devices:
                if record.get("revoked"):
                    continue
                if hmac.compare_digest(str(record.get("token_hash") or ""), digest):
                    record["last_seen"] = time.time()
                    self._save()
                    return self._public(record)
        return None

    def revoke(self, device_id: str) -> bool:
        with self._lock:
            for record in self._devices:
                if record.get("id") == device_id and not record.get("revoked"):
                    record["revoked"] = True
                    self._save()
                    return True
        return False

    def list(self) -> list[dict]:
        with self._lock:
            return [self._public(r) for r in self._devices]

    def count(self) -> int:
        with self._lock:
            return len([d for d in self._devices if not d.get("revoked")])


class PairingStore:
    """配对码 + 设备存储的组合入口（由 SecurityState 持有）。"""

    def __init__(self, state_dir: Path):
        self.codes = PairCodes()
        self.devices = DeviceStore(Path(state_dir) / "devices.json")


def snapshot(store: PairingStore) -> dict:
    return {"pending_codes": store.codes.pending(),
            "devices": store.devices.list()}
