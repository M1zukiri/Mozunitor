"""安全审计日志：append-only JSONL，字段白名单 + 敏感值遮蔽。"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

SECRET_KEYS = frozenset({
    "password", "passwd", "token", "secret", "credential", "cookie",
    "authorization", "mac", "preset_password", "key",
})


def mask(value) -> str:
    text = str(value)
    if len(text) <= 8:
        return "***"
    return text[:4] + "…" + text[-2:]


def scrub(mapping: dict) -> dict:
    out = {}
    for key, value in mapping.items():
        if any(secret in str(key).lower() for secret in SECRET_KEYS):
            out[key] = mask(value)
        elif isinstance(value, dict):
            out[key] = scrub(value)
        else:
            out[key] = value
    return out


class AuditLog:
    def __init__(self, path: Path, *, max_bytes: int = 4 * 1024 * 1024,
                 clock=time.time):
        self.path = Path(path)
        self.max_bytes = int(max_bytes)
        self._clock = clock
        self._lock = threading.Lock()

    def write(self, event: str, **fields) -> None:
        record = {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(self._clock())),
                  "event": event, **scrub(fields)}
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size > self.max_bytes:
                    self.path.replace(self.path.with_name(self.path.name + ".1"))
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
            except OSError:
                pass
