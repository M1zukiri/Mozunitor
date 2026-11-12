"""登录/配对失败限流：窗口内失败计数 → 临时锁定。"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Entry:
    failures: int = 0
    window_start: float = 0.0
    locked_until: float = 0.0


class AttemptLimiter:
    def __init__(self, *, window_s: int = 300, max_failures: int = 5,
                 lockout_s: int = 300, clock=time.time):
        self.window_s = int(window_s)
        self.max_failures = int(max_failures)
        self.lockout_s = int(lockout_s)
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}

    def allow(self, key: str) -> tuple[bool, float]:
        """返回 (是否允许, 建议等待秒数)。"""
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            if not entry:
                return True, 0.0
            if entry.locked_until > now:
                return False, round(entry.locked_until - now, 1)
            if entry.window_start and now - entry.window_start > self.window_s:
                self._entries.pop(key, None)
            return True, 0.0

    def fail(self, key: str) -> int:
        """记一次失败；达到阈值开始锁定。返回当前窗口失败次数。"""
        now = self._clock()
        with self._lock:
            entry = self._entries.setdefault(key, _Entry(window_start=now))
            if not entry.window_start:
                entry.window_start = now
            entry.failures += 1
            if entry.failures >= self.max_failures:
                entry.locked_until = now + self.lockout_s
                entry.failures = 0
                entry.window_start = now
            return entry.failures

    def success(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()

    def locked(self, key: str) -> float:
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            return max(0.0, entry.locked_until - now) if entry else 0.0
