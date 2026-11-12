"""Mozunitor 安全核心（1.1.0 重构）。

设计见 docs/SPEC-security-hardening.md：零隐式信任、双平面、设备配对、TLS。
本包在 P1 阶段只提供与 HTTP 传输无关的安全原语；P2 起由 net/http 管线接入。
"""

__version__ = "1.0.6"          # C 位检查点：Android 客户端配对
