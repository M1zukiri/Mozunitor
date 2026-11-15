"""Mozunitor 安全核心（1.1.0 重构）。

设计见 docs/SPEC.md：零隐式信任、三套身份、设备配对、TLS；本包只放与 HTTP 传输无关的安全原语。
"""

__version__ = "1.1.4"          # B 位：安全重构 + ops 与生产切换
