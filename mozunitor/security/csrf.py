"""来源校验：Host / Origin / Sec-Fetch-Site / CSRF token。

原则：
- Host 只接受该 listener 的合法地址集合（防 DNS rebinding）。
- 浏览器带 Origin 的请求必须同源；`Sec-Fetch-Site: cross-site` 一律拒绝。
- Cookie 认证的写请求必须带与会话绑定的 CSRF token；Header 认证（本地/设备 token）豁免。
"""
from __future__ import annotations

import hmac
from urllib.parse import urlsplit

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def host_allowed(host_header: str, allowed_hosts: set[str]) -> bool:
    """Host 头必须与允许集合完全一致（大小写不敏感；带端口比较）。"""
    host = (host_header or "").strip().lower()
    return bool(host) and host in {h.lower() for h in allowed_hosts}


def origin_matches(origin: str, allowed_origins: set[str]) -> bool:
    """同源判定：scheme+host+port 与允许集合之一完全一致。缺 Origin 视为非浏览器请求。"""
    origin = (origin or "").strip().lower()
    if not origin or origin == "null":
        return False
    parsed = urlsplit(origin)
    normalized = f"{parsed.scheme}://{parsed.netloc}".lower()
    return normalized in {o.lower() for o in allowed_origins}


def sec_fetch_site_ok(value: str) -> bool:
    """cross-site 直接拒绝；same-origin/none/缺省放行（缺省可能是非浏览器客户端）。"""
    value = (value or "").strip().lower()
    return value not in ("cross-site",)


def csrf_token_ok(supplied: str, expected: str) -> bool:
    return bool(supplied) and bool(expected) and hmac.compare_digest(
        str(supplied), str(expected))


def mutation_allowed(*, method: str, origin: str, sec_fetch_site: str,
                     csrf_header: str, session_csrf: str,
                     allowed_origins: set[str], cookie_auth: bool) -> tuple[bool, str]:
    """写请求的统一判定，返回 (ok, reason)。"""
    if method.upper() in SAFE_METHODS:
        return True, ""
    if not sec_fetch_site_ok(sec_fetch_site):
        return False, "cross-site 请求被拒绝"
    if origin and not origin_matches(origin, allowed_origins):
        return False, "Origin 不在允许列表"
    if cookie_auth and not csrf_token_ok(csrf_header, session_csrf):
        return False, "缺少或错误的 CSRF token"
    return True, ""
