"""声明式路由权限表：每条 API 路由必须显式声明 scope / listener / CSRF / Content-Type。

新增接口时先在这里登记；`security_selftest.py` 会断言"写接口没有漏声明"。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

SCOPE_RANK = {"read": 1, "write": 2, "admin": 3}
# 不需要会话、但要限流的公开流程端点（登录 / 初始化 / 配对 / 壳 token 交换）
PUBLIC_FLOWS = {
    "/api/setup/status": "any",
    "/api/setup/complete": "any",
    "/api/session/login": "any",
    "/api/session/launch": "local",
    "/api/pair/complete": "network",
    "/api/nodes/pair/complete": "network",
}


@dataclass(frozen=True, slots=True)
class Route:
    methods: tuple[str, ...]
    pattern: re.Pattern
    scope: str | None            # None 表示公开（仅限 PUBLIC_FLOWS）
    listener: str = "any"        # local / network / any
    csrf: bool = False
    content_type: str | None = None   # "json" 时必须 application/json
    audit: bool = False
    note: str = ""

    def matches(self, method: str, path: str) -> bool:
        return method.upper() in self.methods and bool(self.pattern.match(path))


def _r(methods: str | tuple[str, ...], pattern: str, scope: str | None, **kw) -> Route:
    methods = (methods,) if isinstance(methods, str) else tuple(methods)
    return Route(methods=tuple(m.upper() for m in methods),
                 pattern=re.compile(pattern), scope=scope, **kw)


ROUTES: tuple[Route, ...] = (
    # ---- 静态（数据全在 /api 下；静态只放页面与资源）
    _r("GET", r"^/$", None, note="面板静态页"),
    _r("GET", r"^/static/", None, note="静态资源"),
    # ---- 初始化/会话
    _r("GET", r"^/api/setup/status$", None, note="是否已完成初始化"),
    _r("POST", r"^/api/setup/complete$", None,
       content_type="json", audit=True, note="一次性 setup code + 设管理员口令"),
    _r("POST", r"^/api/session/login$", None, content_type="json", note="口令登录"),
    _r("POST", r"^/api/session/launch$", None, listener="local",
       content_type="json", note="壳 launch token 换会话"),
    _r("GET", r"^/api/session$", "read"),
    _r("POST", r"^/api/session/logout$", "read", csrf=True, content_type="json",
       audit=True),
    # ---- 监控数据（read）
    _r("GET", r"^/api/state$", "read"),
    _r("GET", r"^/api/node$", "read"),
    _r("GET", r"^/api/history$", "read"),
    _r("GET", r"^/api/op$", "read", note="视图/链接，动作走 POST"),
    _r("GET", r"^/api/settings$", "read", note="远端不下发命令字段"),
    _r("GET", r"^/api/service-settings$", "read"),
    # ---- 操作（write + CSRF + audit）
    _r("POST", r"^/api/restart$", "write", csrf=True, content_type="json", audit=True),
    _r("POST", r"^/api/stop$", "write", csrf=True, content_type="json", audit=True),
    _r("POST", r"^/api/op$", "write", csrf=True, content_type="json", audit=True,
       note="脚本/动作；具体 op 的 level 在服务内再判"),
    _r("POST", r"^/api/settings$", "write", csrf=True, content_type="json", audit=True,
       note="commands 段另要求 admin + local"),
    _r("POST", r"^/api/service-settings$", "write", csrf=True, content_type="json",
       audit=True),
    # ---- 安全面（admin；网络/口令改动仅本地）
    _r("GET", r"^/api/security$", "admin"),
    _r("POST", r"^/api/security/network$", "admin", listener="local",
       csrf=True, content_type="json", audit=True),
    _r("POST", r"^/api/security/password$", "admin", listener="local",
       csrf=True, content_type="json", audit=True),
    _r("GET", r"^/api/devices$", "admin"),
    _r("POST", r"^/api/devices/revoke$", "admin", csrf=True, content_type="json",
       audit=True),
    # ---- 配对
    _r("POST", r"^/api/pair/start$", "admin", csrf=True, content_type="json",
       audit=True, note="生成一次性配对码"),
    _r("POST", r"^/api/pair/complete$", None, listener="network",
       content_type="json", audit=True, note="设备凭配对码换取 token；限流"),
    # ---- 节点互联（P5）
    _r("GET", r"^/api/nodes$", "read", note="已配对节点与最近使用时间"),
    _r("POST", r"^/api/nodes/pair/start$", "admin", csrf=True, content_type="json",
       audit=True, note="生成节点配对码（交给对端管理员）"),
    _r("POST", r"^/api/nodes/pair$", "admin", listener="local", csrf=True,
       content_type="json", audit=True, note="主动配对一个对端（出站）"),
    _r("POST", r"^/api/nodes/pair/complete$", None, listener="network",
       content_type="json", audit=True, note="对端凭配对码换取节点 token；限流"),
    _r("POST", r"^/api/nodes/revoke$", "admin", listener="local", csrf=True,
       content_type="json", audit=True),
    # ---- 转发 ticket（短 TTL；代理面按 ticket 鉴权）
    _r("POST", r"^/api/forward/ticket$", "read", csrf=True,
       content_type="json", audit=True, note="签发短 TTL 转发 ticket"),
)

# 1.0.0 的旧通道：明确下线，返回 410 并指向新流程；不再接受任何凭据。
GONE_PATHS: frozenset[str] = frozenset({
    "/api/auth", "/api/credentials", "/api/token", "/api/login",
})


def find_route(method: str, path: str) -> Route | None:
    for route in ROUTES:
        if route.matches(method, path):
            return route
    return None


def path_known(path: str) -> bool:
    return any(route.pattern.match(path) for route in ROUTES)


def allowed_methods(path: str) -> tuple[str, ...]:
    methods: list[str] = []
    for route in ROUTES:
        if route.pattern.match(path):
            methods.extend(route.methods)
    return tuple(dict.fromkeys(methods))


def required_scope(route: Route) -> str:
    return route.scope or "read"


def settings_section_requires_admin(section: str) -> bool:
    """设置写入中只有 commands 段是 admin + local；其余显示/采样/tier 为 write。"""
    return section == "commands"


def check_route_table() -> list[str]:
    """静态自查：返回问题列表（空 = 通过）。供 security_selftest 使用。"""
    problems: list[str] = []
    for route in ROUTES:
        path = _sample_path(route.pattern.pattern)
        if route.scope is None and path not in PUBLIC_FLOWS and path != "/" \
                and not path.startswith("/static"):
            problems.append(f"{path}: 公开路由未登记在 PUBLIC_FLOWS")
        if route.scope is not None and route.scope not in SCOPE_RANK:
            problems.append(f"{path}: 未知 scope {route.scope!r}")
        expected = PUBLIC_FLOWS.get(path)
        if expected and expected != "any" and route.listener != expected:
            problems.append(f"{path}: listener 应为 {expected}，实际 {route.listener}")
        mutating = any(m in route.methods for m in ("POST", "PUT", "PATCH", "DELETE"))
        if mutating and route.scope is not None and not route.csrf:
            problems.append(f"{path}: 写接口没有声明 csrf")
        if mutating and route.scope is not None and route.content_type is None:
            problems.append(f"{path}: 写接口没有声明 content_type=json")
    return problems


def _sample_path(pattern: str) -> str:
    """把简单正则还原成一条示例路径，仅用于自查提示。"""
    text = pattern.lstrip("^")
    text = text.replace("\\$", "").replace("$", "")
    text = text.replace(r"\.", ".").replace(".*", "")
    return text.rstrip("/") or "/"
