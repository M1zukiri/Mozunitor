#!/usr/bin/env python3
"""安全核心自检（1.1.0 P1 检查点）。

用法::

    python tools\\security_selftest.py

只测 `mozunitor/security/` 原语与路由表不变量，不起 HTTP 服务、不碰真实配置。
全 PASS 返回 0。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mozunitor import tls as mtls  # noqa: E402
from mozunitor.net import listeners  # noqa: E402
from mozunitor.security import (audit, authz, csrf, identity, pairing,
                                passwords, ratelimit, sessions)  # noqa: E402
from mozunitor.security import nodes as peer_nodes  # noqa: E402
from mozunitor.security import tickets as ticket_mod  # noqa: E402
from mozunitor.security import state as security_state  # noqa: E402


def _hdr(**kw) -> dict:
    base = {"Host": "127.0.0.1:8097"}
    base.update(kw)
    return base


class SecurityStateTests(unittest.TestCase):
    def _state(self, tmp: str):
        st = security_state.SecurityState(Path(tmp), port=8097,
                                          net_host="127.0.0.1", lockout_s=30)
        st.launch_token = "LAUNCH-TEST"
        return st

    def test_no_implicit_loopback(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)
            r = st.authorize(method="GET", path="/api/state", headers=_hdr(),
                             client_ip="127.0.0.1", loopback=True)
            check("管线：回环未登录仍 401", r.status == 401, str(r.status))
            r = st.authorize(method="GET", path="/api/state",
                             headers=_hdr(**{"X-Mozunitor-Local-Token": st.local_token.load()}),
                             client_ip="127.0.0.1", loopback=True)
            check("管线：本地 token 放行（admin）", r.status == 200 and r.scope == "admin",
                  f"{r.status}/{r.scope}")
            r = st.authorize(method="GET", path="/api/security",
                             headers=_hdr(**{"X-Mozunitor-Local-Token": st.local_token.load()}),
                             client_ip="127.0.0.1", loopback=True)
            check("管线：本地 token 可进 admin 路由", r.status == 200)

    def test_route_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)
            r = st.authorize(method="POST", path="/api/auth", headers=_hdr(),
                             client_ip="127.0.0.1", loopback=True)
            check("管线：旧 /api/auth 返回 410", r.status == 410)
            r = st.authorize(method="GET", path="/api/nope", headers=_hdr(),
                             client_ip="127.0.0.1", loopback=True)
            check("管线：未知路径 404", r.status == 404)
            r = st.authorize(method="GET", path="/api/state",
                             headers=_hdr(Host="evil.example.com"),
                             client_ip="127.0.0.1", loopback=True)
            check("管线：Host 伪造拒绝", r.status == 403, str(r.status))
            r = st.authorize(method="POST", path="/api/setup/complete",
                             headers=_hdr(), client_ip="10.0.0.1", loopback=False)
            check("管线：网络入口未开时拒绝远端", r.status == 403, str(r.status))

    def test_setup_login_csrf(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)
            check("初始化：初始 needs_setup", st.needs_setup)
            try:
                st.complete_setup("short", client_ip="127.0.0.1")
                check("初始化：弱口令拒绝", False)
            except security_state.AuthError as exc:
                check("初始化：弱口令拒绝", exc.status == 400)
            sess, cookie = st.complete_setup("password123", client_ip="127.0.0.1")
            check("初始化：设置口令成功", not st.needs_setup)
            cookie_pair = cookie.split(";")[0]
            ck = cookie_pair.split("=", 1)
            h = _hdr(Cookie=f"{ck[0]}={ck[1]}")
            r = st.authorize(method="GET", path="/api/state", headers=h,
                             client_ip="127.0.0.1", loopback=True)
            check("会话：setup 后可直接读", r.status == 200 and r.via == "session")
            r = st.authorize(method="POST", path="/api/restart",
                             headers=_hdr(**{"Host": "127.0.0.1:8097",
                                             "Cookie": cookie_pair,
                                             "Content-Type": "application/json"}),
                             client_ip="127.0.0.1", loopback=True)
            check("CSRF：缺 token 的写请求拒绝", r.status == 403, f"{r.status}/{r.error}")
            r = st.authorize(method="POST", path="/api/restart",
                             headers=_hdr(**{"Cookie": cookie_pair,
                                             "Content-Type": "application/json",
                                             "X-Mozunitor-CSRF": sess.csrf,
                                             "Origin": "http://127.0.0.1:8097"}),
                             client_ip="127.0.0.1", loopback=True)
            check("CSRF：带 token 的写请求放行", r.status == 200, f"{r.status}/{r.error}")
            r = st.authorize(method="POST", path="/api/restart",
                             headers=_hdr(**{"Cookie": cookie_pair,
                                             "Content-Type": "application/json",
                                             "X-Mozunitor-CSRF": sess.csrf,
                                             "Origin": "http://evil.example"}),
                             client_ip="127.0.0.1", loopback=True)
            check("CSRF：跨源 Origin 拒绝", r.status == 403)
            r = st.authorize(method="POST", path="/api/restart",
                             headers=_hdr(**{"Cookie": cookie_pair,
                                             "Content-Type": "text/plain",
                                             "X-Mozunitor-CSRF": sess.csrf}),
                             client_ip="127.0.0.1", loopback=True)
            check("CSRF：非 JSON Content-Type 拒绝", r.status == 415, str(r.status))

    def test_login_rate_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)
            st.complete_setup("password123", client_ip="127.0.0.1")
            for _ in range(5):
                try:
                    st.login("wrong", client_ip="10.0.0.9")
                except security_state.AuthError:
                    pass
            try:
                st.login("wrong", client_ip="10.0.0.9")
                check("登录：失败 5 次后限流 429", False)
            except security_state.AuthError as exc:
                check("登录：失败 5 次后限流 429", exc.status == 429, str(exc.status))
            sess, _ = st.login("password123", client_ip="10.0.0.8")
            check("登录：正确口令签发 admin 会话", sess.scope == "admin")

    def test_change_password_revokes(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)
            sess, cookie = st.complete_setup("password123",
                                             client_ip="127.0.0.1")
            pair = cookie.split(";")[0]
            st.change_password("password123", "newpassword123", client_ip="127.0.0.1")
            r = st.authorize(method="GET", path="/api/state",
                             headers=_hdr(Cookie=pair),
                             client_ip="127.0.0.1", loopback=True)
            check("改密：旧会话全部失效", r.status == 401, str(r.status))
            sess2, _ = st.login("newpassword123", client_ip="127.0.0.1")
            check("改密：新口令可登录", sess2.scope == "admin")

FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    enc = sys.stdout.encoding or "utf-8"
    line = f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  {detail}" if detail else "")
    print(line.encode(enc, "replace").decode(enc, "replace"))
    if not cond:
        FAILS.append(name)
    return bool(cond)


class PasswordTests(unittest.TestCase):
    def test_roundtrip_and_reject(self):
        rec = passwords.hash_password("correct horse battery staple")
        check("口令：正确口令通过", passwords.verify_password("correct horse battery staple", rec))
        check("口令：错误口令拒绝", not passwords.verify_password("wrong", rec))
        check("口令：记录不含明文", "correct horse" not in json.dumps(rec))
        bad = dict(rec, hash=rec["hash"][:-2] + "AA")
        check("口令：篡改哈希拒绝", not passwords.verify_password("correct horse battery staple", bad))
        check("口令：空口令拒绝", not passwords.verify_password("", rec))

    def test_needs_rehash(self):
        rec = passwords.hash_password("x")
        check("口令：当前参数不需重哈希", not passwords.needs_rehash(rec))
        check("口令：旧参数建议重哈希", passwords.needs_rehash(dict(rec, n=1024)))


class SessionTests(unittest.TestCase):
    def _store(self):
        now = [1000.0]
        store = sessions.SessionStore(b"k" * 32, ttl_s=60, max_age_s=3600,
                                      clock=lambda: now[0])
        return store, now

    def test_cookie_roundtrip_and_forgery(self):
        store, _ = self._store()
        sess, cookie = store.create("write", listener="local")
        got = store.get(cookie)
        check("会话：Cookie 可取回", got is not None and got.sid == sess.sid)
        mid = len(cookie) // 2
        forged = cookie[:mid] + ("A" if cookie[mid] != "A" else "B") + cookie[mid + 1:]
        check("会话：篡改 Cookie 拒绝", store.get(forged) is None)
        check("会话：乱码 Cookie 拒绝", store.get("not-a-cookie") is None)

    def test_expiry_and_max_age(self):
        store, now = self._store()
        _, cookie = store.create("read")
        now[0] += 61
        check("会话：TTL 过期拒绝", store.get(cookie) is None)
        store2, now2 = self._store()
        _, cookie2 = store2.create("read")
        now2[0] += 61
        # 每 30s 续期一次仍应超过 max_age 后被回收
        for _ in range(130):
            now2[0] += 30
            store2.get(cookie2)
        check("会话：超过 max_age 回收", store2.get(cookie2) is None)

    def test_revoke(self):
        store, _ = self._store()
        sess, cookie = store.create("write", device_id="dev-1")
        check("会话：吊销单条", store.revoke(sess.sid) and store.get(cookie) is None)
        store.create("write", device_id="dev-2")
        store.create("write", device_id="dev-2")
        check("会话：按设备吊销", store.revoke_device("dev-2") == 2 and store.count() == 0)


class AuthzTests(unittest.TestCase):
    def test_route_table_invariants(self):
        problems = authz.check_route_table()
        check("路由：表自身不自检失败", problems == [], "; ".join(problems))
        check("路由：未知路径不放行", authz.find_route("GET", "/api/nope") is None)
        for gone in ("/api/auth", "/api/credentials", "/api/token"):
            check(f"路由：旧通道 {gone} 已列入 GONE", gone in authz.GONE_PATHS)
            check(f"路由：旧通道 {gone} 不再有路由", authz.find_route("POST", gone) is None)

    def test_key_routes(self):
        cases = {
            ("GET", "/api/state"): ("read", "any"),
            ("POST", "/api/restart"): ("write", "any"),
            ("POST", "/api/op"): ("write", "any"),
            ("GET", "/api/security"): ("admin", "any"),
            ("POST", "/api/security/network"): ("admin", "local"),
            ("POST", "/api/setup/complete"): (None, "any"),
            ("POST", "/api/session/login"): (None, "any"),
            ("POST", "/api/pair/complete"): (None, "network"),
        }
        for (method, path), (scope, listener) in cases.items():
            route = authz.find_route(method, path)
            ok = route is not None and route.scope == scope and route.listener == listener
            check(f"路由：{method} {path} → {scope}/{listener}", ok,
                  f"实际 {route.scope if route else None}/{route.listener if route else None}")

    def test_mutations_declare_csrf_and_json(self):
        for route in authz.ROUTES:
            path = authz._sample_path(route.pattern.pattern)
            mutating = any(m in route.methods for m in ("POST", "PUT", "PATCH", "DELETE"))
            if not mutating or route.scope is None:
                continue
            if route.content_type != "json":
                check(f"路由：{path} 写接口声明 JSON", False, str(route.content_type))
            if not route.csrf:
                check(f"路由：{path} 写接口声明 CSRF", False)
        check("路由：全部写接口都有 CSRF + JSON（无失败项）", True)

    def test_settings_section_policy(self):
        check("设置：commands 段要求 admin/local", authz.settings_section_requires_admin("commands"))
        check("设置：ui 段不升级为 admin", not authz.settings_section_requires_admin("ui"))


class CsrfTests(unittest.TestCase):
    def test_hosts_origins(self):
        allowed = {"127.0.0.1:8090", "localhost:8090"}
        check("来源：合法 Host", csrf.host_allowed("127.0.0.1:8090", allowed))
        check("来源：大小写 Host", csrf.host_allowed("LOCALHOST:8090", allowed))
        check("来源：伪造 Host 拒绝", not csrf.host_allowed("evil.example.com", allowed))
        check("来源：同源 Origin",
              csrf.origin_matches("http://127.0.0.1:8090", {"http://127.0.0.1:8090"}))
        check("来源：异源 Origin 拒绝",
              not csrf.origin_matches("http://evil.example", {"http://127.0.0.1:8090"}))
        check("来源：Sec-Fetch-Site cross-site 拒绝",
              not csrf.sec_fetch_site_ok("cross-site"))
        check("来源：Sec-Fetch-Site same-origin 放行",
              csrf.sec_fetch_site_ok("same-origin"))

    def test_mutation_matrix(self):
        ok, _ = csrf.mutation_allowed(
            method="POST", origin="http://127.0.0.1:8090", sec_fetch_site="same-origin",
            csrf_header="x", session_csrf="x",
            allowed_origins={"http://127.0.0.1:8090"}, cookie_auth=True)
        check("CSRF：同源 + token 通过", ok)
        ok, _ = csrf.mutation_allowed(
            method="POST", origin="http://evil.example", sec_fetch_site="cross-site",
            csrf_header="", session_csrf="x",
            allowed_origins={"http://127.0.0.1:8090"}, cookie_auth=True)
        check("CSRF：跨源页面拒绝", not ok)
        ok, _ = csrf.mutation_allowed(
            method="POST", origin="http://127.0.0.1:8090", sec_fetch_site="same-origin",
            csrf_header="", session_csrf="x",
            allowed_origins={"http://127.0.0.1:8090"}, cookie_auth=True)
        check("CSRF：缺 token 拒绝", not ok)
        ok, _ = csrf.mutation_allowed(
            method="POST", origin="", sec_fetch_site="",
            csrf_header="", session_csrf="",
            allowed_origins=set(), cookie_auth=False)
        check("CSRF：Header 认证的本地脚本豁免 CSRF", ok)


class RateLimitTests(unittest.TestCase):
    def test_lockout_and_recover(self):
        now = [0.0]
        limiter = ratelimit.AttemptLimiter(window_s=60, max_failures=3,
                                           lockout_s=30, clock=lambda: now[0])
        for _ in range(2):
            limiter.fail("ip")
        check("限流：阈值内允许", limiter.allow("ip")[0])
        limiter.fail("ip")
        allowed, wait = limiter.allow("ip")
        check("限流：达阈值锁定", not allowed and wait > 0)
        now[0] += 31
        check("限流：锁定到期恢复", limiter.allow("ip")[0])
        limiter.success("ip")
        check("限流：成功后清空", limiter.allow("ip")[0])


class AuditTests(unittest.TestCase):
    def test_masking(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "security.jsonl"
            log = audit.AuditLog(path)
            log.write("login", ip="1.2.3.4", password="S3cret-Pass",
                      token="abcdef1234567890", user="admin")
            text = path.read_text(encoding="utf-8")
            check("审计：写入事件", "login" in text and "1.2.3.4" in text)
            check("审计：口令不落明文", "S3cret-Pass" not in text)
            check("审计：token 不落明文", "abcdef1234567890" not in text)
            check("审计：字段可解析", json.loads(text.strip())["event"] == "login")


class IdentityTests(unittest.TestCase):
    def test_node_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            ident = identity.NodeIdentity(Path(tmp)).ensure()
            data = b"pair-me"
            sig = ident.sign(data)
            check("身份：签名可验证", ident.verify(sig, data, ident.public_pem()))
            check("身份：篡改数据拒绝", not ident.verify(sig, b"pair-you", ident.public_pem()))
            check("身份：指纹 64 hex", len(ident.fingerprint()) == 64)

    def test_local_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = identity.LocalToken(Path(tmp) / "local-token")
            token = store.ensure()
            check("本地 token：创建后可校验", store.verify(token))
            check("本地 token：错误 token 拒绝", not store.verify("nope"))
            rotated = store.rotate()
            check("本地 token：轮换后旧值失效", not store.verify(token))
            check("本地 token：轮换后新值可用", store.verify(rotated))


class NetConfigTests(unittest.TestCase):
    def test_cidr_parse_and_match(self):
        nets = listeners.parse_cidrs(["192.168.0.0/16", "127.0.0.0/8"])
        check("网络：CIDR 解析", len(nets) == 2)
        check("网络：白名单命中", listeners.ip_in_cidrs("127.0.0.1", nets))
        check("网络：白名单外拒绝", not listeners.ip_in_cidrs("10.1.2.3", nets))
        check("网络：非法 IP 拒绝", not listeners.ip_in_cidrs("not-an-ip", nets))
        try:
            listeners.parse_cidrs(["300.0.0.1/8"])
            check("网络：非法 CIDR 报错", False)
        except listeners.NetworkConfigError:
            check("网络：非法 CIDR 报错", True)

    def test_config_validation(self):
        cfg = listeners.NetworkConfig.from_dict(
            {"enabled": True, "mode": "lan", "bind": "192.168.1.10",
             "port": 8443, "allowed_cidrs": ["192.168.0.0/16"]})
        check("网络：配置解析", cfg.enabled and cfg.bind == "192.168.1.10")
        for bad in ({"mode": "public"}, {"bind": "no-ip"}, {"port": 80},
                    {"port": "x"}, {"allowed_cidrs": ["bad"]}):
            try:
                listeners.NetworkConfig.from_dict({"enabled": True, **bad})
                check("网络：拒绝非法配置 " + json.dumps(bad, ensure_ascii=False), False)
            except listeners.NetworkConfigError:
                check("网络：拒绝非法配置 " + json.dumps(bad, ensure_ascii=False), True)
        check("网络：默认关闭", not listeners.NetworkConfig().enabled)

    def test_category_guard(self):
        with mock.patch.dict(os.environ, {"MOZU_NET_CATEGORY": "Public"}):
            try:
                listeners.ensure_allowed(
                    listeners.NetworkConfig(enabled=True, mode="lan", bind="127.0.0.1"))
                check("网络：公用网络拒绝开启", False)
            except listeners.NetworkConfigError:
                check("网络：公用网络拒绝开启", True)
        with mock.patch.dict(os.environ, {"MOZU_NET_CATEGORY": "Private"}):
            got = listeners.ensure_allowed(
                listeners.NetworkConfig(enabled=True, mode="lan", bind="127.0.0.1"))
            check("网络：专用网络允许开启", got.enabled and got.bind == "127.0.0.1")
        with mock.patch.dict(os.environ, {"MOZU_NET_CATEGORY": "Private"}):
            try:
                listeners.ensure_allowed(
                    listeners.NetworkConfig(enabled=True, mode="tailnet", bind="192.168.1.5"))
                check("网络：tailnet 只接受 100.64/10", False)
            except listeners.NetworkConfigError:
                check("网络：tailnet 只接受 100.64/10", True)


class TlsTests(unittest.TestCase):
    def test_cert_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx, fp, cert_path = mtls.ensure(Path(tmp), ["mozu.test"],
                                             ["127.0.0.1", "192.168.1.10"])
            check("TLS：生成 SSLContext", ctx is not None)
            check("TLS：指纹 64 hex",
                  len(fp) == 64 and all(c in "0123456789ABCDEF" for c in fp))
            check("TLS：证书文件存在", Path(cert_path).is_file())
            cert = mtls.load(Path(cert_path), Path(tmp) / "tls" / "key.pem")
            check("TLS：SAN 覆盖绑定地址", mtls._covers(cert, ["mozu.test"], ["192.168.1.10"]))
            _, fp2, _ = mtls.ensure(Path(tmp), ["mozu.test"], ["127.0.0.1"])
            check("TLS：未改绑定复用证书", fp2 == fp)
            _, fp3, _ = mtls.ensure(Path(tmp), ["mozu.test"], ["127.0.0.1"], rotate=True)
            check("TLS：轮换后指纹变化", fp3 != fp)
            check("TLS：指纹可格式化", mtls.format_fingerprint(fp).count(":") == 31)


class NetworkStateTests(unittest.TestCase):
    def _state(self, tmp, network=None):
        st = security_state.SecurityState(
            Path(tmp), port=8097, net_port=8443, network=network, lockout_s=30)
        st.launch_token = "LAUNCH-TEST"
        return st

    def test_network_source_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            net = listeners.NetworkConfig(
                enabled=True, mode="lan", bind="127.0.0.1", port=8443,
                allowed_cidrs=("127.0.0.0/8",))
            st = self._state(tmp, net)
            hdr = {"Host": "127.0.0.1:8443"}
            r = st.authorize(method="GET", path="/api/state", headers=hdr,
                             client_ip="127.0.0.1", loopback=False)
            check("网络：白名单来源未登录 401", r.status == 401, str(r.status))
            r = st.authorize(method="GET", path="/api/state", headers=hdr,
                             client_ip="10.1.2.3", loopback=False)
            check("网络：白名单外 403", r.status == 403, str(r.status))
            r = st.authorize(method="GET", path="/api/setup/status", headers=hdr,
                             client_ip="127.0.0.1", loopback=False)
            check("网络：初始化状态对网络入口可读（无桌面机器只能远端初始化）",
                  r.status == 200, str(r.status))
            check("网络：Host 允许绑定地址", "127.0.0.1:8443" in st.allowed_hosts(False))
            check("网络：Origin 用 https",
                  "https://127.0.0.1:8443" in st.allowed_origins(False))
            st.set_network(listeners.NetworkConfig(
                enabled=True, mode="lan", bind="127.0.0.1", port=9443,
                allowed_cidrs=("127.0.0.0/8",)))
            check("网络：端口切换后 Host 跟随", "127.0.0.1:9443" in st.allowed_hosts(False))

    def test_disabled_network_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)
            r = st.authorize(method="GET", path="/api/state",
                             headers={"Host": "127.0.0.1:8443"},
                             client_ip="127.0.0.1", loopback=False)
            check("网络：未开启时网络入口 403", r.status == 403, str(r.status))


class PairingTests(unittest.TestCase):
    def test_pair_codes(self):
        now = [1000.0]
        codes = pairing.PairCodes(ttl_s=60, clock=lambda: now[0])
        code, expires = codes.issue()
        check("配对：码长度", len(code) == pairing.PAIR_CODE_LEN)
        check("配对：过期时间", expires == 1060.0)
        check("配对：错误码拒绝", not codes.redeem("WRONG000"))
        check("配对：正确码一次性", codes.redeem(code) and not codes.redeem(code))
        code2, _ = codes.issue()
        now[0] += 61
        check("配对：过期码拒绝", not codes.redeem(code2))

    def test_device_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = pairing.DeviceStore(Path(tmp) / "devices.json")
            device, token = store.register("手机", fingerprint="fp", scope="write")
            check("配对：token 前缀", token.startswith("mozd_"))
            check("配对：返回记录不含 token", "token" not in device)
            check("配对：token 可校验", (store.verify(token) or {}).get("id") == device["id"])
            check("配对：错误 token 拒绝", store.verify("mozd_deadbeef") is None)
            text = (Path(tmp) / "devices.json").read_text(encoding="utf-8")
            check("配对：文件不存明文 token", token not in text and "token_hash" in text)
            check("配对：吊销成功", store.revoke(device["id"]))
            check("配对：吊销后拒绝", store.verify(token) is None)
            check("配对：列表隐藏哈希", all("token_hash" not in d for d in store.list()))

    def test_state_pair_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = security_state.SecurityState(Path(tmp), port=8097, lockout_s=30)
            st.complete_setup("password123", client_ip="127.0.0.1")
            issued = st.start_pairing(client_ip="127.0.0.1")
            check("配对：生成配对码", bool(issued.get("code")))
            try:
                st.complete_pairing("WRONG", "手机", client_ip="10.0.0.5")
                check("配对：错误码拒绝", False)
            except security_state.AuthError as exc:
                check("配对：错误码拒绝", exc.status == 403)
            device, token = st.complete_pairing(issued["code"], "手机", "fp-1",
                                                client_ip="10.0.0.5")
            check("配对：完成并下发 token", token.startswith("mozd_"))
            hdr = _hdr(Authorization="Bearer " + token)
            r = st.authorize(method="GET", path="/api/state", headers=hdr,
                             client_ip="127.0.0.1", loopback=True)
            check("配对：设备 token 可读", r.status == 200 and r.via == "device",
                  f"{r.status}/{r.via}")
            r = st.authorize(method="GET", path="/api/security", headers=hdr,
                             client_ip="127.0.0.1", loopback=True)
            check("配对：设备 token 进不了 admin", r.status == 403, str(r.status))
            st.revoke_device(device["id"], client_ip="127.0.0.1")
            r = st.authorize(method="GET", path="/api/state", headers=hdr,
                             client_ip="127.0.0.1", loopback=True)
            check("配对：吊销后 401", r.status == 401, str(r.status))

    def test_pair_complete_rate_limited(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = security_state.SecurityState(Path(tmp), port=8097, lockout_s=30,
                                              login_max_failures=2, login_window_s=60)
            st.complete_setup("password123", client_ip="127.0.0.1")
            for _ in range(2):
                try:
                    st.complete_pairing("WRONG", "手机", client_ip="10.0.0.5")
                except security_state.AuthError:
                    pass
            try:
                st.complete_pairing("WRONG", "手机", client_ip="10.0.0.5")
                check("配对：失败限流 429", False)
            except security_state.AuthError as exc:
                check("配对：失败限流 429", exc.status == 429, str(exc.status))


class NodeTests(unittest.TestCase):
    def test_node_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = peer_nodes.NodeStore(Path(tmp))
            record = store.register("node-b", "B", "https://b:8443", "mozn_in")
            check("节点：注册记录", record["id"] == "node-b")
            check("节点：入站 token 可校验",
                  (store.verify("mozn_in") or {}).get("id") == "node-b")
            check("节点：错误 token 拒绝", store.verify("mozn_bad") is None)
            store.set_outgoing("node-b", "mozn_out")
            check("节点：出站 token 可取", store.outgoing("node-b") == "mozn_out")
            text = (Path(tmp) / "nodes.json").read_text(encoding="utf-8")
            check("节点：记录不存明文 token", "mozn_in" not in text)
            check("节点：吊销", store.revoke("node-b") and store.verify("mozn_in") is None)

    def test_state_node_pairing(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = security_state.SecurityState(Path(tmp), port=8097, lockout_s=30)
            st.complete_setup("password123", client_ip="127.0.0.1")
            issued = st.start_node_pairing(client_ip="127.0.0.1")
            check("节点：生成配对码", len(issued["code"]) == pairing.PAIR_CODE_LEN)
            record, outgoing = st.complete_node_pairing(
                issued["code"], "node-a", "A", "https://a:8443", "mozn_peer_token",
                client_ip="10.0.0.5")
            check("节点：完成配对并返回出站 token", outgoing.startswith("mozn_"))
            hdr = _hdr(Authorization="Bearer mozn_peer_token")
            r = st.authorize(method="GET", path="/api/state", headers=hdr,
                             client_ip="127.0.0.1", loopback=True)
            check("节点：节点 token 可读", r.status == 200 and r.via == "node",
                  f"{r.status}/{r.via}")
            r = st.authorize(method="GET", path="/api/security", headers=hdr,
                             client_ip="127.0.0.1", loopback=True)
            check("节点：节点 token 进不了 admin", r.status == 403, str(r.status))
            st.revoke_node("node-a", client_ip="127.0.0.1")
            r = st.authorize(method="GET", path="/api/state", headers=hdr,
                             client_ip="127.0.0.1", loopback=True)
            check("节点：吊销后 401", r.status == 401, str(r.status))


class TicketTests(unittest.TestCase):
    def test_ticket_lifecycle(self):
        now = [1000.0]
        store = ticket_mod.TicketStore(ttl_s=60, clock=lambda: now[0])
        ticket, expires = store.issue("panel", 8123, allowed_cidrs=["127.0.0.0/8"])
        check("ticket：签发", ticket.startswith("mozt_") and expires == 1060.0)
        rec = store.redeem(ticket, "127.0.0.1")
        check("ticket：核销", rec is not None and rec["target_port"] == 8123)
        check("ticket：白名单外拒绝", store.redeem(ticket, "10.1.2.3") is None)
        check("ticket：错误值拒绝", store.redeem("mozt_bad", "127.0.0.1") is None)
        now[0] += 61
        check("ticket：过期拒绝", store.redeem(ticket, "127.0.0.1") is None)
        once, _ = store.issue("panel", 8123, uses=1)
        check("ticket：次数用尽",
              store.redeem(once, "127.0.0.1") is not None
              and store.redeem(once, "127.0.0.1") is None)

    def test_state_forward_ticket(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = security_state.SecurityState(Path(tmp), port=8097, lockout_s=30)
            st.complete_setup("password123", client_ip="127.0.0.1")
            issued = st.issue_forward_ticket("panel", 8097, client_ip="127.0.0.1",
                                             allowed_cidrs=["127.0.0.0/8"])
            check("ticket：SecurityState 签发", issued["ticket"].startswith("mozt_"))
            rec = st.redeem_forward_ticket(issued["ticket"], "127.0.0.1")
            check("ticket：SecurityState 核销", rec is not None)


def main() -> int:
    print("=== security core selftest (1.1.5 check) ===")
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    check("整体：unittest 无失败", result.wasSuccessful(),
          f"failures={len(result.failures)} errors={len(result.errors)}")
    print(f"\n=== {'全部 PASS' if not FAILS else '存在失败'}（{len(FAILS)} 项失败）===")
    return 0 if not FAILS else 1


if __name__ == "__main__":
    raise SystemExit(main())
