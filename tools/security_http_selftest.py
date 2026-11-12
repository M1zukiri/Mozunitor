#!/usr/bin/env python3
"""P2 HTTP 管线回归：隔离实例 + 真实请求。

用法::

    python tools\\security_http_selftest.py

覆盖：回环也要登录、旧通道 410、初始化/登录/launch、CSRF、Origin、Host、
Content-Type、本地 token、登录限流、凭据不落明文。全 PASS 返回 0。
不起真实配置、不碰 8090、不写真实 .state。
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = 8123
BASE = f"http://127.0.0.1:{PORT}"
SETUP_CODE = "TESTSETUP"
LAUNCH = "TESTLAUNCH"
PASSWORD = "password123"
FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    enc = sys.stdout.encoding or "utf-8"
    line = f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  {detail}" if detail else "")
    print(line.encode(enc, "replace").decode(enc, "replace"))
    if not cond:
        FAILS.append(name)
    return bool(cond)


def build_config(path: Path) -> None:
    cfg = {
        "listen": {"host": "127.0.0.1", "port": PORT},
        "node": {"id": "http-selftest", "name": "HTTP-Selftest"},
        "peers": {"list": [], "discover": {"tailscale": False}},
        "access": {"tokens_file": ".state/access-tokens.json"},
        "forwards": {"bind": "127.0.0.1", "ports": []},
        "intervals": {"probe_local_ms": 5000, "sample_local_ms": 60000,
                      "sample_remote_ms": 60000, "peer_poll_ms": 60000,
                      "keepalive_ms": 60000},
        "ui": {}, "relay": {"enabled": False},
        "groups": [{"id": "local", "title": "本地"}],
        "services": [{"id": "panel", "name": "面板", "group": "local", "tier": "core",
                      "probe": {"kind": "tcp", "host": "127.0.0.1", "port": PORT},
                      "restart": {"kind": "none"}}],
    }
    path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.jar))

    def req(self, method: str, path: str, *, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        hdrs = dict(headers or {})
        if data is not None:
            hdrs.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(BASE + path, data=data, method=method, headers=hdrs)
        try:
            with self.opener.open(req, timeout=15) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()
        except Exception as exc:  # noqa: BLE001
            return -1, {}, repr(exc).encode()


def main() -> int:
    print("=== security http selftest (1.0.2 check) ===")
    tmp = Path(tempfile.mkdtemp(prefix="mozu-p2-"))
    cfg = tmp / "services.json"
    state = tmp / "state"
    build_config(cfg)
    env = dict(os.environ)
    env.update({
        "MOZU_CONFIG": str(cfg),
        "MOZU_STATE_DIR": str(state),
        "MOZU_SETUP_CODE": SETUP_CODE,
        "MOZU_LAUNCH_TOKEN": LAUNCH,
        "MOZU_ACTION_LOG": str(tmp / "actions.jsonl"),
        "PYTHONIOENCODING": "utf-8",
    })
    proc = subprocess.Popen([sys.executable, "-u", str(ROOT / "monitor_server.py")],
                            cwd=str(ROOT), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        up = False
        for _ in range(40):
            try:
                with urllib.request.urlopen(BASE + "/api/setup/status", timeout=1) as r:
                    if r.status == 200:
                        up = True
                        break
            except Exception:  # noqa: BLE001
                time.sleep(0.25)
        if not check("实例启动", up):
            return 1

        anon = Client()
        code, _, body = anon.req("GET", "/api/setup/status")
        payload = json.loads(body)
        check("初始化：needs_setup=true", code == 200 and payload.get("needs_setup") is True)
        code, _, _ = anon.req("GET", "/api/state")
        check("回归：回环未登录 401", code == 401, str(code))
        code, _, _ = anon.req("POST", "/api/auth", body={"user": "x"})
        check("回归：旧 /api/auth 410", code == 410, str(code))
        code, _, _ = anon.req("GET", "/api/credentials")
        check("回归：旧 /api/credentials 410", code == 410, str(code))

        code, _, body = anon.req("POST", "/api/setup/complete",
                                 body={"password": PASSWORD, "proof": "WRONG"})
        check("初始化：错误 setup code 403", code == 403, str(code))
        code, hdr, body = anon.req("POST", "/api/setup/complete",
                                   body={"password": PASSWORD, "proof": SETUP_CODE})
        d = json.loads(body)
        check("初始化：正确 setup code 200 + 会话", code == 200 and d.get("ok"), str(code))
        csrf = d.get("csrf") or ""
        check("会话：拿到 CSRF", bool(csrf))

        code, _, _ = anon.req("GET", "/api/state")
        check("回归：初始化后可读状态", code == 200, str(code))

        code, _, _ = anon.req("POST", "/api/settings",
                              body={"section": "ui", "values": {"mobile_hide_optional": True}})
        check("CSRF：无 token 写请求 403", code == 403, str(code))
        code, _, _ = anon.req("POST", "/api/settings",
                              body={"section": "ui", "values": {"mobile_hide_optional": True}},
                              headers={"X-Mozunitor-CSRF": csrf})
        check("CSRF：带 token 写请求 200", code == 200, str(code))
        code, _, _ = anon.req("POST", "/api/settings",
                              body={"section": "ui", "values": {"mobile_hide_optional": True}},
                              headers={"X-Mozunitor-CSRF": csrf,
                                       "Origin": "http://evil.example"})
        check("CSRF：跨源 Origin 403", code == 403, str(code))
        code, _, _ = anon.req("POST", "/api/settings",
                              body={"section": "ui", "values": {"mobile_hide_optional": True}},
                              headers={"X-Mozunitor-CSRF": csrf,
                                       "Content-Type": "text/plain"})
        check("CSRF：text/plain 415", code == 415, str(code))
        code, _, _ = anon.req("GET", "/api/state", headers={"Host": "evil.example"})
        check("Host：伪造 Host 403", code == 403, str(code))

        fresh = Client()
        code, _, body = fresh.req("POST", "/api/session/launch", body={"token": LAUNCH})
        d = json.loads(body)
        check("launch：launch token 换会话", code == 200 and d.get("scope") == "write", str(code))

        local_tok = (state / "local-token").read_text(encoding="utf-8").strip()
        local_client = Client()
        code, _, _ = local_client.req("GET", "/api/security",
                                      headers={"X-Mozunitor-Local-Token": local_tok})
        check("本地 token：可进 admin 路由", code == 200, str(code))

        good = Client()
        code, _, body = good.req("POST", "/api/session/login", body={"password": PASSWORD})
        check("登录：正确口令 200", code == 200, str(code))

        bad = Client()
        for _ in range(5):
            bad.req("POST", "/api/session/login", body={"password": "wrong"})
        code, _, _ = bad.req("POST", "/api/session/login", body={"password": "wrong"})
        check("限流：失败 5 次后 429", code == 429, str(code))

        sec = state / "security.json"
        text = sec.read_text(encoding="utf-8") if sec.exists() else ""
        check("凭据：security.json 不含明文口令", PASSWORD not in text)
        check("凭据：不存在旧 credentials.json", not (state / "credentials.json").exists())
        check("凭据：不存在旧 access-tokens.json", not (state / "access-tokens.json").exists())
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    print(f"\n=== {'全部 PASS' if not FAILS else '存在失败'}（{len(FAILS)} 项失败）===")
    return 0 if not FAILS else 1


if __name__ == "__main__":
    raise SystemExit(main())
