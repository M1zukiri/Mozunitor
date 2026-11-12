"""节点互联：配对记录、节点 token（只存哈希）、出站 token 与钉指纹的 HTTP 客户端。"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import secrets
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from .identity import harden_file

NODE_TOKEN_PREFIX = "mozn_"
TIMEOUT_S = 15.0


class NodeError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def new_token() -> str:
    return NODE_TOKEN_PREFIX + secrets.token_hex(24)


def hash_token(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def cert_fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest().upper()


class NodeStore:
    """对端节点记录 + 出站 token。记录里只存入站 token 的哈希，出站 token 单独落盘。"""

    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir)
        self.records_path = self.dir / "nodes.json"
        self.tokens_path = self.dir / "node-tokens.json"
        self._lock = threading.RLock()
        self._nodes: list[dict] = []
        self._outgoing: dict[str, str] = {}
        self._load()

    # ---------------------------------------------------------------- 持久化
    def _load(self) -> None:
        try:
            raw = json.loads(self.records_path.read_text(encoding="utf-8"))
            self._nodes = [n for n in raw.get("nodes", []) if isinstance(n, dict)]
        except (OSError, json.JSONDecodeError):
            self._nodes = []
        try:
            raw = json.loads(self.tokens_path.read_text(encoding="utf-8"))
            self._outgoing = {str(k): str(v) for k, v in raw.items()
                              if isinstance(k, str) and isinstance(v, str)}
        except (OSError, json.JSONDecodeError):
            self._outgoing = {}

    def _save(self) -> None:
        tmp = self.records_path.with_name(self.records_path.name + ".tmp")
        tmp.write_text(json.dumps({"version": 1, "nodes": self._nodes},
                                  ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.records_path)
        harden_file(self.records_path)
        tmp = self.tokens_path.with_name(self.tokens_path.name + ".tmp")
        tmp.write_text(json.dumps(self._outgoing, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        os.replace(tmp, self.tokens_path)
        harden_file(self.tokens_path)

    # ---------------------------------------------------------------- 记录
    def register(self, node_id: str, name: str, url: str, incoming_token: str,
                 fingerprint: str = "") -> dict:
        node_id = str(node_id or "").strip()
        if not node_id:
            raise NodeError(400, "缺少节点 id")
        with self._lock:
            self._nodes = [n for n in self._nodes if n.get("id") != node_id]
            record = {"id": node_id, "name": str(name or node_id)[:40],
                      "url": str(url or "").rstrip("/"),
                      "fingerprint": str(fingerprint or "")[:64],
                      "token_hash": hash_token(incoming_token),
                      "created": time.time(), "last_seen": 0.0}
            self._nodes.append(record)
            self._save()
            return self._public(record)

    def set_outgoing(self, node_id: str, token: str) -> None:
        with self._lock:
            self._outgoing[str(node_id)] = str(token)
            self._save()

    def outgoing(self, node_id: str) -> str:
        with self._lock:
            return self._outgoing.get(str(node_id), "")

    def verify(self, token: str) -> dict | None:
        token = str(token or "")
        if not token:
            return None
        digest = hash_token(token)
        with self._lock:
            for record in self._nodes:
                if hmac.compare_digest(str(record.get("token_hash") or ""), digest):
                    record["last_seen"] = time.time()
                    self._save()
                    return self._public(record)
        return None

    def revoke(self, node_id: str) -> bool:
        with self._lock:
            before = len(self._nodes)
            self._nodes = [n for n in self._nodes if n.get("id") != node_id]
            self._outgoing.pop(str(node_id), None)
            if len(self._nodes) == before:
                return False
            self._save()
            return True

    def get(self, node_id: str) -> dict | None:
        with self._lock:
            for record in self._nodes:
                if record.get("id") == node_id:
                    return self._public(record)
        return None

    def list(self) -> list[dict]:
        with self._lock:
            return [self._public(r) for r in self._nodes]

    @staticmethod
    def _public(record: dict) -> dict:
        return {k: v for k, v in record.items() if k != "token_hash"}


def request(url: str, method: str, path: str, *, body=None, token: str = "",
            expected_fingerprint: str = "", timeout: float = TIMEOUT_S
            ) -> tuple[int, dict, str]:
    """带钉指纹的 HTTP(S) 请求；返回 (状态码, JSON, 证书指纹)。"""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    base = parts.path.rstrip("/") + path if parts.path else path
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    fp = ""
    if scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True) or b""
        fp = cert_fingerprint(der)
        if expected_fingerprint and not hmac.compare_digest(
                fp, str(expected_fingerprint).upper()):
            conn.close()
            raise NodeError(400, "对端证书指纹与记录不一致，已拒绝连接")
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method.upper(), base, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {"error": f"对端返回非 JSON（HTTP {resp.status}）"}
        return resp.status, payload, fp
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
