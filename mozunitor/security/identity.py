"""节点身份、密钥与文件 ACL。

- 节点签名密钥：Ed25519（配对/审计用）。
- 本地管理 token：32 B 随机值，落 `.state/local-token`，ACL 收紧。
- launch token：壳启动时生成，仅内存。
"""
from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def random_token(nbytes: int = 32) -> str:
    return b64u(os.urandom(nbytes))


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def harden_file(path: Path) -> bool:
    """把文件 ACL 收紧到当前用户 + SYSTEM + Administrators，并去掉继承。

    Windows 上用 icacls（Python 的 chmod 在 Windows 上只改只读位，改不了 ACL）。
    非 Windows 或调用失败返回 False，由调用方决定是否降级并告警。
    """
    path = Path(path)
    try:
        if os.name != "nt":
            path.chmod(0o600)
            return True
        user = getpass.getuser()
        domain = os.environ.get("USERDOMAIN") or ""
        principal = f"{domain}\\{user}" if domain else user
        subprocess.run(
            ["icacls", str(path), "/inheritance:r",
             "/grant:r", f"{principal}:(F)", "SYSTEM:(F)", "Administrators:(F)"],
            capture_output=True, timeout=30, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return True
    except (OSError, subprocess.SubprocessError):
        return False


@dataclass(frozen=True, slots=True)
class LocalToken:
    path: Path

    def load(self) -> str:
        return self.path.read_text(encoding="utf-8").strip()

    def rotate(self) -> str:
        token = random_token()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(token + "\n", encoding="utf-8")
        harden_file(self.path)
        return token

    def ensure(self) -> str:
        try:
            token = self.load()
            if token:
                return token
        except OSError:
            pass
        return self.rotate()

    def verify(self, candidate: str) -> bool:
        try:
            return hmac.compare_digest(str(candidate or ""), self.load())
        except OSError:
            return False


class NodeIdentity:
    """节点身份：Ed25519 私钥 + 公钥指纹；首次运行生成并收紧 ACL。"""

    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir) / "identity"
        self.key_path = self.dir / "node-ed25519.pem"
        self.pub_path = self.dir / "node-ed25519.pub.pem"
        self._key: Ed25519PrivateKey | None = None

    def ensure(self) -> "NodeIdentity":
        self.dir.mkdir(parents=True, exist_ok=True)
        if not self.key_path.exists():
            key = Ed25519PrivateKey.generate()
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            self.key_path.write_bytes(pem)
            harden_file(self.key_path)
            self.pub_path.write_bytes(key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
        self._key = serialization.load_pem_private_key(
            self.key_path.read_bytes(), password=None)
        return self

    @property
    def key(self) -> Ed25519PrivateKey:
        if self._key is None:
            self.ensure()
        assert self._key is not None
        return self._key

    def public_pem(self) -> bytes:
        return self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def fingerprint(self) -> str:
        """公钥 DER 的 SHA256 指纹（十六进制，分组展示由 UI 负责）。"""
        return sha256_hex(self.key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    def sign(self, data: bytes) -> bytes:
        return self.key.sign(data)

    def verify(self, signature: bytes, data: bytes, public_pem: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            pub = serialization.load_pem_public_key(public_pem)
            assert isinstance(pub, Ed25519PublicKey)
            pub.verify(signature, data)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
