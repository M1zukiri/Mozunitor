"""安全原语：口令派生与校验（scrypt，标准库）。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

N = 2 ** 14
R = 8
P = 1
SALT_LEN = 16
KEY_LEN = 32
ALG = "scrypt"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str, *, salt: bytes | None = None) -> dict:
    """返回可落盘的派生记录；明文口令不得进入返回值。"""
    if not isinstance(password, str) or not password:
        raise ValueError("口令不能为空")
    salt = salt or os.urandom(SALT_LEN)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=N, r=R, p=P,
                            dklen=KEY_LEN)
    return {"alg": ALG, "n": N, "r": R, "p": P, "salt": _b64(salt), "hash": _b64(digest)}


def verify_password(password: str, record: dict) -> bool:
    """常量时间校验；record 缺字段或算法不符一律 False。"""
    if not isinstance(password, str) or not isinstance(record, dict):
        return False
    if record.get("alg") != ALG:
        return False
    try:
        salt = _unb64(str(record["salt"]))
        expect = _unb64(str(record["hash"]))
        n, r, p = int(record["n"]), int(record["r"]), int(record["p"])
    except (KeyError, ValueError, TypeError):
        return False
    if not (n >= 2 ** 14 and r >= 8 and p >= 1):
        return False
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                            dklen=len(expect))
    return hmac.compare_digest(digest, expect)


def needs_rehash(record: dict) -> bool:
    return (not isinstance(record, dict) or record.get("alg") != ALG
            or int(record.get("n") or 0) < N or int(record.get("r") or 0) < R
            or int(record.get("p") or 0) < P)
