"""自签 TLS 证书：ECDSA P-256，SAN 覆盖主机名与各接口 IP。

证书与私钥落在 `<state>/tls/`，ACL 收紧；指纹用于手机端钉证书。
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .security.identity import harden_file

CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"
VALID_DAYS = 397
CN = "Mozunitor"


class TlsError(RuntimeError):
    pass


def tls_dir(state_dir: Path) -> Path:
    return Path(state_dir) / "tls"


def _sans(hostnames, ips) -> list:
    names: list = []
    seen: set[str] = set()
    for host in hostnames or []:
        host = str(host).strip()
        if not host or host in seen:
            continue
        seen.add(host)
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    for ip in ips or []:
        ip = str(ip).strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError as exc:
            raise TlsError(f"不是合法的 IP：{ip}") from exc
    return names


def fingerprint(cert: x509.Certificate) -> str:
    """SHA256 指纹，大写十六进制（不含冒号），与手机端钉证书的展示格式一致。"""
    digest = cert.fingerprint(hashes.SHA256())
    return digest.hex().upper()


def format_fingerprint(fp: str) -> str:
    pairs = [fp[i:i + 2] for i in range(0, len(fp), 2)]
    return ":".join(pairs)


def create(state_dir: Path, hostnames, ips) -> tuple[Path, Path, str]:
    """生成新证书与私钥；返回 (cert, key, fingerprint)。"""
    state_dir = Path(state_dir)
    target = tls_dir(state_dir)
    target.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CN),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, CN)])
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.SubjectAlternativeName(_sans(hostnames, ips)), critical=False)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                              critical=False))
    cert = builder.sign(key, hashes.SHA256())
    cert_path = target / CERT_FILE
    key_path = target / KEY_FILE
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_bytes = key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption())
    key_path.write_bytes(key_bytes)
    harden_file(key_path)
    harden_file(cert_path)
    return cert_path, key_path, fingerprint(cert)


def load(cert_path: Path, key_path: Path) -> x509.Certificate:
    try:
        cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    except (OSError, ValueError) as exc:
        raise TlsError(f"证书读取失败：{exc}") from exc
    if not Path(key_path).is_file():
        raise TlsError("私钥文件不存在")
    return cert


def _covers(cert: x509.Certificate, hostnames, ips) -> bool:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    have_ips = {str(x) for x in san.get_values_for_type(x509.IPAddress)}
    have_names = {str(x) for x in san.get_values_for_type(x509.DNSName)}
    for host in hostnames or []:
        host = str(host).strip()
        if not host:
            continue
        try:
            if str(ipaddress.ip_address(host)) not in have_ips:
                return False
        except ValueError:
            if host not in have_names:
                return False
    for ip in ips or []:
        ip = str(ip).strip()
        if ip and ip not in have_ips:
            return False
    return True


def ensure(state_dir: Path, hostnames, ips, *, rotate: bool = False) -> tuple[ssl.SSLContext, str, Path]:
    """确保证书存在且覆盖当前绑定地址；返回 (SSLContext, 指纹, 证书路径)。"""
    state_dir = Path(state_dir)
    cert_path = tls_dir(state_dir) / CERT_FILE
    key_path = tls_dir(state_dir) / KEY_FILE
    if rotate or not (cert_path.is_file() and key_path.is_file()):
        cert_path, key_path, fp = create(state_dir, hostnames, ips)
    else:
        cert = load(cert_path, key_path)
        if not _covers(cert, hostnames, ips):
            cert_path, key_path, fp = create(state_dir, hostnames, ips)
        else:
            fp = fingerprint(cert)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx, fp, cert_path
