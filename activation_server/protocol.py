"""Wire format shared by the activation server and its clients."""
from datetime import datetime, timedelta, timezone
import hashlib
from ipaddress import ip_address, ip_network
import re
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ACTIVATION_PATH = "/api/v1/activate"
# 区分未审批/删除后重注册（需客户端清除本地在线缓存）与普通已审批停发
APPROVAL_REQUIRED_DETAIL = "approval_required"
ISSUANCE_DISABLED_DETAIL = "issuance_disabled"
UID_PATTERN = r"[0-9a-f]{64}"
MAX_EXPIRY = 253402300799  # Last whole Unix second representable as a UTC datetime.
_CODE_PATTERN = re.compile(rf"PL1\.({UID_PATTERN})\.([1-9][0-9]{{0,11}})\.([0-9a-f]{{128}})")
_UTC_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


# Explicit private-use blocks keep public, link-local, and special-purpose addresses on HTTPS.
PRIVATE_LAN_NETWORKS = tuple(ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
_HTTP_IP_AUTHORITY = re.compile(r"(?:[0-9.]+|\[[0-9a-f:.]+\])(?::[0-9]+)?", re.IGNORECASE)


def is_private_lan_address(address):
    return any(address in network for network in PRIVATE_LAN_NETWORKS)


def activation_origin(value: str) -> str:
    try:
        if not isinstance(value, str) or "\\" in value or any(ch.isspace() or not ch.isprintable() for ch in value):
            raise ValueError
        url = urlsplit(value)
        if (url.scheme not in {"http", "https"} or not url.hostname or url.netloc.endswith(":") or url.port == 0
                or url.username is not None or url.path not in {"", "/"} or url.query or url.fragment):
            raise ValueError
    except ValueError:
        raise ValueError("Expected an HTTP or HTTPS origin without credentials or a path") from None
    if url.scheme == "http":
        error = "HTTPS is required for domains and non-private LAN IP addresses"
        try:
            address = ip_address(url.hostname)
        except ValueError:
            raise ValueError(error) from None
        if not _HTTP_IP_AUTHORITY.fullmatch(url.netloc) or not is_private_lan_address(address):
            raise ValueError(error)
    return f"{url.scheme}://{url.netloc}"


def utc_datetime(seconds: int) -> datetime:
    # Arithmetic avoids the platform C runtime's narrower timestamp range on Windows.
    return _UTC_EPOCH + timedelta(seconds=seconds)


def load_public_key(path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (ValueError, UnsupportedAlgorithm):
        key = None
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"Expected an Ed25519 PEM public key at {path}")
    return key


def public_key_fingerprint(key) -> str:
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def signing_message(uid: str, expiry: int, *, offline=False) -> bytes:
    prefix = "PLO1" if offline else "PL1"
    return f"{prefix}.{uid}.{expiry}".encode("ascii")


def verify_code(code: str, uid: str, public_key) -> int:
    match = _CODE_PATTERN.fullmatch(code) if isinstance(code, str) else None
    if not match:
        raise ValueError("Invalid online activation code format")
    signed_uid, seconds, signature = match.groups()
    expiry = int(seconds)
    if signed_uid != uid or expiry > MAX_EXPIRY:
        raise ValueError("Invalid online activation UID or expiry")
    try:
        public_key.verify(bytes.fromhex(signature), signing_message(signed_uid, expiry))
    except InvalidSignature:
        raise ValueError("Invalid online activation signature") from None
    return expiry
