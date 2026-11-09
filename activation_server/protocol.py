"""Wire format shared by the activation server and its clients."""
from datetime import datetime, timedelta, timezone
import re

from cryptography.exceptions import InvalidSignature


ACTIVATION_PATH = "/api/v1/activate"
UID_PATTERN = r"[0-9a-f]{64}"
MAX_EXPIRY = 253402300799  # Last whole Unix second representable as a UTC datetime.
_CODE_PATTERN = re.compile(rf"PL1\.({UID_PATTERN})\.([1-9][0-9]{{0,11}})\.([0-9a-f]{{128}})")
_UTC_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def utc_datetime(seconds: int) -> datetime:
    # Arithmetic avoids the platform C runtime's narrower timestamp range on Windows.
    return _UTC_EPOCH + timedelta(seconds=seconds)


def signing_message(uid: str, expiry: int) -> bytes:
    return f"PL1.{uid}.{expiry}".encode("ascii")


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
