"""Publish complete Windows releases with a signed, versioned manifest."""
import base64
import hashlib
import json
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization


UPDATES_PATH = "/api/v1/updates/windows-x64"
SIGNING_PREFIX = b"PerfLensUpdateV1\0"
VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
MANIFEST_FILENAME = "update.json"


def artifact_names(version):
    return {"installer": f"PerfLens-Setup-{version}-x64.exe", "unpacked": f"PerfLens-Unpacked-{version}-win-x64.zip"}


def latest_version(directory):
    if not directory.is_dir():
        return None
    versions = (entry.name for entry in directory.iterdir()
                if VERSION_PATTERN.fullmatch(entry.name) and (entry / MANIFEST_FILENAME).is_file())
    return max(versions, key=lambda version: tuple(map(int, version.split("."))), default=None)


def publish_update(data_dir, release_dir, signing_key):
    record = json.loads((release_dir / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(record, dict):
        raise ValueError("Invalid packaging manifest")
    version = record.get("version")
    if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Updates require a stable X.Y.Z version")
    origin = record.get("activation_server")
    if not isinstance(origin, str) or any(ch.isspace() or not ch.isprintable() for ch in origin) or "\\" in origin:
        raise ValueError("Package must specify an HTTP(S) activation server origin")
    url = urlsplit(origin)
    if (url.scheme not in {"http", "https"} or not url.hostname or url.username is not None or url.port == 0
            or url.netloc.endswith(":") or url.path or url.query or url.fragment):
        raise ValueError("Package must specify an HTTP(S) activation server origin")
    public_key = signing_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if record.get("activation_public_key_sha256") != hashlib.sha256(public_key).hexdigest():
        raise ValueError("Package activation public key does not match this server")
    entries = record.get("artifacts")
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        raise ValueError("Invalid artifact list in packaging manifest")
    names = artifact_names(version)
    artifacts = {}
    for kind, name in names.items():
        matches = [entry for entry in entries if entry.get("file") == name]
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one {name} in packaging manifest")
        size, digest = matches[0].get("bytes"), matches[0].get("sha256")
        if type(size) is not int or not 0 < size < 2**53 or not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
            raise ValueError(f"Invalid size or SHA-256 for {name}")
        artifacts[kind] = {"bytes": size, "sha256": digest}

    updates = data_dir / "updates"
    updates.mkdir(parents=True, exist_ok=True)
    target = updates / version
    if target.exists():
        raise ValueError(f"Version {version} is already published")
    stage = Path(tempfile.mkdtemp(prefix=".publishing-", dir=updates))
    try:
        for kind, name in names.items():
            digest, size = hashlib.sha256(), 0
            with (release_dir / name).open("rb") as source, (stage / name).open("xb") as copy:
                while block := source.read(1024 * 1024):
                    size += len(block)
                    if size > artifacts[kind]["bytes"]:
                        raise ValueError(f"Size mismatch for {name}")
                    digest.update(block)
                    copy.write(block)
            if artifacts[kind] != {"bytes": size, "sha256": digest.hexdigest()}:
                raise ValueError(f"Size or SHA-256 mismatch for {name}")

        payload = json.dumps({"schema": 1, "version": version, "server_url": origin, "artifacts": artifacts},
                             separators=(",", ":")).encode("utf-8")
        signature = signing_key.sign(SIGNING_PREFIX + payload)
        envelope = {"payload": base64.b64encode(payload).decode("ascii"),
                    "signature": base64.b64encode(signature).decode("ascii")}
        (stage / MANIFEST_FILENAME).write_text(json.dumps(envelope), encoding="ascii")
        # Readers see both immutable artifacts and their manifest in one rename.
        stage.rename(target)
    finally:
        if stage.is_dir():
            for name in (*names.values(), MANIFEST_FILENAME):
                (stage / name).unlink(missing_ok=True)
            stage.rmdir()
    return version
