"""Publish complete Windows releases with a signed, versioned manifest."""
import base64
import errno
import hashlib
import json
import logging
from pathlib import Path
import re
import secrets
import tempfile
from threading import Lock
import time
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization


UPDATES_PATH = "/api/v1/updates/windows-x64"
SIGNING_PREFIX = b"PerfLensUpdateV1\0"
VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
MANIFEST_FILENAME = "update.json"
DISABLED_MARKER = ".disabled"
CANARY_MARKER = ".canary"
STAGE_RELEASED = "released"
STAGE_CANARY = "canary"
STAGE_DISABLED = "disabled"
VALID_STAGES = frozenset({STAGE_RELEASED, STAGE_CANARY, STAGE_DISABLED})
RELEASE_META_FILENAME = "meta.json"
STAGING_PREFIX = ".publishing-"
UPLOAD_STAGE_PREFIX = ".uploading-"
UPLOAD_CHUNK_BYTES = 8 * 1024 * 1024
UPLOAD_SESSION_TTL_SECONDS = 6 * 3600
DISTRIBUTION_POLL_SECONDS = 5
_READ_BLOCK_BYTES = 1024 * 1024


class UpdateConflictError(ValueError):
    """Raised when attempting to publish a version that already exists."""


def artifact_names(version):
    return {"installer": f"PerfLens-Setup-{version}-x64.exe", "unpacked": f"PerfLens-Unpacked-{version}-win-x64.zip"}


def _version_parts(version):
    return tuple(map(int, version.split(".")))


def version_stage(version_dir):
    if (version_dir / DISABLED_MARKER).exists():
        return STAGE_DISABLED
    if (version_dir / CANARY_MARKER).exists():
        return STAGE_CANARY
    return STAGE_RELEASED


def is_version_enabled(version_dir):
    return version_stage(version_dir) == STAGE_RELEASED


def latest_version(directory, *, include_disabled=False, include_canary=False):
    if not directory.is_dir():
        return None
    allowed = {STAGE_RELEASED}
    if include_canary:
        allowed.add(STAGE_CANARY)
    if include_disabled:
        allowed.add(STAGE_DISABLED)
    versions = (
        entry.name for entry in directory.iterdir()
        if entry.is_dir()
        and VERSION_PATTERN.fullmatch(entry.name)
        and (entry / MANIFEST_FILENAME).is_file()
        and version_stage(entry) in allowed
    )
    return max(versions, key=_version_parts, default=None)


def resolve_latest_version(directory, is_canary_member=None):
    if not directory.is_dir():
        return None
    candidates = []
    for entry in directory.iterdir():
        if not entry.is_dir() or not VERSION_PATTERN.fullmatch(entry.name) or not (entry / MANIFEST_FILENAME).is_file():
            continue
        stage = version_stage(entry)
        if stage == STAGE_RELEASED or (stage == STAGE_CANARY and is_canary_member is not None and is_canary_member(entry.name)):
            candidates.append(entry.name)
    return max(candidates, key=_version_parts, default=None)


def is_version_accessible(updates_dir, version, *, is_canary_member=None):
    if not VERSION_PATTERN.fullmatch(version):
        return False
    version_dir = updates_dir / version
    if not version_dir.is_dir() or not (version_dir / MANIFEST_FILENAME).is_file():
        return False
    stage = version_stage(version_dir)
    if stage == STAGE_RELEASED:
        return True
    if stage == STAGE_CANARY:
        return is_canary_member is not None and bool(is_canary_member(version))
    return False


def _validate_manifest_record(record, signing_key):
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
    return version, origin, names, artifacts


def _build_signed_envelope(version, origin, artifacts, signing_key):
    payload = json.dumps(
        {"schema": 1, "version": version, "server_url": origin, "artifacts": artifacts},
        separators=(",", ":"),
    ).encode("utf-8")
    signature = signing_key.sign(SIGNING_PREFIX + payload)
    envelope = {
        "payload": base64.b64encode(payload).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(envelope)


def _write_release_files(stage_dir, version, origin, artifacts, signing_key, *, stage=STAGE_CANARY, source="unknown", published_at=None):
    if stage not in VALID_STAGES:
        raise ValueError(f"Invalid release stage: {stage}")
    (stage_dir / MANIFEST_FILENAME).write_text(_build_signed_envelope(version, origin, artifacts, signing_key), encoding="ascii")
    meta = {"published_at": int(time.time() if published_at is None else published_at), "source": source}
    (stage_dir / RELEASE_META_FILENAME).write_text(json.dumps(meta), encoding="utf-8")
    if stage == STAGE_DISABLED:
        (stage_dir / DISABLED_MARKER).write_text("disabled\n", encoding="ascii")
    elif stage == STAGE_CANARY:
        (stage_dir / CANARY_MARKER).write_text("canary\n", encoding="ascii")


def _cleanup_flat_dir(directory):
    if not directory.is_dir():
        return
    for entry in list(directory.iterdir()):
        if entry.is_file() or entry.is_symlink():
            entry.unlink(missing_ok=True)
    directory.rmdir()


def _verify_staged_file(staged_file, name, expected):
    digest, size = hashlib.sha256(), 0
    with staged_file.open("rb") as handle:
        while block := handle.read(_READ_BLOCK_BYTES):
            size += len(block)
            if size > expected["bytes"]:
                raise ValueError(f"Size mismatch for {name}")
            digest.update(block)
    if expected != {"bytes": size, "sha256": digest.hexdigest()}:
        raise ValueError(f"Size or SHA-256 mismatch for {name}")


def _copy_and_verify_file(source_file, staged_file, name, expected):
    digest, size = hashlib.sha256(), 0
    with source_file.open("rb") as source, staged_file.open("xb") as copy:
        while block := source.read(_READ_BLOCK_BYTES):
            size += len(block)
            if size > expected["bytes"]:
                raise ValueError(f"Size mismatch for {name}")
            digest.update(block)
            copy.write(block)
    if expected != {"bytes": size, "sha256": digest.hexdigest()}:
        raise ValueError(f"Size or SHA-256 mismatch for {name}")


def publish_update(
    data_dir,
    release_dir,
    signing_key,
    *,
    newer_only=False,
    move_artifacts=False,
    source="cli",
    stage=STAGE_CANARY,
    on_published=None,
):
    if stage not in VALID_STAGES:
        raise ValueError(f"Invalid release stage: {stage}")
    manifest_path = release_dir / "manifest.json"
    record = json.loads(manifest_path.read_text(encoding="utf-8"))
    version, origin, names, artifacts = _validate_manifest_record(record, signing_key)
    updates = data_dir / "updates"
    if newer_only:
        current = latest_version(updates, include_disabled=True, include_canary=True)
        if current is not None and _version_parts(version) <= _version_parts(current):
            return None

    target = updates / version
    if target.exists():
        raise UpdateConflictError(f"Version {version} is already published")
    # An upload may still be in progress. Check both sizes before staging either file.
    for kind, name in names.items():
        if (release_dir / name).stat().st_size != artifacts[kind]["bytes"]:
            raise ValueError(f"Size mismatch for {name}")

    updates.mkdir(parents=True, exist_ok=True)
    stage_dir = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=updates))
    moved_files = []
    copied_sources = []
    try:
        for kind, name in names.items():
            source_file = release_dir / name
            staged_file = stage_dir / name
            if move_artifacts:
                try:
                    # Same-filesystem rename avoids duplicating ~400 MiB and isolates the file from external writes.
                    source_file.replace(staged_file)
                    moved_files.append((source_file, staged_file))
                    _verify_staged_file(staged_file, name, artifacts[kind])
                    continue
                except OSError as error:
                    if error.errno != errno.EXDEV:
                        raise
            _copy_and_verify_file(source_file, staged_file, name, artifacts[kind])
            if move_artifacts:
                copied_sources.append(source_file)

        _write_release_files(stage_dir, version, origin, artifacts, signing_key, stage=stage, source=source)
        # Initialize canary roster before exposing target directory so no window exists without allowlist entries.
        if on_published is not None:
            on_published(version, stage)
        # Readers see both immutable artifacts and their manifest in one rename.
        stage_dir.rename(target)
    except BaseException:
        # Restore any files moved out of release_dir if verification or publishing failed.
        for source_file, staged_file in moved_files:
            if staged_file.exists() and not source_file.exists():
                try:
                    staged_file.replace(source_file)
                except OSError:
                    pass
        raise
    finally:
        _cleanup_flat_dir(stage_dir)

    if move_artifacts:
        for source_file in copied_sources:
            source_file.unlink(missing_ok=True)
        manifest_path.unlink(missing_ok=True)
    return version


def list_versions(updates_dir):
    if not updates_dir.is_dir():
        return []
    current_latest = latest_version(updates_dir)
    canary_candidates = [
        entry.name for entry in updates_dir.iterdir()
        if entry.is_dir() and VERSION_PATTERN.fullmatch(entry.name) and (entry / MANIFEST_FILENAME).is_file()
        and version_stage(entry) == STAGE_CANARY
    ]
    latest_canary = max(canary_candidates, key=_version_parts, default=None)
    items = []
    for entry in updates_dir.iterdir():
        if not entry.is_dir() or not VERSION_PATTERN.fullmatch(entry.name):
            continue
        manifest_file = entry / MANIFEST_FILENAME
        if not manifest_file.is_file():
            continue
        try:
            envelope = json.loads(manifest_file.read_text(encoding="ascii"))
            payload = json.loads(base64.b64decode(envelope["payload"]).decode("utf-8"))
        except (OSError, ValueError, KeyError, TypeError):
            continue
        version = entry.name
        names = artifact_names(version)
        artifacts_meta = payload.get("artifacts") if isinstance(payload.get("artifacts"), dict) else {}
        artifacts = {}
        for kind, filename in names.items():
            info = artifacts_meta.get(kind) if isinstance(artifacts_meta.get(kind), dict) else {}
            file_path = entry / filename
            artifacts[kind] = {
                "filename": filename,
                "bytes": info.get("bytes") if isinstance(info.get("bytes"), int) else (file_path.stat().st_size if file_path.is_file() else 0),
                "sha256": info.get("sha256") if isinstance(info.get("sha256"), str) else "",
                "exists": file_path.is_file(),
            }
        published_at = int(manifest_file.stat().st_mtime)
        source = "unknown"
        meta_file = entry / RELEASE_META_FILENAME
        if meta_file.is_file():
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                if isinstance(meta.get("published_at"), int):
                    published_at = meta["published_at"]
                if isinstance(meta.get("source"), str) and meta["source"]:
                    source = meta["source"]
            except (OSError, ValueError):
                pass
        stage = version_stage(entry)
        items.append({
            "version": version,
            "stage": stage,
            "enabled": stage == STAGE_RELEASED,
            "is_latest": version == current_latest,
            "is_latest_canary": version == latest_canary,
            "published_at": published_at,
            "source": source,
            "server_url": payload.get("server_url", ""),
            "artifacts": artifacts,
        })
    items.sort(key=lambda item: _version_parts(item["version"]), reverse=True)
    return items


def set_version_stage(updates_dir, version, stage):
    if stage not in VALID_STAGES:
        raise ValueError("Invalid version stage")
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Invalid version")
    target = updates_dir / version
    if not target.is_dir() or not (target / MANIFEST_FILENAME).is_file():
        return False
    disabled_marker = target / DISABLED_MARKER
    canary_marker = target / CANARY_MARKER
    # Always write the stricter marker before removing the old one to prevent transient full exposure.
    if stage == STAGE_DISABLED:
        disabled_marker.write_text("disabled\n", encoding="ascii")
        canary_marker.unlink(missing_ok=True)
    elif stage == STAGE_CANARY:
        canary_marker.write_text("canary\n", encoding="ascii")
        disabled_marker.unlink(missing_ok=True)
    else:
        disabled_marker.unlink(missing_ok=True)
        canary_marker.unlink(missing_ok=True)
    return True


def set_version_enabled(updates_dir, version, enabled):
    return set_version_stage(updates_dir, version, STAGE_RELEASED if enabled else STAGE_DISABLED)


def delete_version(updates_dir, version):
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Invalid version")
    target = updates_dir / version
    if not target.is_dir() or not (target / MANIFEST_FILENAME).is_file():
        return False
    # Disable first so active downloads are blocked before removing the binary artifacts.
    (target / DISABLED_MARKER).write_text("disabled\n", encoding="ascii")
    (target / CANARY_MARKER).unlink(missing_ok=True)
    for filename in artifact_names(version).values():
        (target / filename).unlink(missing_ok=True)
    (target / MANIFEST_FILENAME).unlink(missing_ok=True)
    (target / RELEASE_META_FILENAME).unlink(missing_ok=True)
    (target / DISABLED_MARKER).unlink(missing_ok=True)
    target.rmdir()
    return True


def _published_version_set(updates_dir):
    if not updates_dir.is_dir():
        return set()
    return {
        entry.name for entry in updates_dir.iterdir()
        if entry.is_dir() and VERSION_PATTERN.fullmatch(entry.name) and (entry / MANIFEST_FILENAME).is_file()
    }


def scan_distribution_redundancy(updates_dir, distribution_dir):
    if distribution_dir is None or not distribution_dir.is_dir():
        return []
    published = _published_version_set(updates_dir)
    if not published:
        return []
    redundant = []
    manifest_file = distribution_dir / "manifest.json"
    manifest_version = None
    if manifest_file.is_file():
        try:
            record = json.loads(manifest_file.read_text(encoding="utf-8"))
            if isinstance(record, dict) and isinstance(record.get("version"), str):
                manifest_version = record["version"]
        except (OSError, ValueError):
            pass
    for entry in sorted(distribution_dir.iterdir(), key=lambda p: p.name):
        if not entry.is_file():
            continue
        name = entry.name
        if name == "manifest.json":
            if manifest_version in published:
                redundant.append({
                    "name": name,
                    "bytes": entry.stat().st_size,
                    "version": manifest_version,
                    "reason": f"版本 {manifest_version} 已发布，清单已冗余",
                })
            continue
        match = re.fullmatch(r"PerfLens-(?:Setup|Unpacked)-([0-9]+(?:\.[0-9]+){2})(?:-x64\.exe|-win-x64\.zip)", name)
        if match and match.group(1) in published:
            redundant.append({
                "name": name,
                "bytes": entry.stat().st_size,
                "version": match.group(1),
                "reason": f"版本 {match.group(1)} 已发布在 updates 中",
            })
    return redundant


def clean_distribution_redundancy(updates_dir, distribution_dir):
    items = scan_distribution_redundancy(updates_dir, distribution_dir)
    deleted_count = 0
    freed_bytes = 0
    for item in items:
        path = distribution_dir / item["name"]
        try:
            size = path.stat().st_size
            path.unlink()
            deleted_count += 1
            freed_bytes += size
        except OSError:
            pass
    return deleted_count, freed_bytes


class UploadSessionManager:
    """Coordinate chunked browser uploads into temporary staging directories before atomic publish."""

    def __init__(self, updates_dir, signing_key, *, chunk_bytes=None, session_ttl=UPLOAD_SESSION_TTL_SECONDS, clock=time.time):
        self.updates_dir = updates_dir
        self.signing_key = signing_key
        self.chunk_bytes = UPLOAD_CHUNK_BYTES if chunk_bytes is None else chunk_bytes
        self.session_ttl = session_ttl
        self.clock = clock
        self._lock = Lock()
        self._sessions = {}

    def prune_stale(self):
        if not self.updates_dir.is_dir():
            return
        cutoff = self.clock() - self.session_ttl
        with self._lock:
            active_dirs = {session["stage_dir"].name for session in self._sessions.values()}
            expired_ids = [sid for sid, session in self._sessions.items() if session["updated_at"] < cutoff]
            for sid in expired_ids:
                expired = self._sessions.pop(sid)
                _cleanup_flat_dir(expired["stage_dir"])
        for entry in self.updates_dir.iterdir():
            if entry.is_dir() and entry.name.startswith(UPLOAD_STAGE_PREFIX) and entry.name not in active_dirs:
                try:
                    if entry.stat().st_mtime < cutoff:
                        _cleanup_flat_dir(entry)
                except OSError:
                    pass

    def create_session(self, manifest_record, *, stage=STAGE_CANARY, inherit_from="default"):
        if stage not in VALID_STAGES:
            raise ValueError(f"Unsupported stage: {stage}")
        normalized_inherit = "default" if inherit_from is None else (str(inherit_from).strip() or "none")
        version, origin, names, artifacts = _validate_manifest_record(manifest_record, self.signing_key)
        self.updates_dir.mkdir(parents=True, exist_ok=True)
        self.prune_stale()
        if (self.updates_dir / version).exists():
            raise UpdateConflictError(f"Version {version} is already published")
        session_id = secrets.token_hex(16)
        stage_dir = Path(tempfile.mkdtemp(prefix=f"{UPLOAD_STAGE_PREFIX}{session_id[:8]}-", dir=self.updates_dir))
        now = self.clock()
        with self._lock:
            self._sessions[session_id] = {
                "version": version,
                "origin": origin,
                "names": names,
                "artifacts": artifacts,
                "stage": stage,
                "inherit_from": normalized_inherit,
                "stage_dir": stage_dir,
                "received": {"installer": 0, "unpacked": 0},
                "hashers": {"installer": hashlib.sha256(), "unpacked": hashlib.sha256()},
                "updated_at": now,
                "file_locks": {"installer": Lock(), "unpacked": Lock()},
            }
        return {
            "session_id": session_id,
            "version": version,
            "stage": stage,
            "inherit_from": normalized_inherit,
            "chunk_bytes": self.chunk_bytes,
            "files": {kind: {"filename": names[kind], **artifacts[kind]} for kind in names},
        }

    def _get_session(self, session_id):
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise KeyError("Upload session not found or expired")
        return session

    def write_chunk(self, session_id, kind, offset, data):
        if kind not in {"installer", "unpacked"}:
            raise ValueError("Invalid artifact kind")
        session = self._get_session(session_id)
        expected_bytes = session["artifacts"][kind]["bytes"]
        filename = session["names"][kind]
        target_file = session["stage_dir"] / filename
        with session["file_locks"][kind]:
            current = session["received"][kind]
            if offset != current:
                raise UpdateConflictError(f"Unexpected chunk offset {offset}; expected {current}")
            if current + len(data) > expected_bytes:
                raise ValueError(f"Size mismatch for {filename}")
            if data:
                with target_file.open("ab") as handle:
                    handle.write(data)
                session["hashers"][kind].update(data)
                session["received"][kind] = current + len(data)
            session["updated_at"] = self.clock()
            return {"received": session["received"][kind], "expected": expected_bytes}

    def complete_session(self, session_id, *, on_published=None):
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise KeyError("Upload session not found or expired")
        version = session["version"]
        stage_dir = session["stage_dir"]
        try:
            for kind, filename in session["names"].items():
                expected = session["artifacts"][kind]
                if session["received"][kind] != expected["bytes"]:
                    raise ValueError(f"Incomplete upload for {filename}")
                if session["hashers"][kind].hexdigest() != expected["sha256"]:
                    raise ValueError(f"SHA-256 mismatch for {filename}")
            target = self.updates_dir / version
            if target.exists():
                raise UpdateConflictError(f"Version {version} is already published")
            _write_release_files(
                stage_dir,
                version,
                session["origin"],
                session["artifacts"],
                self.signing_key,
                stage=session["stage"],
                source="web",
            )
            # Initialize canary roster before atomic rename exposes the release.
            if on_published is not None:
                on_published(version, session["stage"], session["inherit_from"])
            stage_dir.rename(target)
        except BaseException:
            # Clean failed or conflicted session so disk space is reclaimed immediately.
            with self._lock:
                self._sessions.pop(session_id, None)
            _cleanup_flat_dir(stage_dir)
            raise
        with self._lock:
            self._sessions.pop(session_id, None)
        return version

    def abort_session(self, session_id):
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        _cleanup_flat_dir(session["stage_dir"])
        return True

    def abort_all(self):
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            _cleanup_flat_dir(session["stage_dir"])


def watch_distribution(data_dir, release_dir, signing_key, stop, *, on_published=None):
    logger = logging.getLogger("uvicorn.error")
    manifest = release_dir / "manifest.json"
    last_error = None
    while not stop.is_set():
        try:
            version = (
                publish_update(
                    data_dir,
                    release_dir,
                    signing_key,
                    newer_only=True,
                    move_artifacts=True,
                    source="distribution",
                    stage=STAGE_CANARY,
                    on_published=on_published,
                )
                if manifest.is_file() else None
            )
        except (OSError, ValueError) as error:
            if str(error) != last_error:
                logger.warning("Cannot publish update from %s: %s", release_dir, error)
                last_error = str(error)
        else:
            last_error = None
            if version is not None:
                logger.info("Published Windows x64 update %s from %s", version, release_dir)
        stop.wait(DISTRIBUTION_POLL_SECONDS)
