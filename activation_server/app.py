"""SQLite issuance policy and the same-origin admin page."""
import asyncio
from collections import Counter
from contextlib import asynccontextmanager, closing
from html import escape
from ipaddress import ip_address
import json
import os
from pathlib import Path
import secrets
import sqlite3
from string import Template
from threading import Event, Thread
import time
from typing import Literal
from urllib.parse import parse_qsl

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic
from pydantic import BaseModel, Field, field_validator

from .protocol import ACTIVATION_PATH, MAX_EXPIRY, UID_PATTERN, signing_message, utc_datetime
from .updates import (
    MANIFEST_FILENAME,
    UPDATES_PATH,
    VERSION_PATTERN,
    UpdateConflictError,
    UploadSessionManager,
    artifact_names,
    clean_distribution_redundancy,
    delete_version,
    is_version_enabled,
    latest_version,
    list_versions,
    scan_distribution_redundancy,
    set_version_enabled,
    watch_distribution,
)


class Registry:
    def __init__(self, path, signing_key, clock=time.time):
        self.path = path
        self.signing_key = signing_key
        self.clock = clock
        with closing(self._connect()) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    duration_minutes INTEGER NOT NULL CHECK (duration_minutes > 0)
                );
                INSERT OR IGNORE INTO settings VALUES (1, 1440);
                CREATE TABLE IF NOT EXISTS clients (
                    uid TEXT PRIMARY KEY,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    auto_issue INTEGER NOT NULL DEFAULT 1 CHECK (auto_issue IN (0, 1)),
                    expires_at INTEGER,
                    client_version TEXT,
                    local_ip TEXT,
                    computer_name TEXT
                );
            """)
            db.execute("BEGIN IMMEDIATE")
            columns = {column["name"] for column in db.execute("PRAGMA table_info(clients)")}
            for name in ("client_version", "local_ip", "computer_name"):
                if name not in columns:
                    db.execute(f"ALTER TABLE clients ADD COLUMN {name} TEXT")

    def _connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def issue(self, uid, client_version=None, *, local_ip=None, computer_name=None):
        with closing(self._connect()) as db, db:
            # Serialize the policy read, registration and lease update with admin writes.
            db.execute("BEGIN IMMEDIATE")
            now = int(self.clock())
            client = db.execute("""
                INSERT INTO clients (uid, first_seen, last_seen) VALUES (?, ?, ?)
                ON CONFLICT(uid) DO UPDATE SET last_seen = excluded.last_seen
                RETURNING auto_issue, expires_at
            """, (uid, now, now)).fetchone()
            if not client["auto_issue"]:
                return None
            expiry = client["expires_at"]
            if expiry is None or expiry <= now:
                minutes = db.execute("SELECT duration_minutes FROM settings WHERE id = 1").fetchone()[0]
                expiry = min(MAX_EXPIRY, now + minutes * 60)
            db.execute("""
                UPDATE clients SET expires_at = ?, client_version = COALESCE(?, client_version),
                    local_ip = COALESCE(?, local_ip), computer_name = COALESCE(?, computer_name)
                WHERE uid = ?
            """, (expiry, client_version, local_ip, computer_name, uid))
            message = signing_message(uid, expiry)
            return f"{message.decode('ascii')}.{self.signing_key.sign(message).hex()}"

    def view(self):
        with closing(self._connect()) as db:
            duration = db.execute("SELECT duration_minutes FROM settings WHERE id = 1").fetchone()[0]
            clients = db.execute("SELECT * FROM clients ORDER BY last_seen DESC, uid").fetchall()
        return duration, clients

    def set_duration(self, minutes):
        if not 1 <= minutes <= (MAX_EXPIRY - int(self.clock())) // 60:
            raise ValueError("Enter a positive duration in minutes within the UTC calendar range")
        with closing(self._connect()) as db, db:
            db.execute("UPDATE settings SET duration_minutes = ? WHERE id = 1", (minutes,))

    def set_auto_issue(self, uid, allowed):
        with closing(self._connect()) as db, db:
            return db.execute("UPDATE clients SET auto_issue = ? WHERE uid = ?", (allowed, uid)).rowcount == 1


class ActivationRequest(BaseModel):
    uid: str = Field(min_length=64, max_length=64, pattern=rf"^{UID_PATTERN}$")
    client_version: str | None = Field(default=None, min_length=1, max_length=64, pattern=r"^[0-9A-Za-z][0-9A-Za-z.+-]*$")
    local_ip: str | None = Field(default=None, max_length=45, pattern=r"^[0-9A-Fa-f:.]+$")
    computer_name: str | None = Field(default=None, min_length=1, max_length=255, pattern=r"^[^\x00-\x1f\x7f]+$")

    @field_validator("local_ip")
    @classmethod
    def normalize_local_ip(cls, value):
        return str(ip_address(value)) if value is not None else None


def _utc(seconds):
    return utc_datetime(seconds).strftime("%Y-%m-%d %H:%M:%S") if seconds is not None else "—"


def _format_bytes(size):
    units = ("B", "KiB", "MiB", "GiB")
    value = float(max(0, size))
    for unit in units[:-1]:
        if value < 1024.0:
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.2f} {units[-1]}"


def _source_label(source):
    return {"web": "网页上传", "distribution": "distribution", "cli": "CLI 命令行"}.get(source, "历史发布")


def _artifact_cell(version, kind, info):
    filename = escape(info["filename"])
    digest = info.get("sha256") or ""
    short_sha = escape(digest[:12] + "…" if len(digest) > 12 else digest)
    size_text = escape(_format_bytes(info.get("bytes", 0)))
    download_label = "下载 EXE" if kind == "installer" else "下载 ZIP"
    sha_html = ""
    if digest:
        sha_html = (
            f'<button type="button" class="sha-copy" data-sha="{escape(digest)}" '
            f'title="点击复制完整 SHA-256: {escape(digest)}">{short_sha}</button>'
        )
    download_html = ""
    if info.get("exists"):
        download_html = (
            f'<a class="btn btn-sm btn-ghost" href="/admin/updates/{escape(version)}/{kind}" '
            f'download="{filename}" title="下载 {filename}">{download_label}</a>'
        )
    return (
        f'<td class="artifact-cell"><div class="artifact-meta">'
        f'<span class="artifact-size">{size_text}</span>{sha_html}{download_html}'
        f"</div></td>"
    )


def _version_row(item, client_count, csrf):
    version = escape(item["version"])
    enabled = item["enabled"]
    is_latest = item["is_latest"]
    if is_latest:
        badge_class, status_label = "badge badge-ok", "当前推送"
    elif enabled:
        badge_class, status_label = "badge badge-accent", "已启用"
    else:
        badge_class, status_label = "badge badge-off", "已停用"
    toggle_label, toggle_val, toggle_cls = ("停用", "0", "btn btn-sm btn-stop") if enabled else ("启用", "1", "btn btn-sm btn-enable")
    published_at = item["published_at"]
    source_label = escape(_source_label(item.get("source")))
    count_html = (
        f'<button type="button" class="chip version-filter-link" data-filter-version="{version}" '
        f'title="在客户端管理中查看使用 {version} 的客户端">{client_count} 台</button>'
        if client_count > 0
        else '<span class="muted-note">0 台</span>'
    )
    return f"""
        <tr data-version="{version}" data-enabled="{1 if enabled else 0}" data-is-latest="{1 if is_latest else 0}" data-published-at="{published_at}">
          <td><div class="version-cell"><code class="version-code">{version}</code><span class="source-tag">{source_label}</span></div></td>
          <td><span class="{badge_class}">{status_label}</span></td>
          <td class="ts-cell" data-ts="{published_at}">{_utc(published_at)}</td>
          {_artifact_cell(item["version"], "installer", item["artifacts"]["installer"])}
          {_artifact_cell(item["version"], "unpacked", item["artifacts"]["unpacked"])}
          <td>{count_html}</td>
          <td class="action-cell">
            <div class="version-actions">
              <form method="post" action="/admin/updates/{version}/status" class="version-toggle-form">
                <input type="hidden" name="csrf" value="{csrf}">
                <button type="submit" name="enabled" value="{toggle_val}" class="{toggle_cls}" aria-label="{toggle_label} {version}">{toggle_label}</button>
              </form>
              <form method="post" action="/admin/updates/{version}/delete" class="version-delete-form">
                <input type="hidden" name="csrf" value="{csrf}">
                <button type="submit" class="btn btn-sm btn-danger-outline" aria-label="删除 {version}">删除</button>
              </form>
            </div>
          </td>
        </tr>
    """


def _distribution_section(redundancy_items, distribution_dir, csrf):
    if distribution_dir is None:
        return '<div class="dist-status muted-note">未启用 <code>distribution</code> 自动监听目录，当前仅通过网页或 CLI 管理版本。</div>'
    if not redundancy_items:
        return (
            f'<div class="dist-status muted-note">'
            f'<code>{escape(str(distribution_dir))}</code> 自动监听已开启（发布后自动移走更新包，当前无历史冗余文件）。'
            f"</div>"
        )
    total_bytes = sum(item["bytes"] for item in redundancy_items)
    rows = "".join(
        f'<li><code>{escape(item["name"])}</code> <span class="muted-note">({_format_bytes(item["bytes"])} · {escape(item["reason"])})</span></li>'
        for item in redundancy_items
    )
    return f"""
      <div class="dist-alert">
        <div class="dist-alert-head">
          <div>
            <strong>检测到 {len(redundancy_items)} 个 <code>distribution</code> 历史冗余文件（共 {_format_bytes(total_bytes)}）</strong>
            <p class="muted-note">这些版本已发布到 <code>updates</code>，保留在 <code>{escape(str(distribution_dir))}</code> 中已无作用。</p>
          </div>
          <form method="post" action="/admin/updates/distribution/clean" class="dist-clean-form" data-clean-count="{len(redundancy_items)}" data-clean-size="{escape(_format_bytes(total_bytes))}">
            <input type="hidden" name="csrf" value="{csrf}">
            <button type="submit" class="btn btn-sm btn-stop">一键清理冗余（释放 {escape(_format_bytes(total_bytes))}）</button>
          </form>
        </div>
        <ul class="dist-list">{rows}</ul>
      </div>
    """


def _client_row(client, csrf):
    uid = escape(client["uid"])
    allowed = bool(client["auto_issue"])
    label, action, new_value = ("启用", "停发", "0") if allowed else ("停发", "启用", "1")
    # Attach raw attributes on the row so client-side sorting, filtering, and time formatting do not depend on rendered text.
    computer_name = escape(client["computer_name"] or "")
    local_ip = escape(client["local_ip"] or "")
    client_version = escape(client["client_version"] or "")
    expires_at = "" if client["expires_at"] is None else str(client["expires_at"])
    badge_class = "badge badge-ok" if allowed else "badge badge-off"
    button_class = "btn btn-sm btn-stop" if allowed else "btn btn-sm btn-enable"
    return f"""
        <tr data-uid="{uid}" data-computer="{computer_name}" data-ip="{local_ip}" data-version="{client_version}" data-first-seen="{client["first_seen"]}" data-last-seen="{client["last_seen"]}" data-expires-at="{expires_at}" data-auto-issue="{1 if allowed else 0}">
          <td class="uid-cell"><code class="uid-code" title="{uid}">{uid}</code></td>
          <td class="computer-name">{escape(client["computer_name"] or "—")}</td>
          <td>{escape(client["local_ip"] or "—")}</td>
          <td>{escape(client["client_version"] or "—")}</td>
          <td class="ts-cell" data-ts="{client["first_seen"]}">{_utc(client["first_seen"])}</td>
          <td class="ts-cell" data-ts="{client["last_seen"]}">{_utc(client["last_seen"])}</td>
          <td class="ts-cell expiry-cell" data-ts="{expires_at}">{_utc(client["expires_at"])}</td>
          <td class="status-cell"><span class="{badge_class}">{label}</span></td>
          <td class="action-cell"><form method="post" action="/admin/clients/{uid}" class="toggle-form">
            <input type="hidden" name="csrf" value="{csrf}">
            <button type="submit" name="auto_issue" value="{new_value}" class="{button_class}" aria-label="{action} {uid}">{action}</button>
          </form></td>
        </tr>
    """


def create_app(registry, username, password, *, distribution_dir=None):
    data_dir = Path(registry.path).parent
    updates = data_dir / "updates"
    upload_manager = UploadSessionManager(updates, registry.signing_key)

    @asynccontextmanager
    async def lifespan(_app):
        stop = Event()
        publisher = None
        if distribution_dir is not None:
            publisher = Thread(
                target=watch_distribution,
                args=(data_dir, distribution_dir, registry.signing_key, stop),
                name="perflens-update-publisher",
                daemon=True,
            )
            publisher.start()
        try:
            yield
        finally:
            stop.set()
            if publisher is not None:
                await asyncio.to_thread(publisher.join)
            upload_manager.abort_all()

    app = FastAPI(title="PerfLens activation", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    basic = HTTPBasic(realm="PerfLens activation")
    csrf = secrets.token_urlsafe(32)
    template = Template(Path(__file__).with_name("admin.html").read_text(encoding="utf-8"))
    # Basic Auth credentials are unencrypted over plain HTTP.
    allow_http_admin = os.getenv("PERFLENS_ADMIN_ALLOW_HTTP") == "1"

    async def require_admin(request: Request):
        if (
            not allow_http_admin
            and request.url.scheme != "https"
            and (not request.client or request.client.host not in {"127.0.0.1", "::1"})
        ):
            raise HTTPException(403, "Admin access requires HTTPS or a loopback connection")
        credentials = await basic(request)
        username_ok = secrets.compare_digest(credentials.username.encode(), username.encode())
        password_ok = secrets.compare_digest(credentials.password.encode(), password.encode())
        if not (username_ok and password_ok):
            raise HTTPException(401, "Invalid admin credentials", headers={"WWW-Authenticate": 'Basic realm="PerfLens activation"'})

    def verify_csrf(token):
        if not isinstance(token, str) or not secrets.compare_digest(token.encode(), csrf.encode()):
            raise HTTPException(403, "Invalid CSRF token")

    async def require_admin_csrf(request: Request, _=Depends(require_admin)):
        verify_csrf(request.headers.get("X-CSRF-Token", ""))

    async def admin_form(request: Request, _=Depends(require_admin)):
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/x-www-form-urlencoded":
            raise HTTPException(415, "Expected an admin form")
        try:
            form = dict(parse_qsl((await request.body()).decode("ascii"), strict_parsing=True, max_num_fields=3))
        except ValueError:
            raise HTTPException(422, "Invalid admin form") from None
        verify_csrf(form.get("csrf", ""))
        return form

    def resolve_artifact_file(version: str, kind: str, *, require_enabled: bool):
        name = artifact_names(version).get(kind) if VERSION_PATTERN.fullmatch(version) else None
        version_dir = updates / version
        if (
            name is None
            or not (version_dir / MANIFEST_FILENAME).is_file()
            or not (version_dir / name).is_file()
            or (require_enabled and not is_version_enabled(version_dir))
        ):
            raise HTTPException(404, "Update artifact not found")
        return version_dir / name, name

    @app.post(ACTIVATION_PATH)
    def activate(request: ActivationRequest):
        code = registry.issue(request.uid, request.client_version, local_ip=request.local_ip, computer_name=request.computer_name)
        if code is None:
            raise HTTPException(403, "issuance_disabled")
        return JSONResponse({"code": code}, headers={"Cache-Control": "no-store"})

    @app.get(f"{UPDATES_PATH}/latest")
    def latest_update():
        version = latest_version(updates)
        headers = {"Cache-Control": "no-store"}
        if version is None:
            return Response(status_code=204, headers=headers)
        return FileResponse(updates / version / MANIFEST_FILENAME, media_type="application/json", headers=headers)

    @app.get(f"{UPDATES_PATH}/{{version}}/{{kind}}")
    def download_update(version: str, kind: str):
        path, name = resolve_artifact_file(version, kind, require_enabled=True)
        return FileResponse(path, filename=name, media_type="application/octet-stream")

    @app.get("/admin", response_class=HTMLResponse, dependencies=[Depends(require_admin)])
    def admin():
        duration, clients = registry.view()
        now = int(registry.clock())
        enabled_count = sum(1 for client in clients if client["auto_issue"])
        disabled_count = len(clients) - enabled_count
        active_lease_count = sum(
            1 for client in clients if client["expires_at"] is not None and client["expires_at"] > now
        )
        rows = "".join(_client_row(client, csrf) for client in clients)
        client_version_counts = Counter(client["client_version"] for client in clients if client["client_version"])
        versions = list_versions(updates)
        enabled_version_count = sum(1 for item in versions if item["enabled"])
        disabled_version_count = len(versions) - enabled_version_count
        version_rows = "".join(
            _version_row(item, client_version_counts.get(item["version"], 0), csrf) for item in versions
        )
        redundancy_items = scan_distribution_redundancy(updates, distribution_dir)
        distribution_html = _distribution_section(redundancy_items, distribution_dir, csrf)
        existing_versions_json = escape(json.dumps([item["version"] for item in versions]))
        return HTMLResponse(
            template.substitute(
                duration=duration,
                csrf=csrf,
                count=len(clients),
                enabled_count=enabled_count,
                disabled_count=disabled_count,
                active_lease_count=active_lease_count,
                server_now=now,
                rows=rows,
                latest_version=latest_version(updates) or "—",
                version_count=len(versions),
                enabled_version_count=enabled_version_count,
                disabled_version_count=disabled_version_count,
                version_rows=version_rows,
                existing_versions_json=existing_versions_json,
                distribution_html=distribution_html,
            ),
            headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"},
        )

    @app.post("/admin/settings")
    def update_settings(form=Depends(admin_form)):
        try:
            registry.set_duration(int(form.get("duration_minutes", "")))
        except ValueError:
            raise HTTPException(422, "Invalid duration in minutes") from None
        return RedirectResponse("/admin", status_code=303)

    @app.post("/admin/clients/{uid}")
    def update_client(uid: str, form=Depends(admin_form)):
        allowed = form.get("auto_issue")
        if allowed not in {"0", "1"}:
            raise HTTPException(422, "Invalid auto-issue value")
        if not registry.set_auto_issue(uid, allowed == "1"):
            raise HTTPException(404, "UID has not registered")
        return RedirectResponse("/admin", status_code=303)

    @app.post("/admin/updates/upload/init", dependencies=[Depends(require_admin)])
    async def init_update_upload(request: Request):
        raw = await request.body()
        if len(raw) > 128 * 1024:
            raise HTTPException(413, "Manifest payload too large")
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise HTTPException(422, "Invalid JSON payload") from None
        if not isinstance(body, dict):
            raise HTTPException(422, "Invalid JSON payload")
        verify_csrf(request.headers.get("X-CSRF-Token") or body.get("csrf", ""))
        enabled = body.get("enabled", True)
        if type(enabled) is not bool:
            raise HTTPException(422, "Invalid enabled flag")
        try:
            session = await asyncio.to_thread(upload_manager.create_session, body.get("manifest"), enabled=enabled)
        except UpdateConflictError as error:
            raise HTTPException(409, str(error)) from None
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        return JSONResponse(session, headers={"Cache-Control": "no-store"})

    @app.post("/admin/updates/upload/{session_id}/complete", dependencies=[Depends(require_admin_csrf)])
    async def complete_update_upload(session_id: str):
        try:
            version = await asyncio.to_thread(upload_manager.complete_session, session_id)
        except KeyError as error:
            raise HTTPException(404, str(error)) from None
        except UpdateConflictError as error:
            raise HTTPException(409, str(error)) from None
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        return JSONResponse({"version": version}, headers={"Cache-Control": "no-store"})

    @app.post("/admin/updates/upload/{session_id}/{kind}", dependencies=[Depends(require_admin_csrf)])
    async def upload_update_chunk(session_id: str, kind: Literal["installer", "unpacked"], request: Request):
        offset_header = request.headers.get("X-Chunk-Offset", "")
        if not offset_header.isascii() or not offset_header.isdecimal():
            raise HTTPException(422, "Missing or invalid X-Chunk-Offset header")
        offset = int(offset_header)
        limit = upload_manager.chunk_bytes
        buffer = bytearray()
        async for part in request.stream():
            if len(buffer) + len(part) > limit:
                raise HTTPException(413, "Upload chunk exceeds allowed limit")
            buffer.extend(part)
        try:
            progress = await asyncio.to_thread(upload_manager.write_chunk, session_id, kind, offset, bytes(buffer))
        except KeyError as error:
            raise HTTPException(404, str(error)) from None
        except UpdateConflictError as error:
            raise HTTPException(409, str(error)) from None
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        return JSONResponse(progress, headers={"Cache-Control": "no-store"})

    @app.delete("/admin/updates/upload/{session_id}", dependencies=[Depends(require_admin_csrf)])
    async def abort_update_upload(session_id: str):
        aborted = await asyncio.to_thread(upload_manager.abort_session, session_id)
        return JSONResponse({"aborted": aborted}, headers={"Cache-Control": "no-store"})

    @app.post("/admin/updates/distribution/clean")
    def clean_distribution(form=Depends(admin_form)):
        clean_distribution_redundancy(updates, distribution_dir)
        return RedirectResponse("/admin", status_code=303)

    @app.get("/admin/updates/{version}/{kind}", dependencies=[Depends(require_admin)])
    def admin_download_update(version: str, kind: str):
        # Admins can always download artifacts, including disabled versions for internal testing.
        path, name = resolve_artifact_file(version, kind, require_enabled=False)
        return FileResponse(path, filename=name, media_type="application/octet-stream", headers={"Cache-Control": "no-store"})

    @app.post("/admin/updates/{version}/status")
    def update_version_status(version: str, form=Depends(admin_form)):
        enabled = form.get("enabled")
        if enabled not in {"0", "1"}:
            raise HTTPException(422, "Invalid enabled value")
        try:
            updated = set_version_enabled(updates, version, enabled == "1")
        except ValueError:
            raise HTTPException(422, "Invalid version") from None
        if not updated:
            raise HTTPException(404, "Version not found")
        return RedirectResponse("/admin", status_code=303)

    @app.post("/admin/updates/{version}/delete")
    def remove_version(version: str, form=Depends(admin_form)):
        try:
            deleted = delete_version(updates, version)
        except ValueError:
            raise HTTPException(422, "Invalid version") from None
        except OSError:
            raise HTTPException(409, "版本文件正被客户端下载占用，已自动设为停用，请稍后再试删除") from None
        if not deleted:
            raise HTTPException(404, "Version not found")
        return RedirectResponse("/admin", status_code=303)

    return app
