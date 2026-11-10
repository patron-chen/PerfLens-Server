"""SQLite issuance policy and the same-origin admin page."""
from contextlib import closing
from html import escape
import os
from pathlib import Path
import secrets
import sqlite3
from string import Template
import time
from urllib.parse import parse_qsl

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic
from pydantic import BaseModel, Field

from .protocol import ACTIVATION_PATH, MAX_EXPIRY, UID_PATTERN, signing_message, utc_datetime
from .updates import MANIFEST_FILENAME, UPDATES_PATH, VERSION_PATTERN, artifact_names, latest_version


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
                    client_version TEXT
                );
            """)
            db.execute("BEGIN IMMEDIATE")
            if not any(column["name"] == "client_version" for column in db.execute("PRAGMA table_info(clients)")):
                db.execute("ALTER TABLE clients ADD COLUMN client_version TEXT")

    def _connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def issue(self, uid, client_version=None):
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
            db.execute("UPDATE clients SET expires_at = ?, client_version = COALESCE(?, client_version) WHERE uid = ?",
                       (expiry, client_version, uid))
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


def _utc(seconds):
    return utc_datetime(seconds).strftime("%Y-%m-%d %H:%M:%S") if seconds is not None else "—"


def _client_row(client, csrf):
    uid = escape(client["uid"])
    allowed = bool(client["auto_issue"])
    label, action, new_value = ("启用", "停发", "0") if allowed else ("停发", "启用", "1")
    return f"""
        <tr>
          <td><code>{uid}</code></td>
          <td>{escape(client["client_version"] or "—")}</td>
          <td>{_utc(client["first_seen"])}</td>
          <td>{_utc(client["last_seen"])}</td>
          <td>{_utc(client["expires_at"])}</td>
          <td>{label}</td>
          <td><form method="post" action="/admin/clients/{uid}">
            <input type="hidden" name="csrf" value="{csrf}">
            <button name="auto_issue" value="{new_value}" aria-label="{action} {uid}">{action}</button>
          </form></td>
        </tr>
    """


def create_app(registry, username, password):
    app = FastAPI(title="PerfLens activation", docs_url=None, redoc_url=None, openapi_url=None)
    basic = HTTPBasic(realm="PerfLens activation")
    csrf = secrets.token_urlsafe(32)
    template = Template(Path(__file__).with_name("admin.html").read_text(encoding="utf-8"))
    updates = Path(registry.path).parent / "updates"
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

    async def admin_form(request: Request, _=Depends(require_admin)):
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/x-www-form-urlencoded":
            raise HTTPException(415, "Expected an admin form")
        try:
            form = dict(parse_qsl((await request.body()).decode("ascii"), strict_parsing=True, max_num_fields=3))
        except ValueError:
            raise HTTPException(422, "Invalid admin form") from None
        if not secrets.compare_digest(form.get("csrf", "").encode(), csrf.encode()):
            raise HTTPException(403, "Invalid CSRF token")
        return form

    @app.post(ACTIVATION_PATH)
    def activate(request: ActivationRequest):
        code = registry.issue(request.uid, request.client_version)
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
        name = artifact_names(version).get(kind) if VERSION_PATTERN.fullmatch(version) else None
        if name is None or not (updates / version / MANIFEST_FILENAME).is_file() or not (updates / version / name).is_file():
            raise HTTPException(404, "Update artifact not found")
        return FileResponse(updates / version / name, filename=name, media_type="application/octet-stream")

    @app.get("/admin", response_class=HTMLResponse, dependencies=[Depends(require_admin)])
    def admin():
        duration, clients = registry.view()
        rows = "".join(_client_row(client, csrf) for client in clients)
        return HTMLResponse(template.substitute(duration=duration, csrf=csrf, count=len(clients), rows=rows,
                                               latest_version=latest_version(updates) or "—"),
                            headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"})

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

    return app
