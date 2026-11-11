"""SQLite issuance policy and the same-origin admin page."""
import asyncio
from collections import Counter
from contextlib import asynccontextmanager, closing
from html import escape
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
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
    STAGE_CANARY,
    STAGE_DISABLED,
    STAGE_RELEASED,
    UPDATES_PATH,
    VALID_STAGES,
    VERSION_PATTERN,
    UpdateConflictError,
    UploadSessionManager,
    artifact_names,
    clean_distribution_redundancy,
    delete_version,
    is_version_accessible,
    latest_version,
    list_versions,
    resolve_latest_version,
    scan_distribution_redundancy,
    set_version_enabled,
    set_version_stage,
    version_stage,
    watch_distribution,
)

_UID_RE = re.compile(rf"^{UID_PATTERN}$")


def _normalize_uid(uid):
    if not isinstance(uid, str):
        raise ValueError("Invalid client UID")
    normalized = uid.strip().lower()
    if not _UID_RE.fullmatch(normalized):
        raise ValueError("Invalid client UID")
    return normalized


def _normalize_uid_list(body):
    if not isinstance(body, dict):
        raise ValueError("Invalid JSON payload")
    raw_items = body.get("uids")
    if raw_items is None:
        if "uid" not in body:
            raise ValueError("Missing client UID")
        raw_items = [body.get("uid")]
    elif not isinstance(raw_items, list) or not raw_items:
        raise ValueError("Expected non-empty UID list")
    normalized = []
    seen = set()
    for item in raw_items:
        uid = _normalize_uid(item)
        if uid not in seen:
            seen.add(uid)
            normalized.append(uid)
    return normalized


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
                CREATE TABLE IF NOT EXISTS canary_default_members (
                    uid TEXT PRIMARY KEY,
                    note TEXT,
                    added_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS canary_version_members (
                    version TEXT NOT NULL,
                    uid TEXT NOT NULL,
                    added_at INTEGER NOT NULL,
                    PRIMARY KEY (version, uid)
                );
                CREATE INDEX IF NOT EXISTS idx_canary_version_uid ON canary_version_members (uid);
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

    def canary_versions_for_uid(self, uid):
        normalized = _normalize_uid(uid)
        with closing(self._connect()) as db:
            rows = db.execute("SELECT version FROM canary_version_members WHERE uid = ?", (normalized,)).fetchall()
        return {row["version"] for row in rows}

    def is_canary_member(self, version, uid):
        if not uid or not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
            return False
        try:
            normalized = _normalize_uid(uid)
        except ValueError:
            return False
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT 1 FROM canary_version_members WHERE version = ? AND uid = ?",
                (version, normalized),
            ).fetchone()
        return row is not None

    def default_canary_uids(self):
        with closing(self._connect()) as db:
            rows = db.execute("SELECT uid FROM canary_default_members").fetchall()
        return {row["uid"] for row in rows}

    def list_default_canary_members(self):
        with closing(self._connect()) as db:
            rows = db.execute("""
                SELECT d.uid, d.note, d.added_at,
                       c.computer_name, c.local_ip, c.client_version, c.last_seen, c.auto_issue
                FROM canary_default_members d
                LEFT JOIN clients c ON c.uid = d.uid
                ORDER BY d.added_at DESC, d.uid
            """).fetchall()
        return [dict(row) for row in rows]

    def add_default_canary_members(self, uids, note=None):
        normalized_uids = [_normalize_uid(uid) for uid in uids]
        if note is not None and not isinstance(note, str):
            raise ValueError("Invalid note")
        cleaned_note = note.strip()[:200] if isinstance(note, str) and note.strip() else None
        now = int(self.clock())
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            for uid in normalized_uids:
                db.execute(
                    """
                    INSERT INTO canary_default_members (uid, note, added_at) VALUES (?, ?, ?)
                    ON CONFLICT(uid) DO UPDATE SET note = COALESCE(excluded.note, canary_default_members.note)
                    """,
                    (uid, cleaned_note, now),
                )
            return db.execute("SELECT COUNT(*) FROM canary_default_members").fetchone()[0]

    def remove_default_canary_members(self, uids):
        normalized_uids = [_normalize_uid(uid) for uid in uids]
        if not normalized_uids:
            return 0
        placeholders = ",".join("?" for _ in normalized_uids)
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute(f"DELETE FROM canary_default_members WHERE uid IN ({placeholders})", normalized_uids)
            return cur.rowcount

    def version_canary_counts(self):
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT version, COUNT(*) AS member_count FROM canary_version_members GROUP BY version"
            ).fetchall()
        return {row["version"]: row["member_count"] for row in rows}

    def list_version_canary_members(self, version):
        if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
            raise ValueError("Invalid version")
        with closing(self._connect()) as db:
            rows = db.execute("""
                SELECT m.uid, m.added_at, d.note,
                       CASE WHEN d.uid IS NULL THEN 0 ELSE 1 END AS in_default,
                       c.computer_name, c.local_ip, c.client_version, c.last_seen, c.auto_issue
                FROM canary_version_members m
                LEFT JOIN clients c ON c.uid = m.uid
                LEFT JOIN canary_default_members d ON d.uid = m.uid
                WHERE m.version = ?
                ORDER BY m.added_at DESC, m.uid
            """, (version,)).fetchall()
        return [dict(row) for row in rows]

    def add_version_canary_members(self, version, uids):
        if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
            raise ValueError("Invalid version")
        normalized_uids = [_normalize_uid(uid) for uid in uids]
        now = int(self.clock())
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            added = 0
            for uid in normalized_uids:
                cur = db.execute(
                    "INSERT OR IGNORE INTO canary_version_members (version, uid, added_at) VALUES (?, ?, ?)",
                    (version, uid, now),
                )
                added += cur.rowcount
            return added

    def remove_version_canary_members(self, version, uids):
        if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
            raise ValueError("Invalid version")
        normalized_uids = [_normalize_uid(uid) for uid in uids]
        if not normalized_uids:
            return 0
        placeholders = ",".join("?" for _ in normalized_uids)
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute(
                f"DELETE FROM canary_version_members WHERE version = ? AND uid IN ({placeholders})",
                [version, *normalized_uids],
            )
            return cur.rowcount

    def inherit_version_canary(self, target_version, source="default", mode="replace", *, updates_dir=None):
        if not isinstance(target_version, str) or not VERSION_PATTERN.fullmatch(target_version):
            raise ValueError("Invalid target version")
        if mode not in {"replace", "merge"}:
            raise ValueError("Invalid inherit mode")
        source_name = "default" if source is None else (str(source).strip() or "none")
        if source_name not in {"default", "none"}:
            if not VERSION_PATTERN.fullmatch(source_name):
                raise ValueError("Invalid inherit source version")
            if source_name == target_version:
                raise ValueError("Cannot inherit canary list from the same version")
            if updates_dir is not None and not (updates_dir / source_name / MANIFEST_FILENAME).is_file():
                raise FileNotFoundError(f"Source version {source_name} not found")
        now = int(self.clock())
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            if source_name == "none":
                source_uids = []
            elif source_name == "default":
                source_uids = [row[0] for row in db.execute("SELECT uid FROM canary_default_members").fetchall()]
            else:
                source_uids = [
                    row[0] for row in db.execute(
                        "SELECT uid FROM canary_version_members WHERE version = ?",
                        (source_name,),
                    ).fetchall()
                ]
            if mode == "replace":
                db.execute("DELETE FROM canary_version_members WHERE version = ?", (target_version,))
            for uid in source_uids:
                db.execute(
                    "INSERT OR IGNORE INTO canary_version_members (version, uid, added_at) VALUES (?, ?, ?)",
                    (target_version, uid, now),
                )
            return db.execute(
                "SELECT COUNT(*) FROM canary_version_members WHERE version = ?",
                (target_version,),
            ).fetchone()[0]

    def init_version_canary(self, version, inherit_from="default", *, updates_dir=None):
        return self.inherit_version_canary(version, source=inherit_from, mode="replace", updates_dir=updates_dir)

    def save_version_canary_as_default(self, version, mode="replace"):
        if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
            raise ValueError("Invalid version")
        if mode not in {"replace", "merge"}:
            raise ValueError("Invalid save mode")
        now = int(self.clock())
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            uids = [
                row[0] for row in db.execute(
                    "SELECT uid FROM canary_version_members WHERE version = ?",
                    (version,),
                ).fetchall()
            ]
            if mode == "replace":
                # Keep notes on UIDs that stay in the default allowlist.
                if uids:
                    placeholders = ",".join("?" for _ in uids)
                    db.execute(f"DELETE FROM canary_default_members WHERE uid NOT IN ({placeholders})", uids)
                else:
                    db.execute("DELETE FROM canary_default_members")
            for uid in uids:
                db.execute(
                    "INSERT OR IGNORE INTO canary_default_members (uid, note, added_at) VALUES (?, NULL, ?)",
                    (uid, now),
                )
            return db.execute("SELECT COUNT(*) FROM canary_default_members").fetchone()[0]

    def delete_version_canary(self, version):
        if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
            raise ValueError("Invalid version")
        with closing(self._connect()) as db, db:
            db.execute("DELETE FROM canary_version_members WHERE version = ?", (version,))


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


def _version_row(item, client_count, canary_count, csrf):
    version = escape(item["version"])
    stage = item["stage"]
    is_latest = item["is_latest"]
    is_latest_canary = item["is_latest_canary"]
    if is_latest:
        badge_class, status_label = "badge badge-ok", "当前推送"
    elif stage == STAGE_RELEASED:
        badge_class, status_label = "badge badge-accent", "全量启用"
    elif stage == STAGE_CANARY:
        badge_class = "badge badge-canary"
        status_label = "灰度推送中" if is_latest_canary else "灰度测试"
    else:
        badge_class, status_label = "badge badge-off", "已停用"

    if stage == STAGE_CANARY:
        stage_buttons = (
            f'<button type="submit" name="stage" value="{STAGE_RELEASED}" class="btn btn-sm btn-enable" aria-label="全量发布 {version}">全量发布</button>'
            f'<button type="submit" name="stage" value="{STAGE_DISABLED}" class="btn btn-sm btn-stop" aria-label="停用 {version}">停用</button>'
        )
    elif stage == STAGE_RELEASED:
        stage_buttons = (
            f'<button type="submit" name="stage" value="{STAGE_CANARY}" class="btn btn-sm btn-canary-outline" aria-label="转为灰度 {version}">转为灰度</button>'
            f'<button type="submit" name="stage" value="{STAGE_DISABLED}" class="btn btn-sm btn-stop" aria-label="停用 {version}">停用</button>'
        )
    else:
        stage_buttons = (
            f'<button type="submit" name="stage" value="{STAGE_CANARY}" class="btn btn-sm btn-canary" aria-label="开启灰度 {version}">开启灰度</button>'
            f'<button type="submit" name="stage" value="{STAGE_RELEASED}" class="btn btn-sm btn-enable" aria-label="全量发布 {version}">全量发布</button>'
        )

    published_at = item["published_at"]
    raw_source = escape(item.get("source") or "")
    source_label = escape(_source_label(item.get("source")))
    installer_bytes = item["artifacts"]["installer"].get("bytes", 0)
    unpacked_bytes = item["artifacts"]["unpacked"].get("bytes", 0)
    count_html = (
        f'<button type="button" class="chip version-filter-link" data-filter-version="{version}" '
        f'title="在客户端管理中查看使用 {version} 的客户端">{client_count} 台</button>'
        if client_count > 0
        else '<span class="muted-note">0 台</span>'
    )
    canary_cell = (
        f'<td><button type="button" class="chip canary-manage-btn" data-manage-canary="{version}" '
        f'data-stage="{stage}" title="管理 {version} 的独立灰度名单">{canary_count} 台 · 管理</button></td>'
    )
    return f"""
        <tr data-version="{version}" data-source="{raw_source}" data-stage="{stage}" data-enabled="{1 if stage == STAGE_RELEASED else 0}" data-is-latest="{1 if is_latest else 0}" data-is-latest-canary="{1 if is_latest_canary else 0}" data-client-count="{client_count}" data-canary-count="{canary_count}" data-installer-bytes="{installer_bytes}" data-unpacked-bytes="{unpacked_bytes}" data-published-at="{published_at}">
          <td><div class="version-cell"><code class="version-code">{version}</code><span class="source-tag">{source_label}</span></div></td>
          <td><span class="{badge_class}">{status_label}</span></td>
          <td class="ts-cell" data-ts="{published_at}">{_utc(published_at)}</td>
          {_artifact_cell(item["version"], "installer", item["artifacts"]["installer"])}
          {_artifact_cell(item["version"], "unpacked", item["artifacts"]["unpacked"])}
          <td>{count_html}</td>
          {canary_cell}
          <td class="action-cell">
            <div class="version-actions">
              <form method="post" action="/admin/updates/{version}/status" class="version-toggle-form">
                <input type="hidden" name="csrf" value="{csrf}">
                {stage_buttons}
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


def _client_row(client, csrf, in_default_canary=False):
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
    canary_badge = ' <span class="badge badge-canary" title="在默认灰度名单中">灰度</span>' if in_default_canary else ""
    canary_btn_cls = "btn-canary-outline" if in_default_canary else "btn-ghost"
    canary_btn_label = "移出灰度" if in_default_canary else "加入灰度"
    return f"""
        <tr data-uid="{uid}" data-computer="{computer_name}" data-ip="{local_ip}" data-version="{client_version}" data-first-seen="{client["first_seen"]}" data-last-seen="{client["last_seen"]}" data-expires-at="{expires_at}" data-auto-issue="{1 if allowed else 0}" data-canary="{1 if in_default_canary else 0}">
          <td class="uid-cell"><code class="uid-code" title="{uid}">{uid}</code></td>
          <td class="computer-name">{escape(client["computer_name"] or "—")}</td>
          <td>{escape(client["local_ip"] or "—")}</td>
          <td>{escape(client["client_version"] or "—")}</td>
          <td class="ts-cell" data-ts="{client["first_seen"]}">{_utc(client["first_seen"])}</td>
          <td class="ts-cell" data-ts="{client["last_seen"]}">{_utc(client["last_seen"])}</td>
          <td class="ts-cell expiry-cell" data-ts="{expires_at}">{_utc(client["expires_at"])}</td>
          <td class="status-cell"><span class="{badge_class}">{label}</span>{canary_badge}</td>
          <td class="action-cell"><div class="client-actions">
            <form method="post" action="/admin/clients/{uid}" class="toggle-form">
              <input type="hidden" name="csrf" value="{csrf}">
              <button type="submit" name="auto_issue" value="{new_value}" class="{button_class}" aria-label="{action} {uid}">{action}</button>
            </form>
            <button type="button" class="btn btn-sm {canary_btn_cls}" data-default-canary-toggle="{uid}" data-in-default="{1 if in_default_canary else 0}" aria-label="{canary_btn_label} {uid}">{canary_btn_label}</button>
          </div></td>
        </tr>
    """


def _default_canary_row(member):
    uid = escape(member["uid"])
    note = escape(member.get("note") or "")
    computer = escape(member.get("computer_name") or "")
    local_ip = escape(member.get("local_ip") or "")
    client_version = escape(member.get("client_version") or "")
    added_at = member["added_at"]
    if computer or local_ip or client_version:
        meta_parts = [part for part in (computer or "已登记设备", local_ip, client_version) if part]
        device_html = f'<span>{" · ".join(meta_parts)}</span>'
    else:
        device_html = '<span class="muted-note">尚未激活（预置白名单）</span>'
    return f"""
        <tr data-uid="{uid}" data-note="{note}" data-computer="{computer}" data-ip="{local_ip}" data-added-at="{added_at}">
          <td class="uid-cell"><code class="uid-code" title="{uid}">{uid}</code></td>
          <td>{device_html}</td>
          <td class="note-cell">{note or '<span class="muted-note">—</span>'}</td>
          <td class="ts-cell" data-ts="{added_at}">{_utc(added_at)}</td>
          <td class="action-cell">
            <button type="button" class="btn btn-sm btn-danger-outline" data-remove-default-canary="{uid}" aria-label="移出默认灰度 {uid}">移出名单</button>
          </td>
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
            def on_dist_published(version, stage):
                if stage == STAGE_CANARY:
                    registry.init_version_canary(version, "default")

            publisher = Thread(
                target=watch_distribution,
                args=(data_dir, distribution_dir, registry.signing_key, stop),
                kwargs={"on_published": on_dist_published},
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

    async def read_admin_json(request: Request, *, max_bytes=128 * 1024):
        raw = await request.body()
        if len(raw) > max_bytes:
            raise HTTPException(413, "Payload too large")
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise HTTPException(422, "Invalid JSON payload") from None
        if not isinstance(body, dict):
            raise HTTPException(422, "Invalid JSON payload")
        return body

    async def admin_form(request: Request, _=Depends(require_admin)):
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/x-www-form-urlencoded":
            raise HTTPException(415, "Expected an admin form")
        try:
            form = dict(parse_qsl((await request.body()).decode("ascii"), strict_parsing=True, max_num_fields=3))
        except ValueError:
            raise HTTPException(422, "Invalid admin form") from None
        verify_csrf(form.get("csrf", ""))
        return form

    def parse_client_uid_header(request: Request):
        raw = request.headers.get("X-PerfLens-UID")
        if not raw:
            return None
        normalized = raw.strip().lower()
        return normalized if _UID_RE.fullmatch(normalized) else None

    def ensure_version_dir(version: str):
        if not VERSION_PATTERN.fullmatch(version):
            raise HTTPException(422, "Invalid version")
        version_dir = updates / version
        if not version_dir.is_dir() or not (version_dir / MANIFEST_FILENAME).is_file():
            raise HTTPException(404, "Version not found")
        return version_dir

    def canary_modal_payload(version: str, stage: str):
        other_versions = [item["version"] for item in list_versions(updates) if item["version"] != version]
        return {
            "version": version,
            "stage": stage,
            "members": registry.list_version_canary_members(version),
            "default_count": len(registry.default_canary_uids()),
            "other_versions": other_versions,
        }

    def resolve_artifact_file(version: str, kind: str, *, require_accessible: bool, client_uid: str | None = None):
        name = artifact_names(version).get(kind) if VERSION_PATTERN.fullmatch(version) else None
        version_dir = updates / version
        if name is None or not (version_dir / MANIFEST_FILENAME).is_file() or not (version_dir / name).is_file():
            raise HTTPException(404, "Update artifact not found")
        if require_accessible:
            allowed = is_version_accessible(
                updates,
                version,
                is_canary_member=lambda ver: client_uid is not None and registry.is_canary_member(ver, client_uid),
            )
            if not allowed:
                raise HTTPException(404, "Update artifact not found")
        return version_dir / name, name

    @app.post(ACTIVATION_PATH)
    def activate(request: ActivationRequest):
        code = registry.issue(request.uid, request.client_version, local_ip=request.local_ip, computer_name=request.computer_name)
        if code is None:
            raise HTTPException(403, "issuance_disabled")
        return JSONResponse({"code": code}, headers={"Cache-Control": "no-store"})

    @app.get(f"{UPDATES_PATH}/latest")
    def latest_update(request: Request):
        uid = parse_client_uid_header(request)
        canary_versions = registry.canary_versions_for_uid(uid) if uid is not None else set()
        version = resolve_latest_version(updates, is_canary_member=lambda ver: ver in canary_versions)
        headers = {"Cache-Control": "no-store", "Vary": "X-PerfLens-UID"}
        if version is None:
            return Response(status_code=204, headers=headers)
        return FileResponse(updates / version / MANIFEST_FILENAME, media_type="application/json", headers=headers)

    @app.get(f"{UPDATES_PATH}/{{version}}/{{kind}}")
    def download_update(version: str, kind: str, request: Request):
        uid = parse_client_uid_header(request)
        path, name = resolve_artifact_file(version, kind, require_accessible=True, client_uid=uid)
        return FileResponse(path, filename=name, media_type="application/octet-stream", headers={"Vary": "X-PerfLens-UID"})

    @app.get("/admin", response_class=HTMLResponse, dependencies=[Depends(require_admin)])
    def admin():
        duration, clients = registry.view()
        now = int(registry.clock())
        enabled_count = sum(1 for client in clients if client["auto_issue"])
        disabled_count = len(clients) - enabled_count
        active_lease_count = sum(
            1 for client in clients if client["expires_at"] is not None and client["expires_at"] > now
        )
        default_canary_members = registry.list_default_canary_members()
        default_canary_uids = {member["uid"] for member in default_canary_members}
        canary_client_count = sum(1 for client in clients if client["uid"] in default_canary_uids)
        rows = "".join(_client_row(client, csrf, client["uid"] in default_canary_uids) for client in clients)
        default_canary_rows = "".join(_default_canary_row(member) for member in default_canary_members)
        client_version_counts = Counter(client["client_version"] for client in clients if client["client_version"])
        versions = list_versions(updates)
        canary_counts = registry.version_canary_counts()
        canary_version_count = sum(1 for item in versions if item["stage"] == STAGE_CANARY)
        released_version_count = sum(1 for item in versions if item["stage"] == STAGE_RELEASED)
        disabled_version_count = len(versions) - canary_version_count - released_version_count
        version_rows = "".join(
            _version_row(
                item,
                client_version_counts.get(item["version"], 0),
                canary_counts.get(item["version"], 0),
                csrf,
            )
            for item in versions
        )
        redundancy_items = scan_distribution_redundancy(updates, distribution_dir)
        distribution_html = _distribution_section(redundancy_items, distribution_dir, csrf)
        existing_versions_json = escape(json.dumps([item["version"] for item in versions]))
        latest_released = latest_version(updates)
        latest_canary = next((item["version"] for item in versions if item["is_latest_canary"]), None)
        latest_canary_pill = (
            f'<button type="button" id="latest-canary-pill" class="version-pill version-pill-canary version-pill-btn" '
            f'title="点击切换到版本管理">当前灰度版本 <strong>{escape(latest_canary)}</strong></button>'
            if latest_canary
            else ""
        )
        return HTMLResponse(
            template.substitute(
                duration=duration,
                csrf=csrf,
                count=len(clients),
                enabled_count=enabled_count,
                disabled_count=disabled_count,
                active_lease_count=active_lease_count,
                canary_client_count=canary_client_count,
                server_now=now,
                rows=rows,
                default_canary_count=len(default_canary_members),
                default_canary_rows=default_canary_rows,
                latest_version=latest_released or "—",
                latest_canary_pill=latest_canary_pill,
                version_count=len(versions),
                canary_version_count=canary_version_count,
                released_version_count=released_version_count,
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

    @app.post("/admin/canary/default/add", dependencies=[Depends(require_admin_csrf)])
    async def add_default_canary(request: Request):
        body = await read_admin_json(request, max_bytes=256 * 1024)
        try:
            uids = _normalize_uid_list(body)
            total = await asyncio.to_thread(registry.add_default_canary_members, uids, note=body.get("note"))
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        return JSONResponse(
            {"default_count": total, "members": registry.list_default_canary_members()},
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/admin/canary/default/remove", dependencies=[Depends(require_admin_csrf)])
    async def remove_default_canary(request: Request):
        body = await read_admin_json(request, max_bytes=256 * 1024)
        try:
            uids = _normalize_uid_list(body)
            removed = await asyncio.to_thread(registry.remove_default_canary_members, uids)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        members = registry.list_default_canary_members()
        return JSONResponse(
            {"removed": removed, "default_count": len(members), "members": members},
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/admin/updates/upload/init", dependencies=[Depends(require_admin)])
    async def init_update_upload(request: Request):
        body = await read_admin_json(request)
        verify_csrf(request.headers.get("X-CSRF-Token") or body.get("csrf", ""))
        stage = body.get("stage", STAGE_CANARY)
        if not isinstance(stage, str) or stage not in VALID_STAGES:
            raise HTTPException(422, "Invalid version stage")
        inherit_from = body.get("inherit_from", "default")
        if not isinstance(inherit_from, str):
            raise HTTPException(422, "Invalid inherit_from value")
        inherit_from = inherit_from.strip() or "none"
        if inherit_from not in {"default", "none"}:
            if not VERSION_PATTERN.fullmatch(inherit_from) or not (updates / inherit_from / MANIFEST_FILENAME).is_file():
                raise HTTPException(422, f"Inherit source version {inherit_from} not found")
        try:
            session = await asyncio.to_thread(
                upload_manager.create_session,
                body.get("manifest"),
                stage=stage,
                inherit_from=inherit_from,
            )
        except UpdateConflictError as error:
            raise HTTPException(409, str(error)) from None
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        return JSONResponse(session, headers={"Cache-Control": "no-store"})

    @app.post("/admin/updates/upload/{session_id}/complete", dependencies=[Depends(require_admin_csrf)])
    async def complete_update_upload(session_id: str):
        initialized_version = None
        published_stage = STAGE_CANARY

        def on_web_published(version, stage, inherit_from):
            nonlocal initialized_version, published_stage
            published_stage = stage
            if stage == STAGE_CANARY:
                registry.init_version_canary(version, inherit_from, updates_dir=updates)
                initialized_version = version

        try:
            version = await asyncio.to_thread(upload_manager.complete_session, session_id, on_published=on_web_published)
        except KeyError as error:
            raise HTTPException(404, str(error)) from None
        except FileNotFoundError as error:
            raise HTTPException(422, str(error)) from None
        except UpdateConflictError as error:
            raise HTTPException(409, str(error)) from None
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        except BaseException:
            if initialized_version is not None:
                registry.delete_version_canary(initialized_version)
            raise
        return JSONResponse({"version": version, "stage": published_stage}, headers={"Cache-Control": "no-store"})

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

    @app.get("/admin/updates/{version}/canary", dependencies=[Depends(require_admin)])
    def get_version_canary(version: str):
        version_dir = ensure_version_dir(version)
        return JSONResponse(canary_modal_payload(version, version_stage(version_dir)), headers={"Cache-Control": "no-store"})

    @app.post("/admin/updates/{version}/canary/add", dependencies=[Depends(require_admin_csrf)])
    async def add_version_canary(version: str, request: Request):
        version_dir = ensure_version_dir(version)
        body = await read_admin_json(request, max_bytes=256 * 1024)
        try:
            uids = _normalize_uid_list(body)
            added = await asyncio.to_thread(registry.add_version_canary_members, version, uids)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        payload = canary_modal_payload(version, version_stage(version_dir))
        payload["added"] = added
        return JSONResponse(payload, headers={"Cache-Control": "no-store"})

    @app.post("/admin/updates/{version}/canary/remove", dependencies=[Depends(require_admin_csrf)])
    async def remove_version_canary(version: str, request: Request):
        version_dir = ensure_version_dir(version)
        body = await read_admin_json(request, max_bytes=256 * 1024)
        try:
            uids = _normalize_uid_list(body)
            removed = await asyncio.to_thread(registry.remove_version_canary_members, version, uids)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        payload = canary_modal_payload(version, version_stage(version_dir))
        payload["removed"] = removed
        return JSONResponse(payload, headers={"Cache-Control": "no-store"})

    @app.post("/admin/updates/{version}/canary/inherit", dependencies=[Depends(require_admin_csrf)])
    async def inherit_version_canary_endpoint(version: str, request: Request):
        version_dir = ensure_version_dir(version)
        body = await read_admin_json(request)
        source = body.get("source", "default")
        mode = body.get("mode", "replace")
        try:
            await asyncio.to_thread(registry.inherit_version_canary, version, source, mode, updates_dir=updates)
        except FileNotFoundError as error:
            raise HTTPException(404, str(error)) from None
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        return JSONResponse(canary_modal_payload(version, version_stage(version_dir)), headers={"Cache-Control": "no-store"})

    @app.post("/admin/updates/{version}/canary/save-default", dependencies=[Depends(require_admin_csrf)])
    async def save_version_canary_default(version: str, request: Request):
        ensure_version_dir(version)
        raw = await request.body()
        if raw:
            try:
                body = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise HTTPException(422, "Invalid JSON payload") from None
            if not isinstance(body, dict):
                raise HTTPException(422, "Invalid JSON payload")
            mode = body.get("mode", "replace")
        else:
            mode = "replace"
        try:
            default_count = await asyncio.to_thread(registry.save_version_canary_as_default, version, mode=mode)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        return JSONResponse({"default_count": default_count}, headers={"Cache-Control": "no-store"})

    @app.get("/admin/updates/{version}/{kind}", dependencies=[Depends(require_admin)])
    def admin_download_update(version: str, kind: str):
        # Admins can always download artifacts, including canary and disabled versions for internal testing.
        path, name = resolve_artifact_file(version, kind, require_accessible=False)
        return FileResponse(path, filename=name, media_type="application/octet-stream", headers={"Cache-Control": "no-store"})

    @app.post("/admin/updates/{version}/status")
    def update_version_status(version: str, form=Depends(admin_form)):
        try:
            if "stage" in form:
                stage = form["stage"]
                if stage not in VALID_STAGES:
                    raise HTTPException(422, "Invalid version stage")
                updated = set_version_stage(updates, version, stage)
            elif "enabled" in form:
                enabled = form["enabled"]
                if enabled not in {"0", "1"}:
                    raise HTTPException(422, "Invalid enabled value")
                updated = set_version_enabled(updates, version, enabled == "1")
            else:
                raise HTTPException(422, "Missing stage value")
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
        registry.delete_version_canary(version)
        return RedirectResponse("/admin", status_code=303)

    return app
