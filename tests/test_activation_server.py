"""Run the issuance and admin routes over loopback with a disposable signing key."""
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
from http.client import HTTPConnection
import json
from pathlib import Path
import re
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import uvicorn

from activation_server.app import Registry, create_app
from activation_server.protocol import ACTIVATION_PATH, verify_code
from activation_server.updates import (
    SIGNING_PREFIX,
    UPDATES_PATH,
    UploadSessionManager,
    artifact_names,
    publish_update,
)


class ActivationServerTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix="perflens-server-test-"))
        self.key = Ed25519PrivateKey.generate()
        self.now = 1800000000
        self.uid = "a" * 64
        self.db = self.folder / "activation.sqlite3"
        self.registry = Registry(self.db, self.key, lambda: self.now)

    def start_server(self, *, distribution_dir=None):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        self.port = listener.getsockname()[1]
        app = create_app(self.registry, "test-admin", "test-password", distribution_dir=distribution_dir)
        server = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="on"))
        worker = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        worker.start()

        def stop_server():
            server.should_exit = True
            worker.join(5)

        self.addCleanup(stop_server)
        deadline = time.monotonic() + 5
        while not server.started:
            self.assertTrue(worker.is_alive() and time.monotonic() < deadline, "Loopback activation server failed to start")
            time.sleep(.01)

    def request(self, method, path, data=None, *, auth=None, content_type=None, headers=None):
        req_headers = dict(headers or {})
        if auth:
            req_headers["Authorization"] = "Basic " + base64.b64encode(auth).decode("ascii")
        if content_type:
            req_headers["Content-Type"] = content_type
        with closing(HTTPConnection("127.0.0.1", self.port, timeout=5)) as connection:
            connection.request(method, path, body=data, headers=req_headers)
            response = connection.getresponse()
            return response.status, response.read().decode("utf-8")

    def write_release(self, folder, version):
        folder.mkdir(exist_ok=True)
        public = self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        artifacts = []
        for name in artifact_names(version).values():
            contents = name.encode("ascii")
            (folder / name).write_bytes(contents)
            artifacts.append({"file": name, "bytes": len(contents), "sha256": hashlib.sha256(contents).hexdigest()})
        record = {"version": version, "activation_server": "http://127.0.0.1:8787", "artifacts": artifacts,
                  "activation_public_key_sha256": hashlib.sha256(public).hexdigest()}
        (folder / "manifest.json").write_text(json.dumps(record), encoding="utf-8")
        return folder

    def test_lan_http_admin_requires_opt_in_and_credentials(self):
        async def get_admin_status(app, auth=None):
            headers = [(b"authorization", b"Basic " + base64.b64encode(auth))] if auth else []
            scope = {
                "type": "http",
                "http_version": "1.1",
                "method": "GET",
                "path": "/admin",
                "scheme": "http",
                "query_string": b"",
                "headers": headers,
                "client": ("192.0.2.10", 50000),
            }
            messages = []

            async def receive():
                return {"type": "http.request", "body": b""}

            async def send(message):
                messages.append(message)

            await app(scope, receive, send)
            return messages[0]["status"]

        auth = b"test-admin:test-password"
        with patch.dict("os.environ", {"PERFLENS_ADMIN_ALLOW_HTTP": ""}):
            restricted = create_app(self.registry, "test-admin", "test-password")
        with patch.dict("os.environ", {"PERFLENS_ADMIN_ALLOW_HTTP": "1"}):
            enabled = create_app(self.registry, "test-admin", "test-password")

        self.assertEqual(asyncio.run(get_admin_status(restricted, auth)), 403)
        self.assertEqual(asyncio.run(get_admin_status(enabled)), 401)
        self.assertEqual(asyncio.run(get_admin_status(enabled, b"test-admin:wrong")), 401)
        self.assertEqual(asyncio.run(get_admin_status(enabled, auth)), 200)

    def test_registration_duration_and_authenticated_admin_writes(self):
        self.start_server()
        auth = b"test-admin:test-password"
        self.assertEqual(self.request("GET", "/admin")[0], 401)
        self.assertEqual(self.request("GET", "/admin", auth=b"test-admin:wrong")[0], 401)
        self.assertEqual(self.request("POST", "/admin/settings")[0], 401)
        status, html = self.request("GET", "/admin", auth=auth)
        self.assertEqual(status, 200)
        self.assertIn('value="1440"', html)
        csrf = re.search(r'name="csrf" value="([^"]+)"', html)[1]

        def submit(path, values):
            return self.request("POST", path, urlencode(values), auth=auth,
                                content_type="application/x-www-form-urlencoded")[0]

        def activate(uid=self.uid):
            status, body = self.request("POST", ACTIVATION_PATH, json.dumps({"uid": uid}), content_type="application/json")
            return status, json.loads(body)

        self.assertEqual(activate("wrong-uid")[0], 422)
        status, initial = activate()
        self.assertEqual(status, 200)
        first_expiry = verify_code(initial["code"], self.uid, self.key.public_key())
        self.assertEqual(first_expiry, self.now + 86400)
        self.assertIn(self.uid, self.request("GET", "/admin", auth=auth)[1])

        self.assertEqual(submit("/admin/settings", {"duration_minutes": 2}), 403)
        self.assertEqual(submit("/admin/settings", {"duration_minutes": 0, "csrf": csrf}), 422)
        self.assertEqual(submit("/admin/settings", {"duration_minutes": 2, "csrf": csrf}), 303)
        self.now += 30
        self.assertEqual(activate(), (200, initial))

        client = f"/admin/clients/{self.uid}"
        self.assertEqual(submit(client, {"auto_issue": "0", "csrf": csrf}), 303)
        self.assertEqual(activate(), (403, {"detail": "issuance_disabled"}))
        reopened = Registry(self.db, self.key, lambda: self.now)
        duration, clients = reopened.view()
        self.assertEqual(duration, 2)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0]["last_seen"], self.now)
        self.assertEqual(clients[0]["expires_at"], first_expiry)
        self.assertIsNone(reopened.issue(self.uid))
        self.assertEqual(submit(client, {"auto_issue": "1", "csrf": csrf}), 303)
        self.assertEqual(reopened.issue(self.uid), initial["code"])
        self.now = first_expiry
        status, renewed = activate()
        self.assertEqual(status, 200)
        self.assertEqual(verify_code(renewed["code"], self.uid, self.key.public_key()), self.now + 120)

    def test_concurrent_first_requests_share_one_lease(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            codes = set(pool.map(self.registry.issue, [self.uid] * 8))
        self.assertEqual(len(codes), 1)
        self.assertEqual(len(self.registry.view()[1]), 1)

    def test_legacy_database_preserves_lease_and_records_latest_client_metadata(self):
        old_db = self.folder / "legacy.sqlite3"
        expiry = self.now + 60
        with closing(sqlite3.connect(old_db)) as db, db:
            db.execute("CREATE TABLE clients (uid TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, "
                       "auto_issue INTEGER NOT NULL DEFAULT 1, expires_at INTEGER)")
            db.execute("INSERT INTO clients VALUES (?, ?, ?, 1, ?)", (self.uid, self.now - 60, self.now, expiry))
        self.registry = Registry(old_db, self.key, lambda: self.now)
        self.start_server()

        def activate(**fields):
            return self.request("POST", ACTIVATION_PATH, json.dumps({"uid": self.uid, **fields}), content_type="application/json")

        auth = b"test-admin:test-password"
        self.assertIn('<td class="computer-name">—</td>', self.request("GET", "/admin", auth=auth)[1])
        code, body = activate(client_version="0.4.1", local_ip="2001:0db8::1", computer_name="测试机<01>")
        self.assertEqual(code, 200)
        self.assertEqual(verify_code(json.loads(body)["code"], self.uid, self.key.public_key()), expiry)
        html = self.request("GET", "/admin", auth=auth)[1]
        self.assertIn("<td>2001:db8::1</td>", html)
        self.assertIn("测试机&lt;01&gt;", html)
        self.assertEqual(activate(), (code, body))
        self.assertEqual(activate(local_ip="192.0.2.41"), (code, body))
        self.registry.set_auto_issue(self.uid, False)
        self.assertEqual(activate(client_version="0.4.2", local_ip="192.0.2.42", computer_name="Other")[0], 403)
        self.assertEqual(activate(client_version="<script>")[0], 422)
        self.assertEqual(activate(local_ip="999.0.0.1")[0], 422)
        reopened = Registry(old_db, self.key, lambda: self.now)
        row = reopened.view()[1][0]
        self.assertEqual((row["first_seen"], row["expires_at"], row["client_version"]), (self.now - 60, expiry, "0.4.1"))
        self.assertEqual((row["local_ip"], row["computer_name"]), ("192.0.2.41", "测试机<01>"))
        html = self.request("GET", "/admin", auth=auth)[1]
        self.assertIn("<td>0.4.1</td>", html)
        self.assertIn("<td>192.0.2.41</td>", html)

    def test_published_manifest_is_signed_and_downloads_stay_versioned(self):
        self.start_server()
        latest = f"{UPDATES_PATH}/latest"
        self.assertEqual(self.request("GET", latest), (204, ""))
        old = self.write_release(self.folder / "old", "0.9.0")
        newest = self.write_release(self.folder / "newest", "0.10.0")
        bad = self.write_release(self.folder / "bad", "0.11.0")
        self.assertEqual(publish_update(self.folder, old, self.key), "0.9.0")
        with self.assertRaisesRegex(ValueError, "already published"):
            publish_update(self.folder, old, self.key)
        with self.assertRaisesRegex(ValueError, "public key"):
            publish_update(self.folder, newest, Ed25519PrivateKey.generate())
        tampered = bad / artifact_names("0.11.0")["unpacked"]
        tampered.write_bytes(b"x" * tampered.stat().st_size)
        with self.assertRaisesRegex(ValueError, "mismatch"):
            publish_update(self.folder, bad, self.key)
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.11.0/installer")[0], 404)
        publish_update(self.folder, newest, self.key)
        code, body = self.request("GET", latest)
        self.assertEqual(code, 200)
        envelope = json.loads(body)
        payload = base64.b64decode(envelope["payload"])
        self.key.public_key().verify(base64.b64decode(envelope["signature"]), SIGNING_PREFIX + payload)
        signed = json.loads(payload)
        self.assertEqual((signed["version"], signed["server_url"]), ("0.10.0", "http://127.0.0.1:8787"))
        for kind, name in artifact_names("0.10.0").items():
            self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/{kind}"), (200, name))
            self.assertEqual(signed["artifacts"][kind]["sha256"], hashlib.sha256(name.encode("ascii")).hexdigest())
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.9.0/installer"), (200, artifact_names("0.9.0")["installer"]))
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/portable")[0], 404)
        self.assertIn("当前发布版本 <strong>0.10.0</strong>", self.request("GET", "/admin", auth=b"test-admin:test-password")[1])

    def test_distribution_publishes_complete_releases_without_restarting(self):
        distribution = self.folder / "custom distribution"
        distribution.mkdir()
        self.enterContext(patch("activation_server.updates.DISTRIBUTION_POLL_SECONDS", 0.02))
        self.start_server(distribution_dir=distribution)
        latest = f"{UPDATES_PATH}/latest"
        self.assertEqual(self.request("GET", latest), (204, ""))

        def wait_for_version(expected):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                code, body = self.request("GET", latest)
                if code == 200:
                    envelope = json.loads(body)
                    payload = base64.b64decode(envelope["payload"])
                    if json.loads(payload)["version"] == expected:
                        signature = base64.b64decode(envelope["signature"])
                        self.key.public_key().verify(signature, SIGNING_PREFIX + payload)
                        return code, body
                time.sleep(.01)
            self.fail(f"Update {expected} did not become available")

        self.write_release(distribution, "0.9.0")
        previous = wait_for_version("0.9.0")
        release = self.write_release(self.folder / "newest", "0.10.0")
        names = artifact_names("0.10.0")
        installer = distribution / names["installer"]
        installer.write_bytes(b"partial")
        (distribution / names["unpacked"]).write_bytes((release / names["unpacked"]).read_bytes())
        with self.assertLogs("uvicorn.error", level="WARNING") as logs:
            (distribution / "manifest.json").write_bytes((release / "manifest.json").read_bytes())
            deadline = time.monotonic() + 5
            while not any("Size mismatch" in line for line in logs.output):
                self.assertLess(time.monotonic(), deadline, "Incomplete upload was not checked")
                time.sleep(.01)
        self.assertEqual(self.request("GET", latest), previous)
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/installer")[0], 404)

        installer.write_bytes((release / installer.name).read_bytes())
        wait_for_version("0.10.0")
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/installer"), (200, installer.name))
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.9.0/installer"), (200, artifact_names("0.9.0")["installer"]))
        # Verify watched distribution consumes published files so no duplicate copies remain.
        self.assertFalse((distribution / "manifest.json").exists())
        self.assertFalse(installer.exists())
        self.assertFalse((distribution / names["unpacked"]).exists())

    def test_admin_page_renders_summary_stats_and_row_metadata(self):
        self.start_server()
        auth = b"test-admin:test-password"
        uid_active = "1" * 64
        uid_expired_disabled = "2" * 64
        self.registry.issue(uid_active, "0.9.0", local_ip="192.168.1.10", computer_name='Node"A"<1>')
        self.now -= 100000
        self.registry.issue(uid_expired_disabled, "0.8.0", local_ip="192.168.1.2", computer_name="NodeB")
        self.registry.set_auto_issue(uid_expired_disabled, False)
        self.now += 100000

        status, html = self.request("GET", "/admin", auth=auth)
        self.assertEqual(status, 200)
        self.assertIn(f'data-server-now="{self.now}"', html)
        self.assertIn('<strong class="stat-value" id="stat-total">2</strong>', html)
        self.assertIn('<strong class="stat-value" id="stat-enabled">1</strong>', html)
        self.assertIn('<strong class="stat-value" id="stat-disabled">1</strong>', html)
        self.assertIn('<strong class="stat-value" id="stat-active">1</strong>', html)
        self.assertIn('data-computer="Node&quot;A&quot;&lt;1&gt;"', html)
        self.assertIn(f'data-uid="{uid_expired_disabled}"', html)
        self.assertIn('data-auto-issue="0"', html)

    def test_move_publish_preserves_sources_on_verification_failure(self):
        bad = self.write_release(self.folder / "bad-move", "0.11.0")
        names = artifact_names("0.11.0")
        tampered = bad / names["unpacked"]
        tampered.write_bytes(b"x" * tampered.stat().st_size)
        with self.assertRaisesRegex(ValueError, "mismatch"):
            publish_update(self.folder, bad, self.key, move_artifacts=True, source="distribution")
        # Both source files and manifest must remain intact if verification fails after staging.
        self.assertTrue((bad / names["installer"]).is_file())
        self.assertTrue(tampered.is_file())
        self.assertTrue((bad / "manifest.json").is_file())

    def test_web_chunked_upload_and_version_lifecycle(self):
        self.enterContext(patch("activation_server.updates.UPLOAD_CHUNK_BYTES", 8))
        self.start_server()
        auth = b"test-admin:test-password"
        self.registry.issue("1" * 64, "0.9.0", computer_name="Node09")

        _, html = self.request("GET", "/admin", auth=auth)
        csrf = re.search(r'name="csrf" value="([^"]+)"', html)[1]

        def upload_release(version, *, enabled=True, tamper=False):
            rel = self.write_release(self.folder / f"web-{version}-{'tamper' if tamper else 'ok'}", version)
            manifest = json.loads((rel / "manifest.json").read_text(encoding="utf-8"))
            status, body = self.request(
                "POST",
                "/admin/updates/upload/init",
                json.dumps({"manifest": manifest, "enabled": enabled}),
                auth=auth,
                content_type="application/json",
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(status, 200, body)
            session = json.loads(body)
            sid = session["session_id"]
            chunk_size = session["chunk_bytes"]
            self.assertEqual(chunk_size, 8)
            for kind, name in artifact_names(version).items():
                payload = (rel / name).read_bytes()
                if tamper and kind == "unpacked":
                    payload = b"X" * len(payload)
                offset = 0
                while offset < len(payload):
                    piece = payload[offset:offset + chunk_size]
                    c_status, c_body = self.request(
                        "POST",
                        f"/admin/updates/upload/{sid}/{kind}",
                        piece,
                        auth=auth,
                        content_type="application/octet-stream",
                        headers={"X-CSRF-Token": csrf, "X-Chunk-Offset": str(offset)},
                    )
                    self.assertEqual(c_status, 200, c_body)
                    offset += len(piece)
            return self.request(
                "POST",
                f"/admin/updates/upload/{sid}/complete",
                b"{}",
                auth=auth,
                content_type="application/json",
                headers={"X-CSRF-Token": csrf},
            ), rel

        # Auth and CSRF checks on upload init.
        self.assertEqual(self.request("POST", "/admin/updates/upload/init", b"{}")[0], 401)
        self.assertEqual(
            self.request("POST", "/admin/updates/upload/init", b"{}", auth=auth, content_type="application/json")[0],
            403,
        )

        # Public key mismatch rejected at init before transferring bytes.
        wrong_manifest = json.loads((self.write_release(self.folder / "wrong-key", "0.8.0") / "manifest.json").read_text())
        wrong_manifest["activation_public_key_sha256"] = "0" * 64
        self.assertEqual(
            self.request(
                "POST",
                "/admin/updates/upload/init",
                json.dumps({"manifest": wrong_manifest}),
                auth=auth,
                content_type="application/json",
                headers={"X-CSRF-Token": csrf},
            )[0],
            422,
        )

        # Tampered artifact rejected on complete with SHA-256 error and staging cleaned up.
        (tamper_status, tamper_body), _ = upload_release("0.8.1", tamper=True)
        self.assertEqual(tamper_status, 422)
        self.assertIn("SHA-256 mismatch", tamper_body)
        self.assertFalse(list((self.folder / "updates").glob(".uploading-*")))

        # Successful upload of 0.9.0 (enabled) and 0.10.0 (disabled initially for internal testing).
        (st_090, body_090), _ = upload_release("0.9.0", enabled=True)
        self.assertEqual(st_090, 200)
        self.assertEqual(json.loads(body_090)["version"], "0.9.0")

        # Duplicate version 0.9.0 rejected with 409 at init.
        dup_manifest = json.loads((self.write_release(self.folder / "dup-0.9.0", "0.9.0") / "manifest.json").read_text())
        self.assertEqual(
            self.request(
                "POST",
                "/admin/updates/upload/init",
                json.dumps({"manifest": dup_manifest}),
                auth=auth,
                content_type="application/json",
                headers={"X-CSRF-Token": csrf},
            )[0],
            409,
        )

        (st_100, _), _ = upload_release("0.10.0", enabled=False)
        self.assertEqual(st_100, 200)

        # Disabled 0.10.0 must not appear in /latest or public downloads, while admin download works.
        latest_code, latest_body = self.request("GET", f"{UPDATES_PATH}/latest")
        self.assertEqual(latest_code, 200)
        latest_payload = json.loads(base64.b64decode(json.loads(latest_body)["payload"]))
        self.assertEqual(latest_payload["version"], "0.9.0")
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/installer")[0], 404)
        self.assertEqual(
            self.request("GET", "/admin/updates/0.10.0/installer", auth=auth),
            (200, artifact_names("0.10.0")["installer"]),
        )

        # Admin HTML reflects version list and client version usage count.
        _, admin_html = self.request("GET", "/admin", auth=auth)
        self.assertIn('data-filter-version="0.9.0"', admin_html)
        self.assertIn("1 台", admin_html)

        # Enable 0.10.0 -> /latest switches to 0.10.0 and public download opens.
        self.assertEqual(
            self.request(
                "POST",
                "/admin/updates/0.10.0/status",
                urlencode({"enabled": "1", "csrf": csrf}),
                auth=auth,
                content_type="application/x-www-form-urlencoded",
            )[0],
            303,
        )
        latest_payload = json.loads(base64.b64decode(json.loads(self.request("GET", f"{UPDATES_PATH}/latest")[1])["payload"]))
        self.assertEqual(latest_payload["version"], "0.10.0")
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/installer")[0], 200)

        # Disable 0.10.0 -> /latest rolls back to 0.9.0 and public download blocks 0.10.0 again.
        self.assertEqual(
            self.request(
                "POST",
                "/admin/updates/0.10.0/status",
                urlencode({"enabled": "0", "csrf": csrf}),
                auth=auth,
                content_type="application/x-www-form-urlencoded",
            )[0],
            303,
        )
        latest_payload = json.loads(base64.b64decode(json.loads(self.request("GET", f"{UPDATES_PATH}/latest")[1])["payload"]))
        self.assertEqual(latest_payload["version"], "0.9.0")
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/installer")[0], 404)

        # Delete 0.10.0 and verify it can be re-uploaded afterward.
        self.assertEqual(
            self.request(
                "POST",
                "/admin/updates/0.10.0/delete",
                urlencode({"csrf": csrf}),
                auth=auth,
                content_type="application/x-www-form-urlencoded",
            )[0],
            303,
        )
        self.assertFalse((self.folder / "updates" / "0.10.0").exists())
        (st_reup, _), _ = upload_release("0.10.0", enabled=True)
        self.assertEqual(st_reup, 200)

        # Abort cleans up staging immediately.
        rel_abort = self.write_release(self.folder / "abort-0.11.0", "0.11.0")
        abort_manifest = json.loads((rel_abort / "manifest.json").read_text(encoding="utf-8"))
        _, init_body = self.request(
            "POST",
            "/admin/updates/upload/init",
            json.dumps({"manifest": abort_manifest}),
            auth=auth,
            content_type="application/json",
            headers={"X-CSRF-Token": csrf},
        )
        abort_sid = json.loads(init_body)["session_id"]
        # Wrong offset rejected with 409; chunk exceeding chunk_bytes rejected with 413.
        self.assertEqual(
            self.request(
                "POST",
                f"/admin/updates/upload/{abort_sid}/installer",
                b"1234",
                auth=auth,
                content_type="application/octet-stream",
                headers={"X-CSRF-Token": csrf, "X-Chunk-Offset": "4"},
            )[0],
            409,
        )
        self.assertEqual(
            self.request(
                "POST",
                f"/admin/updates/upload/{abort_sid}/installer",
                b"123456789",
                auth=auth,
                content_type="application/octet-stream",
                headers={"X-CSRF-Token": csrf, "X-Chunk-Offset": "0"},
            )[0],
            413,
        )
        self.assertEqual(
            self.request(
                "POST",
                f"/admin/updates/upload/{abort_sid}/installer",
                b"1234",
                auth=auth,
                content_type="application/octet-stream",
                headers={"X-CSRF-Token": csrf, "X-Chunk-Offset": "0"},
            )[0],
            200,
        )
        self.assertTrue(list((self.folder / "updates").glob(".uploading-*")))
        del_status, del_body = self.request(
            "DELETE",
            f"/admin/updates/upload/{abort_sid}",
            auth=auth,
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(del_status, 200)
        self.assertTrue(json.loads(del_body)["aborted"])
        self.assertFalse(list((self.folder / "updates").glob(".uploading-*")))

        # Disabling all remaining versions makes /latest return 204.
        for ver in ("0.9.0", "0.10.0"):
            self.request(
                "POST",
                f"/admin/updates/{ver}/status",
                urlencode({"enabled": "0", "csrf": csrf}),
                auth=auth,
                content_type="application/x-www-form-urlencoded",
            )
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/latest"), (204, ""))

    def test_distribution_redundancy_scan_and_clean_preserves_unknown_files(self):
        distribution = self.folder / "dist-redundant"
        distribution.mkdir()
        self.start_server(distribution_dir=distribution)
        auth = b"test-admin:test-password"

        rel_090 = self.write_release(self.folder / "src-0.9.0", "0.9.0")
        publish_update(self.folder, rel_090, self.key, move_artifacts=False)
        # Simulate historical leftovers in distribution for an already published version.
        self.write_release(distribution, "0.9.0")
        keep_note = distribution / "keep-me.txt"
        keep_note.write_text("unrelated", encoding="utf-8")
        # Also keep an unpublished version artifact that shouldn't be removed by redundancy cleaner.
        unpublished_name = artifact_names("0.11.0")["installer"]
        unpublished_file = distribution / unpublished_name
        unpublished_file.write_bytes(b"new-build")

        _, html = self.request("GET", "/admin", auth=auth)
        self.assertIn("历史冗余文件", html)
        self.assertIn(artifact_names("0.9.0")["installer"], html)
        csrf = re.search(r'name="csrf" value="([^"]+)"', html)[1]

        status, _ = self.request(
            "POST",
            "/admin/updates/distribution/clean",
            urlencode({"csrf": csrf}),
            auth=auth,
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(status, 303)
        self.assertFalse((distribution / "manifest.json").exists())
        self.assertFalse((distribution / artifact_names("0.9.0")["installer"]).exists())
        self.assertFalse((distribution / artifact_names("0.9.0")["unpacked"]).exists())
        self.assertTrue(keep_note.is_file())
        self.assertTrue(unpublished_file.is_file())

    def test_upload_session_manager_prunes_stale_staging_dirs(self):
        updates = self.folder / "updates"
        updates.mkdir()
        stale = updates / ".uploading-deadbeef-123"
        stale.mkdir()
        (stale / "part.bin").write_bytes(b"stale")
        now = 2000000000
        manager = UploadSessionManager(updates, self.key, session_ttl=60, clock=lambda: now)
        # Force mtime older than TTL.
        import os
        os.utime(stale, (now - 120, now - 120))
        manager.prune_stale()
        self.assertFalse(stale.exists())
