"""Run the issuance and admin routes over loopback with a disposable signing key."""
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stderr
import hashlib
from http.client import HTTPConnection
from io import StringIO
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
from activation_server.protocol import ACTIVATION_PATH, public_key_fingerprint, verify_code
from activation_server.updates import (
    SIGNING_PREFIX,
    STAGE_CANARY,
    STAGE_DISABLED,
    STAGE_RELEASED,
    UPDATES_PATH,
    UploadSessionManager,
    artifact_names,
    publish_update,
)


class ActivationServerTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix="perflens-server-test-"))
        self.key = Ed25519PrivateKey.generate()
        self.public_key = self.key.public_key()
        self.now = 1800000000
        self.uid = "a" * 64
        self.db = self.folder / "activation.sqlite3"
        self.registry = Registry(self.db, self.key, lambda: self.now)

    def application(self, **options):
        return create_app(self.registry, "test-admin", "test-password", **options)

    def start_server(self, *, distribution_dir=None):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        self.port = listener.getsockname()[1]
        app = self.application(distribution_dir=distribution_dir)
        server = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="on", proxy_headers=False))
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

    def read_update_manifest(self, body):
        envelope = json.loads(body)
        self.assertEqual(set(envelope), {"payload", "signature"})
        payload = base64.b64decode(envelope["payload"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        self.public_key.verify(signature, SIGNING_PREFIX + payload)
        return json.loads(payload)

    def write_release(self, folder, version, *, origin="https://activation.example.test:8787"):
        folder.mkdir(exist_ok=True)
        artifacts = []
        for name in artifact_names(version).values():
            contents = name.encode("ascii")
            (folder / name).write_bytes(contents)
            artifacts.append({"file": name, "bytes": len(contents), "sha256": hashlib.sha256(contents).hexdigest()})
        record = {"version": version, "activation_server": origin, "artifacts": artifacts,
                  "activation_public_key_sha256": public_key_fingerprint(self.public_key)}
        (folder / "manifest.json").write_text(json.dumps(record), encoding="utf-8")
        return folder

    def test_remote_transport_requires_lan_opt_in_and_admin_authentication(self):
        async def request_status(app, scheme, peer="192.168.8.10", auth=None, path="/admin", payload=None):
            headers = [(b"x-forwarded-for", b"192.168.8.10")]
            if auth:
                headers.append((b"authorization", b"Basic " + base64.b64encode(auth)))
            if payload is not None:
                headers.append((b"content-type", b"application/json"))
            scope = {
                "type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
                "http_version": "1.1", "method": "GET" if payload is None else "POST", "path": path,
                "scheme": scheme, "query_string": b"", "headers": headers, "client": (peer, 50000),
            }
            messages = []

            async def receive():
                return {"type": "http.request", "body": payload or b""}

            async def send(message):
                messages.append(message)

            await app(scope, receive, send)
            return messages[0]["status"]

        auth = b"test-admin:test-password"
        restricted = self.application()
        restricted_admin = self.application(admin_networks=["192.168.8.0/24"])
        lan = self.application(allow_http=True)
        lan_with_admin_filter = self.application(allow_http=True, admin_networks=["192.168.8.11/32"])
        self.assertEqual(asyncio.run(request_status(restricted, "https", auth=auth)), 403)
        self.assertEqual(asyncio.run(request_status(restricted_admin, "http", auth=auth)), 403)
        self.assertEqual(asyncio.run(request_status(restricted_admin, "https", peer="203.0.113.11", auth=auth)), 403)
        self.assertEqual(asyncio.run(request_status(restricted_admin, "https", auth=auth)), 200)
        self.assertEqual(asyncio.run(request_status(lan, "http")), 401)
        self.assertEqual(asyncio.run(request_status(lan, "http", auth=b"test-admin:wrong")), 401)
        self.assertEqual(asyncio.run(request_status(lan, "http", auth=auth)), 200)
        self.assertEqual(asyncio.run(request_status(lan, "http", peer="203.0.113.11", auth=auth)), 403)
        self.assertEqual(asyncio.run(request_status(lan_with_admin_filter, "http", auth=auth)), 403)

        payload = json.dumps({"uid": self.uid}).encode("ascii")
        self.assertEqual(asyncio.run(request_status(lan, "http", path=ACTIVATION_PATH, payload=payload)), 403)
        self.assertTrue(self.registry.set_auto_issue(self.uid, True))
        self.assertEqual(asyncio.run(request_status(lan, "http", path=ACTIVATION_PATH, payload=payload)), 200)
        self.assertEqual(asyncio.run(request_status(lan, "http", peer="203.0.113.11", path=ACTIVATION_PATH, payload=payload)), 403)

        release = self.write_release(self.folder / "lan-release", "1.0.0", origin="http://192.168.8.20:8787")
        publish_update(self.folder, release, self.key, stage=STAGE_RELEASED)
        latest = f"{UPDATES_PATH}/latest"
        self.assertEqual(asyncio.run(request_status(lan, "http", path=latest)), 200)
        self.assertEqual(asyncio.run(request_status(lan, "http", path=f"{UPDATES_PATH}/1.0.0/installer")), 200)
        self.assertEqual(asyncio.run(request_status(lan, "http", peer="203.0.113.11", path=latest)), 403)

    def test_publication_rejects_domains_and_non_lan_http_addresses(self):
        release = self.write_release(self.folder / "https-release", "1.0.0")
        manifest_path = release / "manifest.json"
        record = json.loads(manifest_path.read_text(encoding="utf-8"))
        for host in ("activation.example.test", "198.51.100.1", "127.0.0.1"):
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, "HTTPS is required"):
                record["activation_server"] = f"http://{host}:8787"
                manifest_path.write_text(json.dumps(record), encoding="utf-8")
                publish_update(self.folder, release, self.key)
        record["activation_server"] = "http://[fd12::1]:8787"
        manifest_path.write_text(json.dumps(record), encoding="utf-8")
        self.assertEqual(publish_update(self.folder, release, self.key), "1.0.0")

    def test_serve_uses_allow_http_for_lan_listeners_only(self):
        from activation_server.__main__ import main as cli_main

        private_pem = self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        (self.folder / "activation-private.pem").write_bytes(private_pem)
        env = {"PERFLENS_ADMIN_USERNAME": "test-admin", "PERFLENS_ADMIN_PASSWORD": "test-password",
               "PERFLENS_ADMIN_NETWORKS": "", "PERFLENS_ADMIN_ALLOW_HTTP": "0"}
        args = ["serve", "--data-dir", str(self.folder), "--host"]
        with patch.dict("os.environ", env), patch("activation_server.__main__.uvicorn.run") as run, redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):
                cli_main(args + ["0.0.0.0"])
            run.assert_not_called()
            with patch.dict("os.environ", {"PERFLENS_ADMIN_ALLOW_HTTP": "1"}):
                for host in ("activation.example.test", "198.51.100.1"):
                    with self.subTest(host=host), self.assertRaises(SystemExit):
                        cli_main(args + [host])
                run.assert_not_called()
                cli_main(args + ["0.0.0.0"])
            run.assert_called_once()
            self.assertIsNone(run.call_args.kwargs["ssl_certfile"])

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
        self.assertEqual(activate(), (403, {"detail": "issuance_disabled"}))
        pending_page = self.request("GET", "/admin", auth=auth)[1]
        self.assertIn("待审批", pending_page)
        self.assertIn(self.uid, pending_page)
        client = f"/admin/clients/{self.uid}"
        self.assertEqual(submit(client, {"auto_issue": "1"}), 403)
        self.assertEqual(activate()[0], 403)
        self.assertEqual(submit(client, {"auto_issue": "1", "csrf": csrf}), 303)
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

    def test_concurrent_registration_stays_pending_and_approved_requests_share_one_lease(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(set(pool.map(self.registry.issue, [self.uid] * 8)), {None})
            self.assertEqual(len(self.registry.view()[1]), 1)
            self.registry.set_auto_issue(self.uid, True)
            codes = set(pool.map(self.registry.issue, [self.uid] * 8))
        self.assertEqual(len(codes), 1)
        self.assertNotIn(None, codes)

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
        self.assertEqual(activate(client_version="0.4.1", local_ip="2001:0db8::1", computer_name="测试机<01>")[0], 403)
        pending = self.registry.view()[1][0]
        self.assertEqual((pending["approved"], pending["expires_at"]), (0, expiry))
        self.assertEqual(pending["computer_name"], "测试机<01>")
        self.registry.set_auto_issue(self.uid, True)
        code, body = activate()
        self.assertEqual(code, 200)
        self.assertEqual(verify_code(json.loads(body)["code"], self.uid, self.key.public_key()), expiry)
        html = self.request("GET", "/admin", auth=auth)[1]
        self.assertIn("<td>127.0.0.1</td>", html)
        self.assertIn("测试机&lt;01&gt;", html)
        self.assertEqual(activate(), (code, body))
        self.assertEqual(activate(local_ip="192.0.2.41"), (code, body))
        self.registry.set_auto_issue(self.uid, False)
        self.assertEqual(activate(client_version="0.4.2", local_ip="192.0.2.42", computer_name="Other")[0], 403)
        self.assertEqual(activate(client_version="<script>")[0], 422)
        self.assertEqual(activate(local_ip="999.0.0.1")[0], 422)
        reopened = Registry(old_db, self.key, lambda: self.now)
        row = reopened.view()[1][0]
        self.assertEqual((row["first_seen"], row["expires_at"], row["client_version"]), (self.now - 60, expiry, "0.4.2"))
        self.assertEqual((row["local_ip"], row["computer_name"]), ("127.0.0.1", "Other"))
        html = self.request("GET", "/admin", auth=auth)[1]
        self.assertIn("<td>0.4.2</td>", html)
        self.assertIn("<td>127.0.0.1</td>", html)

    def activate_from(self, source_ip, *, reported_ip=None, headers=()):
        payload = {"uid": self.uid, "computer_name": "Public client", "client_version": "0.4.9"}
        if reported_ip is not None:
            payload["local_ip"] = reported_ip
        body = json.dumps(payload).encode("utf-8")
        app = self.application()

        async def dispatch():
            messages = []

            async def receive():
                return {"type": "http.request", "body": body}

            async def send(message):
                messages.append(message)

            await app({
                "type": "http", "http_version": "1.1", "method": "POST", "scheme": "https",
                "path": ACTIVATION_PATH, "query_string": b"",
                "headers": [(b"content-type", b"application/json"), *headers],
                "client": (source_ip, 50000) if source_ip is not None else None,
            }, receive, send)
            return messages[0]["status"], json.loads(b"".join(item.get("body", b"") for item in messages))

        return asyncio.run(dispatch())

    def test_registration_records_connection_ip_instead_of_reported_lan_ip(self):
        self.assertEqual(self.activate_from("203.0.113.40", reported_ip="192.168.1.100")[0], 403)
        self.assertEqual(self.registry.view()[1][0]["local_ip"], "203.0.113.40")
        self.registry.set_auto_issue(self.uid, True)
        for source_ip,normalized in [("203.0.113.41", "203.0.113.41"),
                                     ("2001:0db8:abcd::1", "2001:db8:abcd::1"),
                                     ("192.168.2.35", "192.168.2.35")]:
            with self.subTest(source_ip=source_ip):
                status,body = self.activate_from(source_ip, reported_ip="192.168.1.100")
                self.assertEqual(status, 200)
                self.assertEqual(verify_code(body["code"], self.uid, self.key.public_key()), self.now+86400)
                row = self.registry.view()[1][0]
                self.assertEqual(row["local_ip"], normalized)
                self.assertEqual((row["computer_name"], row["client_version"]), ("Public client", "0.4.9"))
        # A renewed request updates the address even while the previously signed lease remains valid.
        self.assertEqual(self.activate_from("198.51.100.22")[0], 200)
        self.assertEqual(self.registry.view()[1][0]["local_ip"], "198.51.100.22")

    def test_registration_ignores_untrusted_forwarded_headers(self):
        self.start_server()
        status,_ = self.request("POST", ACTIVATION_PATH, json.dumps({"uid": self.uid, "local_ip": "192.168.1.10"}),
                                content_type="application/json", headers={"X-Forwarded-For": "203.0.113.99"})
        self.assertEqual(status, 403)
        self.assertEqual(self.registry.view()[1][0]["local_ip"], "127.0.0.1")
        html = self.request("GET", "/admin", auth=b"test-admin:test-password")[1]
        self.assertIn("来源 IP", html)
        self.assertNotIn("本机 IP", html)

    def test_registration_without_connection_address_retains_legacy_ip_fallback(self):
        self.assertEqual(self.activate_from(None, reported_ip="2001:0db8::1")[0], 403)
        self.assertEqual(self.registry.view()[1][0]["local_ip"], "2001:db8::1")

    def test_published_manifest_is_signed_and_downloads_stay_versioned(self):
        self.start_server()
        latest = f"{UPDATES_PATH}/latest"
        self.assertEqual(self.request("GET", latest), (204, ""))
        old = self.write_release(self.folder / "old", "0.9.0")
        newest = self.write_release(self.folder / "newest", "0.10.0")
        bad = self.write_release(self.folder / "bad", "0.11.0")
        self.assertEqual(publish_update(self.folder, old, self.key, stage=STAGE_RELEASED), "0.9.0")
        with self.assertRaisesRegex(ValueError, "already published"):
            publish_update(self.folder, old, self.key, stage=STAGE_RELEASED)
        with self.assertRaisesRegex(ValueError, "public key"):
            publish_update(self.folder, newest, Ed25519PrivateKey.generate(), stage=STAGE_RELEASED)
        tampered = bad / artifact_names("0.11.0")["unpacked"]
        tampered.write_bytes(b"x" * tampered.stat().st_size)
        with self.assertRaisesRegex(ValueError, "mismatch"):
            publish_update(self.folder, bad, self.key, stage=STAGE_RELEASED)
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.11.0/installer")[0], 404)
        publish_update(self.folder, newest, self.key, stage=STAGE_RELEASED)
        # A canary version published by default remains hidden from clients without an allowed UID.
        canary_rel = self.write_release(self.folder / "canary-next", "0.12.0")
        self.assertEqual(publish_update(self.folder, canary_rel, self.key), "0.12.0")
        code, body = self.request("GET", latest)
        self.assertEqual(code, 200)
        manifest = self.read_update_manifest(body)
        self.assertEqual(body, (self.folder / "updates" / "0.10.0" / "update.json").read_text(encoding="ascii"))
        self.assertEqual((manifest["schema"], manifest["version"], manifest["server_url"]),
                         (1, "0.10.0", "https://activation.example.test:8787"))
        for kind, name in artifact_names("0.10.0").items():
            self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/{kind}"), (200, name))
            self.assertEqual(manifest["artifacts"][kind],
                             {"bytes": len(name), "sha256": hashlib.sha256(name.encode("ascii")).hexdigest()})
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.9.0/installer"), (200, artifact_names("0.9.0")["installer"]))
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.12.0/installer")[0], 404)
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/portable")[0], 404)
        admin_html = self.request("GET", "/admin", auth=b"test-admin:test-password")[1]
        self.assertIn("当前发布版本 <strong>0.10.0</strong>", admin_html)
        self.assertIn("当前灰度版本 <strong>0.12.0</strong>", admin_html)

    def test_distribution_publishes_complete_releases_without_restarting(self):
        distribution = self.folder / "custom distribution"
        distribution.mkdir()
        canary_uid = "c" * 64
        other_uid = "d" * 64
        self.registry.add_default_canary_members([canary_uid], note="dist-canary")
        self.enterContext(patch("activation_server.updates.DISTRIBUTION_POLL_SECONDS", 0.02))
        self.start_server(distribution_dir=distribution)
        latest = f"{UPDATES_PATH}/latest"
        canary_headers = {"X-PerfLens-UID": canary_uid}
        other_headers = {"X-PerfLens-UID": other_uid}
        self.assertEqual(self.request("GET", latest, headers=canary_headers), (204, ""))

        def wait_for_version(expected):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                code, body = self.request("GET", latest, headers=canary_headers)
                if code == 200 and self.read_update_manifest(body)["version"] == expected:
                    return code, body
                time.sleep(.01)
            self.fail(f"Update {expected} did not become available")

        self.write_release(distribution, "0.9.0")
        previous = wait_for_version("0.9.0")
        # Non-canary clients must not receive watcher-published canary releases before full promotion.
        self.assertEqual(self.request("GET", latest), (204, ""))
        self.assertEqual(self.request("GET", latest, headers=other_headers), (204, ""))
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.9.0/installer", headers=other_headers)[0], 404)

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
        self.assertEqual(self.request("GET", latest, headers=canary_headers), previous)
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/installer", headers=canary_headers)[0], 404)

        installer.write_bytes((release / installer.name).read_bytes())
        wait_for_version("0.10.0")
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/installer", headers=canary_headers), (200, installer.name))
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.9.0/installer", headers=canary_headers), (200, artifact_names("0.9.0")["installer"]))
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
        self.registry.set_auto_issue(uid_active, True)
        self.registry.issue(uid_active)
        self.now -= 100000
        self.registry.issue(uid_expired_disabled, "0.8.0", local_ip="192.168.1.2", computer_name="NodeB")
        self.registry.set_auto_issue(uid_expired_disabled, True)
        self.registry.issue(uid_expired_disabled)
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
        for table_id in ("clients", "versions", "default-canary", "modal-members"):
            self.assertIn(f'data-table-id="{table_id}"', html)
            self.assertIn(f'data-sort-table="{table_id}"', html)
            self.assertIn(f'data-reset-table="{table_id}"', html)
        self.assertIn('data-ver-filter="canary"', html)
        self.assertIn('id="default-canary-search-clear"', html)
        self.assertIn('id="modal-members-search"', html)
        self.assertIn('id="upload-progress"', html)
        self.assertIn('id="progress-stats"', html)
        self.assertIn('id="progress-speed"', html)
        self.assertNotIn("uploadEnabledCheckbox", html)

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

        def upload_release(version, *, stage=None, inherit_from=None, tamper=False):
            rel = self.write_release(self.folder / f"web-{version}-{'tamper' if tamper else 'ok'}", version)
            manifest = json.loads((rel / "manifest.json").read_text(encoding="utf-8"))
            init_payload = {"manifest": manifest}
            if stage is not None:
                init_payload["stage"] = stage
            if inherit_from is not None:
                init_payload["inherit_from"] = inherit_from
            status, body = self.request(
                "POST",
                "/admin/updates/upload/init",
                json.dumps(init_payload),
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

        # Upload without stage defaults to canary and stays hidden from regular clients.
        (st_default, body_default), _ = upload_release("0.8.2")
        self.assertEqual(st_default, 200)
        self.assertEqual(json.loads(body_default)["stage"], STAGE_CANARY)
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/latest"), (204, ""))

        # Successful upload of 0.9.0 (released) and 0.10.0 (disabled initially for internal testing).
        (st_090, body_090), _ = upload_release("0.9.0", stage=STAGE_RELEASED)
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

        (st_100, _), _ = upload_release("0.10.0", stage=STAGE_DISABLED)
        self.assertEqual(st_100, 200)

        # Disabled 0.10.0 must not appear in /latest or public downloads, while admin download works.
        latest_code, latest_body = self.request("GET", f"{UPDATES_PATH}/latest")
        self.assertEqual(latest_code, 200)
        latest_payload = self.read_update_manifest(latest_body)
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
        self.assertIn('data-version="0.9.0" data-source="web"', admin_html)
        self.assertIn('data-client-count="1"', admin_html)
        self.assertIn('data-installer-bytes="', admin_html)
        self.assertIn('data-unpacked-bytes="', admin_html)

        # Enable 0.10.0 -> /latest switches to 0.10.0 and public download opens.
        self.assertEqual(
            self.request(
                "POST",
                "/admin/updates/0.10.0/status",
                urlencode({"stage": STAGE_RELEASED, "csrf": csrf}),
                auth=auth,
                content_type="application/x-www-form-urlencoded",
            )[0],
            303,
        )
        latest_payload = self.read_update_manifest(self.request("GET", f"{UPDATES_PATH}/latest")[1])
        self.assertEqual(latest_payload["version"], "0.10.0")
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/installer")[0], 200)

        # Disable 0.10.0 -> /latest rolls back to 0.9.0 and public download blocks 0.10.0 again.
        self.assertEqual(
            self.request(
                "POST",
                "/admin/updates/0.10.0/status",
                urlencode({"stage": STAGE_DISABLED, "csrf": csrf}),
                auth=auth,
                content_type="application/x-www-form-urlencoded",
            )[0],
            303,
        )
        latest_payload = self.read_update_manifest(self.request("GET", f"{UPDATES_PATH}/latest")[1])
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
        (st_reup, _), _ = upload_release("0.10.0", stage=STAGE_RELEASED)
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

    def test_canary_allowlist_routing_inheritance_and_cleanup(self):
        self.start_server()
        auth = b"test-admin:test-password"
        uid_qa = "a" * 64
        uid_dev = "b" * 64
        uid_regular = "c" * 64
        uid_extra = "d" * 64
        # Pre-register uid_dev (never activated) + activated uid_qa.
        self.registry.issue(uid_qa, "0.8.0", computer_name="QA-Box")
        self.registry.issue(uid_regular, "0.8.0", computer_name="User-PC")

        _, html = self.request("GET", "/admin", auth=auth)
        csrf = re.search(r'name="csrf" value="([^"]+)"', html)[1]

        def post_json(path, payload):
            return self.request(
                "POST",
                path,
                json.dumps(payload),
                auth=auth,
                content_type="application/json",
                headers={"X-CSRF-Token": csrf},
            )

        def latest_for(uid=None):
            hdrs = {"X-PerfLens-UID": uid} if uid is not None else None
            code, body = self.request("GET", f"{UPDATES_PATH}/latest", headers=hdrs)
            if code == 204:
                return 204, None
            return code, self.read_update_manifest(body)["version"]

        # Manage default canary allowlist (pre-registered + activated UID).
        st, body = post_json("/admin/canary/default/add", {"uids": [uid_qa.upper(), uid_dev], "note": "QA团队"})
        self.assertEqual(st, 200, body)
        self.assertEqual(json.loads(body)["default_count"], 2)

        # Publish full 0.9.0 and canary 0.10.0 inheriting default allowlist.
        rel_090 = self.write_release(self.folder / "rel-0.9.0", "0.9.0")
        publish_update(self.folder, rel_090, self.key, stage=STAGE_RELEASED)
        rel_100 = self.write_release(self.folder / "rel-0.10.0", "0.10.0")
        publish_update(
            self.folder,
            rel_100,
            self.key,
            stage=STAGE_CANARY,
            on_published=lambda ver, stg: self.registry.init_version_canary(ver, "default"),
        )

        # Removing uid_dev from default allowlist must not mutate already-created 0.10.0 roster.
        self.assertEqual(post_json("/admin/canary/default/remove", {"uid": uid_dev})[0], 200)
        st_v10, body_v10 = self.request("GET", "/admin/updates/0.10.0/canary", auth=auth)
        self.assertEqual(st_v10, 200, body_v10)
        self.assertEqual({m["uid"] for m in json.loads(body_v10)["members"]}, {uid_qa, uid_dev})

        # Verify client routing isolation + download gating + case-insensitive header tolerance.
        self.assertEqual(latest_for(None), (200, "0.9.0"))
        self.assertEqual(latest_for(uid_regular), (200, "0.9.0"))
        self.assertEqual(latest_for("not-a-uid"), (200, "0.9.0"))
        self.assertEqual(latest_for(uid_qa.upper()), (200, "0.10.0"))
        self.assertEqual(latest_for(uid_dev), (200, "0.10.0"))
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/installer", headers={"X-PerfLens-UID": uid_regular})[0], 404)
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.10.0/installer", headers={"X-PerfLens-UID": uid_qa})[0], 200)

        # Higher full release overrides older canary version for canary users too.
        rel_110 = self.write_release(self.folder / "rel-0.11.0", "0.11.0")
        publish_update(self.folder, rel_110, self.key, stage=STAGE_RELEASED)
        self.assertEqual(latest_for(uid_qa), (200, "0.11.0"))
        self.assertEqual(latest_for(uid_regular), (200, "0.11.0"))
        self.request(
            "POST",
            "/admin/updates/0.11.0/status",
            urlencode({"stage": STAGE_DISABLED, "csrf": csrf}),
            auth=auth,
            content_type="application/x-www-form-urlencoded",
        )

        # Web upload 0.12.0 inheriting directly from 0.10.0, then mutate and save back to default.
        manifest_120 = json.loads((self.write_release(self.folder / "rel-0.12.0", "0.12.0") / "manifest.json").read_text())
        _, init_120 = post_json("/admin/updates/upload/init", {"manifest": manifest_120, "inherit_from": "0.10.0"})
        sid_120 = json.loads(init_120)["session_id"]
        for kind, name in artifact_names("0.12.0").items():
            data = (self.folder / "rel-0.12.0" / name).read_bytes()
            self.assertEqual(
                self.request(
                    "POST",
                    f"/admin/updates/upload/{sid_120}/{kind}",
                    data,
                    auth=auth,
                    content_type="application/octet-stream",
                    headers={"X-CSRF-Token": csrf, "X-Chunk-Offset": "0"},
                )[0],
                200,
            )
        self.assertEqual(post_json(f"/admin/updates/upload/{sid_120}/complete", {})[0], 200)

        # Add uid_extra and merge/remove on 0.12.0, then save 0.12.0 as default (preserving uid_qa note).
        self.assertEqual(post_json("/admin/updates/0.12.0/canary/add", {"uid": uid_extra})[0], 200)
        self.assertEqual(post_json("/admin/updates/0.12.0/canary/remove", {"uid": uid_dev})[0], 200)
        st_save, body_save = post_json("/admin/updates/0.12.0/canary/save-default", {"mode": "replace"})
        self.assertEqual(st_save, 200, body_save)
        self.assertEqual(json.loads(body_save)["default_count"], 2)
        default_notes = {m["uid"]: m["note"] for m in self.registry.list_default_canary_members()}
        self.assertEqual(default_notes[uid_qa], "QA团队")
        self.assertIn(uid_extra, default_notes)
        self.assertNotIn(uid_dev, default_notes)

        # Pausing 0.12.0 (disabled) falls back to 0.10.0/0.9.0, resuming restores 0.12.0 without losing roster.
        self.request(
            "POST",
            "/admin/updates/0.12.0/status",
            urlencode({"stage": STAGE_DISABLED, "csrf": csrf}),
            auth=auth,
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(latest_for(uid_extra), (200, "0.9.0"))
        self.request(
            "POST",
            "/admin/updates/0.12.0/status",
            urlencode({"stage": STAGE_CANARY, "csrf": csrf}),
            auth=auth,
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(latest_for(uid_extra), (200, "0.12.0"))

        # Inherit default (merge) recovers uid_qa/uid_extra and deleting version clears SQLite roster rows.
        self.assertEqual(
            post_json("/admin/updates/0.10.0/canary/inherit", {"source": "0.12.0", "mode": "merge"})[0],
            200,
        )
        self.assertTrue(self.registry.is_canary_member("0.10.0", uid_extra))
        self.request(
            "POST",
            "/admin/updates/0.12.0/delete",
            urlencode({"csrf": csrf}),
            auth=auth,
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(self.registry.list_version_canary_members("0.12.0"), [])

    def test_cli_publish_update_canary_and_full_flags(self):
        from activation_server.__main__ import main as cli_main

        (self.folder / "activation-private.pem").write_bytes(self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        uid_qa = "e" * 64
        self.registry.add_default_canary_members([uid_qa], note="cli-qa")

        rel_canary = self.write_release(self.folder / "cli-0.9.0", "0.9.0")
        cli_main(["publish-update", "--data-dir", str(self.folder), "--release-dir", str(rel_canary)])
        self.assertTrue(self.registry.is_canary_member("0.9.0", uid_qa))

        rel_empty = self.write_release(self.folder / "cli-0.10.0", "0.10.0")
        cli_main(["publish-update", "--data-dir", str(self.folder), "--release-dir", str(rel_empty), "--inherit-from", "none"])
        self.assertEqual(self.registry.list_version_canary_members("0.10.0"), [])

        rel_full = self.write_release(self.folder / "cli-0.11.0", "0.11.0")
        cli_main(["publish-update", "--data-dir", str(self.folder), "--release-dir", str(rel_full), "--full"])
        self.assertNotIn("0.11.0", self.registry.version_canary_counts())
        from activation_server.updates import version_stage
        version_dir = self.folder / "updates" / "0.11.0"
        self.assertEqual(version_stage(version_dir), STAGE_RELEASED)
        self.assertEqual(self.read_update_manifest((version_dir / "update.json").read_text(encoding="ascii"))["version"], "0.11.0")

    def test_groups_default_creation_migration_and_inheritance_overrides(self):
        """Verify default group auto-creation, legacy override migration, and group/client precedence."""
        groups = self.registry.list_groups()
        self.assertEqual(len(groups), 1)
        default_group = groups[0]
        self.assertEqual(default_group["is_default"], 1)
        self.assertEqual(default_group["auto_issue"], 0)
        self.assertEqual(default_group["canary_default"], 0)
        self.assertIsNone(default_group["duration_minutes"])

        # Legacy DB without groups / auto_issue_override should migrate auto_issue=0 into single-client override=0.
        legacy_db = self.folder / "legacy_groups.sqlite3"
        uid_enabled = "1" * 64
        uid_disabled = "2" * 64
        with closing(sqlite3.connect(legacy_db)) as db, db:
            db.execute(
                "CREATE TABLE clients (uid TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, "
                "auto_issue INTEGER NOT NULL DEFAULT 1, expires_at INTEGER)"
            )
            db.execute("INSERT INTO clients VALUES (?, ?, ?, 1, ?)", (uid_enabled, self.now - 100, self.now - 50, self.now + 60))
            db.execute("INSERT INTO clients VALUES (?, ?, ?, 0, NULL)", (uid_disabled, self.now - 100, self.now - 50))

        migrated = Registry(legacy_db, self.key, lambda: self.now)
        _, clients = migrated.view()
        by_uid = {c["uid"]: c for c in clients}
        self.assertEqual(by_uid[uid_enabled]["group_is_default"], 1)
        self.assertIsNone(by_uid[uid_enabled]["auto_issue_override"])
        self.assertEqual(by_uid[uid_enabled]["effective_auto_issue"], 0)
        self.assertIsNone(migrated.issue(uid_enabled))
        self.assertEqual(by_uid[uid_disabled]["group_is_default"], 1)
        self.assertEqual(by_uid[uid_disabled]["auto_issue_override"], 0)
        self.assertEqual(by_uid[uid_disabled]["effective_auto_issue"], 0)
        self.assertIsNone(migrated.issue(uid_disabled, "0.9.0"))

        # New client auto-assigns to default group and honors custom group policy + duration override.
        uid_a = "3" * 64
        uid_b = "4" * 64
        code_a = self.registry.issue(uid_a, "0.9.0", computer_name="Alpha")
        code_b = self.registry.issue(uid_b, "0.9.0", computer_name="Beta")
        self.assertIsNone(code_a)
        self.assertIsNone(code_b)

        vip = self.registry.create_group(
            "VIP-QA",
            color="#059669",
            note="受控测试组",
            auto_issue=False,
            canary_default=True,
            duration_minutes=120,
        )
        self.registry.set_clients_group([uid_a, uid_b], vip["id"], clear_override=False)

        # Un-overridden clients inherit group auto_issue=False after expiry.
        self.now += 1500 * 60
        self.assertIsNone(self.registry.issue(uid_a, "0.9.0"))

        # Single-client override="1" allows activation AND uses group custom duration_minutes=120.
        self.registry.set_auto_issue_mode(uid_a, "1")
        custom_code = self.registry.issue(uid_a, "0.9.0")
        self.assertEqual(verify_code(custom_code, uid_a, self.key.public_key()), self.now + 120 * 60)

        # Explicit reset of one client or whole group returns to inheriting group auto_issue=False.
        self.registry.set_auto_issue_mode(uid_b, "1")
        self.assertEqual(self.registry.get_group(vip["id"])["override_count"], 2)
        self.registry.set_auto_issue_mode(uid_b, "inherit")
        self.assertEqual(self.registry.get_group(vip["id"])["override_count"], 1)
        self.assertEqual(self.registry.reset_group_overrides(vip["id"]), 1)
        self.assertEqual(self.registry.get_group(vip["id"])["override_count"], 0)

        self.now += 200 * 60
        self.assertIsNone(self.registry.issue(uid_a, "0.9.0"))

        # Switching group back to auto_issue=True and duration_minutes=None restores global duration fallback.
        self.registry.update_group(vip["id"], auto_issue=True, duration_minutes=None)
        unapproved_uid = "5" * 64
        self.assertIsNone(self.registry.issue(unapproved_uid))
        self.registry.set_clients_group([unapproved_uid], vip["id"], clear_override=True)
        self.assertIsNone(self.registry.issue(unapproved_uid))
        global_dur, _ = self.registry.view()
        reissued = self.registry.issue(uid_a, "0.9.0")
        self.assertEqual(verify_code(reissued, uid_a, self.key.public_key()), self.now + global_dur * 60)

    def test_group_crud_validation_delete_reassignment_and_csrf(self):
        """Verify HTTP admin group endpoints, CSRF protection, validation errors, and member reassignment on delete."""
        self.start_server()
        auth = b"test-admin:test-password"
        uid1 = "5" * 64
        uid2 = "6" * 64
        self.registry.issue(uid1, "0.9.0", computer_name="Dev-1")
        self.registry.issue(uid2, "0.9.0", computer_name="Dev-2")

        code, html = self.request("GET", "/admin", auth=auth)
        self.assertEqual(code, 200)
        self.assertIn("分组管理", html)
        self.assertIn("默认分组", html)
        csrf = re.search(r'name="csrf" value="([^"]+)"', html)[1]

        def req_json(method, path, payload=None, *, include_csrf=True):
            hdrs = {"X-CSRF-Token": csrf} if include_csrf else None
            body = json.dumps(payload) if payload is not None else None
            return self.request(method, path, body, auth=auth, content_type="application/json" if body is not None else None, headers=hdrs)

        # Missing CSRF must return 403 across group and client-group endpoints.
        self.assertEqual(req_json("POST", "/admin/groups", {"name": "NoCSRF"}, include_csrf=False)[0], 403)
        self.assertEqual(req_json("POST", "/admin/clients/group", {"uids": [uid1], "group_id": 1}, include_csrf=False)[0], 403)

        # Validation failures return 422.
        self.assertEqual(req_json("POST", "/admin/groups", {"name": "   "})[0], 422)
        self.assertEqual(req_json("POST", "/admin/groups", {"name": "BadColor", "color": "#zzz"})[0], 422)
        self.assertEqual(req_json("POST", "/admin/groups", {"name": "BadDur", "duration_minutes": 0})[0], 422)

        # Create custom group & reject duplicate names.
        c_code, c_body = req_json(
            "POST",
            "/admin/groups",
            {"name": "QA Team", "color": "#dc2626", "note": "QA", "auto_issue": True, "canary_default": True, "duration_minutes": 30},
        )
        self.assertEqual(c_code, 200)
        qa = json.loads(c_body)["group"]
        self.assertEqual(req_json("POST", "/admin/groups", {"name": "QA Team"})[0], 422)
        self.assertEqual(req_json("POST", "/admin/groups/1/reset-overrides", {}, include_csrf=False)[0], 403)
        self.assertEqual(req_json("DELETE", f"/admin/groups/{qa['id']}", include_csrf=False)[0], 403)
        # Default group cannot be deleted.
        default_gid = [g["id"] for g in self.registry.list_groups() if g["is_default"]][0]
        self.assertEqual(req_json("DELETE", f"/admin/groups/{default_gid}")[0], 422)
        self.assertEqual(req_json("POST", f"/admin/groups/{default_gid}", {"auto_issue": True})[0], 422)

        # Override uid1 to disabled, then assign [uid1, uid2] to qa with clear_override=True.
        self.registry.set_auto_issue_mode(uid1, "0")
        m_code, m_body = req_json(
            "POST",
            "/admin/clients/group",
            {"uids": [uid1, uid2], "group_id": qa["id"], "clear_override": True},
        )
        self.assertEqual(m_code, 200)
        self.assertEqual(json.loads(m_body)["updated"], 2)

        _, clients = self.registry.view()
        client_map = {c["uid"]: c for c in clients}
        self.assertEqual(client_map[uid1]["group_id"], qa["id"])
        self.assertIsNone(client_map[uid1]["auto_issue_override"])

        # Form post supporting auto_issue="inherit" after setting override="0".
        self.registry.set_auto_issue_mode(uid1, "0")
        inh_code, _ = self.request(
            "POST",
            f"/admin/clients/{uid1}",
            urlencode({"csrf": csrf, "auto_issue": "inherit"}),
            auth=auth,
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(inh_code, 303)
        _, clients_after = self.registry.view()
        self.assertIsNone({c["uid"]: c for c in clients_after}[uid1]["auto_issue_override"])

        # Deleting custom group reassigns both clients back to default group.
        d_code, d_body = req_json("DELETE", f"/admin/groups/{qa['id']}")
        self.assertEqual(d_code, 200)
        self.assertEqual(json.loads(d_body)["reassigned"], 2)
        _, clients_final = self.registry.view()
        self.assertTrue(all(c["group_id"] == default_gid for c in clients_final))

    def test_canary_groups_dynamic_membership_inheritance_and_sync(self):
        """Verify dynamic group-based canary delivery, inheritance, and group canary sync."""
        self.start_server()
        auth = b"test-admin:test-password"
        uid_qa = "7" * 64
        uid_mover = "8" * 64
        self.registry.issue(uid_qa, "0.8.0", computer_name="QA-1")
        self.registry.issue(uid_mover, "0.8.0", computer_name="Mover-1")

        qa_group = self.registry.create_group("Canary-QA", canary_default=True)
        dev_group = self.registry.create_group("Canary-Dev", canary_default=False)
        default_gid = [g["id"] for g in self.registry.list_groups() if g["is_default"]][0]
        self.registry.set_clients_group([uid_qa], qa_group["id"])

        r_09 = self.write_release(self.folder / "r09", "0.9.0")
        publish_update(self.folder, r_09, self.key, stage=STAGE_CANARY)
        self.registry.init_version_canary("0.9.0", "default", updates_dir=self.folder / "updates")

        def latest_ver(uid):
            code, body = self.request("GET", f"{UPDATES_PATH}/latest", headers={"X-PerfLens-UID": uid})
            if code == 204:
                return 204, None
            return code, self.read_update_manifest(body)["version"]

        self.assertEqual(latest_ver(uid_qa), (200, "0.9.0"))
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.9.0/installer", headers={"X-PerfLens-UID": uid_qa})[0], 200)
        self.assertEqual(latest_ver(uid_mover), (204, None))
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.9.0/installer", headers={"X-PerfLens-UID": uid_mover})[0], 404)

        _, html = self.request("GET", "/admin", auth=auth)
        csrf = re.search(r'name="csrf" value="([^"]+)"', html)[1]

        def post_json(path, payload):
            return self.request(
                "POST",
                path,
                json.dumps(payload),
                auth=auth,
                content_type="application/json",
                headers={"X-CSRF-Token": csrf},
            )

        # Moving uid_mover into qa_group via HTTP grants immediate canary access; moving uid_qa out revokes it.
        self.assertEqual(post_json("/admin/clients/group", {"uids": [uid_mover], "group_id": qa_group["id"]})[0], 200)
        self.assertEqual(latest_ver(uid_mover), (200, "0.9.0"))
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.9.0/installer", headers={"X-PerfLens-UID": uid_mover})[0], 200)

        self.assertEqual(post_json("/admin/clients/group", {"uids": [uid_qa], "group_id": default_gid})[0], 200)
        self.assertEqual(latest_ver(uid_qa), (204, None))
        self.assertEqual(self.request("GET", f"{UPDATES_PATH}/0.9.0/installer", headers={"X-PerfLens-UID": uid_qa})[0], 404)

        # Publish 0.10.0 and explicitly bind dev_group via HTTP API.
        r_10 = self.write_release(self.folder / "r10", "0.10.0")
        publish_update(self.folder, r_10, self.key, stage=STAGE_CANARY)
        self.registry.init_version_canary("0.10.0", "none", updates_dir=self.folder / "updates")
        self.registry.set_clients_group([uid_qa], dev_group["id"])

        g_code, g_body = post_json("/admin/updates/0.10.0/canary/groups", {"group_ids": [dev_group["id"]]})
        self.assertEqual(g_code, 200)
        g_payload = json.loads(g_body)
        self.assertEqual(g_payload["summary"]["group_count"], 1)
        self.assertEqual(g_payload["summary"]["effective_count"], 1)
        self.assertEqual(latest_ver(uid_qa), (200, "0.10.0"))

        # Inheriting from 0.10.0 copies bound groups too.
        r_11 = self.write_release(self.folder / "r11", "0.11.0")
        publish_update(self.folder, r_11, self.key, stage=STAGE_CANARY)
        self.registry.init_version_canary("0.11.0", "0.10.0", updates_dir=self.folder / "updates")
        self.assertEqual(latest_ver(uid_qa), (200, "0.11.0"))

        # Updating a group with sync_active_canary=True binds it to all active canary versions; save-default syncs canary_default flags.
        u_code, _ = post_json(
            f"/admin/groups/{default_gid}",
            {"canary_default": True, "sync_active_canary": True},
        )
        self.assertEqual(u_code, 200)
        default_bound = [g["id"] for g in self.registry.list_version_canary_groups("0.10.0") if g["selected"]]
        self.assertIn(default_gid, default_bound)

        s_code, s_body = post_json("/admin/updates/0.10.0/canary/save-default", {"mode": "replace"})
        self.assertEqual(s_code, 200)
        self.assertEqual(json.loads(s_body)["default_group_count"], 2)
        group_flags = {g["id"]: g["canary_default"] for g in self.registry.list_groups()}
        self.assertEqual(group_flags[qa_group["id"]], 0)
        self.assertEqual(group_flags[dev_group["id"]], 1)
        self.assertEqual(group_flags[default_gid], 1)

        # Batch update default canary groups via /admin/canary/default/groups with optional active canary sync.
        self.assertEqual(
            self.request(
                "POST",
                "/admin/canary/default/groups",
                json.dumps({"group_ids": [qa_group["id"]]}),
                auth=auth,
                content_type="application/json",
            )[0],
            403,
        )
        self.assertEqual(post_json("/admin/canary/default/groups", {"group_ids": "bad"})[0], 422)
        self.assertEqual(post_json("/admin/canary/default/groups", {"group_ids": [999999]})[0], 404)

        dg_code, dg_body = post_json(
            "/admin/canary/default/groups",
            {"group_ids": [qa_group["id"]], "sync_active_canary": True},
        )
        self.assertEqual(dg_code, 200)
        self.assertEqual(json.loads(dg_body)["default_group_count"], 1)
        group_flags_after = {g["id"]: g["canary_default"] for g in self.registry.list_groups()}
        self.assertEqual(group_flags_after[qa_group["id"]], 1)
        self.assertEqual(group_flags_after[dev_group["id"]], 0)
        self.assertEqual(group_flags_after[default_gid], 0)
        v10_selected = [g["id"] for g in self.registry.list_version_canary_groups("0.10.0") if g["selected"]]
        self.assertEqual(v10_selected, [qa_group["id"]])

        # Verify /admin renders group-aware controls and sortable table headers for picker tables.
        self.registry.add_default_canary_members([uid_qa], note="grp-member")
        _, updated_html = self.request("GET", "/admin", auth=auth)
        for marker in (
            'id="default-groups-save-btn"',
            'class="default-canary-group-cb"',
            'data-table-id="default-picker"',
            'data-table-id="modal-picker"',
            'data-sort-table="default-picker" data-sort="computer"',
            'data-sort-table="modal-picker" data-sort="canaryStatus"',
            'id="default-picker-group-filter"',
            'id="default-canary-group-filter"',
            'id="modal-picker-group-filter"',
            'id="modal-members-group-filter"',
            f'data-group-id="{dev_group["id"]}"',
        ):
            self.assertIn(marker, updated_html)
