"""Run the issuance and admin routes over loopback with a disposable signing key."""
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
from urllib.parse import urlencode

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import uvicorn

from activation_server.app import Registry, create_app
from activation_server.protocol import ACTIVATION_PATH, verify_code
from activation_server.updates import SIGNING_PREFIX, UPDATES_PATH, artifact_names, publish_update


class ActivationServerTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix="perflens-server-test-"))
        self.key = Ed25519PrivateKey.generate()
        self.now = 1800000000
        self.uid = "a" * 64
        self.db = self.folder / "activation.sqlite3"
        self.registry = Registry(self.db, self.key, lambda: self.now)

    def start_server(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        self.port = listener.getsockname()[1]
        app = create_app(self.registry, "test-admin", "test-password")
        server = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="off"))
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

    def request(self, method, path, data=None, *, auth=None, content_type=None):
        headers = {}
        if auth:
            headers["Authorization"] = "Basic " + base64.b64encode(auth).decode("ascii")
        if content_type:
            headers["Content-Type"] = content_type
        with closing(HTTPConnection("127.0.0.1", self.port, timeout=5)) as connection:
            connection.request(method, path, body=data, headers=headers)
            response = connection.getresponse()
            return response.status, response.read().decode("utf-8")

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

    def test_legacy_database_preserves_lease_and_records_latest_successful_version(self):
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
        self.assertIn("<td>—</td>", self.request("GET", "/admin", auth=auth)[1])
        code, body = activate(client_version="0.4.1")
        self.assertEqual(code, 200)
        self.assertEqual(verify_code(json.loads(body)["code"], self.uid, self.key.public_key()), expiry)
        self.assertEqual(activate(), (code, body))
        self.registry.set_auto_issue(self.uid, False)
        self.assertEqual(activate(client_version="0.4.2")[0], 403)
        self.assertEqual(activate(client_version="<script>")[0], 422)
        reopened = Registry(old_db, self.key, lambda: self.now)
        row = reopened.view()[1][0]
        self.assertEqual((row["first_seen"], row["expires_at"], row["client_version"]), (self.now - 60, expiry, "0.4.1"))
        self.assertIn("<td>0.4.1</td>", self.request("GET", "/admin", auth=auth)[1])

    def test_published_manifest_is_signed_and_downloads_stay_versioned(self):
        self.start_server()
        latest = f"{UPDATES_PATH}/latest"
        self.assertEqual(self.request("GET", latest), (204, ""))
        public = self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

        def release(version):
            folder = self.folder / f"release-{version}"
            folder.mkdir()
            artifacts = []
            for name in artifact_names(version).values():
                contents = name.encode("ascii")
                (folder / name).write_bytes(contents)
                artifacts.append({"file": name, "bytes": len(contents), "sha256": hashlib.sha256(contents).hexdigest()})
            record = {"version": version, "activation_server": "http://127.0.0.1:8787", "artifacts": artifacts,
                      "activation_public_key_sha256": hashlib.sha256(public).hexdigest()}
            (folder / "manifest.json").write_text(json.dumps(record), encoding="utf-8")
            return folder

        old = release("0.9.0")
        newest = release("0.10.0")
        bad = release("0.11.0")
        self.assertEqual(publish_update(self.folder, old, self.key), "0.9.0")
        with self.assertRaisesRegex(ValueError, "already published"):
            publish_update(self.folder, old, self.key)
        with self.assertRaisesRegex(ValueError, "public key"):
            publish_update(self.folder, newest, Ed25519PrivateKey.generate())
        (bad / artifact_names("0.11.0")["unpacked"]).write_bytes(b"tampered")
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
