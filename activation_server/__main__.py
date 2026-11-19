"""Initialize activation keys, sign licenses, and run the activation server."""
import argparse
from datetime import datetime
from ipaddress import ip_address
import json
import logging
import os
from pathlib import Path
import re
import time

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .app import Registry, create_app
from .protocol import MAX_EXPIRY, UID_PATTERN, is_private_lan_address, signing_message
from .server_log import file_log_handler
from .updates import STAGE_CANARY, STAGE_RELEASED, publish_update


def load_private_key(path):
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 signing key")
    return key


def initialize(directory, purpose="activation"):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_path = directory / f"{purpose}-private.pem"
    public_path = directory / f"{purpose}-public.pem"
    if private_path.exists():
        key = load_private_key(private_path)
    else:
        if public_path.exists():
            raise ValueError("Restore the signing key that matches the existing public key")
        key = Ed25519PrivateKey.generate()
        encoded = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        with os.fdopen(os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
            handle.write(encoded)
    public_key = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if public_path.exists():
        if public_path.read_bytes() != public_key:
            raise ValueError("The existing public key does not match the signing key")
    else:
        with public_path.open("xb") as handle:
            handle.write(public_key)
    print(f"Verification key: {public_path.resolve()}")


def issue_offline(args):
    uid = args.uid.strip().lower()
    if not re.fullmatch(UID_PATTERN, uid):
        raise ValueError("Expected a 64-character hexadecimal device UID")
    expiry_date = datetime.fromisoformat(args.expires_at)
    if expiry_date.tzinfo is None:
        raise ValueError("Specify an expiration with an explicit timezone, for example 2027-01-01T00:00:00Z")
    expiry = int(expiry_date.timestamp())
    if not time.time() < expiry <= MAX_EXPIRY:
        raise ValueError("Offline expiration must be in the future within the supported UTC calendar range")
    message = signing_message(uid, expiry, offline=True)
    key = load_private_key(args.signing_key)
    record = {"code": f"{message.decode('ascii')}.{key.sign(message).hex()}"}
    with args.output.open("x", encoding="utf-8", newline="\r\n") as handle:
        json.dump(record, handle, indent=2)
        handle.write("\n")
    print(f"Issued offline authorization: {args.output.resolve()}")


def allows_plain_http(host, allow_lan):
    if host.lower() == "localhost":
        return True
    try:
        address = ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or (allow_lan and (address.is_unspecified or is_private_lan_address(address)))


def main(argv=None):
    parser = argparse.ArgumentParser(description="PerfLens activation server")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create the server signing key and export its public key")
    init.add_argument("--data-dir", type=Path, required=True)
    keygen = commands.add_parser("init-signing-key", help="Generate a dedicated offline license signing key")
    keygen.add_argument("--purpose", choices=("offline-license",), required=True)
    keygen.add_argument("--key-dir", type=Path, required=True)
    offline = commands.add_parser("issue-offline", help="Sign an offline authorization on the administrator's machine")
    offline.add_argument("--signing-key", type=Path, required=True)
    offline.add_argument("--uid", required=True)
    offline.add_argument("--expires-at", required=True, help="ISO 8601 expiration with an explicit timezone")
    offline.add_argument("--output", type=Path, required=True)
    publish = commands.add_parser("publish-update", help="Publish a signed Windows x64 update")
    publish.add_argument("--data-dir", type=Path, required=True)
    publish.add_argument("--release-dir", type=Path, required=True)
    publish.add_argument("--move", action="store_true", help="Move artifacts into updates instead of copying")
    publish.add_argument("--full", action="store_true", help="Publish directly as full release instead of canary stage")
    publish.add_argument(
        "--inherit-from",
        default="default",
        help="Canary allowlist source when publishing in canary stage: default, none, or an existing version",
    )
    setup_cmd = commands.add_parser("setup", help="Initialize environment, dependencies, and keys")
    setup_cmd.add_argument("--python", help="Path to Python 3.13 64-bit interpreter to use")
    setup_cmd.add_argument("--mirror", help="Mirror URL prefix for downloading standalone Python")
    setup_cmd.add_argument("--pip-index-url", help="PyPI index URL override for pip install")
    setup_cmd.add_argument("--force", action="store_true", help="Force recreate virtual environment")
    setup_cmd.add_argument("--data-dir", type=Path, default=Path("private/activation"), help=argparse.SUPPRESS)
    setup_cmd.add_argument("--venv-dir", type=Path, default=Path("private/activation-venv"), help=argparse.SUPPRESS)
    setup_cmd.add_argument("--distribution-dir", type=Path, default=Path("distribution"), help=argparse.SUPPRESS)
    setup_cmd.add_argument("--log-dir", type=Path, default=Path("log"), help=argparse.SUPPRESS)
    serve = commands.add_parser("serve", help="Start the activation API and admin page")
    serve.add_argument("--data-dir", type=Path, required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--distribution-dir", type=Path, help="Watch a release directory for newer versions")
    serve.add_argument("--ssl-certfile")
    serve.add_argument("--ssl-keyfile")
    serve.add_argument("--admin-network", action="append", help="Allowed administrator CIDR, repeatable (in addition to loopback)")
    serve.add_argument("--log-dir", type=Path, help="Write timestamped, rotating logs to this directory")
    args = parser.parse_args(argv)
    logger = None
    try:
        if args.command == "init":
            initialize(args.data_dir)
            return
        if args.command == "init-signing-key":
            initialize(args.key_dir, args.purpose)
            return
        if args.command == "issue-offline":
            issue_offline(args)
            return
        if args.command == "publish-update":
            key = load_private_key(args.data_dir / "activation-private.pem")
            stage = STAGE_RELEASED if args.full else STAGE_CANARY
            updates_dir = args.data_dir / "updates"

            def on_cli_published(version, published_stage):
                if published_stage == STAGE_CANARY:
                    # Touch the roster only after the manifest and artifacts have been verified.
                    registry = Registry(args.data_dir / "activation.sqlite3", key)
                    registry.init_version_canary(version, args.inherit_from, updates_dir=updates_dir)

            version = publish_update(
                args.data_dir,
                args.release_dir,
                key,
                move_artifacts=args.move,
                source="cli",
                stage=stage,
                on_published=on_cli_published,
            )
            print(f"Published Windows x64 update {version} ({stage})")
            return
        if args.command == "setup":
            from .setup import run_setup
            return run_setup(args)
        if args.log_dir is not None:
            logging.basicConfig(level=logging.INFO, handlers=[file_log_handler(args.log_dir)], force=True)
            logger = logging.getLogger("uvicorn.error")
        username = os.environ.get("PERFLENS_ADMIN_USERNAME", "")
        password = os.environ.get("PERFLENS_ADMIN_PASSWORD", "")
        if not username or ":" in username or not password or not (username.isascii() and password.isascii()):
            raise ValueError("Set PERFLENS_ADMIN_USERNAME and PERFLENS_ADMIN_PASSWORD to nonempty ASCII credentials")
        if bool(args.ssl_certfile) != bool(args.ssl_keyfile):
            raise ValueError("Specify both --ssl-certfile and --ssl-keyfile for HTTPS")
        allow_http = os.getenv("PERFLENS_ADMIN_ALLOW_HTTP") == "1"
        if not args.ssl_certfile and not allows_plain_http(args.host, allow_http):
            raise ValueError("Configure HTTPS, or set PERFLENS_ADMIN_ALLOW_HTTP=1 for a private LAN listener")
        if not 1 <= args.port <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        key = load_private_key(args.data_dir / "activation-private.pem")
        admin_networks = args.admin_network or [network.strip() for network in os.getenv("PERFLENS_ADMIN_NETWORKS", "").split(",")
                                                if network.strip()]
        registry = Registry(args.data_dir / "activation.sqlite3", key)
        if args.distribution_dir is not None:
            args.distribution_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        app = create_app(registry, username, password, admin_networks=admin_networks, allow_http=allow_http,
                         distribution_dir=args.distribution_dir)
        log_config = None if logger is not None else uvicorn.config.LOGGING_CONFIG
        uvicorn.run(app, host=args.host, port=args.port, workers=1, log_config=log_config,
                    proxy_headers=False, ssl_certfile=args.ssl_certfile, ssl_keyfile=args.ssl_keyfile)
    except (OSError, ValueError, TypeError) as error:
        if logger is not None:
            logger.error("%s", error)
        parser.exit(1, f"ERROR: {error}\n")
    except Exception:
        if logger is None:
            raise
        logger.exception("Activation server failed")
        parser.exit(1)


if __name__ == "__main__":
    main()
