"""Initialize keys, publish updates, and run the standalone activation server."""
import argparse
import logging
import os
from pathlib import Path

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .app import Registry, create_app
from .server_log import file_log_handler
from .updates import publish_update


def load_private_key(path):
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 signing key")
    return key


def initialize(directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_path = directory / "activation-private.pem"
    public_path = directory / "activation-public.pem"
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
    print(f"Client verification key: {public_path.resolve()}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="PerfLens activation server")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create the server signing key and export its public key")
    init.add_argument("--data-dir", type=Path, required=True)
    publish = commands.add_parser("publish-update", help="Publish a signed Windows x64 update")
    publish.add_argument("--data-dir", type=Path, required=True)
    publish.add_argument("--release-dir", type=Path, required=True)
    serve = commands.add_parser("serve", help="Start the activation API and admin page")
    serve.add_argument("--data-dir", type=Path, required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--distribution-dir", type=Path, help="Watch a release directory for newer versions")
    serve.add_argument("--ssl-certfile")
    serve.add_argument("--ssl-keyfile")
    serve.add_argument("--log-dir", type=Path, help="Write timestamped, rotating logs to this directory")
    args = parser.parse_args(argv)
    logger = None
    try:
        if args.command == "init":
            initialize(args.data_dir)
            return
        if args.command == "publish-update":
            key = load_private_key(args.data_dir / "activation-private.pem")
            version = publish_update(args.data_dir, args.release_dir, key)
            print(f"Published Windows x64 update {version}")
            return
        if args.log_dir is not None:
            logging.basicConfig(level=logging.INFO, handlers=[file_log_handler(args.log_dir)], force=True)
            logger = logging.getLogger("uvicorn.error")
        username = os.environ.get("PERFLENS_ADMIN_USERNAME", "")
        password = os.environ.get("PERFLENS_ADMIN_PASSWORD", "")
        if not username or ":" in username or not password or not (username.isascii() and password.isascii()):
            raise ValueError("Set PERFLENS_ADMIN_USERNAME and PERFLENS_ADMIN_PASSWORD to nonempty ASCII credentials")
        if bool(args.ssl_certfile) != bool(args.ssl_keyfile):
            raise ValueError("Specify both --ssl-certfile and --ssl-keyfile for HTTPS")
        if not 1 <= args.port <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        key = load_private_key(args.data_dir / "activation-private.pem")
        registry = Registry(args.data_dir / "activation.sqlite3", key)
        if args.distribution_dir is not None:
            args.distribution_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        app = create_app(registry, username, password, distribution_dir=args.distribution_dir)
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
