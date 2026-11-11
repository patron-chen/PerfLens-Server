"""Setup and initialize the PerfLens activation server environment."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = ROOT / "private" / "activation"
DEFAULT_VENV_DIR = ROOT / "private" / "activation-venv"
DEFAULT_DISTRIBUTION_DIR = ROOT / "distribution"
DEFAULT_LOG_DIR = ROOT / "log"
REQUIREMENTS_FILE = ROOT / "activation_server" / "requirements.txt"

STANDALONE_RELEASE = "20250115"
STANDALONE_DISTRIBUTIONS = {
    ("Windows", "x86_64"): {
        "url": f"https://github.com/astral-sh/python-build-standalone/releases/download/{STANDALONE_RELEASE}/cpython-3.13.1+{STANDALONE_RELEASE}-x86_64-pc-windows-msvc-install_only.tar.gz",
        "sha256": "92021e1151d118db94689a38407248de96d8a2b8ffa9c4ae31b990441fda0aa0",
        "python_rel_path": Path("python/python.exe"),
    },
    ("Linux", "x86_64"): {
        "url": f"https://github.com/astral-sh/python-build-standalone/releases/download/{STANDALONE_RELEASE}/cpython-3.13.1+{STANDALONE_RELEASE}-x86_64-unknown-linux-gnu-install_only.tar.gz",
        "sha256": "5e7d73b3144d51f15fca492c0f8afd9f690fd3e7bfa61e259beb3650d0336e1b",
        "python_rel_path": Path("python/bin/python3"),
    },
}


def normalize_arch(machine: str) -> str:
    m = machine.lower()
    if m in ("amd64", "x86_64", "x64"):
        return "x86_64"
    return m


def apply_mirror(url: str, mirror: str | None = None) -> str:
    mirror_val = (mirror or os.environ.get("GH_PROXY") or "").strip()
    if not mirror_val:
        return url
    if mirror_val.endswith("/"):
        return f"{mirror_val}{url}"
    if "proxy" in mirror_val.lower():
        return f"{mirror_val}/{url}"
    return url.replace("https://github.com", mirror_val.rstrip("/"))


def verify_sha256(file_path: Path, expected_sha256: str) -> bool:
    if not file_path.is_file():
        return False
    hasher = hashlib.sha256()
    with file_path.open("rb") as handle:
        while chunk := handle.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().lower() == expected_sha256.lower()


def is_python_313(python_bin: Path | str) -> bool:
    candidate = Path(python_bin) if isinstance(python_bin, str) and ("/" in python_bin or "\\" in python_bin) else shutil.which(str(python_bin))
    if not candidate or not Path(candidate).is_file():
        return False
    try:
        command = [
            str(candidate),
            "-B",
            "-c",
            "import sys, struct; sys.exit(0 if sys.version_info[:2] == (3, 13) and struct.calcsize('P') == 8 else 1)"
        ]
        result = subprocess.run(command, capture_output=True, timeout=5)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def download_standalone_python(target_root: Path, mirror: str | None = None) -> Path:
    system = platform.system()
    arch = normalize_arch(platform.machine())
    key = (system, arch)
    if key not in STANDALONE_DISTRIBUTIONS:
        raise RuntimeError(f"Automated Python download not supported for {system} {arch}; please provide Python 3.13 via --python.")

    info = STANDALONE_DISTRIBUTIONS[key]
    url = apply_mirror(info["url"], mirror)
    cache_dir = target_root / "private" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    archive_name = info["url"].rsplit("/", 1)[-1]
    archive_path = cache_dir / archive_name
    expected_sha256 = info["sha256"]

    if archive_path.is_file() and verify_sha256(archive_path, expected_sha256):
        print(f"Using cached standalone archive: {archive_path}")
    else:
        print(f"Downloading standalone Python 3.13 from {url} ...", flush=True)
        temp_path = cache_dir / f"{archive_name}.part"
        request = urllib.request.Request(url, headers={"User-Agent": "PerfLens-Setup/1.0"})
        with urllib.request.urlopen(request, timeout=180) as response, temp_path.open("wb") as handle:
            shutil.copyfileobj(response, handle)

        if not verify_sha256(temp_path, expected_sha256):
            temp_path.unlink(missing_ok=True)
            raise ValueError(f"Checksum mismatch for downloaded archive from {url}")
        temp_path.replace(archive_path)
        print("Download verified successfully.", flush=True)

    print("Extracting standalone Python...", flush=True)
    private_dir = target_root / "private"
    private_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as archive:
        if hasattr(tarfile, "data_filter"):
            archive.extractall(path=private_dir, filter="data")
        else:
            archive.extractall(path=private_dir)

    standalone_bin = private_dir / info["python_rel_path"]
    if not standalone_bin.is_file():
        raise RuntimeError(f"Expected extracted Python binary not found at {standalone_bin}")

    if os.name != "nt":
        standalone_bin.chmod(0o755)
    return standalone_bin


def find_base_python(override: str | None = None, mirror: str | None = None) -> Path:
    if override:
        candidate = Path(override).resolve()
        if not is_python_313(candidate):
            raise ValueError(f"Specified Python interpreter '{override}' is not a 64-bit Python 3.13.")
        return candidate

    standalone_python = ROOT / "private" / "python" / ("python.exe" if os.name == "nt" else "bin/python3")
    if is_python_313(standalone_python):
        return standalone_python

    if is_python_313(sys.executable):
        try:
            if not Path(sys.executable).resolve().is_relative_to(DEFAULT_VENV_DIR.resolve()):
                return Path(sys.executable)
        except (ValueError, OSError):
            pass

    for name in ("python3.13", "py -3.13-64", "python3", "python"):
        if " " in name:
            parts = name.split()
            exe = shutil.which(parts[0])
            if exe and is_python_313(exe):
                return Path(exe)
        else:
            exe = shutil.which(name)
            if exe and is_python_313(exe):
                return Path(exe)

    return download_standalone_python(ROOT, mirror=mirror)


def pip_env() -> dict[str, str]:
    env = dict(os.environ)
    # pip's bundled urllib3 requires the third-party 'pysocks' package to handle socks proxies.
    # Without pysocks, pip crashes with "Missing dependencies for SOCKS support".
    has_socks = any(env.get(k, "").lower().startswith("socks") for k in (
        "all_proxy", "ALL_PROXY", "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"
    ))
    if has_socks:
        for k in ("all_proxy", "ALL_PROXY", "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
            if env.get(k, "").lower().startswith("socks"):
                env.pop(k, None)
    return env


def is_venv_healthy(venv_python: Path) -> bool:
    if not is_python_313(venv_python):
        return False
    check_command = [
        str(venv_python),
        "-B",
        "-c",
        "import cryptography; import fastapi; import uvicorn"
    ]
    try:
        return subprocess.run(check_command, capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def setup_venv(base_python: Path, venv_dir: Path, force: bool = False) -> Path:
    venv_python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    need_create = force or not venv_python.is_file() or not is_venv_healthy(venv_python)
    if need_create:
        print(f"Creating virtual environment in {venv_dir}...", flush=True)
        command = [str(base_python), "-m", "venv"]
        if venv_dir.exists():
            command.append("--clear")
        command.append(str(venv_dir))
        subprocess.run(command, check=True)
    return venv_python


def install_requirements(venv_python: Path, requirements_path: Path, pip_index: str | None = None) -> None:
    print(f"Installing dependencies from {requirements_path}...", flush=True)
    command = [
        str(venv_python),
        "-B",
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "-r",
        str(requirements_path)
    ]
    index_url = pip_index or os.environ.get("PIP_INDEX_URL")
    if index_url:
        command.extend(["-i", index_url])
    subprocess.run(command, check=True, env=pip_env())

    # Verify that critical packages can be imported without binary ABI conflicts
    check_command = [
        str(venv_python),
        "-B",
        "-c",
        "import cryptography; import fastapi; import uvicorn"
    ]
    check = subprocess.run(check_command, capture_output=True, text=True)
    if check.returncode != 0:
        print("Detected incompatible packages in virtual environment, reinstalling cleanly...", flush=True)
        reinstall_cmd = command + ["--force-reinstall"]
        subprocess.run(reinstall_cmd, check=True, env=pip_env())
        subprocess.run(check_command, check=True)


def initialize_data(venv_python: Path, data_dir: Path) -> None:
    print(f"Initializing signing key and database in {data_dir}...", flush=True)
    subprocess.run(
        [str(venv_python), "-B", "-m", "activation_server", "init", "--data-dir", str(data_dir)],
        check=True
    )


def run_setup(args: argparse.Namespace) -> int:
    try:
        if os.name != "nt":
            os.umask(0o077)

        print("[1/4] Detecting Python 3.13 runtime...", flush=True)
        base_python = find_base_python(override=args.python, mirror=args.mirror)
        print(f"Using base Python: {base_python}", flush=True)

        print("[2/4] Setting up virtual environment...", flush=True)
        venv_python = setup_venv(base_python, args.venv_dir, force=args.force)

        print("[3/4] Installing dependencies...", flush=True)
        install_requirements(venv_python, REQUIREMENTS_FILE, pip_index=args.pip_index_url)

        print("[4/4] Initializing server directories and signing keys...", flush=True)
        args.distribution_dir.mkdir(parents=True, exist_ok=True)
        args.log_dir.mkdir(parents=True, exist_ok=True)
        args.data_dir.mkdir(parents=True, exist_ok=True)
        initialize_data(venv_python, args.data_dir)

        print("\nSetup completed successfully!", flush=True)
        if os.name == "nt":
            print("Next: Fill in PERFLENS_ADMIN_USERNAME and PERFLENS_ADMIN_PASSWORD in deploy.bat, then run deploy.bat", flush=True)
        else:
            print("Next: Fill in PERFLENS_ADMIN_USERNAME and PERFLENS_ADMIN_PASSWORD in deploy.sh, then run bash deploy.sh", flush=True)
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"\nERROR: Setup failed: {error}", file=sys.stderr, flush=True)
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="activation_server.setup",
        description="Initialize the environment, dependencies, and keys for PerfLens Activation Server."
    )
    parser.add_argument("--python", help="Path to Python 3.13 64-bit interpreter to use")
    parser.add_argument("--mirror", help="Mirror URL prefix for downloading standalone Python")
    parser.add_argument("--pip-index-url", help="PyPI index URL override for pip install")
    parser.add_argument("--force", action="store_true", help="Force recreate virtual environment")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR, help=argparse.SUPPRESS)
    parser.add_argument("--venv-dir", type=Path, default=DEFAULT_VENV_DIR, help=argparse.SUPPRESS)
    parser.add_argument("--distribution-dir", type=Path, default=DEFAULT_DISTRIBUTION_DIR, help=argparse.SUPPRESS)
    parser.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR, help=argparse.SUPPRESS)
    parser.add_argument("--no-pause", action="store_true", help=argparse.SUPPRESS)

    parsed = parser.parse_args(argv)
    return run_setup(parsed)


if __name__ == "__main__":
    sys.exit(main())
