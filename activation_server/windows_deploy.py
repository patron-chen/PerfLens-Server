"""Manage the Windows launcher and stream its output to the service log."""
import argparse
import ctypes
from ctypes import wintypes
import logging
import msvcrt
import os
from pathlib import Path
import subprocess
import sys

from .server_log import LOG_DIR, LOG_NAME, file_log_handler


STATE_FILE = Path("private/activation-server.pid")
VENV_DIR = Path("private/activation-venv")
VENV_PYTHON = VENV_DIR / "Scripts" / "python.exe"
DATA_DIR = "private/activation"
TH32CS_SNAPPROCESS = 0x00000002
ERROR_NO_MORE_FILES = 18


class ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * wintypes.MAX_PATH),
    ]


def creation_time(pid):
    # A PID can be reused after a crash or reboot. Match its creation time before stopping it.
    command = (
        "$ErrorActionPreference = 'Stop'\n"
        f"$process = Get-Process -Id {pid} -ErrorAction SilentlyContinue\n"
        "if ($process) { $process.StartTime.ToUniversalTime().Ticks }\n"
        "exit 0\n"
    )
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                            check=True, capture_output=True, text=True,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    return result.stdout.strip()


def running_pid(state):
    entry = state.read().split()
    if not entry:
        return None
    try:
        pid, started = map(int, entry)
    except ValueError as error:
        raise ValueError(f"Invalid process state in {STATE_FILE}") from error
    if pid > 0 and creation_time(pid) == str(started):
        return pid
    return None


def process_tree(pid):
    # The launcher and Windows venv redirector have different PIDs from the server.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    for read_entry in (kernel.Process32FirstW, kernel.Process32NextW):
        read_entry.argtypes = (wintypes.HANDLE, ctypes.POINTER(ProcessEntry))
        read_entry.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())

    children = {}
    entry = ProcessEntry(dwSize=ctypes.sizeof(ProcessEntry))
    try:
        found = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while found:
            children.setdefault(entry.th32ParentProcessID, set()).add(entry.th32ProcessID)
            found = kernel.Process32NextW(snapshot, ctypes.byref(entry))
        error = ctypes.get_last_error()
        if error != ERROR_NO_MORE_FILES:
            raise ctypes.WinError(error)
    finally:
        kernel.CloseHandle(snapshot)

    pids = {pid}
    pending = [pid]
    while pending:
        new_children = children.get(pending.pop(), set()) - pids
        pids.update(new_children)
        pending.extend(new_children)
    return pids


def show_status(pid):
    if pid is None:
        print("Status: stopped")
        return 0

    pids = process_tree(pid)
    result = subprocess.run(["netstat.exe", "-ano"], check=True, capture_output=True, encoding="ascii",
                            errors="replace", creationflags=subprocess.CREATE_NO_WINDOW)
    listeners = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 5 and fields[0] == "TCP" and fields[3] in ("LISTEN", "LISTENING"):
            owner = int(fields[4])
            if owner in pids:
                listeners.add((owner, fields[1]))

    if not listeners:
        print(f"Status: starting\nLauncher PID: {pid}\nListening: none")
        return 0

    print("Status: running")
    for owner, endpoint in sorted(listeners):
        print(f"PID: {owner}\nListening: {endpoint}")
    return 0


def record_process(state, pid):
    started = creation_time(pid)
    if not started:
        raise RuntimeError(f"Activation server exited during launch. See {LOG_DIR / LOG_NAME}")
    state.seek(0)
    state.truncate()
    state.write(f"{pid} {started}\n".encode("ascii"))
    state.flush()


def stop_process(pid):
    # Include the venv launcher and its Python child.
    subprocess.run(["taskkill.exe", "/F", "/T", "/PID", str(pid)], check=True,
                   stdout=subprocess.DEVNULL)


def run_logged(command):
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, encoding="utf-8", errors="replace",
                          env={**os.environ, "PYTHONIOENCODING": "utf-8"}) as process:
        for line in process.stdout:
            logging.info("%s", line.rstrip("\r\n"))
    if process.returncode:
        raise subprocess.CalledProcessError(process.returncode, command)


def run_server():
    logging.basicConfig(level=logging.INFO, handlers=[file_log_handler(LOG_DIR, "%(asctime)s %(message)s")])
    try:
        if not VENV_PYTHON.is_file():
            run_logged([sys.executable, "-m", "venv", str(VENV_DIR)])
        run_logged([VENV_PYTHON, "-B", "-m", "pip", "install", "--disable-pip-version-check",
                    "-r", "activation_server/requirements.txt"])
        run_logged([VENV_PYTHON, "-B", "-m", "activation_server", "init", "--data-dir", DATA_DIR])
        run_logged([VENV_PYTHON, "-u", "-B", "-m", "activation_server", "serve", "--data-dir", DATA_DIR,
                    "--host", os.environ.get("ACTIVATION_HOST", "0.0.0.0"),
                    "--port", os.environ.get("ACTIVATION_PORT", "8787"),
                    "--distribution-dir", os.environ.get("DISTRIBUTION_DIR", "distribution"),
                    "--ssl-certfile", os.environ.get("ACTIVATION_TLS_CERTFILE", ""),
                    "--ssl-keyfile", os.environ.get("ACTIVATION_TLS_KEYFILE", "")])
    except subprocess.CalledProcessError as error:
        logging.error("Deployment command exited with status %s", error.returncode)
        return error.returncode
    except OSError:
        logging.exception("Deployment failed")
        return 1
    return 0


def launch_background(state):
    process = subprocess.Popen([sys.executable, "-B", "-m", "activation_server.windows_deploy", "--run-hidden"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        record_process(state, process.pid)
    except (Exception, KeyboardInterrupt):
        if process.poll() is None:
            stop_process(process.pid)
        raise


def main():
    parser = argparse.ArgumentParser(prog="deploy.bat", description="Manage the PerfLens activation server")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--foreground", action="store_true", help="Run in the foreground")
    mode.add_argument("--status", action="store_true", help="Show the current PID and listening address")
    mode.add_argument("--stop", action="store_true", help="Stop the running server")
    mode.add_argument("--restart", action="store_true", help="Stop the server and start it in the background")
    mode.add_argument("--run-hidden", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.run_hidden:
        return run_server()
    credentials = ("PERFLENS_ADMIN_USERNAME", "PERFLENS_ADMIN_PASSWORD")
    if not (args.stop or args.status) and not all(os.environ.get(name) for name in credentials):
        parser.error("Fill in PERFLENS_ADMIN_USERNAME and PERFLENS_ADMIN_PASSWORD in deploy.bat.")

    if args.status and not STATE_FILE.exists():
        return show_status(None)
    if not args.status:
        STATE_FILE.parent.mkdir(exist_ok=True, mode=0o700)
    with STATE_FILE.open("rb" if args.status else "a+b") as state:
        state.seek(0)
        # Serialize launcher commands. The OS releases the lock when the file closes.
        msvcrt.locking(state.fileno(), msvcrt.LK_NBLCK, 1)
        pid = running_pid(state)
        if args.status:
            return show_status(pid)
        if args.stop:
            if pid is not None:
                stop_process(pid)
            print("Activation server stopped.")
            return 0
        log_path = (LOG_DIR / LOG_NAME).resolve()
        if pid is not None and not args.restart:
            print(f"Activation server is already running. Log: {log_path}")
            return 0
        # Check log access before stopping a running instance or hiding the new one.
        file_log_handler(LOG_DIR).close()
        if pid is not None:
            stop_process(pid)
        if not args.foreground:
            launch_background(state)
            print(f"Activation server launch requested. Log: {log_path}")
            return 0
        record_process(state, os.getpid())

    print(f"Activation server log: {log_path}", flush=True)
    return run_server()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"ERROR: {error}")
    except KeyboardInterrupt:
        sys.exit(130)
