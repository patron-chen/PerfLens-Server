#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
ROOT_DIR=$PWD
PRIVATE_DIR=$ROOT_DIR/private
CACHE_DIR=$PRIVATE_DIR/cache
STANDALONE_PYTHON=$PRIVATE_DIR/python/bin/python3
VENV_PYTHON=$PRIVATE_DIR/activation-venv/bin/python

show_help()
{
    cat <<'EOF'
Usage: bash setup.sh [OPTIONS]

Initialize the PerfLens activation server environment on Linux.

Options:
  -h, --help           Show this help message
  --python <path>      Specify an existing Python 3.13 x86_64 executable
  --mirror <url>       Download mirror URL prefix for GitHub / PyPI
  --force              Re-create the virtual environment and reinstall dependencies

Examples:
  bash setup.sh
  bash setup.sh --mirror https://ghproxy.net/
  bash setup.sh --python /usr/local/bin/python3.13
EOF
}

explicit_python=''
mirror_url=''
force=0

forward_args=()
while (( $# > 0 )); do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        --python)
            if (( $# < 2 )); then
                printf 'Missing argument for --python\n' >&2
                exit 2
            fi
            explicit_python=$2
            forward_args+=("$1" "$2")
            shift 2
            ;;
        --mirror)
            if (( $# < 2 )); then
                printf 'Missing argument for --mirror\n' >&2
                exit 2
            fi
            mirror_url=$2
            forward_args+=("$1" "$2")
            shift 2
            ;;
        --force)
            force=1
            forward_args+=("$1")
            shift
            ;;
        *)
            forward_args+=("$1")
            shift
            ;;
    esac
done

is_python_313()
{
    local candidate=$1
    if [[ ! -x $candidate ]] && ! command -v "$candidate" >/dev/null 2>&1; then
        return 1
    fi
    "$candidate" -B -c "import sys, struct; sys.exit(0 if sys.version_info[:2] == (3, 13) and struct.calcsize('P') == 8 else 1)" >/dev/null 2>&1
}

setup_python=''

if [[ -n $explicit_python ]]; then
    if is_python_313 "$explicit_python"; then
        setup_python=$explicit_python
    else
        printf 'ERROR: Specified interpreter "%s" is not a 64-bit Python 3.13.\n' "$explicit_python" >&2
        exit 2
    fi
elif is_python_313 "$STANDALONE_PYTHON"; then
    setup_python=$STANDALONE_PYTHON
elif is_python_313 python3.13; then
    setup_python=python3.13
elif is_python_313 python3; then
    setup_python=python3
elif is_python_313 python; then
    setup_python=python
fi

if [[ -z $setup_python ]]; then
    printf 'No Python 3.13 detected on host. Downloading standalone Python runtime...\n'
    umask 077
    mkdir -p "$PRIVATE_DIR" "$CACHE_DIR"

    standalone_url='https://github.com/astral-sh/python-build-standalone/releases/download/20250115/cpython-3.13.1+20250115-x86_64-unknown-linux-gnu-install_only.tar.gz'
    standalone_sha256='5e7d73b3144d51f15fca492c0f8afd9f690fd3e7bfa61e259beb3650d0336e1b'
    archive_file=$CACHE_DIR/cpython-3.13.1-x86_64-unknown-linux-gnu.tar.gz

    download_url=$standalone_url
    if [[ -n $mirror_url ]]; then
        if [[ $mirror_url == */ ]]; then
            download_url="${mirror_url}${standalone_url}"
        else
            download_url="${mirror_url}/${standalone_url}"
        fi
    elif [[ -n ${GH_PROXY:-} ]]; then
        if [[ $GH_PROXY == */ ]]; then
            download_url="${GH_PROXY}${standalone_url}"
        else
            download_url="${GH_PROXY}/${standalone_url}"
        fi
    fi

    printf 'Downloading from %s ...\n' "$download_url"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 2 --connect-timeout 15 --max-time 300 -o "$archive_file" "$download_url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 15 -O "$archive_file" "$download_url"
    else
        printf 'ERROR: curl or wget is required to download standalone Python.\n' >&2
        exit 1
    fi

    printf 'Verifying checksum...\n'
    if command -v sha256sum >/dev/null 2>&1; then
        if ! echo "$standalone_sha256  $archive_file" | sha256sum -c - >/dev/null 2>&1; then
            printf 'ERROR: SHA-256 verification failed for downloaded Python archive.\n' >&2
            rm -f -- "$archive_file"
            exit 1
        fi
    fi

    printf 'Extracting standalone Python...\n'
    tar -xzf "$archive_file" -C "$PRIVATE_DIR"
    chmod -R u+w,u+x "$PRIVATE_DIR/python" 2>/dev/null || true

    if [[ ! -x $STANDALONE_PYTHON ]]; then
        printf 'ERROR: Expected Python interpreter not found at %s\n' "$STANDALONE_PYTHON" >&2
        exit 1
    fi

    setup_python=$STANDALONE_PYTHON
fi

exec "$setup_python" -B -m activation_server.setup "${forward_args[@]}"
