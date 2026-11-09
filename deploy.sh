#!/usr/bin/env bash
set -euo pipefail

# Fill in the admin credentials before deployment.
PERFLENS_ADMIN_USERNAME=''
PERFLENS_ADMIN_PASSWORD=''
listen_host=0.0.0.0
listen_port=8787
python_exe=python3.13
tls_certfile=''
tls_keyfile=''

if [[ -z $PERFLENS_ADMIN_USERNAME || -z $PERFLENS_ADMIN_PASSWORD ]]; then
    printf '%s\n' 'Fill in PERFLENS_ADMIN_USERNAME and PERFLENS_ADMIN_PASSWORD in deploy.sh.' >&2
    exit 2
fi

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
# Restrict new files, including the SQLite registry and signing key.
umask 077
venv_dir=private/activation-venv
venv_python=$venv_dir/bin/python
data_dir=private/activation

if [[ ! -x $venv_python ]]; then
    "$python_exe" -m venv "$venv_dir"
fi
"$venv_python" -B -m pip install --disable-pip-version-check -r activation_server/requirements.txt

# Init reuses the signing key and prints the public key path for packaging.
"$venv_python" -B -m activation_server init --data-dir "$data_dir"
export PERFLENS_ADMIN_USERNAME PERFLENS_ADMIN_PASSWORD
exec "$venv_python" -B -m activation_server serve --data-dir "$data_dir" --host "$listen_host" --port "$listen_port" \
    --ssl-certfile "$tls_certfile" --ssl-keyfile "$tls_keyfile"
