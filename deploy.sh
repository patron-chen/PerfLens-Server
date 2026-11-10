#!/usr/bin/env bash
set -euo pipefail

# Fill in the admin credentials before deployment.
PERFLENS_ADMIN_USERNAME=''
PERFLENS_ADMIN_PASSWORD=''
listen_host=0.0.0.0
listen_port=8787
python_exe=python3.13
distribution_dir=distribution
tls_certfile=''
tls_keyfile=''
# Set to 1 to allow HTTP admin on a trusted LAN.
export PERFLENS_ADMIN_ALLOW_HTTP=0

mode=${1:-}
unit=perflens-activation.service
admin=()
if (( EUID != 0 )); then
    admin=(sudo)
fi

find_foreground_pid()
{
    local workdir candidates candidate
    workdir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    # A match from another deployment directory belongs to a different instance.
    candidates=$(pgrep -f -- '^private/activation-venv/bin/python -u -B -m activation_server serve( |$)') || [[ $? == 1 ]] || return 1
    for candidate in $candidates; do
        if [[ $(readlink "/proc/$candidate/cwd" 2>/dev/null) == "$workdir" ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    done
}

show_status()
{
    local properties name value state=inactive pid=0 service_user=0 listeners
    if properties=$(systemctl show "$unit" --property=ActiveState,MainPID,User 2>/dev/null); then
        while IFS='=' read -r name value; do
            case $name in
                ActiveState) state=$value ;;
                MainPID) pid=${value:-0} ;;
                User) service_user=${value:-0} ;;
            esac
        done <<< "$properties"
    fi
    if [[ $pid == 0 ]]; then
        pid=$(find_foreground_pid)
        if [[ -z $pid ]]; then
            if [[ $state == inactive ]]; then
                state=stopped
            fi
            printf 'Status: %s\n' "$state"
            return
        fi
        service_user=$EUID
    fi

    printf 'Status: running\nPID: %s\n' "$pid"
    local -a socket_reader=(ss)
    if (( EUID != 0 )) && [[ $service_user != "$EUID" && $service_user != "$(id -un)" ]]; then
        socket_reader=("${admin[@]}" ss)
    fi
    listeners=$("${socket_reader[@]}" -H -ltnp | awk -v pid="$pid" 'index($0, "pid=" pid ",") { print $4 }' | sort -u)
    printf 'Listening: %s\n' "${listeners:-none}"
}

case $mode in
    --status)
        show_status
        exit
        ;;
    --stop|--restart)
        exec "${admin[@]}" systemctl "${mode#--}" "$unit"
        ;;
    ''|--install-service|--serve) ;;
    *)
        printf 'Usage: bash deploy.sh [--install-service|--status|--stop|--restart]\n' >&2
        exit 2
        ;;
esac

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
log_dir=log

install_service()
{
    local script_path=$PWD/${BASH_SOURCE[0]##*/}

    # ExecStart uses systemd quoting and specifiers instead of shell quoting.
    script_path=${script_path//\\/\\\\}
    script_path=${script_path//\"/\\\"}
    script_path=${script_path//%/%%}
    script_path=${script_path//$'\n'/\\n}
    script_path=${script_path//$'\r'/\\r}

    (
        umask 022
        "${admin[@]}" tee "/etc/systemd/system/$unit" >/dev/null
    ) <<EOF
[Unit]
Description=PerfLens Activation Server
After=network.target

[Service]
User=$EUID
ExecStart=:/bin/bash "$script_path" --serve
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    "${admin[@]}" systemctl daemon-reload
    "${admin[@]}" systemctl enable --now "$unit"
}

if [[ $mode == --install-service ]] && ! systemctl show --property=Version >/dev/null; then
    printf '%s\n' '--install-service requires a running systemd system manager.' >&2
    exit 1
fi

# Only deployment installs dependencies and initializes the signing key.
if [[ $mode != --serve ]]; then
    if [[ ! -x $venv_python ]]; then
        "$python_exe" -m venv "$venv_dir"
    fi
    "$venv_python" -B -m pip install --disable-pip-version-check -r activation_server/requirements.txt
    "$venv_python" -B -m activation_server init --data-dir "$data_dir"
    printf 'Activation server log: %s/%s/activation-server.log\n' "$PWD" "$log_dir"
fi

if [[ $mode == --install-service ]]; then
    install_service
    exit 0
fi

export PERFLENS_ADMIN_USERNAME PERFLENS_ADMIN_PASSWORD
exec "$venv_python" -u -B -m activation_server serve --data-dir "$data_dir" --host "$listen_host" --port "$listen_port" \
    --distribution-dir "$distribution_dir" \
    --ssl-certfile "$tls_certfile" --ssl-keyfile "$tls_keyfile" --log-dir "$log_dir"
