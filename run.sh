#!/usr/bin/env bash
# Launcher for pm2.
#
# The password lives outside the project directory in a file readable only by
# this user, so it is never at risk of being committed or copied along with the
# source. pm2 has no equivalent of systemd's EnvironmentFile, hence the
# sourcing here.
set -euo pipefail

ENV_FILE="${HOME}/.config/sonoff-mqtt/env"
if [ ! -r "${ENV_FILE}" ]; then
    echo "Missing or unreadable ${ENV_FILE}" >&2
    exit 1
fi

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

cd "$(dirname "$0")"
export PYTHONPATH="$(pwd)/src"
exec .venv/bin/python -m sonoff_mqtt --config config/config.yml
