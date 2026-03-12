#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root"
  exit 1
fi

APP_ROOT="/opt/ndr"
ETC_ROOT="/etc/ndr"
SYSTEMD_UNIT="/etc/systemd/system/ndr-server.service"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

id -u ndr >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/ndr --shell /usr/sbin/nologin ndr

mkdir -p "${APP_ROOT}/bin" /var/lib/ndr/exports "${ETC_ROOT}"
cp "${REPO_ROOT}/bin/ndr-server" "${APP_ROOT}/bin/ndr-server"

if [[ ! -f "${ETC_ROOT}/server.env" ]]; then
  cp "${REPO_ROOT}/deploy/env/server.env.example" "${ETC_ROOT}/server.env"
  echo "created ${ETC_ROOT}/server.env, edit it before starting the service"
fi

cp "${REPO_ROOT}/deploy/systemd/ndr-server.service" "${SYSTEMD_UNIT}"
chown -R ndr:ndr "${APP_ROOT}" /var/lib/ndr

systemctl daemon-reload
echo "server installed."
echo "next:"
echo "1. edit ${ETC_ROOT}/server.env"
echo "2. systemctl enable --now ndr-server"
echo "3. systemctl status ndr-server"
