#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root"
  exit 1
fi

APP_ROOT="/opt/ndr-probe"
ETC_ROOT="/etc/ndr"
SYSTEMD_UNIT="/etc/systemd/system/ndr-probe-agent.service"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

id -u ndr >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/ndr-probe --shell /usr/sbin/nologin ndr

mkdir -p "${APP_ROOT}/bin" /var/lib/ndr-probe/buffer "${ETC_ROOT}"
cp "${REPO_ROOT}/bin/probe-agent" "${APP_ROOT}/bin/probe-agent"

if [[ ! -f "${ETC_ROOT}/probe-agent.env" ]]; then
  cp "${REPO_ROOT}/deploy/env/probe-agent.env.example" "${ETC_ROOT}/probe-agent.env"
  echo "created ${ETC_ROOT}/probe-agent.env, edit it before starting the service"
fi

cp "${REPO_ROOT}/deploy/systemd/ndr-probe-agent.service" "${SYSTEMD_UNIT}"
chown -R ndr:ndr "${APP_ROOT}" /var/lib/ndr-probe

systemctl daemon-reload
echo "probe agent installed."
echo "next:"
echo "1. edit ${ETC_ROOT}/probe-agent.env"
echo "2. ensure Suricata writes eve.json to NDR_EVE_FILE"
echo "3. systemctl enable --now ndr-probe-agent"
echo "4. systemctl status ndr-probe-agent"
