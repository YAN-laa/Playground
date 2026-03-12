#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

mkdir -p "${ROOT_DIR}/bin"

echo "[1/2] building ndr-server"
GOCACHE="${ROOT_DIR}/.cache/go-build" go build -o "${ROOT_DIR}/bin/ndr-server" "${ROOT_DIR}/cmd/server"

echo "[2/2] building probe-agent"
GOCACHE="${ROOT_DIR}/.cache/go-build" go build -o "${ROOT_DIR}/bin/probe-agent" "${ROOT_DIR}/cmd/probe-agent"

echo "build completed:"
ls -lh "${ROOT_DIR}/bin/ndr-server" "${ROOT_DIR}/bin/probe-agent"
