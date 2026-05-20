#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${ROOT}/build"
PORT="${1:-9000}"

if [[ ! -x "${BUILD}/cypherock_server" ]]; then
  echo "Build first: cmake -B build && cmake --build build -j"
  exit 1
fi

"${BUILD}/cypherock_server" --port "${PORT}" &
SERVER_PID=$!

cleanup() {
  kill "${SERVER_PID}" 2>/dev/null || true
  wait "${SERVER_PID}" 2>/dev/null || true
}
trap cleanup EXIT

sleep 1

set +e
"${BUILD}/cypherock_client" --port "${PORT}"
CLIENT_STATUS=$?
set -e

if [[ "${CLIENT_STATUS}" -ne 0 ]]; then
  echo "demo failed: client exited with status ${CLIENT_STATUS}"
  exit "${CLIENT_STATUS}"
fi

# Server exits on its own after a successful session; trap still reaps it.
wait "${SERVER_PID}" 2>/dev/null || true
exit 0
