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
sleep 1
"${BUILD}/cypherock_client" --port "${PORT}" || true
kill "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true
