#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

TARGET_PATH="${TARGET_PATH:-$HOME/Desktop}"
PORT="${PORT:-8776}"
WORKSPACE="${WORKSPACE:-}"

if [[ -z "$WORKSPACE" && -d "$HOME/.openclaw" ]]; then
  WORKSPACE="$HOME/.openclaw"
fi

if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi

"$ROOT/.venv/bin/python" -m pip install --upgrade pip wheel setuptools
"$ROOT/.venv/bin/python" -m pip install -r requirements.txt

(
  sleep 2
  if [[ "$OSTYPE" == darwin* ]]; then
    open "http://127.0.0.1:${PORT}" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://127.0.0.1:${PORT}" >/dev/null 2>&1 || true
  fi
) &

ARGS=("tools/liquefy_desktop_viz.py" "live" "$TARGET_PATH" "--desktop" "--port" "$PORT")
if [[ -n "$WORKSPACE" ]]; then
  ARGS+=("--workspace" "$WORKSPACE")
fi

exec "$ROOT/.venv/bin/python" "${ARGS[@]}"
