#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/.codex_backups/standalone_export_20260303T120000Z"
cp "$SRC/liquefy_desktop_viz.py" "$ROOT/tools/liquefy_desktop_viz.py"
cp "$SRC/test_desktop_viz.py" "$ROOT/tests/test_desktop_viz.py"
echo "Restored standalone export from $SRC"
