#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/Parad0x-Labs/Parad0x-Command.git}"
DEST_ROOT="${DEST_ROOT:-$HOME/Desktop}"
FOLDER_NAME="${FOLDER_NAME:-Parad0x Command}"
PORT="${PORT:-8776}"
WORKSPACE="${WORKSPACE:-}"
SKIP_INSTALL=0
NO_LAUNCH=0

usage() {
  cat <<EOF
Usage:
  bash install_parad0x_command.sh [options]

Options:
  --repo-url URL        Repo to clone. Default: $REPO_URL
  --dest-root DIR       Parent dir for install folder. Default: $DEST_ROOT
  --folder-name NAME    Install folder name. Default: $FOLDER_NAME
  --port PORT           Local port. Default: $PORT
  --workspace PATH      Optional workspace path
  --skip-install        Skip pip install step
  --no-launch           Do not auto-open browser after install
  -h, --help            Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --dest-root) DEST_ROOT="$2"; shift 2 ;;
    --folder-name) FOLDER_NAME="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --skip-install) SKIP_INSTALL=1; shift ;;
    --no-launch) NO_LAUNCH=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

INSTALL_DIR="$DEST_ROOT/$FOLDER_NAME"
if [[ -z "$WORKSPACE" && -d "$HOME/.openclaw" ]]; then
  WORKSPACE="$HOME/.openclaw"
fi

mkdir -p "$DEST_ROOT"

if [[ ! -d "$INSTALL_DIR/.git" ]]; then
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi

if [[ "$SKIP_INSTALL" -eq 0 ]]; then
  .venv/bin/python -m pip install --upgrade pip wheel setuptools
  .venv/bin/python -m pip install -r requirements.txt
fi

cat > "$INSTALL_DIR/launch_parad0x_command.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT_FILE="$ROOT/.parad0x_command.env"

TARGET_PATH="$HOME/Desktop"
PORT="8776"
WORKSPACE=""
if [[ -f "$PORT_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$PORT_FILE"
fi
if [[ -z "${WORKSPACE:-}" && -d "$HOME/.openclaw" ]]; then
  WORKSPACE="$HOME/.openclaw"
fi

CMD=("$ROOT/.venv/bin/python" "$ROOT/tools/liquefy_desktop_viz.py" "live" "$TARGET_PATH")
if [[ -n "${WORKSPACE:-}" ]]; then
  CMD+=("--workspace" "$WORKSPACE")
fi
CMD+=("--desktop" "--port" "$PORT")

if ! curl -fsS "http://127.0.0.1:${PORT}" >/dev/null 2>&1; then
  nohup "${CMD[@]}" >/tmp/parad0x_command.log 2>&1 </dev/null &
  sleep 2
fi

if [[ "$OSTYPE" == darwin* ]]; then
  open "http://127.0.0.1:${PORT}"
else
  xdg-open "http://127.0.0.1:${PORT}" >/dev/null 2>&1 || true
fi
EOF
chmod +x "$INSTALL_DIR/launch_parad0x_command.sh"

cat > "$INSTALL_DIR/.parad0x_command.env" <<EOF
TARGET_PATH="$HOME/Desktop"
PORT="$PORT"
WORKSPACE="$WORKSPACE"
EOF

cat > "$DEST_ROOT/Parad0x Command.command" <<EOF
#!/usr/bin/env bash
exec "$INSTALL_DIR/launch_parad0x_command.sh"
EOF
chmod +x "$DEST_ROOT/Parad0x Command.command"

if [[ "$OSTYPE" == linux-gnu* ]]; then
  cat > "$DEST_ROOT/Parad0x Command.desktop" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=Parad0x Command
Comment=Local command surface for apps, processes, files, and agents
Exec=$INSTALL_DIR/launch_parad0x_command.sh
Terminal=false
Categories=Utility;System;
EOF
  chmod +x "$DEST_ROOT/Parad0x Command.desktop"
  mkdir -p "$HOME/.local/share/applications"
  cp "$DEST_ROOT/Parad0x Command.desktop" "$HOME/.local/share/applications/parad0x-command.desktop"
fi

echo "Parad0x Command installed to: $INSTALL_DIR"
echo "Launcher created at: $DEST_ROOT/Parad0x Command.command"
if [[ "$OSTYPE" == linux-gnu* ]]; then
  echo "Desktop entry created at: $DEST_ROOT/Parad0x Command.desktop"
fi
if [[ -n "$WORKSPACE" ]]; then
  echo "Workspace autodetected/configured: $WORKSPACE"
else
  echo "Workspace: none (standalone mode)"
fi

if [[ "$NO_LAUNCH" -eq 0 ]]; then
  "$INSTALL_DIR/launch_parad0x_command.sh"
fi
