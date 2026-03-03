#!/bin/zsh
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
PORT="${PORT:-8776}"
VM_PROJECT_DIR=$("$ROOT_DIR/scripts/linux-vm-sync-parad0x-command.sh")

echo "Stopping existing Parad0x Command instance in the Linux VM..."
"$ROOT_DIR/scripts/linux-vm-stop-parad0x-command.sh" >/dev/null 2>&1 || true
sleep 1

REMOTE_CMD="cd $VM_PROJECT_DIR && setsid env PORT=$(printf %q "$PORT") bash ./run_parad0x_command_export.sh >/tmp/parad0x-command-linux.log 2>&1 </dev/null & pid=\$!; echo \$pid"

echo "Starting Parad0x Command in the Linux VM..."
PID=$(multipass exec linux-browser-lab -- bash -lc "$REMOTE_CMD")
sleep 3

STATUS="starting"
if multipass exec linux-browser-lab -- bash -lc "curl -fsS --max-time 2 http://127.0.0.1:${PORT} >/dev/null 2>&1"; then
  STATUS="ready"
fi

echo "Started Parad0x Command in the Linux VM. PID: $PID"
echo "App URL inside the VM: http://127.0.0.1:${PORT}"
echo "VM project copy: $VM_PROJECT_DIR"
echo "Log: /tmp/parad0x-command-linux.log"
if [[ "$STATUS" == "ready" ]]; then
  echo "Status: ready"
else
  echo "Status: starting; give it a few seconds, then refresh the Linux browser"
fi
