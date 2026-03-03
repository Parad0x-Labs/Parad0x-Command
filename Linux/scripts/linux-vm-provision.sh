#!/bin/zsh
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
VM_NAME=linux-browser-lab
STATE_DIR="$ROOT_DIR/.state"
PASS_FILE="$STATE_DIR/linux-browser-lab-vnc-password"

mkdir -p "$STATE_DIR"

if [[ ! -f "$PASS_FILE" ]]; then
  openssl rand -hex 7 >"$PASS_FILE"
fi

VNC_PASSWORD=$(cat "$PASS_FILE")

multipass transfer "$PASS_FILE" "$VM_NAME:/home/ubuntu/vnc-password.txt"
multipass transfer "$ROOT_DIR/scripts/linux-vm-provision-remote.sh" "$VM_NAME:/home/ubuntu/linux-vm-provision-remote.sh"
multipass exec "$VM_NAME" -- sudo bash /home/ubuntu/linux-vm-provision-remote.sh

IP=$(multipass info "$VM_NAME" | awk '/IPv4/ {print $2; exit}')

echo "VNC password: $VNC_PASSWORD"
echo "Open: http://$IP:6080/vnc.html"
