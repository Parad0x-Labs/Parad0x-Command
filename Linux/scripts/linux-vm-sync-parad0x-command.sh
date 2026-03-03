#!/bin/zsh
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
PROJECT_ROOT=$(cd "$ROOT_DIR/.." && pwd)
ARCHIVE=/tmp/parad0x-command-linux-sync.tar.gz
VM_NAME=linux-browser-lab
VM_ARCHIVE=/home/ubuntu/parad0x-command-linux-sync.tar.gz
VM_PROJECT_DIR=/home/ubuntu/parad0x-command-test

COPYFILE_DISABLE=1 COPY_EXTENDED_ATTRIBUTES_DISABLE=1 tar --format ustar -czf "$ARCHIVE" \
  -C "$PROJECT_ROOT" \
  README.md \
  requirements.txt \
  parad0x-command \
  run_parad0x_command_export.sh \
  "Start Parad0x Command on Linux.sh" \
  install_parad0x_command.sh \
  restore_parad0x_command_export.sh \
  docs \
  tools

echo "Syncing Parad0x Command into the Linux VM..." >&2
multipass transfer "$ARCHIVE" "$VM_NAME:$VM_ARCHIVE"
multipass exec "$VM_NAME" -- bash -lc "mkdir -p $VM_PROJECT_DIR && tar -xzf $VM_ARCHIVE -C $VM_PROJECT_DIR && rm -f $VM_ARCHIVE"

echo "$VM_PROJECT_DIR"
