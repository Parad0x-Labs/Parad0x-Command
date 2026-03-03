#!/bin/zsh
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
PROJECT_ROOT=$(cd "$ROOT_DIR/.." && pwd)
VM_NAME=linux-browser-lab
MOUNT_TARGET=/home/ubuntu/project

if ! multipass info "$VM_NAME" >/dev/null 2>&1; then
  multipass launch --name "$VM_NAME" --cpus 4 --memory 4G --disk 40G --cloud-init "$ROOT_DIR/cloud-init/linux-browser-lab.yaml"
fi

multipass start "$VM_NAME"

VM_INFO=$(multipass info "$VM_NAME")
EXPECTED_MOUNT="$PROJECT_ROOT => $MOUNT_TARGET"
if ! grep -Fq "$EXPECTED_MOUNT" <<<"$VM_INFO"; then
  if grep -Fq "=> $MOUNT_TARGET" <<<"$VM_INFO"; then
    multipass umount "$VM_NAME:$MOUNT_TARGET" || true
  fi
  multipass mount "$PROJECT_ROOT" "$VM_NAME:$MOUNT_TARGET"
fi

echo "VM is running."
echo "Provision desktop/browser services with: $ROOT_DIR/scripts/linux-vm-provision.sh"
