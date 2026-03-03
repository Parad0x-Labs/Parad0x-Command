#!/bin/zsh
set -euo pipefail

IP=$(multipass info linux-browser-lab | awk '/IPv4/ {print $2; exit}')

if [[ -z "${IP:-}" ]]; then
  echo "Linux VM has no IPv4 address yet."
  exit 1
fi

URL="vnc://$IP:5901"
echo "$URL"
open "$URL"
