#!/bin/zsh
set -euo pipefail

multipass exec linux-browser-lab -- bash -lc "pkill -f 'tools/liquefy_desktop_viz.py|run_parad0x_command_export.sh' || true"
echo "Stopped Parad0x Command processes in the Linux VM."
