#!/bin/zsh
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <command> [args...]"
  exit 1
fi

CMD=$(printf '%q ' "$@")
CMD=${CMD% }

multipass exec linux-browser-lab -- bash -lc "cd /home/ubuntu/project && $CMD"
