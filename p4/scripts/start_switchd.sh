#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDE_DIR="${SDE_DIR:-$HOME/bf-sde-link}"
if pgrep -x bf_switchd >/dev/null; then
  echo 'bf_switchd is already running; inspect it before replacing it.' >&2
  exit 1
fi
mkdir -p "$TASK_ROOT/build"
cd "$SDE_DIR"
source ./set_sde.bash
nohup ./run_switchd.sh -p rubato > "$TASK_ROOT/build/switchd.log" 2>&1 < /dev/null &
echo "$!" > "$TASK_ROOT/build/switchd_launcher.pid"
echo "Started switchd launcher $!; verify build/switchd.log and hardware readiness."
