#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDE_DIR="${SDE_DIR:-$HOME/bf-sde-link}"

cd "$SDE_DIR"
source ./set_sde.bash

PY_VER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
for PY_SITE in \
  "$SDE_INSTALL/lib/python$PY_VER/site-packages" \
  "$SDE_INSTALL/lib/python$PY_VER/site-packages/tofino" \
  "$SDE_INSTALL/lib/python$PY_VER/site-packages/tofino/bfrt_grpc" \
  "$SDE_INSTALL/lib/python3.5/site-packages" \
  "$SDE_INSTALL/lib/python3.5/site-packages/tofino" \
  "$SDE_INSTALL/lib/python3.5/site-packages/tofino/bfrt_grpc" \
  "$SDE_INSTALL/lib/python3.8/site-packages" \
  "$SDE_INSTALL/lib/python3.8/site-packages/tofino" \
  "$SDE_INSTALL/lib/python3.8/site-packages/tofino/bfrt_grpc"; do
  if [[ -d "$PY_SITE" ]]; then
    export PYTHONPATH="$PY_SITE:${PYTHONPATH:-}"
  fi
done

exec python3 "$ROOT_DIR/control/rubato_controller.py" \
  --config "$ROOT_DIR/config/rubato_config.yaml" \
  "$@"
