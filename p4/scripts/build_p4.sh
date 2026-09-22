#!/usr/bin/env bash
set -euo pipefail

SDE_DIR="${SDE_DIR:-$HOME/bf-sde-link}"
TARGET="${1:-tf1}"
P4_NAME="${P4_NAME:-rubato}"
BUILD_SUFFIX="${RUBATO_BUILD_SUFFIX:-_online_alignment}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
P4_SRC="${P4_SRC:-$REPO_DIR/p4src/rubato.p4}"

cd "$SDE_DIR"
source ./set_sde.bash

case "$TARGET" in
  tf1|tofino|tofino1)
    ./p4_build.sh --with-tofino --with-suffix "$BUILD_SUFFIX" "$P4_SRC" P4_NAME="$P4_NAME" P4_PREFIX="$P4_NAME"
    ;;
  tf2|tofino2)
    ./p4_build.sh --with-tofino2 --with-suffix "$BUILD_SUFFIX" "$P4_SRC" P4_NAME="$P4_NAME" P4_PREFIX="$P4_NAME"
    ;;
  *)
    echo "unknown target: $TARGET" >&2
    exit 2
    ;;
esac
