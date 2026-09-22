#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLANNER_DIR="$ROOT_DIR/planner"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build}"

mkdir -p "$BUILD_DIR"
g++ -std=c++17 -O2 -Wall -Wextra -Werror -I "$PLANNER_DIR" \
  "$PLANNER_DIR/dbsp_main.cc" "$PLANNER_DIR/dbsp-solver.cc" \
  -o "$BUILD_DIR/dbsp_planner"

sha256sum "$PLANNER_DIR/dbsp-solver.cc" "$PLANNER_DIR/dbsp-solver.h"
