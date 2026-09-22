# Rubato P4/Tofino implementation

This directory contains the hardware implementation path used by Rubato. The
P4 program performs parsing, candidate observation, identity lookup, telemetry,
forwarding, and queue selection. The Python controller confirms media flows,
runs online DBSP, assigns the finite video-queue pool with DQA, and programs the
Tofino Traffic Manager.

## Layout

- `p4src/rubato.p4`: Tofino 1/2 data plane.
- `control/rubato_controller.py`: BF-RT/TM controller and lifecycle entrypoint.
- `control/behavior.py`: burst-based behavioral confirmation.
- `control/video_identity.py`: persistent media-flow identity state.
- `control/ingress_observer.py`: wire-observation digest receiver.
- `control/online_planner.py`: causal DBSP inputs and persistent DQA assignment.
- `control/aligned_runtime.py`: online planning and hardware actuation loop.
- `control/hardware_policy.py`: safe prepare/activate/drain policy transitions.
- `control/watchdog.py`: independent fail-safe watchdog.
- `planner/`: native DBSP/DQA planner used by the controller.
- `config/`: minimal runtime configuration and calibrated platform profiles.
- `scripts/`: build and launch commands.

Offline analysis, experiment orchestration, plotting, and legacy queue-control
prototypes are deliberately excluded.

## Requirements

- Intel/Barefoot P4 Studio SDE with Tofino or Tofino 2 support.
- Python 3 with the SDE BF-RT and Traffic Manager bindings.
- A C++17 compiler for the native planner.
- Optional PyYAML; the supplied configuration is JSON-compatible YAML and can
  be parsed without it.

The sample port numbers, queue limits, link capacity, and device ports in
`config/rubato_config.yaml` are deployment settings. Review them before touching
hardware.

## Build

```bash
cd p4
export SDE_DIR="$HOME/bf-sde-link"
./scripts/build_p4.sh tf1       # use tf2 for Tofino 2
./scripts/build_planner.sh
```

The planner is written to `build/dbsp_planner`. The P4 build is handled by the
SDE's `p4_build.sh`.

## Run

Start the compiled program, then launch the controller:

```bash
cd p4
export SDE_DIR="$HOME/bf-sde-link"
./scripts/start_switchd.sh
./scripts/run_controller.sh --install-ports --install-tm
```

Use `--dry-run` to validate configuration and controller logic without writing
hardware state. Use `--skip-port-init` when ports are managed externally. The
controller writes runtime audit and heartbeat data under `results/`, which is
not part of the source package.

## Execution contract

Default/non-video traffic uses q0. Confirmed media traffic uses the configured
q1..qN pool. DQA maps more flows than physical queues into deterministic shared
groups; shaping is therefore exact per queue and aggregate per group, not a
per-flow guarantee inside a shared FIFO. Queue reassignment follows the
controller's prepare/drain/activate lifecycle.

This snapshot implements identification, DBSP, DQA, and TM actuation. It does
not enable the paper's PD-ECN feedback extension; that mechanism is available in
the ns-3 model.

