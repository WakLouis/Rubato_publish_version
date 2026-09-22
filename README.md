# Rubato implementation

This directory contains the publication-oriented Rubato implementation. It is
split into two independent code paths:

- [`p4/`](p4/README.md): the Tofino P4 data plane, online controller, native
  DBSP planner, DQA queue management, and the minimum build/run scripts.
- [`ns-3/`](ns-3/README.md): the reusable ns-3 model for DBSP, DQA, queue
  shaping/scheduling, and quota-based PD-ECN.

The package intentionally excludes experiment runners, plotting programs,
result-analysis scripts, generated figures, packet captures, frozen outputs,
and superseded prototypes. Configuration files are included only when they are
required to run the implementation.

## Mechanism map

| Rubato component | P4/Tofino implementation | ns-3 implementation |
|---|---|---|
| Identification | P4 candidate/DNS digests plus `behavior.py` and `video_identity.py` | Outside this model; simulations provide known video-flow identities |
| DBSP | `dbsp_planner` and `online_planner.py` | `DbspSolver` |
| DQA | `DemandQueues` plus TM queue installation | `AllocateDqaQueues` and `RubatoQueueDisc` |
| Shaping and scheduling | P4 selects a queue; the controller configures fixed-function Tofino TM shaping and DWRR | Token-bucket shaping and byte-based DWRR in `RubatoQueueDisc` |
| PD-ECN | Not enabled in this hardware snapshot | `PecnQuota` and the PECN path in `RubatoQueueDisc` |

The Tofino Traffic Manager is fixed-function. The P4 program selects queue IDs,
while the controller configures queue rates, burst sizes, priorities, and DWRR
weights through the SDE APIs.

## Repository hygiene

All source, comments, diagnostics, and documentation in this directory are in
English. Generated `build/`, `results/`, and Python cache directories are
ignored.

