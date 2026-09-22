# Rubato ns-3 model

This directory is a minimal reusable ns-3 module containing Rubato's mechanism
implementation without experiment harnesses or analysis code.

## Included mechanisms

- `DbspSolver`: two-stage lexicographic DBSP optimization and safe delay-budget
  calculation.
- `AllocateDqaQueues`: deterministic demand-balanced mapping from flows to a
  finite queue pool.
- `RubatoQueueDisc`: shared-buffer queueing, explicit flow-to-queue mapping,
  token-bucket shaping, byte-based DWRR, and queue telemetry.
- `PecnQuota`: epoch-based eligibility, rank-based marking quotas, budget
  accounting, and cooldown for PD-ECN.

The directory does not include traffic generators, comparison baselines,
scenario configuration, batch runners, plotting, result parsing, or tests.

## Add to ns-3

Copy this directory into an ns-3 source tree as `contrib/rubato`:

```bash
cp -r ns-3 /path/to/ns-3/contrib/rubato
cd /path/to/ns-3
./ns3 configure --build-profile=optimized
./ns3 build rubato
```

The supplied `CMakeLists.txt` builds a `rubato` contrib library and links the
ns-3 core, network, internet, and traffic-control modules.

## Integration outline

1. Construct `DbspFlowInput` values from measured or configured video profiles.
2. Call `DbspSolver::Solve` for the local protected egress.
3. Map the resulting per-flow demands to the available queues with
   `AllocateDqaQueues`.
4. Configure `RubatoQueueDisc` with the explicit map, per-queue group rates,
   burst sizes, phases, and DWRR byte budgets.
5. When evaluating PD-ECN, configure `PecnQuota` and provide each flow's
   remaining DBSP budget before enabling marking.

`RubatoQueueDisc` uses q0 for non-video traffic and q1..qN for identified video
traffic. When several flows share a queue, FIFO order and shaping apply to the
group; individual DBSP shares are not strictly enforceable inside that queue.

The model exposes mechanism code only. Simulation topology, workload semantics,
and metric collection remain the responsibility of the embedding experiment.

