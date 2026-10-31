# Idle memory and capacity input

Case `fc-jailer-idle-density-768`: one snapshot per requested group size, zero warmups, one L1 boot/session, no cache flush; each guest has 1 vCPU, 768 MiB, a private fresh 512 MiB XFS disk, no network device, jailer UID/GID 10000 and default seccomp. Production boot mode runs the normal first kiln true and DNS startup. RSS/PSS come from each VMM process smaps_rollup after five seconds idle following the last observed KG_READY. Launches are staggered by 100 ms. These are idle snapshots, not workload peaks or boot latency samples.

The legacy bundle is the retained 1534330 build B, independently matched to the recorded manifest digest `cdbf4d1b19505875bb6e633d32ae8d7107e260c7339c55ffd1df93cc8bcb6593`. Hardened comparisons use the unchanged original hardening bundle `dfc3494e84f81848536fb6efd8aeaf61350e59a1c5dfc859064a3d06f284e59e`; only host backing changes between its profiles. All six density runs share L1 boot `6bf12a50-cfc0-4431-9589-2d385a59dd27`.

| Configuration | Requested VMs | Total RSS MiB | Total PSS MiB | Outcome |
|---|---:|---:|---:|---|
| Hardened + THP | 1 | 770.35 | 770.34 | Stable idle snapshot |
| Hardened/default backing | 1 | 768.34 | 768.34 | Stable idle snapshot |
| 1534330/default backing | 1 | 58.93 | 58.92 | Stable idle snapshot |
| 1534330/default backing | 5 | 294.58 | 294.54 | Stable idle snapshot |
| Hardened + THP | 5 | unavailable | unavailable | Contained cgroup OOM; no stable five-VM snapshot |
| Hardened/default backing | 5 | unavailable | unavailable | Contained cgroup OOM; no stable five-VM snapshot |

The old five-guest mean PSS was 58.91 MiB per guest. The earlier approximate 39 MiB reference was not reproduced at this documented readiness/idle boundary; the retained bundle measured about 59 MiB here. Raw per-VMM values and host memory snapshots are preserved in each density.json. RSS counts shared pages repeatedly; PSS apportions them. Neither includes all external host kernel/KVM overhead.

Both hardened five-guest attempts launched all five VMMs, then hit the temporary test cgroup memory.max of 3 GiB, with swap.max=0 and memory.oom.group=1. memory.peak reached 3072 MiB in both cases; memory.events records a group OOM. No unguarded five-hardened-guest run was attempted on the shared 4 GiB/no-swap L1. A failed run has no idle RSS/PSS total: multiplying the single-VM result is an estimate, not a measured five-VM snapshot.

The corrected runner uses the pinned jailer's --parent-cgroup option to enter the configured group before Firecracker exec. Each single-VM run verifies actual membership and charged private RAM before its proof file can authorize the matching five-VM attempt. The controller remains outside the capped group. This is test containment, not a Phase 1b admission implementation. Old post-launch-migration results are retained under experiments/post-launch-density and are superseded; those earlier group counters did not account for all already-allocated RAM. All figures in this table use the corrected runner.

With the measured single-VM PSS, five hardened guests alone would require approximately 3852 MiB with THP or 3842 MiB with default backing, before external kernel/KVM overhead. The L1 exposed 3905 MiB total and 3428 MiB available before the THP single-VM run. Thus five cannot safely fit. Four is a planning upper bound under this measured 4 GiB L1 headroom, not a demonstrated four-VM workload result. Reserve capacity for its kernel, installed services, VMM/KVM overhead and workload/network/disk caches.

For a 3 GiB (3072 MiB) kilnd node budget, four configured guests already reserve all 3072 MiB, leaving zero for VMM/KVM overhead. At this guest size, the planning limit is **three sessions**, with overhead still reserved. The old lazy-resident image does not change the safe reservation rule: its guests can later dirty their full 768 MiB. Admission must reserve configured guest RAM plus overhead, not admit from idle PSS.

THP fixes the first-touch latency; it does not reclaim the pages dirtied by init-on-free. No initialization policy, node budget, service setting or admission limit was changed because of these capacity measurements.
