# Guest boot regression — validated result

The delay is in early whole-RAM initialization enabled by
`CONFIG_INIT_ON_FREE_DEFAULT_ON`, interacting with small host backing pages
under nested virtualization. No security policy change or new kernel patch
is proposed. Firecracker 1.17.0 supports `huge_pages: Transparent`, which
requests MADV_HUGEPAGE for its private anonymous guest-RAM mapping. The guest
still has 4 KiB pages and retains zeroing on allocation/free, KASLR, lockdown,
W^X and every required/forbidden policy symbol.

The launch profile is now explicit in the bundle manifest and read by the
jailer validation harness. Consumers must apply it too; changing only an image
cannot change Firecracker's host memory mapping. THP is best effort: host
policy/fragmentation/pressure can make the safe fallback slow. It does not
relax guest page permissions or share RAM between guests. No installed kiln or
kilnd binary or service is replaced by this task.

## Isolation and timing evidence

The seven hardening commits were read alongside README, the prior acceptance
and conditions, and the original break-it review. `31c0cff` enabled allocation
and free initialization. `a599132` removed kexec; `7b56893` fixed Cargo/staging
provenance; `6d42725` changed kiln and confined DNS; `d116ddb` added noexec;
`db87487` documented future admission/restore blockers. `79482f0` added the
KASLR compatibility replacement and full evidence. DNS/network bootstrap is
still after KG_FIRST_COMMAND. The only serial-timer implementation change
retains a marker's first observation even if reads coalesce. It cannot explain
the early-kernel silent interval. The Popen-to-first-command boundary did not
change.

Exploratory traces used case fc-jailer-kiln-none-768, 1 vCPU, 768 MiB,
a fresh private 512 MiB XFS disk, 100 ms idle, one measured boot, zero warmups,
one L1 boot per trace, no cache flush, default jailer seccomp/UID 10000,
no network device, kiln.test=1 and printk timestamps at loglevel 7. Timing
is host monotonic immediately before spawning jailer to serial marker receipt;
staging/formatting/teardown are outside. These are diagnostic samples, not
production latency percentiles. The old traces use L1 boot
`eab785a8-6820-4e61-b812-cf2decc3d4e5`; later verified comparisons record their
new L1 boot ID in conditions. The VM was restarted before the comparisons.

In trace-original, CRNG initialization was already reported by host elapsed
85.37 ms. The memory-clearing announcement arrived at 604.37 ms, and SLUB at
23753.66 ms: a 23149.28 ms silent interval. printk timestamps remain zero
through this early phase because sched_clock is initialized afterward. Raw
serial byte-offset/host-monotonic observations capture it despite that.
With only init_on_free=0 for diagnosis, SLUB arrived at 606.35 ms and the long
interval disappeared. It was not entropy, DNS, seccomp or kiln waiting.

Replacing the complete arm64 clear_page ZVA path with its existing ordinary
STNP fallback did not remove the interval. That extra kernel patch was
rejected. The experiment source/build log and raw trace-stores evidence remain
under experiments/ and adjacent logs. Warm userspace probes did not show a
generic ZVA/DCZID trap cost; they do not identify cold EL1 fault behavior.
The supported VMM backing switch, with unchanged Image/rootfs/kiln/config,
is the successful discriminating experiment. Process minor-fault counters
are host VMM counters, not direct counts of nested stage-2 exits.

## Repeated comparisons and acceptance

The final production-mode acceptance run passed: **447.92 ms p50 and
462.30 ms nearest-rank p95**, with zero failures. The historical hardened
run was 24839.72 / 27335.94 ms; the pre-hardening 1534330 baseline was
1136.77 / 1179.63 ms. Those historical runs use the original documented case,
2 warmups/20 measured boots, 100 ms requested gap, one L1 session, no cache
flush, and the same first-command boundary. They used default backing;
the new launch profile explicitly changes that backing to Transparent.

A controlled comparison on the *unchanged original hardened bundle* gives:

| Option | p50 ms | nearest-rank p95 ms | Initialization security cost |
|---|---:|---:|---|
| Default backing, alloc/free on | 22933.32 | 25311.16 | None |
| THP, alloc/free on | 438.49 | 452.48 | None |
| Default backing, allocation-only | 1190.28 | 1231.47 | Prompt free-time erasure removed; not adopted |

The default-backing diagnostic used short lock batches, including one
host-side orchestration recovery after ten complete records. Requested
per-launch sleep remained 100 ms; inter-batch gaps were not fixed. No failed
or duplicate record was removed. The THP and allocation-only comparison
blocks and the final production acceptance block were uninterrupted.
See comparison-notes.json. All controlled samples share the same L1 boot ID.
The historical acceptance remains the uninterrupted original reference.

VMM process minor-fault medians sampled after KG_READY were 196352 with
small-page default backing versus 643 with THP. Allocation-only was 14664.5.
These are process totals after readiness, not counts confined to the timed
interval or direct counts of nested stage-2 exits. Actual THP backing in
every final measured VMM was 786432 KiB (768 MiB). The host THP policy was
madvise; no global host THP setting was changed.

## Final paired phase trace

These are **single diagnostic boots**, not percentiles: same final bundle,
case fc-jailer-kiln-none-768, 1 vCPU, 768 MiB, private 512 MiB XFS, no NIC,
100 ms requested gap, zero warmups, one measured boot for each backing,
one L1 session, no cache flush, kiln.test=1, printk.time=1 and loglevel=7.
Host monotonic receipt times include serial logging; instrumentation makes
these totals longer than the loglevel-3 production acceptance. Every executed
artifact is verified and its manifest/config/observations archived.

| Host-observed interval | Default backing ms | THP ms |
|---|---:|---:|
| Spawn to memory-clearing announcement | 623.21 | 382.27 |
| RAM initialization announcement to SLUB | 18989.13 | 222.34 |
| SLUB to starting PID 1 | 1753.40 | 1303.97 |
| PID 1 setup and mounts before kiln | 158.19 | 69.44 |
| First kiln command | 297.17 | 108.88 |
| Completion-marker delivery | 6.21 | 4.09 |
| Total to KG_FIRST_COMMAND | 21827.32 | 2090.98 |
| Additional interval to KG_READY | 346.37 | 87.41 |

Raw boundaries/intervals are in acceptance.json and phase-before/phase-after.
The original exploratory trace's longer sweep and these paired traces all
locate the delay in the same pre-clock interval; host load is uncontrolled.

## Builds, policy and integration

Two new full builds of corrected source 8803e81 independently unpacked and
compiled the entire kernel and fresh verified Cargo sources in work-a and
work-b. VM cmp and host read-bytes comparisons matched all four artifacts
and the complete manifests exactly. Build logs and manifests are retained.
The first full build pair at 0a625e2 is retained separately as superseded
evidence; after review changes the corrected source was fully rebuilt twice.

Both corrected manifests SHA-256:
`a62d227c56d95151a4ef0868a40cceb401d4670fd92d8c0f08f4313c0f14ae86`

Source inventory SHA-256:
`a3f840cd500939f333cb7195eec1775224b27ebf100dda5ee352fc598a2bfa68`

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| Image | 17807872 | `62d02303bad5272946cdb37d76a501c6a38209e7d2c3378f9fe8fd9015d8e032` |
| kernel.config | 95560 | `f4cc5f557c66c86acd75276d5053db6bd56992cff40471f3044ab5570d2dea2d` |
| kiln | 2376016 | `54442ccc0ce12b9a9236c927b9073019d7d4774c2e2d82f4d55d0db491925c64` |
| rootfs.squashfs | 7380992 | `8bfa9d71c676ed6e4b1c7cb7ebcb47d84c9a755d6913fd6784c224df15ce5e13` |

Image, kernel.config and kiln are also byte-identical to the original
hardened bundle. Only PID 1 diagnostics/rootfs and launch/provenance metadata
change. All 22 required and 26 forbidden kernel symbols pass. The full
jailer suite passes offline and with the fixed test-only TAP/NAT network,
including runtime KASLR, allocation/free/stack initialization, lockdown,
compiled-out interfaces, DNS privilege/capability/seccomp confinement,
noexec/direct-exec denial and overlay execution, resource/persistence/XFS
quota and egress tests. Installed kiln/kilnd binary hashes are unchanged
during validation. Host and native test suites pass; their platform-specific
skips are recorded. Dedicated negative aggregation tests also pass.

Source fixes are 0a625e2 and 8803e81, authored by Stephen Estrada without
trailers, on fix/guest-boot-regression. No remote or image was published;
the review branch is retained rather than integrating another checkout.

## Idle memory / capacity

See DENSITY.md and the six raw density directories. Corrected tests place
VMMs in the capped group through jailer *before exec*, verify membership and
private-RAM charging with one VM, then authorize the matching five-VM attempt.
One idle hardened VMM uses about 768 MiB PSS with default backing or 770 MiB
with THP. The retained 1534330 bundle uses about 59 MiB; five old VMs use
about 295 MiB total. Both hardened five-VM cohorts hit the preconfigured
3 GiB cgroup limit; no stable five-VM RSS/PSS exists. No unguarded overload
of the shared no-swap L1 was attempted.

Four is the RAM planning upper bound with the measured 4 GiB L1 headroom,
not a demonstrated four-VM workload result. A 3 GiB node budget permits
**three** 768 MiB sessions after reserving overhead: four nominal guest-RAM
reservations already consume the entire budget. Old lazy-resident guests
can also grow to their configured RAM. Admission must reserve guest RAM plus
VMM/KVM and host overhead, not idle PSS. No node limit or guest policy was
changed in response to these measurements.

## Cleanup and limits

cleanup.json records no remaining VMM, per-test density cgroup, test TAP,
test firewall table or kernel build tree. Temporary diagnostic bundles,
legacy copies and duplicate first-pass artifacts were removed after raw
collection. The verified cache is 235697314 bytes, below 2 GiB. The VM lock
was released; shared installed services remain active. The final two bundles
remain in dist/bundle-a and dist/bundle-b.

THP is a best-effort host allocation hint; fragmentation/pressure or a host
policy that disallows it can restore slow but still hardened boots. These
are nested cold-boot measurements under a toolchain/environment lock, not
a hermetic build, bare-metal claim, snapshot result, production admission
implementation or end-to-end broker readiness benchmark.

All repeated options use 2 warmups then 20 measured boots, 100 ms requested per-launch sleep,
1 L1 boot/session, no cache flush, 1 vCPU, 768 MiB, private fresh 512 MiB XFS,
and the same Popen-to-KG_FIRST_COMMAND boundary. Diagnostic comparisons use
kiln.test=1 at loglevel 3, while final acceptance uses the original production
boot arguments without kiln.test or any initialization override. Host backing
is the explicitly varied condition; the historical run omitted huge_pages
(Firecracker None). The new profile requests Transparent. Each result's
conditions.json records that difference, host THP policy and bundle identity;
records include actual VMM AnonHugePages and host fault counters sampled after
the timing endpoint. p50 is the median; p95 is nearest rank.

Allocation-only (`init_on_alloc=1 init_on_free=0`) remains an explicitly
labelled diagnostic option, not an adopted policy. It protects newly allocated
memory from stale contents but removes prompt erasure of freed memory, leaving
residual secrets readable until reuse or another overwrite. All other
hardening remains on. The THP launch profile has no such policy reduction.

## Evidence integrity and KASLR

New diagnostic runs verify every artifact's length and SHA-256 before launch,
archive the verified manifest and launch config, and preserve observations
and errors. Diagnostic repacks identify the base manifest and actual source
and compiler hashes, rather than claiming the original source inventory.
Acceptance rejects diagnostic-labelled bundles. Earlier exploratory traces
predate these checks and are labelled accordingly; they are not acceptance
results. The final build comparison and production test use independent full
builds and the normal verifier.

See KASLR-ASSESSMENT.md for the separate source review. Its conclusion is to
retain the current pinned compatibility replacement for trusted fresh cold
boots. No supported Firecracker configuration/cmdline supplies the missing
early kaslr-seed. A future VMM-generated independent kaslr-seed is cleaner.
The seed patch is unchanged by this fix; snapshots remain disabled.

Primary source for the backing option:
https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/vmm/src/vmm_config/machine_config.rs
and its application to anonymous memory:
https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/vmm/src/vstate/memory.rs


Final Codex Astra review found no remaining concrete findings. Nine portable
regression/negative tests passed in that independent pass; the reviewer also
recomputed summaries, compared bundle bytes/source inventory, and checked
production arguments and corrected density records. See adversarial-review.json.
