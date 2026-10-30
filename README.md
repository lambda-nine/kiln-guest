# kiln-guest

A local, versioned Firecracker guest bundle for **VM outside, kiln inside**.
Phase 1a only: no kilnd changes and no broker protocol. No remote repository
or published image is created.

The bundle contains Linux 6.18.56 for aarch64 (4 KiB pages), kiln at
`e48f0e785ad484d0b2947897f6d48d0756059d7e`, a read-only squashfs root, and
the complete resolved kernel configuration. `manifest.json` schema 1 pins
each artifact's size and SHA-256, kiln's source commit, build-input digests,
the compatible Firecracker version and the work-disk contract.

## Contents and boot contract

The kernel starts from Firecracker v1.17.0's checked-in aarch64 6.18 CI config.
The original config, its upstream URL and digest, the final config, and the
required built-in symbols are under `config/`. Modules are disabled.
The guest includes namespaces, cgroup v2 CPU/memory/PIDs/I/O controllers,
overlayfs, XFS project quotas, iocost, seccomp, Landlock, virtio MMIO/block/net,
serial, ext4, squashfs and virtio-vsock. The missing inet nftables family,
masquerade, reject/inet reject, connection limits, conntrack and NAT are built
in and exercised through kiln's whole ruleset.

The outer root contains only compiled PID 1, static kiln, nft and its exact
shared libraries, minimal resolver configuration and the Alpine sandbox
image. There is no root shell, SSH server, interactive console, package
manager, or downloaded setup script. The Alpine image *inside the sandbox*
includes BusyBox and the normal minirootfs tools. Its IDs are shifted by
2,000,000,000 using `lchown` without dereferencing symlinks; modes, links and
numeric IDs survive squashfs packing. The package archives are verified but
their maintainer scripts are never run. XFS tools run on the host and are
unnecessary inside the guest.

Attach `Image`, read-only `rootfs.squashfs` as `/dev/vda`, and a **private**,
preformatted XFS disk of at least 512 MiB as `/dev/vdb`. Init mounts the work
disk at `/var/lib/kiln/runs` with `prjquota`; root stays read-only. Example:

```sh
truncate -s 512M work.xfs
mkfs.xfs -q -f work.xfs
```

Boot arguments:

```text
console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/init loglevel=3
```

PID 1 fails closed on mounting, sandbox smoke-test, firewall or DNS startup
failure. It mounts bounded tmpfs `/run` and `/tmp`, proc/sysfs/cgroup2, creates
the `/dev/fd` links kiln/nft need, disconnects stdin, sets an explicit minimal
environment, restricts kernel pointers/dmesg/BPF, supervises DNS, reaps orphan
children, and handles orderly shutdown. `KG_FIRST_COMMAND` follows completion
of the initial `kiln run -- true`; `KG_READY` follows a live DNS listener.
e48f0e7's DNS service creates its bridge and reconciles the whole shared
ruleset before binding; it has no separate `network-setup` subcommand. The broker hook
is a disabled placeholder, with **no vsock or serial command listener**.
At the requested e48f0e7 pin, kiln DNS runs as guest root. A later bundle can
adopt the Phase 0 service privilege changes.

`kiln.test=1` selects the fixed integration suite, then powers off. This is
trusted test configuration, not a remote execution interface. `kiln.net=1`
adds the fixed test-only `172.30.99.2/30` address and gateway `.1` on `eth0`.
That addressing is not suitable for multiple concurrent sessions. Production
Phase 1b must configure per-session transport and addressing; the present
production default has no virtio network device. Resolver `1.1.1.1` is pinned
test configuration, not a promise that outbound DNS is available.

## Build

Build on Linux aarch64 with Python 3.12+, GCC 13, binutils, make, flex, bison,
bc, libssl/libelf development headers, squashfs-tools, xfsprogs, gpg/curl and
the Rust toolchain named in `config/build-lock.json`. The existing Lima VM is
`kiln`. Keep build directories outside mounted checkouts. The wrapper stages
the local repo into `~/kiln-guest-build/repo`, owns the shared `.vm-lock` for
each session, waits three minutes between lock attempts, and releases it on
exit. It never replaces the installed kiln or kilnd.

```sh
python3 scripts/lima.py stage
python3 scripts/lima.py prepare
python3 scripts/lima.py build-a
python3 scripts/lima.py build-b
python3 scripts/lima.py test
python3 scripts/lima.py collect
python3 scripts/verify.py dist/bundle-a dist/bundle-b
python3 scripts/lima.py cleanup
```

`prepare` checks the kernel source against its pinned upstream SHA-256 and
the Firecracker release against the spike's verified release checksum. Alpine
is SHA-256 pinned and verified against the pinned Alpine release signing key.
It exports kiln from the exact commit, with Cargo.lock fixing crate checksums,
and downloads exact Ubuntu .deb versions from authenticated apt metadata.
It captures compiler/tool binary hashes and package versions in the build
lock. A later prepare that would silently repin it is refused. Existing
builds require an exact toolchain match and recheck all cached inputs.

Each build unpacks clean sources into a different absolute directory and
deletes them in `finally`. Rust and kernel paths, kernel build metadata and
squashfs timestamps are normalized. Kernel objects and Rust target output
are not shared between builds. The reusable download/Cargo cache must remain
under 2 GiB. `build-lock.json` is an environment lock, **not a hermetic build
container**; a different compiler or package set needs an intentional repin
and another two-build validation. Exact old Ubuntu package URLs can disappear;
retain the verified cache for offline recovery. Kernel timestamp controls
follow the [kernel reproducibility guidance](https://docs.kernel.org/kbuild/reproducible-builds.html).

Artifacts are retained locally in `dist/bundle-a` and `dist/bundle-b` after
collection; they are intentionally not checked into Git. Their manifests and
raw test evidence are checked into `results/`. Writable XFS disks are created
per test and are not bundle artifacts: UUIDs, metadata times and allocator
state are intentionally fresh rather than reproducible tenant state.

Both independently compiled kernels, both clean rootfs builds, kiln, the
resolved config and the complete manifests matched byte for byte. Build A's
rootfs was rebuilt from fresh source while correcting init and library setup,
retaining its own independently compiled kernel; build B then ran the whole
build from clean, separate source and object directories. No compiled output
was shared between A and B. `results/builds.json` and the build logs record
these boundaries. The common manifest SHA-256 is
`cdbf4d1b19505875bb6e633d32ae8d7107e260c7339c55ffd1df93cc8bcb6593`.

## Validation

Run `tests/firecracker.py` as root under the VM lock. It verifies the bundle
and release checksums, launches the matching Firecracker 1.17.0 jailer with
UID/GID 10000 and default seccomp, and removes its private jails, work disks,
TAP and firewall table in `finally`. It records installed-binary hashes.

The fixed guest suite exercises one-shot true, Landlock write denial, memory
and PID cgroup values, actual OOM and fork-limit enforcement, a real XFS
quota-exhausting write, persistent create/
exec/write/read/remove, full and allowlist nft policy loads, and rejection of
a metadata/private allow destination. The network pass adds guest-owned kiln
DNS queries, HTTP egress, allowed-host HTTP and refused off-list DNS. Its
temporary host nft table permits only public TCP/80 and UDP/53 to 1.1.1.1,
blocks guest access to host services/private ranges, and NATs only the test
guest address. Existing firewall tables and forwarding state are preserved.

Boot measurements use case `fc-jailer-kiln-none-768`, tier `strong-isolation`,
one guest at a time, 1 vCPU, 768 MiB, a private 512 MiB XFS disk, no network
device, two warmups then twenty measured boots, 100 ms idle gap, one Lima
boot/session, and no cache flush. Monotonic timing starts immediately before
spawning jailer and ends when serial delivers `KG_FIRST_COMMAND`, after the
initial kiln true exits. Staging/formatting and teardown are outside timing;
kernel startup, mounts and initial sandbox lifecycle are included. DNS and
network bootstrap happen after that marker. p95 uses nearest rank. These are
nested virtualization measurements on mini-one, not bare-metal results or
an end-to-end kilnd backend benchmark. The test jailer has no extra outer
cgroup limits or new PID namespace; Phase 1b must add those production limits.

See `results/test-results.json`, `results/conditions.json`, `results/records.jsonl`
and console logs for the measured outcome. No steady-state speed claim is
made; kiln remains experimental and has not been professionally audited.

The 2026-10-30 run passed both offline and real TAP/NAT network integration.
All 20 measured boots succeeded: p50 **1,136.77 ms**, nearest-rank p95
**1,179.63 ms**, min 1,091.35 ms, max 1,180.40 ms, under the conditions above.
Installed kiln and kilnd executable hashes were unchanged during the run.

## Threat notes and Phase 1b

The guest kernel and Firecracker/jailer form the outer wall. Kiln is an
additional containment layer inside it; its namespaces, seccomp denylist and
Landlock are not a hostile multi-tenant boundary on their own. A compromised
guest must still face host-owned per-session TAP/egress controls and resource
limits. Do not put provider credentials in this image or tool sandboxes.

Snapshots are trusted VMM input. Accept only backend-created snapshots pinned
to compatible VMM, CPU/GIC, kernel/rootfs and a matching private work-disk
version. Never reuse a tenant-used snapshot seed across tenants. A trusted
unassigned seed must establish new identity, entropy and credentials after
restore and reconnect vsock; snapshotting cannot undo external side effects.

Phase 1b's `FirecrackerRuntime` needs to validate schema and every artifact
digest before allocation; journal per-session ownership and manifests;
reserve total guest memory plus VMM overhead and disk; launch dedicated
jailer identities with outer cgroups/PID isolation; attach a private quota
disk and host-filtered TAP; and configure per-session addressing. The future
broker should replace only the disabled init hook, stay outside tool
sandboxes, use bounded/versioned vsock frames and an image/protocol readiness
handshake, and supervise cancellation/output drainage. Report ready only
after `KG_READY` plus the broker handshake, not merely a live VMM or the
benchmark marker. Guest image version and inner `SandboxSpec.image` are
separate concepts. Phase 1b follows kilnd Phase 0 and is outside this repo.

Source basis: [Firecracker custom image documentation](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/rootfs-and-kernel-setup.md),
the sibling spike report `research/2026-10-30-firecracker-spike.md`, and kiln's
README/agent notes at the source pin.
