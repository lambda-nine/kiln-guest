# kiln-guest

A local, versioned Firecracker guest bundle for **VM outside, kiln inside**.
Phase 1a only: no kilnd changes and no broker protocol. No remote repository
or published image is created.

The bundle contains Linux 6.18.56 for aarch64 (4 KiB pages), kiln at
`00d61c546db7aa67ad283d10c2ca6165ca5f8166`, a read-only squashfs root, and
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
disk at `/var/lib/kiln/runs` with `nosuid,nodev,noexec,prjquota`; root stays read-only. Example:

```sh
truncate -s 512M work.xfs
mkfs.xfs -q -f work.xfs
```

Boot arguments:

```text
console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/init loglevel=3
```

The manifest's `launch_profile` selects Firecracker machine configuration
`"huge_pages": "Transparent"`, alongside `"vcpu_count": 1` and
`"mem_size_mib": 768`. This requests host transparent huge pages for guest RAM;
the guest still uses 4 KiB pages. Keep both allocation and free initialization
enabled. On the nested Lima target, the initial whole-RAM clearing sweep is
sensitive to host backing-page faults. THP avoids changing the kernel or its
security policy. It is an allocation hint, so memory pressure or host THP policy
can make boots slower without reducing protection. The validation evidence
records host THP policy and actual VMM huge-page backing for every measured boot.
See `results/boot-regression/` for controlled comparisons and phase traces.

PID 1 fails closed on mounting, sandbox smoke-test, firewall or DNS startup
failure. It mounts bounded tmpfs `/run` and `/tmp`, proc/sysfs/cgroup2, creates
the `/dev/fd` links kiln/nft need, disconnects stdin, sets an explicit minimal
environment, restricts kernel pointers/dmesg/BPF, supervises DNS, reaps orphan
children, and handles orderly shutdown. `KG_FIRST_COMMAND` follows completion
of the initial `kiln run -- true`; `KG_READY` follows a live DNS listener.
The root-owned `kiln network-setup` command creates the bridge and reconciles
the ruleset, then exits. Init starts DNS as UID/GID 65532 with only
CAP_NET_BIND_SERVICE in its effective/permitted/inheritable/bounding/ambient
sets. It applies no-new-privileges and a syscall allowlist, allows only thread
clones and AF_INET/AF_UNIX sockets, hides tenant storage and leases, exposes
read-only policies and proc/sys/run, provides private tmp/devices, and caps
file descriptors, processes and core dumps. The test mode verifies the live
post-exec credentials/capabilities and attempts prohibited operations. The
broker hook remains disabled, with **no vsock or serial command listener**.

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
the local repo into a new empty directory and atomically exchanges it with
`~/kiln-guest-build/repo`, including on each build. It owns the shared `.vm-lock` for
each session, waits three minutes between lock attempts, and releases it on
exit. It never replaces the installed kiln or kilnd.

```sh
python3 scripts/lima.py stage
python3 scripts/lima.py prepare
python3 scripts/lima.py collect
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
builds require an exact toolchain match. Each build starts with an empty
CARGO_HOME and vendor tree, verifies each compressed crate against Cargo.lock,
then extracts it afresh. Cargo uses that directory source with `--frozen` and
file checksums; unpacked registry sources are never shared. Only verified
compressed downloads may be cached. Inherited Cargo/Rust configuration and
ancestor Cargo config files cannot silently redirect a build.

Staging records an exhaustive sorted inventory of ordinary source files,
including modes, lengths and SHA-256, and checks it against the digest computed
in this checkout. `.git`, `__pycache__`, `dist` and `results` are excluded at any
level; they are metadata or outputs. All other files are inputs. A stale,
extra, missing or modified staged input fails validation. Each manifest records
that inventory and digest, the kiln archive/commit, Cargo.lock and every crate
checksum, kernel/Alpine inputs and the complete package/toolchain lock. Outputs
are published from a new directory only on success; existing bundles are never
overlaid. `configure` intentionally resolves a changed policy; run `collect`
after `prepare` or `configure` before a build so their reviewed config changes
reach the local checkout that the next build stages.

Each build unpacks clean sources into a different absolute directory and
deletes them in `finally`. Rust and kernel paths, kernel build metadata and
squashfs timestamps are normalized. Kernel objects and Rust target output
are not shared between builds. The reusable compressed-download cache must remain
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

The original baseline evidence remains in `results/`. Hardening build logs,
complete manifests and byte-comparison results are under `results/hardening/`.
`results/hardening/reproducibility.json` records the new independent full-build
outcome; only a successful comparison supports a reproducibility claim. Both
builds must compile the complete kernel and rootfs in separate clean work trees.

## Validation

Run `tests/firecracker.py` as root under the VM lock. It verifies the bundle
and release checksums, launches the matching Firecracker 1.17.0 jailer with
UID/GID 10000 and default seccomp, and removes its private jails, work disks,
TAP and firewall table in `finally`. It records installed-binary hashes.

The fixed guest suite exercises the kernel policy and guest-root attack-surface probes,
DNS service credentials/capabilities/confinement, direct work-disk execution
denial, executable sandbox overlays, one-shot true, Landlock write denial, memory
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

Host backing is an explicit experimental variable: the historical baseline
and hardening run omitted `huge_pages` (Firecracker `None`); the new launch
profile requests `Transparent`. The comparison diagnostics retain the same
bundle while changing only backing or an explicitly labelled test-mode
initialization override. They are separate from production-mode acceptance
measurements, and do not authorize lowering the security policy. Diagnostic
bundles are rejected by the acceptance verifier. `tests/trace_boot.py` verifies
artifact hashes before launch and archives the manifest and raw timestamped
serial observations, including on failure.

See `results/test-results.json`, `results/conditions.json`, `results/records.jsonl`
and console logs for the measured outcome. No steady-state speed claim is
made; kiln remains experimental and has not been professionally audited.

The hardening run's raw console logs, conditions, records and test outcome are
under `results/hardening/validation/`. That run uses the case, gap, measured
count, warmups, L1 sessions, cache policy and timing boundaries above. Its
`test-results.json` contains the measured values; no earlier baseline number
is presented as a result for the hardened bundle. Installed kiln/kilnd hashes
are recorded before and after the validation run.

## Threat notes and Phase 1b

The guest kernel and Firecracker/jailer form the outer wall. Kiln is an
additional containment layer inside it; its namespaces, seccomp denylist and
Landlock are not a hostile multi-tenant boundary on their own. A compromised
guest must still face host-owned per-session TAP/egress controls and resource
limits. Do not put provider credentials in this image or tool sandboxes.

KG-06 is a hard Phase 1b admission requirement: the host must pin an independently approved manifest digest
(or an authenticated release identity that resolves to that digest). Before
creating any host resource, it must validate the entire manifest schema,
architecture/version, exact artifact set and safe names against that approved
identity, then every artifact's length and digest. Coordinated image/manifest
substitution must fail before creating any host resource. `scripts/verify.py`
checks reproducibility and internal consistency; it provides no admission
authenticity. Phase 1b must add adversarial admission tests; there is no backend
admission implementation in this repository.

KG-07 is a hard Phase 1b restore requirement. Snapshots are disabled until a
mandatory restore handshake proves fresh host-provided entropy, per-session
identity and fresh credentials before any tenant work or readiness. Bind every
snapshot to approved VMM/CPU/GIC, kernel/rootfs and the matching private disk
version. A test with two restores from one seed must demonstrate distinct
identity and random output, and refusal on disk-version mismatch or an
incomplete handshake. Never reuse a tenant-used seed across tenants. Snapshot
restore cannot undo external side effects. This repository only cold-boots;
it implements no restore/reseed path.

Phase 1b's `FirecrackerRuntime` must also journal per-session ownership and manifests;
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

## Kernel security policy

`config/security-policy.json` lists required values and forbidden interfaces.
The builder checks the resolved config after `olddefconfig`; the jailer suite
checks the bundled config and probes the unavailable interfaces as guest root.
Kexec is compiled out; init also sets `kernel.kexec_load_disabled=1` before
starting children when that sysctl exists. With kexec entirely absent Linux
omits that sysctl, which the integration suite checks along with both syscalls.

Kiln at Phase 0 commit `00d61c5` uses classic BPF for seccomp through
`seccomp(SECCOMP_SET_MODE_FILTER)`; it never calls the general BPF syscall or
uses cgroup BPF device programs. Thus BPF's interpreter and seccomp remain,
while the BPF syscall, cgroup BPF, JIT, io_uring, userfaultfd, perf, debugfs,
proc kcore, devmem/kmem, modules, probes, ftrace, hibernation, checkpoint/restore,
and binfmt_misc are forbidden. User namespaces remain necessary for kiln's
shifted sandbox IDs. Cgroup controllers, nftables, overlayfs and XFS remain
necessary and are exercised by the integration suite.

Required defenses include KASLR, FORTIFY, default-on hardened usercopy,
allocation/free initialization, zeroed stack variables, strong stack canaries,
shadow call stack, strict kernel W^X, slab freelist and list hardening, and early
forced confidentiality lockdown. GCC 13 supports the selected static arm64
shadow call stack and zero-initialization. Dynamic SCS requires Clang; CFI's
KCFI toolchain requirement is not met by this pinned GCC toolchain. Neither is
claimed. Kernel Kconfig evidence is preserved in
`results/hardening/toolchain-hardening-evaluation.txt`. This is an enforced
security baseline derived from kiln's needs, not an exhaustive kernel audit.

Firecracker 1.17 supplies a 64-byte host-CSPRNG `rng-seed`, while Linux arm64's
early KASLR expects a separate `kaslr-seed` or RNDR. mini-one's nested guest has
no RNDR. The reviewed local replacement `src/kernel-kaslr-early.c` retains the
standard seed's priority, otherwise consumes and erases eight bytes from an
exactly 64-byte RNG seed. The remaining 56 CSPRNG output bytes seed the
kernel RNG; Linux subsequently removes that property. Both the upstream file
and replacement hashes are pinned and checked before compilation and recorded
in manifest inputs. Tests exercise the actual seed function's length checks,
erasure and remaining bytes; guest tests require `KASLR enabled` in the kernel
log. The earlier seedless boot is retained as negative evidence. This local
kernel change needs review whenever the kernel or VMM is upgraded.
See [Firecracker's FDT implementation](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/vmm/src/arch/aarch64/fdt.rs)
and `results/hardening/kaslr-seed-contract.txt` for the input contract.
