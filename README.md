# kiln-guest

Build scripts, init program and tests for a Firecracker guest image that runs
[kiln](https://github.com/lambda-nine/kiln) **inside a microVM** ("VM outside,
kiln inside"). The scripts fetch pinned sources (a Linux kernel, an Alpine
root filesystem, Ubuntu nftables packages, kiln and kilnd's guest broker),
verify them, and build a reproducible aarch64 bundle: kernel, read-only
squashfs root and a manifest that pins every artifact.

**Status: experimental, Phase 1b.** The image is used only by kilnd's
Firecracker test deployments; that backend is disabled for production, and
backend admission of an approved manifest is not implemented. Built images,
bundles and releases are not published. Builds and measurements have run only
under nested virtualization in a Lima VM on Apple silicon. It is **not a
boundary for hostile multi-tenant workloads.** Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

Licensed under [Apache-2.0](LICENSE), except `src/kernel-kaslr-early.c`
(GPL-2.0-only, a modified Linux file). The build downloads third-party
software under other licenses, and **a built image is not redistributable
under Apache-2.0 alone**; see [THIRD-PARTY.md](THIRD-PARTY.md).

## Lambda IX repositories

| Repository | What it is |
|------------|------------|
| [kiln](https://github.com/lambda-nine/kiln) | Shared-kernel Linux sandbox runtime (namespaces, cgroups v2, seccomp, Landlock, nftables); runs inside this guest |
| [kilnd](https://github.com/lambda-nine/kilnd) | Per-node control daemon with a gRPC API. Its Firecracker backend boots this image, and its `kilnd-guest-broker` crate is built into it |
| **kiln-guest** (this repository) | The guest image build |
| [kiln-harness](https://github.com/lambda-nine/kiln-harness) | Provider-neutral agent loop on top of kilnd's API |

## Quickstart

Unprivileged tests run on Linux or macOS with Python 3.12+; VM and root-only
cases skip themselves:

```sh
git clone https://github.com/lambda-nine/kiln-guest
cd kiln-guest
python3 -m unittest discover -s tests
```

A full build needs Linux aarch64 with KVM. The supported setup is kiln's Lima
VM (Apple silicon Mac with nested virtualization; see kiln's README, "Dev
setup (macOS)") with `kiln`, `kilnd` and `kiln-guest` cloned side by side,
because `scripts/lima.py` reads the pinned kiln and kilnd commits from the
sibling checkouts:

```sh
mkdir -p ~/Projects/lambda-nine && cd ~/Projects/lambda-nine
git clone https://github.com/lambda-nine/kiln
git clone https://github.com/lambda-nine/kilnd
git clone https://github.com/lambda-nine/kiln-guest
# create and start kiln's Lima VM from kiln/lima.yaml first
cd kiln-guest
python3 scripts/lima.py stage
python3 scripts/lima.py prepare
```

`prepare` downloads and verifies every pinned input. Builds then run inside a
squashfs snapshot of the build VM's toolchain, pinned by digest in
`config/build-environment.json`. Another VM's toolchain produces a different
snapshot, so a first build elsewhere needs its own pin: install the toolchain
packages listed in `config/build-lock.json`, delete
`config/build-environment.json` (the snapshot refuses to overwrite a pin), run
`python3 scripts/lima.py snapshot`, review the new pin, then continue with
[Build](#build). A bundle built that way is a new, locally pinned artifact,
not the one recorded in `results/`.

## Overview
A versioned Firecracker guest bundle for **VM outside, kiln inside**. Since
Phase 1b step B5 the image carries kilnd's guest broker (`kilnd-guest-broker`,
broker protocol 1) built from a pinned kilnd commit. Phase 1b's contract is
frozen below; its schema 2 production bundle is still refused. Images, bundles
and releases are never published.

The bundle contains Linux 6.18.56 for aarch64 (4 KiB pages), kiln at
`00d61c546db7aa67ad283d10c2ca6165ca5f8166`, the guest broker, a read-only
squashfs root, and the complete resolved kernel configuration. `manifest.json`
schema 1 (the local benchmark format) pins each artifact's size and SHA-256,
kiln's and kilnd's source commits, the broker record, build-input digests, the
compatible Firecracker version and the work-disk contract.

## Contents and boot contract

The kernel starts from Firecracker v1.17.0's checked-in aarch64 6.18 CI config.
The original config, its upstream URL and digest, the final config, and the
required built-in symbols are under `config/`. Modules are disabled.
The guest includes namespaces, cgroup v2 CPU/memory/PIDs/I/O controllers,
overlayfs, XFS project quotas, iocost, seccomp, Landlock, virtio MMIO/block/net,
serial, ext4, squashfs and virtio-vsock. The missing inet nftables family,
masquerade, reject/inet reject, connection limits, conntrack and NAT are built
in and exercised through kiln's whole ruleset.

The outer root contains only compiled PID 1, static kiln at
`/usr/local/bin/kiln`, the static guest broker at
`/usr/local/bin/kilnd-guest-broker`, nft and its exact shared libraries,
minimal resolver configuration and the Alpine sandbox image. There is one copy
of each binary. There is no root shell, SSH server, interactive console, package
manager, or downloaded setup script. The Alpine image *inside the sandbox*
includes BusyBox and the normal minirootfs tools. Its IDs are shifted by
2,000,000,000 using `lchown` without dereferencing symlinks; modes, links and
numeric IDs survive squashfs packing. The package archives are verified but
their maintainer scripts are never run. XFS tools run on the host and are
unnecessary inside the guest.

Attach `Image`, read-only `rootfs.squashfs` as `/dev/vda`, and a **private**,
preformatted XFS disk of at least 512 MiB as `/dev/vdb`. A production boot also
needs the read-only 4096-byte `KID1` identity drive as `/dev/vdc` and the vsock
device of the `offline-768-v1` recipe, which only kilnd-helper supplies. The
schema 1 `launch_contract` production profile has neither, so such a boot stops
at the identity check and powers off. Init mounts the work disk at
`/var/lib/kiln/runs` with `nosuid,nodev,noexec,prjquota`; root stays read-only. Example:

```sh
truncate -s 512M work.xfs
mkfs.xfs -q -f work.xfs
```

Boot arguments:

```text
console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/init loglevel=3 randomize_kstack_offset=on
```

The manifest's canonical `launch_contract` binds the exact command line, vCPU,
memory, SMT, dirty-page tracking, CPU template absence, ordered drives and
read-only flags, NIC/vsock absence, and jailer UID/GID, cgroup and seccomp
settings. It has separate fixed production, offline-test and network-test
profiles. `scripts/launch_contract.py` rejects all deviations before the test
launcher allocates resources. Production may select only its production profile;
test profiles require an explicit test launch. The future backend must validate
the actual effective settings against the independently approved identity.
Init checks the exact allowed command line, active KASLR, heap allocation/free
initialization, lockdown and compiled-out kexec before any kiln work; stack-offset
randomization is compiled default-on and checked via its exact bound `on` argument.
There is no independent kernel ABI exposing that static key to PID 1.
The contract also pins Firecracker's automatically appended `pci=off`, root
and read-only arguments and its exact early-console MMIO argument; init compares
the complete observed line, including that suffix.

The manifest's `launch_profile` selects Firecracker machine configuration
`"huge_pages": "Transparent"`, alongside `"vcpu_count": 1` and
`"mem_size_mib": 768`. This requests host transparent huge pages for guest RAM;
the guest still uses 4 KiB pages. Keep both allocation and free initialization
enabled. On the nested Lima target, the initial whole-RAM clearing sweep is
sensitive to host backing-page faults. THP avoids changing the kernel or its
security policy. It is an allocation hint, so memory pressure or host THP policy
can make boots slower without reducing protection. The validation evidence
records host THP policy and actual VMM huge-page backing for every measured boot.
See `results/boot-regression/REPORT.md` for the controlled comparisons; the raw
phase traces are in Git history ([results/README.md](results/README.md)).

In both modes PID 1 fails closed on mounting or runtime-hardening failure. It
mounts bounded tmpfs `/run` and `/tmp`, proc/sysfs/cgroup2, creates the
`/dev/fd` links kiln/nft need, disconnects stdin, sets an explicit minimal
environment (`PATH=/usr/bin:/usr/sbin`, which kiln uses to find `nft`), restricts
kernel pointers/dmesg/BPF, brings up loopback, reaps orphan children, and handles
orderly shutdown on SIGTERM, SIGINT or SIGHUP.

**Production boot (offline, broker).** Without `kiln.test=1`, init skips the
whole network bootstrap (design section 5.1): no `network-setup`, DNS, initial
`kiln run -- true`, `KG_FIRST_COMMAND` or `KG_READY`. The broker's Initialize
creates the persistent sandbox and runs the smoke `true`; only the host's
validated broker handshake establishes readiness. Init then:

- opens `/dev/vdc` read-only (`O_CLOEXEC|O_NOFOLLOW`), requires a read-only block
  device of exactly 4096 bytes, magic `KID1`, a big-endian u32 length of 1–4088 and
  all-zero padding after `8+length`. Any failure is `KG_FATAL identity ...` and
  power-off. Init does not parse the JSON; the broker parses it strictly;
- creates root-owned `/run/kilnd-broker` with mode 0700 (an existing entry fails);
- prints `KG_BROKER_START` and forks the broker. The child calls `setsid`, sets
  umask 077, changes to `/run/kilnd-broker`, clears the environment to exactly
  `PATH=/usr/local/bin:/usr/bin:/usr/sbin`, sets `RLIMIT_CORE` 0 and
  `RLIMIT_NOFILE` 256, `no_new_privs` and non-dumpable, points stdin and stdout
  at `/dev/null`, keeps stderr on the console, closes every descriptor above 3,
  and executes `/usr/local/bin/kilnd-guest-broker` with no arguments. Any setup
  failure exits the child, which init treats as broker death;
- passes the bootstrap on fd 3 (a pipe): the 4096 identity bytes, `KGH1`, a
  big-endian u32 runtime-hardening mask, then EOF. Bits 0–6 are `cmdline`,
  `kernel-log-bounded`, `kaslr-enabled`, `memory-initialization`,
  `kstack-offset-enabled`, `lockdown-confidentiality` and kexec absent (both
  kexec syscalls). Init dies on any failed check, so a running broker always
  receives all seven;
- supervises it: when the broker exits, init prints
  `KG_BROKER_EXIT status=<raw wait status>` and powers off. It never restarts
  the broker, which may have died around a running command.

The broker is the only listener (vsock port 5252, host CID 2). Init itself
opens no vsock and there is no serial command input.

**Test boot.** `kiln.test=1` keeps the schema 1 flow unchanged and powers off
after the suite; it has no identity drive and starts no broker. Init runs the
initial `kiln run -- true` (`KG_FIRST_COMMAND` follows its completion), sets up
the network and DNS, and prints `KG_READY` after a live DNS listener. Those
markers are schema 1 diagnostics only. The root-owned `kiln network-setup`
command creates the bridge and reconciles the ruleset, then exits. Init starts DNS as UID/GID 65532 with only
CAP_NET_BIND_SERVICE in its effective/permitted/inheritable/bounding/ambient
sets. A separate `kg_dns` nft output chain confines UID 65532 to TCP/UDP
`1.1.1.1:53` and tracked DNS replies from `10.88.0.1:53` to existing client
flows in `10.88.0.0/16`; all other output is rejected, including new connections
to tenants, other resolvers and host/private addresses. This table survives
kiln sandbox ruleset reconciliation. The upstream matches the immutable resolver
configuration. It applies no-new-privileges and a syscall allowlist, allows only thread
clones and AF_INET/AF_UNIX sockets, hides tenant storage and leases, exposes
read-only policies and proc/sys/run, provides private tmp/devices, and caps
file descriptors, processes and core dumps. The test mode verifies the live
post-exec credentials/capabilities and attempts prohibited operations. DNS
runs only in test mode; the offline production boot has none.

`kiln.test=1` selects the fixed integration suite, then powers off. This is
trusted test configuration, not a remote execution interface. Test mode does not
exercise the broker; kilnd's B5 tests do, through kilnd-helper. `kiln.net=1`
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
each session, waits five seconds between lock attempts, and releases it on
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

The broker comes from the sibling `kilnd` repository. `prepare`, `build-a` and
`build-b` each run `git archive --format=tar` of `pins.json`'s `kilnd_commit` on
the host (byte-identical for a commit), refuse an export whose SHA-256 differs
from `kilnd_source_sha256`, and write it to `~/kiln-guest-build/cache/kilnd.tar`.
`prepare` records that digest in `build-lock.json` as `kilnd_source_sha256`,
mirroring kiln's: the lock follows only a reviewed pin. Each build unpacks the
archive into `work/kilnd`, vendors kilnd's `Cargo.lock` into its own fresh
`work/kilnd-deps/{vendor,cargo-home}` (every registry crate, including
platform-only ones such as `windows-sys` that `--frozen` still requires), and
runs `cargo build -p kilnd-guest-broker --release --target aarch64-unknown-linux-gnu`
with kiln's flags: `--frozen` against the verified vendor tree, crt-static,
stripped symbols, no build ID, `--remap-path-prefix` of the work tree, and a
target directory inside `work/kilnd`. The result must be a static aarch64 ELF
with no `INTERP`, and its SHA-256 and size must equal `broker_sha256` and
`broker_bytes`.

Pinning a new broker: commit it in kilnd, set `kilnd_commit` and
`kilnd_source_sha256` (`git -C ../kilnd archive --format=tar <commit> | shasum -a 256`),
run `prepare`, then one `build-a --allow-unpinned-broker`. That flag accepts a
differing broker, prints its digest and size loudly at the broker step and at
the end, records them in the manifest, and marks the bundle `diagnostic_only`,
which `verify.py` refuses for acceptance. Review and record the printed values,
then build `bundle-a` and `bundle-b` afresh without the flag.
The build executes inside a digest-verified squashfs toolchain rootfs,
mounted read-only in a private mount namespace and chroot. Its fixed PATH is
`/opt/rust/bin:/usr/sbin:/usr/bin`; inherited environment and user configuration
are discarded. The snapshot includes the complete installed `/usr`, the selected
Rust distribution, loader configuration and alternatives. Every file and symlink
is inventoried in `config/toolchain-files.json`, including `dpkg-deb`, compiler
helpers, linker scripts, headers and all runtime libraries. The rootfs digest and
inventory digest are pinned in `config/build-environment.json` and recorded with
the full inventory in each manifest. PATH drift and altered images fail closed;
builds cannot write the tool directories. The cached image is root-owned and
marked filesystem-immutable before mounting, and is mounted from the verified
open descriptor. Build-root has no capability to remove that immutable flag.
An intentional environment repin must first clear it with `sudo chattr -i`. Only CHOWN, FOWNER and DAC_OVERRIDE
remain for rootfs ownership assembly; no mount or chroot capability remains.
`python3 scripts/lima.py snapshot` creates a new environment only when no pin
exists; replacing a pin requires explicit review. `pin-toolchain` checks all
previously pinned binary hashes before recording their new rootfs paths. Each build starts with an empty
CARGO_HOME and vendor tree, verifies each compressed crate against Cargo.lock,
then extracts it afresh. Cargo uses that directory source with `--frozen` and
file checksums; unpacked registry sources are never shared. Only verified
compressed downloads may be cached. Inherited Cargo/Rust configuration and
ancestor Cargo config files cannot silently redirect a build.

The manifest's `broker` record is `{"enabled": true, "protocol": 1, "crate":
"kilnd-guest-broker", "port": 5252, "kilnd_commit", "sha256", "bytes"}`, and
the binary is the `kilnd-guest-broker` bundle artifact. `inputs.kilnd` records the
commit and archive digest, the archive's `Cargo.lock` and root `Cargo.toml`
digests, a sorted `{path, sha256, size}` inventory of `crates/kilnd-guest-broker`,
`crates/kilnd-broker-protocol` and `crates/kilnd-exec-core`, every vendored crate
checksum, and the compiler: exact `rustc -vV`, `RUSTFLAGS` and cargo argv with
the work path rewritten to `/build` as the compiler's remap does, target and
profile. The manifest stays schema 1; `build.py --profile offline-768-v1` still
refuses.

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
under 2 GiB. The pinned rootfs is a snapshot of this Lima VM, not a separately trusted
compiler distribution. A/B are isolated clean builds under that same measured
environment, not independent provenance authorities or diverse compilation.
Any environment update requires an intentional repin and two full builds. Exact old Ubuntu package URLs can disappear;
retain the verified cache for offline recovery. Kernel timestamp controls
follow the [kernel reproducibility guidance](https://docs.kernel.org/kbuild/reproducible-builds.html).

Artifacts are retained locally in `dist/bundle-a` and `dist/bundle-b` after
collection; they are intentionally not checked into Git. Curated summaries of
their test evidence are in `results/`; the raw manifests, logs and traces are
in Git history ([results/README.md](results/README.md)). Writable XFS disks are created
per test and are not bundle artifacts: UUIDs, metadata times and allocator
state are intentionally fresh rather than reproducible tenant state.

The original baseline summary remains in `results/`. Hardening build logs,
complete manifests and byte-comparison results were under `results/hardening/`
and are now in Git history.
`results/hardening/reproducibility.json` records the new independent full-build
outcome; only a successful comparison supports a reproducibility claim. Both
builds must compile the complete kernel and rootfs in separate clean work trees.

## Validation

Run `tests/firecracker.py` as root under the VM lock. It verifies the bundle
and release checksums, launches the matching Firecracker 1.17.0 jailer with
UID/GID 10000 and default seccomp, and removes its private jails, work disks,
TAP and firewall table in `finally`. It records installed-binary hashes.

KR-05: the launcher atomically copies the pinned jailer and Firecracker into
`/var/lib/kiln-guest-launch/vmm-<archive-sha256>/`, then hashes each installed regular file
through an `O_NOFOLLOW` descriptor. It retains the jailer descriptor through
`Popen(executable=/proc/self/fd/<fd>, pass_fds=...)`; `--exec-file` names the
verified Firecracker in that same protected tree. Every path component from `/`
must be root-owned, without group/world write permission or symlinks; unsafe
paths are rejected. Fresh private session roots also live under this tree.
Kernel and rootfs are copied from opened source descriptors and their private
copies checked against the manifest before use; config and work disks are
created only in that session. Source cache paths are never executed.

Phase 1b's `kilnd-helper` must follow this same rule: authenticate the approved
manifest and VMM archive, atomically install and rehash executables and artifacts
in a root-owned tree whose **every ancestor is root-owned and not group- or
world-writable**, reject symlinks and unsafe ownership/modes, retain and execute
the verified jailer inode by descriptor, bind `--exec-file` to the verified
Firecracker inside that tree, and bind `--chroot-base-dir` to a fresh protected
session root. A root-owned child below a user-writable parent is insufficient.
The regression is `tests/test_vmm_path_race.py` (run as Linux root).

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

**Retired in B5.** `tests/firecracker.py` no longer measures production boots:
a B5 production boot needs the identity drive and vsock, prints no
`KG_FIRST_COMMAND`, and only starts the broker. B5's boot timings are measured
through kilnd-helper's create-to-READY path. `tests/idle_density.py` is retired
for the same reason. The paragraph below describes the historical pre-B5
measurement, whose summary remains in `results/`; none of its numbers apply to
a broker bundle.

Historical boot measurements used case `fc-jailer-kiln-none-768`, tier `strong-isolation`,
one guest at a time, 1 vCPU, 768 MiB, a private 512 MiB XFS disk, no network
device, two warmups then twenty measured boots, 100 ms idle gap, one Lima
boot/session, and no cache flush. Monotonic timing starts immediately before
spawning jailer and ends when serial delivers `KG_FIRST_COMMAND`, after the
initial kiln true exits. Staging/formatting and teardown are outside timing;
kernel startup, mounts and initial sandbox lifecycle are included. DNS and
network bootstrap happen after that marker. p95 uses nearest rank. These are
nested virtualization measurements on the development Mac mini (Apple M4, in
Lima), not bare-metal results or
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
and the console logs in Git history for the measured outcome. No steady-state speed claim is
made; kiln remains experimental and has not been professionally audited.

The hardening run's conditions and test outcome are under
`results/hardening/validation/`; its raw console logs and records are in Git
history. That run uses the case, gap, measured
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

The guest broker runs as **guest root, outside kiln's sandbox**, with the full
root capability set: kiln's namespaces, UID maps, mounts and cgroups need it. Its
`no_new_privs`, non-dumpable state, empty environment, descriptor and core limits
narrow accidents, not a compromised broker. It offers only typed
initialization, validation and kiln execution over vsock, but a broker bug is a
guest-root compromise, bounded by the VM wall above and nothing else in the
guest. Its reports, including the hardening mask init passes it, are trusted
within the session and are not attestation: a compromised guest kernel can
forge them. Init powers the VM off on broker death instead of restarting it.

The 2026-10-30 re-attack review (`2026-10-30-guest-reattack.md`, not published;
KR-01/KG-06 and KG-07) confirms both requirements below remain deployment
blockers; fixing the local launch checker does not implement backend admission.

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
it implements no restore/reseed path. Every clone of one ready snapshot
shares one KASLR layout: restore-time entropy cannot relocate the captured
kernel. Phase 1b must cold-boot per tenant, or use tenant-specific snapshots
never cloned across trust domains, with the mandatory restore handshake.
Cross-tenant cloning needs an explicit security review accepting lost KASLR
diversity; reseeding alone does not satisfy it.

Phase 1b's `FirecrackerRuntime` must also journal per-session ownership and manifests;
reserve total guest memory plus VMM overhead and disk; launch dedicated
jailer identities with outer cgroups/PID isolation; attach a private quota
disk and host-filtered TAP; and configure per-session addressing. The broker
replaces the formerly disabled init hook; it stays outside tool sandboxes, uses
bounded/versioned vsock frames and an image/protocol readiness handshake, and
supervises cancellation/output drainage. Report ready only
after the broker handshake, not merely a live VMM or a marker: `KG_READY` and
`KG_FIRST_COMMAND` are schema 1 diagnostics. Guest image version and inner `SandboxSpec.image` are
separate concepts. Phase 1b follows kilnd Phase 0 and is outside this repo.

## Phase 1b contract (B1)

`offline-768-v1` is manifest and launch contract schema 2. It freezes a template
plus exhaustive typed substitutions: separate VMM UID and GID records (an unequal
pair is the golden fixture), relay leases, CID, IDs, nonce, work UUID, validated
inner spec and the verified executable identity vector. The recipe is
`config/phase1b-contract.json`, pinned by digest in `config/phase1b-inputs.json`,
and `scripts/phase1b_contract.py` validates strict JSON, spec bindings, the `KID1` identity
block, VMM argv and `/proc/<vmm>/status`. Schema 1 remains the local bundle format.

**Production stays disabled.** `build.py --profile offline-768-v1` refuses, and
`verify.py` refuses schema 2 and fixture material unconditionally. There is no
fixture switch. `tests/phase1b_fixture.py` alone constructs `FixturePlan` with
schema `kiln-test-plan-v1` and profile `test-only-b1`, from a
`kiln-test-manifest-v1` manifest; these cannot become a deployable plan or
PreparedCreate. Independently approving or relabeling the stand-ins cannot open
production. The reviewed jailer patch and approved bundle do not exist; the broker
is built into the schema 1 image from a pinned kilnd commit (B5).
Root ownership and protected ancestry are exercised only by the Linux fixtures.
Schema 2 `inputs` carry digests rather than inventories, because the 4 MiB
manifest cap cannot hold schema 1's 33 MB record.

`tests/generate_phase1b_fixtures.py` regenerates `tests/fixtures/firecracker/`
byte for byte; kilnd carries an identical copy in
`crates/kilnd/tests/fixtures/firecracker/`. The fixture manifest's `inputs` bind the
digests of `config/pins.json`, `config/build-lock.json` and `src/init.c`, so any
change to those files requires regenerating the fixtures and copying them to kilnd. `tests/test_launch_contract.py` mutates
every manifest and plan leaf, including with a recomputed approval, and every
identity byte. `conformance.json` is the same corpus used by Rust's production
strict parser/canonicalizer, spec validator and launch recipe derivation. Its
Unicode, number, duplicate-key, schema and leaf-mutation cases require identical
verdicts, canonical ASCII bytes and SHA-256. Canonical JSON sorts Unicode scalar
keys, escapes all non-ASCII using lowercase UTF-16 escapes, permits only integers
in [-2**63, 2**64-1] (no negative zero), rejects floats/duplicates, and caps depth
at 32 (root zero, keys/values add one). Raw manifest approval hashes original bytes.
The complete effective host spec, including labels, binds `host_spec_sha256` in
the plan/journal contract; the label-free projection binds
`guest_exec_spec_sha256` in vdc/Hello/Initialize. Label-only changes alter the host
and plan digests, not the guest digest. B2 still owns the durable journal migration. `tests/exec_identity_fixture.py` runs each executable role through
real `execveat` races after verification and before exec. It compares the running
process's `/proc/<pid>/exe` device, inode, size and FD-computed digest with the
journal tuple; a pathname-exec control with matching argv and digest is refused.
These are real static test ELFs, not the jailer or VMM. B4 proves the real J/V
chain, its capability masks and the handoff. Raw evidence, including the measured
Firecracker suffix for this topology, is in `results/phase1b-b1/`.

Source basis: [Firecracker custom image documentation](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/rootfs-and-kernel-setup.md),
an unpublished Firecracker feasibility spike, and kiln's
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
early KASLR expects a separate `kaslr-seed` or RNDR. The development host's
nested guest has no RNDR. The reviewed local replacement `src/kernel-kaslr-early.c` retains the
standard seed's priority, otherwise consumes and erases eight bytes from an
exactly 64-byte RNG seed. The remaining 56 CSPRNG output bytes seed the
kernel RNG; Linux subsequently removes that property. Both the upstream file
and replacement hashes are pinned and checked before compilation and recorded
in manifest inputs. Tests exercise the actual seed function's length checks,
erasure and remaining bytes; guest tests require `KASLR enabled` in the kernel
log. The earlier seedless boot is retained as negative evidence. This local
kernel change needs review whenever the kernel or VMM is upgraded.
See [Firecracker's FDT implementation](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/vmm/src/arch/aarch64/fdt.rs)
and `results/boot-regression/KASLR-ASSESSMENT.md` for the assessment (the full
input contract, `results/hardening/kaslr-seed-contract.txt`, is in Git history).

## License

Copyright 2026 Stephen Estrada. Licensed under the
[Apache License, Version 2.0](LICENSE), except `src/kernel-kaslr-early.c`,
which is GPL-2.0-only. See [THIRD-PARTY.md](THIRD-PARTY.md) for what the build
downloads and what redistributing a built image involves.
