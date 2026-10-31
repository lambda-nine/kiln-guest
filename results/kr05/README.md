# KR-05 validation — 2026-10-31

The privileged launcher now installs the archive-pinned VMMs by atomic copy into
`/var/lib/kiln-guest-launch/vmm-<archive-sha256>/`. It validates every directory
component with root ownership, no group/world write permission and no symlinks,
opens and hashes installed executables by descriptor, and retains the jailer
inode through privileged execution. The Firecracker pathname and per-session
jail root are bound in the actual argv. Kernel and rootfs copies are checked
against the verified manifest in the protected session, rather than hard-linked
from the build user's bundle. Config is created read-only in that session.

The original PoC topology is reproduced in
`tests/test_vmm_path_race.py::test_source_parent_swap_and_fd_execution`: the
unprivileged cache-parent rename succeeds, but cannot affect the installed VMM;
renaming its protected release fails. Even a root replacement of the installed
pathname leaves descriptor execution on the approved inode. The separate
`test_vm_executes_held_jailer_inode` exercises that replacement at the real
`VM.__init__` Popen boundary and confirms the approved fixture exits successfully
instead of executing the replacement. Unsafe ancestor modes/ownership,
symlinks, executable tampering, and artifact-source substitution are rejected.

Final checks:

- Linux/aarch64 root unit suite: 69 tests, 62 passed, 7 expected checkout-context
  skips (`kr05-unit.log`), including launch-contract and all four KR-05 tests.
- macOS unit suite: 69 tests, 52 passed, 17 platform/context skips (`host-tests.log`).
- Jailer integration: offline and network passed, including all runtime,
  confinement, resource, persistence and DNS egress assertions.
- Final quick boot check: case `fc-jailer-kiln-none-768`, requested idle gap
  100 ms, 5 measured boots after 2 warmups, 1 sequential L1 session, no cache
  drop; 1 vCPU, 768 MiB, Transparent huge pages, no network device. Timing starts
  immediately before jailer Popen and ends at serial KG_FIRST_COMMAND after
  the initial kiln true command exits; staging and teardown are excluded.
  All measured boots and warmups reached KG_READY. Raw conditions, serial output,
  observations and records are in `results-kr05-final/`; the earlier successful
  check is retained separately in `results-kr05/`. No performance claim changes.
- Both existing bundles passed artifact verification and exact manifest
  comparison (`artifacts.log`). Manifest SHA-256 remains
  `e855fbee1914cc6ea5e57a1250610e128412c85a905c94a48fb54afdaa47f3d3`.
  Guest artifacts did not change, so no full rebuild was needed.
- Installed kiln/kilnd hashes are unchanged. No remaining VMM, TAP, test nft
  table or private session root (`cleanup.json`). Each VM wrapper invocation
  owned and released the shared `.vm-lock`.

The final staged source inventory digest was
`798f8bcaa6b04b1b81005caeea9554bfcb3de14a5e25a954f4a750318fb9e802`.
The dedicated root-owned VMM installation remains for subsequent launches.
The first regression attempt found `/run` mounted noexec; the installation was
moved to the executable `/var/lib` filesystem before successful validation.
