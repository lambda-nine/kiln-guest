# Phase 1b B1 evidence

Linux aarch64 `kiln` Lima VM (6.8.0-147-generic, nested KVM, 4 GiB), Firecracker
v1.17.0 from the pinned release, under the shared VM lock. Nothing was installed
over kiln or kilnd, and no daemon was involved.

- `suffix-probe.json`: `tests/phase1b_suffix_probe.py` booted the existing schema 1
  bundle (`firecracker --no-api --config-file`, no jailer) with two drives, two plus
  vsock, three drives, and the contract's three drives plus vsock. All four append
  ` pci=off root=/dev/vda ro earlycon=uart,mmio,0x40002000`, and that init's exact
  comparison printed PASS for production and test boot arguments. Pinned in
  `config/phase1b-inputs.json`. A later bundle must still pass this comparison.
- `retained-fd.json`: `tests/exec_identity_fixture.py` ran every role (jailer,
  firecracker, mkfs.xfs, kilnd-helper) through five races after verification and
  before `execveat`: source parent rename by unprivileged UID 10001, installed name
  replacement, identical-bytes replacement inode, installed parent swap (those three
  are test-only root fault injection), and retained FD close/reuse. Each record
  holds the expected journal tuple and the running process's actual `/proc/<pid>/exe`
  device, inode, size and FD-computed digest. The pathname-exec control has matching
  argv and, for identical bytes, a matching digest, and is refused on identity.
  `surviving_fds` is the real descriptor table: 0-4 after S to J, 0-2 after J to V.
  These are static test ELFs that spin. They model both handoff boundaries; B4 must
  prove the actual jailer, VMM, capability masks and bootstrap gate.
- `unittest-root.log`, `unittest-user.log`: the full unit suite in the VM. The root
  run includes the ACL, ownership, mode, hardlink, file-capability and rename tests
  and refuses the real 33 MB schema 1 manifest (sha256 `e855fbee...`), which exceeds
  the 4 MiB cap. Skips are the seven git-checkout wrapper tests and the two tests of
  this directory, which is not staged into the VM.
- `init-binary-identity.txt`: `src/init.c` changed only in comments. The stripped
  static binary from the previous and current source is byte-identical, so the guest
  integration and twenty-boot suites were not re-run; nothing boot-relevant changed.
