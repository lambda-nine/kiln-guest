# kiln-guest

Build and run on Linux aarch64 inside the `kiln` Lima VM. The sibling kiln
and kilnd checkouts and installed services belong to other tasks; do not edit
or install over them. Acquire the sibling `.vm-lock` directory before each VM
session; `scripts/lima.py` manages ownership and releases it even on failure.
Keep all Linux build trees in `~/kiln-guest-build`, outside mounted checkouts.

This is a local-only repository. Do not create a remote, publish images, or
change kilnd. Commits use Stephen Estrada <stcrestrada@gmail.com>, no trailers.

The production root has no shell, package manager, or interactive console.
Keep diagnostic workloads in the explicitly selected test boot mode. Never
add an arbitrary command listener here: the future broker is Phase 1b.

Validate config requirements, two independent full builds, integration through
the jailer, and twenty measured boots before changing reproducibility or
performance claims. Preserve raw results; give case, idle gap, measured count,
warmups, L1 sessions, cache policy and timing boundaries with every number.
