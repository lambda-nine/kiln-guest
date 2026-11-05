# Third-party software

kiln-guest's own scripts, tests, init program and documentation are licensed
under [Apache-2.0](LICENSE), with the one exception listed under
"Third-party files in this repository" below.

**This repository distributes no third-party binaries, kernel images, root
filesystems or packages.** Its build scripts download the pinned sources and
packages below, verify each by SHA-256 (and the kernel and Alpine archives by
signature), and build a guest image locally. Built images, bundles and
releases are not published. The small ELF files under
`tests/fixtures/firecracker/` are generated stand-ins written by
`tests/generate_phase1b_fixtures.py`, not third-party programs.

**If you redistribute a built guest image or bundle, you are distributing the
software below under its own licenses.** In particular, the image contains a
Linux kernel built from modified source (GPL-2.0-only): you must offer the
complete corresponding source, including `src/kernel-kaslr-early.c` and the
resolved kernel configuration, under the GPL's terms. The image also contains
GPL-2.0 and LGPL packages from Alpine and Ubuntu, and static binaries linked
against glibc (LGPL-2.1-or-later), with their own notice, source and
relinking obligations. Apache-2.0 for this repository does not cover any of
that; treat redistribution as a separate license review.

## What the build downloads

Versions and digests are pinned in `config/pins.json` and
`config/build-lock.json`. Licenses below are each project's declared license
at the pinned version; the authoritative text ships with each source archive or
package (`/usr/share/doc/<package>/copyright` for Debian packages,
`/lib/apk/db/installed` for Alpine).

### In the guest image

| Component | Version | Source | License |
|-----------|---------|--------|---------|
| Linux kernel | 6.18.56 | cdn.kernel.org | GPL-2.0-only WITH Linux-syscall-note (some files dual-licensed) |
| Alpine Linux minirootfs (the sandbox image inside the guest) | 3.24.2, aarch64 | dl-cdn.alpinelinux.org | Mixed per package: BusyBox, apk-tools and alpine-baselayout GPL-2.0; musl MIT; OpenSSL Apache-2.0; zlib Zlib; ca-certificates MPL-2.0 and MIT; others as listed in the image's `/lib/apk/db/installed` |
| nftables, libnftables1 | 1.0.9-1ubuntu0.1 | ports.ubuntu.com | GPL-2.0-only |
| libnftnl11 | 1.2.6-2build1 | ports.ubuntu.com | GPL-2.0-or-later |
| libxtables12 | 1.8.10-3ubuntu2 | ports.ubuntu.com | GPL-2.0-or-later (iptables) |
| libmnl0 | 1.0.5-2build1 | ports.ubuntu.com | LGPL-2.1-or-later |
| libgmp10 | 2:6.3.0+dfsg-2ubuntu6.1 | ports.ubuntu.com | LGPL-3.0-or-later OR GPL-2.0-or-later |
| libc6 (glibc) | 2.39-0ubuntu8.9 | ports.ubuntu.com | LGPL-2.1-or-later, with other notices in its copyright file |
| libgcc-s1 | 14.2.0-4ubuntu2~24.04.1 | ports.ubuntu.com | GPL-3.0-or-later WITH GCC-exception-3.1 |
| libedit2 | 3.1-20230828-1build1 | ports.ubuntu.com | BSD-3-Clause |
| libjansson4 | 2.14-2build2 | ports.ubuntu.com | MIT |
| libtinfo6 (ncurses) | 6.4+20240113-1ubuntu2.2 | ports.ubuntu.com | X11-style (MIT-like) |
| libbsd0 | 0.12.1-1build1.1 | ports.ubuntu.com | BSD-3-Clause and other permissive licenses |
| libmd0 | 1.1.0-2build1.1 | ports.ubuntu.com | BSD-2-Clause, BSD-3-Clause, ISC and public domain |
| kiln (static binary) | commit `00d61c5` | [lambda-nine/kiln](https://github.com/lambda-nine/kiln) | Apache-2.0; its Rust dependencies are listed in kiln's `THIRD-PARTY-LICENSES.md` |
| kilnd-guest-broker (static binary) | kilnd commit in `config/pins.json` | [lambda-nine/kilnd](https://github.com/lambda-nine/kilnd) | Apache-2.0; Rust dependencies from kilnd's `Cargo.lock` (Apache-2.0, MIT and similar permissive licenses) |
| Rust crates vendored for kiln and the broker | from each `Cargo.lock` | crates.io | Mostly MIT OR Apache-2.0; see each crate |

kiln and the broker are linked statically (`crt-static`) against glibc, so
those binaries include glibc code under LGPL-2.1-or-later.

### Used by the build or tests, not shipped in the image

| Component | Version | Source | License |
|-----------|---------|--------|---------|
| Firecracker and jailer (test launcher) | 1.17.0, aarch64 | github.com/firecracker-microvm | Apache-2.0 |
| Ubuntu 24.04 toolchain snapshot (GCC 13, binutils, make, flex, bison, bc, OpenSSL and libelf headers, squashfs-tools, xfsprogs) | `config/build-lock.json` | Ubuntu archive | GPL-2.0/GPL-3.0 family, LGPL and permissive licenses per package |
| Rust toolchain | 1.99.0 | rust-lang.org | MIT OR Apache-2.0 |

## Third-party files in this repository

| File | Origin | License |
|------|--------|---------|
| `src/kernel-kaslr-early.c` | Modified copy of Linux `arch/arm64/kernel/pi/kaslr_early.c` (Copyright 2022 Google LLC) | GPL-2.0-only, as its SPDX header says. It is not covered by this repository's Apache-2.0 license. |
| `config/firecracker-v1.17.0-aarch64.config` | Firecracker's `resources/guest_configs/microvm-kernel-ci-aarch64-6.18.config` at v1.17.0 | Apache-2.0 (Firecracker) |
| `config/kernel.config` | Kernel configuration resolved from the file above by the kernel's Kconfig | Configuration data for the kernel build |
| `config/kernel-sha256sums.asc` | kernel.org signed checksum list | Published by kernel.org for verification |
| `config/alpine-ncopa.asc` | Alpine Linux release signing public key | Public key, included for signature verification |
