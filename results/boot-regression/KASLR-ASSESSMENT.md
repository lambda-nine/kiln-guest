# KASLR compatibility assessment — Linux 6.18.56 / Firecracker 1.17.0

The replacement was introduced in 79482f0, after 31c0cff enabled KASLR.
It changes only get_kaslr_seed() in arch/arm64/kernel/pi/kaslr_early.c.
The standard, exactly eight-byte kaslr-seed property retains priority. If
missing or malformed, the function accepts only an exactly 64-byte rng-seed,
reads its first eight bytes in FDT big-endian order, zeroes those eight bytes
in place, and returns them. All other early KASLR logic, including RNDR
fallback on a zero result and the randomized virtual-image offset, is upstream.

The remaining 56 CSPRNG output bytes are untouched. Their security depends on
the trusted generator, not output length alone. Later
Linux early_init_dt_scan_chosen() passes the 64-byte property, now containing
eight zero bytes and 56 CSPRNG output bytes, to add_bootloader_randomness(). The RNG
credits at most its 256-bit capacity, within the intended security strength of the trusted CSPRNG, then the FDT
code nops the property and updates the FDT CRC. Seed bytes consumed for KASLR
are not reused for RNG initialization. The function does not introduce an
entropy wait. A zero 64-bit KASLR value can still disable KASLR when RNDR is
absent, with the same 2^-64 edge case as the upstream standard-seed path.

The design depends on trusted fresh CSPRNG bytes from the pinned VMM at each
cold boot. It does not make snapshots safe. The full source file and its
upstream and replacement hashes are checked before compilation; changes in
kernel/VMM versions require re-review. Tests execute the actual C seed function
for priority, invalid lengths, zeroing, and preservation. The inherited FDT
pointer alignment/access behavior is unchanged from the upstream function.

Firecracker v1.17.0 creates a fresh 64-byte array with aws_lc_rs::rand::fill
and emits chosen/rng-seed, but no kaslr-seed. Its boot source exposes kernel,
boot arguments and initrd, with no custom FDT or seed field. Its machine
configuration likewise exposes no seed injection. A virtio-rng device starts
too late for this early virtual KASLR selection. random.trust_bootloader
controls RNG credit, not this KASLR seed lookup; no supported cmdline seed
parameter bridges the two properties in this pinned kernel.

A cleaner future fix is for Firecracker to emit a separate eight-byte
kaslr-seed from fresh CSPRNG output, retaining its 64-byte rng-seed. That uses
the upstream Linux ABI and removes this kernel replacement, but requires a
reviewed VMM change/version and new pinning/validation. No configuration-only
alternative was found for the present pinned VMM/CPU (which has no RNDR).
A constant seed in a custom tree or command line would not be an acceptable
alternative. Keep the current small, pinned compatibility replacement for now.

Sources:
- https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/vmm/src/arch/aarch64/fdt.rs#L237-L264
- https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/entropy.md
- https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/firecracker/swagger/firecracker.yaml
- Pinned Linux source excerpt: ../hardening/kaslr-seed-contract.txt
- Local replacement: ../../src/kernel-kaslr-early.c
- Live no-seed negative evidence: ../hardening/results-kaslr-probe/
