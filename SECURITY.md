# Security policy

## Supported versions

kiln-guest has no releases, and built images are not published. Security
fixes go to the `main` branch only.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub:
<https://github.com/lambda-nine/kiln-guest/security/advisories/new>

Please don't open a public issue, pull request or discussion for a
vulnerability. Include what you can of:

- the kiln-guest commit, and the kiln and kilnd commits pinned in
  `config/pins.json`
- the host, Firecracker version and launch profile used
- what code in the guest or a sandbox could do that it shouldn't, and the
  steps to reproduce it

kiln-guest is maintained by one person. Responses are best effort, with no
guaranteed response or fix time. When a fix is ready, it is disclosed through
the same advisory, with credit if you want it.

## Scope

In scope:

- the guest init program (`src/`), its boot checks and its supervision of the
  guest broker
- the kernel security policy (`config/security-policy.json`) and the kernel
  configuration it enforces, including `src/kernel-kaslr-early.c`
- the launch contract and its checker (`scripts/launch_contract.py`,
  `scripts/phase1b_contract.py`) and the test launcher
- build integrity: anything that lets an unpinned or modified input reach a
  bundle without failing the build or `scripts/verify.py`

Out of scope here (report them to the repository that owns them):

- kiln's sandbox inside the guest: [kiln](https://github.com/lambda-nine/kiln)
- the guest broker and kilnd's Firecracker backend:
  [kilnd](https://github.com/lambda-nine/kilnd)
- Firecracker, the Linux kernel, Alpine or Ubuntu packages themselves: report
  those upstream

## Security boundary today

kiln-guest is **experimental software** and is **not a boundary for hostile
multi-tenant workloads.** The Firecracker microVM is the intended outer wall
and kiln an extra layer inside it, but:

- kilnd's Firecracker backend that consumes this image is disabled for
  production; the image is exercised only by test deployments.
- Backend admission of an independently approved manifest (KG-06) and a
  restore handshake for snapshots (KG-07) are not implemented. This
  repository only cold-boots, and `scripts/verify.py` checks reproducibility
  and consistency, not authenticity.
- The guest broker runs as guest root outside kiln's sandbox; a broker bug is
  a guest-root compromise bounded only by the VM.
- The kernel carries one local change (`src/kernel-kaslr-early.c`) that needs
  review on every kernel or VMM upgrade.
- Measurements and tests ran under nested virtualization in one Lima VM on
  Apple silicon. Other hosts are untested.
- The design and code have had adversarial reviews by AI models. No
  professional security audit has been done.

The README's "Threat notes and Phase 1b" section has the details.
