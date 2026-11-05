# Changelog

Notable changes to kiln-guest. The repository has no releases; built images,
bundles and releases are not published.

## Unreleased

- Prepare the repository for public visibility: add the Apache-2.0 `LICENSE`
  (matching kiln and kilnd; `src/kernel-kaslr-early.c` stays GPL-2.0-only),
  `THIRD-PARTY.md` listing what the build downloads, its licenses and the
  obligations of redistributing a built image, `SECURITY.md`, this changelog,
  and a README opening for new readers (status, the four Lambda IX
  repositories, a quickstart).
- Remove about 1,080 raw VM evidence files (console logs, traces, build logs,
  complete manifests) from the tree. Curated summaries and the pinned
  Phase 1b B1 evidence stay under `results/`, indexed by `results/README.md`;
  the raw files remain in Git history. `results/` output is now ignored.
- `scripts/lima.py` resolves the VM's build root from the guest's home
  directory instead of a hard-coded user path.
