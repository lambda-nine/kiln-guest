# Results

Curated summaries of the VM runs behind the claims in the
[README](../README.md). The raw evidence (about 1,100 serial console logs,
boot traces, build logs, complete bundle manifests and byte comparisons) was
removed from the tree before the repository was made public. It is still in
Git history, at the last commit that tracked it:

```sh
git show 95d621c5dc40321e8eb9f2ff9a9e84e4855e3431 --stat -- results/   # what was there
git restore --source=95d621c5dc40321e8eb9f2ff9a9e84e4855e3431 -- results/
```

New raw output from `scripts/lima.py` lands here and is ignored by Git.

| Path | What it is |
|------|------------|
| `test-results.json`, `conditions.json`, `records.jsonl` | Historical pre-B5 baseline: twenty measured boots, their conditions and per-boot records |
| `hardening/validation/test-results.json`, `hardening/validation/conditions.json` | The same measurement for the hardened bundle |
| `hardening/reproducibility.json` | Outcome of the two independent full builds |
| `hardening/toolchain-hardening-evaluation.txt` | Kernel Kconfig evidence for the hardening baseline |
| `boot-regression/REPORT.md`, `DENSITY.md`, `KASLR-ASSESSMENT.md`, `adversarial-review.json` | Boot-regression investigation, idle density, KASLR seed assessment and its review |
| `kr05/README.md` | KR-05 launcher validation |
| `launch-contract/summary.json` | Launch-contract validation summary |
| `phase1b-b1/` | Phase 1b B1 evidence; `suffix-probe.json` is pinned by `config/phase1b-inputs.json` and read by `tests/test_launch_contract.py` |

The reports name raw files (console logs, traces, raw density directories)
that are only in the history above. Home-directory paths in
`phase1b-b1/b1-fixes-linux.txt` are shown as `<user>`.
