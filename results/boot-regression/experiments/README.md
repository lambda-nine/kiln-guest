# Rejected ordinary-store experiment

This was a diagnostic kernel-only build, not an independent accepted bundle.
The production kernel replacement was never adopted. Both alloc/free
initialization policy defaults stayed enabled. Replacing clear_page.S's DC
ZVA loop with its upstream STNP fallback did not remove the long early-RAM
sweep. Therefore instruction-specific trapping is not established by this
experiment. The embedded source comment was a hypothesis, not a conclusion.

The source, exploratory build driver and native test source are retained here
as experiment inputs; their original locations were src/kernel-clear-page.S,
tests/build_trace_kernel.py and tests/test_clear_page.py. The archived drivers
expect those original locations. The raw build log is ../store-kernel-build.log
and console/timestamp evidence is ../trace-stores/.

Earlier traces preceded the diagnostic provenance checks. Their manifests are
retrospectively verified against the retained bundles when collected; they
are exploratory evidence, not acceptance results. Subsequent traces verify
and archive the executed bundle manifest before launch and preserve failures.
