# Instrumented qualification observations, 2026-09-18

The first two instrumented CI attempts failed during archive verification.
Their timings survived the failures and are retained in the
[machine-readable observations](2026-09-18-qualification-timing-observations.json).
Neither run is passing qualification evidence or a complete performance sample.
The [historical passing baseline](2026-09-18-sustainability-baseline.md) remains
the reference for complete installed-job time.

| Completed group or nested activity | First attempt | Second attempt |
| --- | --- | --- |
| Core lifecycle | 39m19s | 38m12s |
| Core configuration reapply, eight calls | 22m59s | 21m56s |
| Core admission waiting | 13m40s | 13m41s |
| Export/import | 30m43s | 30m37s |
| Export/import admission waiting | 24m55s | 24m57s |
| Export/import operator calls | 4m31s | 4m24s |
| Initial converge | 6m41s | 6m27s |
| Initial idempotence | 3m22s | 3m16s |

These are controller monotonic durations on four-CPU GitHub runners with local
MinIO, Python 3.14.7, and the unchanged production admission policy. Group time
includes nested activity: do not add these rows. Cache state and queue time were
not measured. Fresh CI fixtures were provisioned; no operator changed them
during execution. Diagnostic capture changed between attempts, and the built
fixture image digests differ, so these are consistent partial observations,
not a controlled before/after speed comparison.

The first entry point ran for 1h48m30s and failed during an ordinary archive
submission. The second ran for 1h43m59s and failed during restore/configuration
overlap: the initial worker exited unsuccessfully, while later recovery left a
successful durable result. The original cause is not established by these
reports. Neither duration estimates a complete successful run. Only 10.3 and
9.1 seconds respectively fall outside the union of recorded spans; this says
nothing about missing detail inside the large parent verification span.

The next changes follow the measurements: use installed admission history to
avoid unnecessary waits, and isolate configuration assertions so unrelated core
checks do not repeat eight full convergences. Merely removing admission waiting
would leave configuration work and fixture setup substantial. Independent
groups must retain those assertions, production rate limits, recovery coverage,
and accounting. Compare their eventual wall time and summed runner cost before
claiming an improvement; obtain further samples through required validation.
