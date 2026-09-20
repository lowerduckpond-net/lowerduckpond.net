# Installed grouping prerequisite, 2026-09-20

The grouped harness passed its original complete installed journey and all
thirteen independent groups in [PR #159](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/159).
This satisfies the coverage prerequisite for activating the separate CI selection
change. It does not complete the sustainability exit gate or qualify production.

The passing [CI run](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35475224829)
tested merge revision `337cc41bb85dc4d3f0b9f87853ba037c13a9deba` for PR head
`da2fac628cf3b21cc5bcfa35b038a9444cb4716f`. The accepted change was squash merged
as `d249397ec2fc4499b29c9e2d2877f7ab2c2c9f11`. These trees are identical.
Every installed timing report identifies artifact
`0b12b64e71007d107263454f2da5cac11d74b5dac3d53e459d5a0ad89b8ef3c2`.
CodeQL, Infrastructure, and all required CI checks passed; both review findings
were corrected before acceptance of the final head.

The [machine-readable observations](2026-09-20-installed-grouping-eligibility.json)
retain the original sanitized timing and completion report fields, their original
byte hashes, artifact ZIP hashes, job timestamps, and tested source. All fourteen
ZIP digests were checked against GitHub metadata. The pending required-result
verifier accepted the thirteen actual group receipts with distinct fixture owners.
No result was relabelled with the squash commit or assigned a newer timestamp.

## Coverage and execution

Each independent group passed its declared tests and final artifact/accounting
check, fresh local accounting, independent whole-bucket absence, and fixture
teardown. The reboot journey carried a full-size site across the supported
export/import and archive/restore paths, then checked durable state, routes,
content, exact replay, and a new operation across an actual restart. The separate
full-size receipt retains matching artifact identity, 5,000 entries,
104,857,600 content bytes, and the verified content digest.

| Installed job | Elapsed, including setup and cleanup |
| --- | ---: |
| Original complete journey | 1h59m49s |
| Core | 26m11s |
| Configuration publication | 19m38s |
| Configuration generation | 19m52s |
| Export roundtrip | 19m36s |
| Export recovery | 22m27s |
| Archive cycles | 28m13s |
| Full-size archive | 13m36s |
| Deletion and quarantine | 19m23s |
| Transport recovery | 19m20s |
| Deployment overlap | 17m33s |
| Routing overlap | 20m41s |
| Reboot journey | 20m27s |
| Credentials | 15m27s |

Every independent job met the 30-minute target in this sample. Together they
consumed 4h22m24s of job execution. The transitional workflow also ran the original
journey, baseline and fast checks: it completed in 2h00m30s and consumed 6h49m35s
of summed CI job execution. Parallelism trades more execution for shorter elapsed
feedback; these are not billing measurements. Other workflows are excluded.

All installed reports describe fresh MinIO fixtures on GitHub runners reporting
four CPUs, the production admission policy and host-history pacing. Cache state
and precise runner queue time were not measured. Job start offsets also include
scheduling/dependency delays. Nested timing categories overlap and must not be
added to obtain total elapsed time. Different fixture images and runner hosts
prevent attributing every difference to the code change.

## Earlier attempts and remaining gate

| Earlier PR #159 attempt | Outcome | Workflow elapsed | Summed CI execution |
| --- | --- | ---: | ---: |
| [35438097298](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35438097298) | Superseded by diagnostic review correction | 9m46s | 2h29m12s |
| [35438509677](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35438509677) | Complete journey failed; independent groups passed | 1h34m26s | 6h16m49s |
| [35474802824](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35474802824) | Superseded by retained-receipt review correction | 9m33s | 2h20m41s |

The failed complete journey used the preceding artifact, now revoked by the
[archive locking correction](2026-09-19-archive-construction-qualification-revocation.md).
Its exact worker exception was unavailable; deterministic lock regressions
establish the corrected defect without proving the cause of every earlier
failure. These failed/cancelled attempts remain costs and diagnostic observations,
not passing qualification or additional completed benchmark samples.

This is the first completed matrix for the corrected runtime and final grouping
design. The selection PR and its final merged-main run supply the next normal
comparison samples. The final sustainability record must assess all three runs,
fast prerequisite delay, total cost, any budget misses, and complete
secure-workstation qualification of the final live harness. Scheduled and manual
CI retain the original complete journey; production credentials and live gates
remain on the secure workstation. Historical M3.10 convergence remains complete.
