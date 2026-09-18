# Sustainability baseline, 2026-09-18

These are existing successful GitHub runs, collected without another full run
solely for measurement. [Machine-readable observations](2026-09-18-sustainability-baseline.json)
preserve the source, job, dates, backend, method, and group intervals.

| Sample | Installed job elapsed | Comparison |
| --- | --- | --- |
| [PR 149](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35292567312/job/105438354451), `db9022f5` | 2h49m03s | Same Git tree as the following `main` run. |
| [Main](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35305647903/job/105477180051), `22147a64` | 2h40m24s | Same tree `cfb7212193ac7659f2be6da08995f9fbe8cbecae`; local MinIO backend. |
| [PR 148](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35197096041/job/105122792235), `348f5ab1` | 2h30m04s | Earlier harness; context, not a third comparable sample. |

The two comparable runs spend about 36–39 minutes in core lifecycle, 30–31 in
export/import, 25–26 in archive, and 31–34 in transport/recovery. Deletion takes
about ten minutes, pre-reboot capture five, and quarantine recovery six.
These intervals include each task's command handling and the time until the
next task starts. They are wall-clock estimates from existing logs, not new
monotonic observations or an attribution to pacing.

About 18–20 minutes lie outside those listed group intervals: runner/tool setup,
fixture provisioning, idempotence, credential checks, reboot, and cleanup. The
new instrumentation separates these categories on the next required run. The
existing logs do not reliably attribute their individual costs or distinguish
waiting from work; we do not fill that gap by assuming every minute is pacing.

For fast-lane context, the original main
[Python job](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35305647903/job/105477179875)
took 7m16s and
[baseline Ansible](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35305647903/job/105477180037)
10m46s. The later S6 PR's
[Python job](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35347792262/job/105608368159)
took 14m04s and
[baseline Ansible](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35347792262/job/105608368391)
12m28s. S6 added workstation-policy regressions and did not run the installed
lane. These different sources and runners are context, not a controlled
performance comparison. They justify also retaining pytest's slowest-test
summary and reporting job-level time separately from installed timings.

This baseline does not satisfy the final three-comparable-run exit requirement,
claim an optimization, or change qualification authority. Collect after-change
samples through normal required validation and include failures and interventions.
