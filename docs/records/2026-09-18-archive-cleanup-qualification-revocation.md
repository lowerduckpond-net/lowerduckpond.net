# Archive cleanup qualification revocation

- Recorded: 2026-09-18
- Affected artifact: `a7ae4afe77c1fe9077ae58c8750a33518b26f7c5dc42485626b1ef22cd192800`
- Historical qualified source: `22147a64e9b39e7965201cf2d96e07aeaa6d3ca1`
- Correction: [PR #153](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/153),
  merged as `6daebc1dc48f22e2c665edb457736ee8b192152e`

The cleanup correction demonstrated that initial archive cleanup could fail
immediately when another process held the required state lock, instead of
waiting within the service's existing deadline. Its real lock-contention
regressions reproduce that behavior in the preceding implementation. This does
not establish the cause of every earlier live or CI failure.

Under [ADR 0029](../adr/0029-bind-qualification-to-inputs-and-live-observations.md),
the [revocation policy](../../scripts/qualification-revocations.json) now rejects
future qualification or completion reuse for the affected artifact. A corrected
candidate still needs its own applicable qualification and fresh live checks.

The successful M3.10 qualification and deployment remain historical facts. This
record does not change production, erase that acceptance, or prevent a qualified
successor from treating the existing installation as its completed predecessor.
It does not authorize deployment or cleanup.
