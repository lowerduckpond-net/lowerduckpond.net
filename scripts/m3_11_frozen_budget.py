"""Provisional changed-path bounds; no human response deadline or proof renewal.

These are fixed operational ceilings. Live full-size sample count is zero for
both composed stages; entry must fit the full remote stage in credential life.
Read-only proof selection retains each proof's own native observation clock.
"""

REMOTE_SECONDS = 21600
LOCAL_SECONDS = 21600
EXPORT_SECONDS = 3600
SNAPSHOT_SECONDS = 3600
SNAPSHOT_CALL_SECONDS = 3900  # 180 startup + complete child + 120 reap/report.
GITHUB_CALL_SECONDS = 900
COLLECT_SECONDS = 14400  # Two complete snapshot calls, six GETs, local proof/report.
CALLER_SECONDS = 25200
REFRESH_SECONDS = 3600  # GET selection + 1800 collector + 600 host + 600 local proof + report.
MAX_REMOTE_BYTES = 1024**3
MAX_LOCAL_BYTES = 128 * 1024**3
MAX_ENTRIES = 100000

MAX_PROVIDER_REQUESTS = 10000
