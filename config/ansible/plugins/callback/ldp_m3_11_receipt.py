"""Record the actual Ansible recap for one explicitly leased production action."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from ansible.plugins.callback import CallbackBase  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from ansible.executor.stats import AggregateStats  # type: ignore[import-untyped]

DOCUMENTATION = """
name: ldp_m3_11_receipt
type: aggregate
short_description: Original production action recap
version_added: '1.0'
description: Record host counters without task parameters or results.
requirements:
  - Explicitly enabled by the leased M3.11 controller.
"""


class CallbackModule(CallbackBase):  # type: ignore[misc]
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "ldp_m3_11_receipt"
    CALLBACK_NEEDS_ENABLED = True

    def v2_playbook_on_stats(self, stats: AggregateStats) -> None:
        context = os.environ["LDP_M3_11_PLAYBOOK_CONTEXT"]
        if re.fullmatch(r"[0-9a-f]{64}", context) is None:
            raise ValueError("invalid production playbook context")
        raw = (
            json.dumps(
                {
                    "format": "lowerduckpond-m3-11-playbook-recap-v1",
                    "context_sha256": context,
                    "hosts": {host: stats.summarize(host) for host in sorted(stats.processed)},
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
        path = Path(os.environ["LDP_M3_11_PLAYBOOK_RECEIPT"])
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
