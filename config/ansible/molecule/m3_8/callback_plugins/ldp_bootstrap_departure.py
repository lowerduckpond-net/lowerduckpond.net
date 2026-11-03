"""Deliberately depart after the first acknowledged bootstrap dependency copy."""

from __future__ import annotations

import os
from pathlib import Path

from ansible.plugins.callback import CallbackBase  # type: ignore[import-untyped]

TASK = "Install bootstrap-independent root recovery admission"
EXIT = 86


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "ldp_bootstrap_departure"
    CALLBACK_NEEDS_ENABLED = True

    def v2_runner_on_ok(self, result: object) -> None:
        task = getattr(result, "_task", None)
        name = getattr(task, "get_name", lambda: "")()
        payload = getattr(result, "_result", {})
        marker = os.environ.get("LDP_M3_11_TEST_DEPARTURE")
        if marker and name.endswith(TASK) and isinstance(payload, dict) and payload.get("changed"):
            descriptor = os.open(
                Path(marker), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(descriptor, "w") as stream:
                stream.write("acknowledged-first-dependency\n")
                stream.flush()
                os.fsync(stream.fileno())
            raise SystemExit(EXIT)
