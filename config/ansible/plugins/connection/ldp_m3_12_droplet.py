"""Reuse the leased successor pipe with the separate disposable action unit."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from ansible.errors import AnsibleConnectionFailure  # type: ignore[import-untyped]
from ansible.plugins.connection import ssh  # type: ignore[import-untyped]

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from config.ansible.plugins.connection.ldp_m3_12 import Connection as SuccessorConnection
from scripts.m3_12_droplet_ssh import source_argv

DOCUMENTATION = ssh.DOCUMENTATION.replace("name: ssh\n", "name: ldp_m3_12_droplet\n", 1)


class Connection(SuccessorConnection):
    transport = "ldp_m3_12_droplet"
    lease_variable = "LDP_M3_12_DROPLET_LEASE_TOKEN"
    action_unit = "lowerduckpond-m3-12-droplet-action.service"

    def action_argv(self, token: str, cmd: str) -> list[str]:
        try:
            return source_argv(os.environ["LDP_M3_12_SOURCE_ARTIFACT"], "action", token, cmd)
        except KeyError, ValueError:
            raise AnsibleConnectionFailure("disposable source authority is unavailable") from None
