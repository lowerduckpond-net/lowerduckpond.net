"""Keep every rollout command and piped transfer under its live remote lease."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import cast

from ansible.errors import AnsibleConnectionFailure  # type: ignore[import-untyped]
from ansible.plugins.connection import ssh  # type: ignore[import-untyped]

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from scripts.m3_11_production_transport import command

# Retain the pinned SSH plugin's complete option definitions and behavior.
DOCUMENTATION = ssh.DOCUMENTATION.replace("name: ssh\n", "name: ldp_m3_11\n", 1)


class Connection(ssh.Connection):  # type: ignore[misc]
    transport = "ldp_m3_11"

    def exec_command(
        self, cmd: str, in_data: bytes | None = None, sudoable: bool = True
    ) -> tuple[int, bytes, bytes]:
        if (
            self.get_option("use_tty")
            or self.get_option("reconnection_retries") != 0
            or not self.get_option("host_key_checking")
        ):
            raise AnsibleConnectionFailure("production transport requires verified nonretrying SSH")
        try:
            guarded = command(
                os.environ["LDP_M3_11_ACTION_HELPER"], os.environ["LDP_M3_11_LEASE_TOKEN"], cmd
            )
        except KeyError, ValueError:
            raise AnsibleConnectionFailure(
                "production transport authority is unavailable"
            ) from None
        return cast(
            tuple[int, bytes, bytes],
            super().exec_command(guarded, in_data=in_data, sudoable=sudoable),
        )

    def _file_transport_command(
        self, in_path: str, out_path: str, sftp_action: str
    ) -> tuple[int, bytes, bytes]:
        # The pinned upstream piped transfer calls this class's exec_command
        # for both dd directions. Refuse every unguarded fallback, including
        # smart mode switching to SFTP/SCP after a connection failure.
        if self.get_option("ssh_transfer_method") != "piped":
            raise AnsibleConnectionFailure("production transfers require the leased pipe")
        return cast(
            tuple[int, bytes, bytes],
            super()._file_transport_command(in_path, out_path, sftp_action),
        )
