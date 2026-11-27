"""Use the pinned SSH and pipe behavior with the distinct M3.12 native lease."""

from __future__ import annotations

import os
import re
import shlex

from ansible.errors import AnsibleConnectionFailure  # type: ignore[import-untyped]
from ansible.plugins.connection import ssh  # type: ignore[import-untyped]

DOCUMENTATION = ssh.DOCUMENTATION.replace("name: ssh\n", "name: ldp_m3_12\n", 1)
EXECUTABLE = "/usr/local/libexec/lowerduckpond/m3-12-successor-action"


class Connection(ssh.Connection):  # type: ignore[misc]
    transport = "ldp_m3_12"
    lease_variable = "LDP_M3_12_LEASE_TOKEN"
    action_unit = "lowerduckpond-m3-12-action.service"

    def action_argv(self, token: str, cmd: str) -> list[str]:
        return [EXECUTABLE, "action", token, cmd]

    def exec_command(
        self, cmd: str, in_data: bytes | None = None, sudoable: bool = True
    ) -> tuple[int, bytes, bytes]:
        token = os.environ.get(self.lease_variable, "")
        if (
            self.get_option("use_tty")
            or self.get_option("reconnection_retries") != 0
            or not self.get_option("host_key_checking")
            or re.fullmatch(r"[0-9a-f]{64}", token) is None
            or token == "0" * 64
            or not cmd
            or "\0" in cmd
        ):
            raise AnsibleConnectionFailure("successor transport requires the verified native lease")
        guarded = shlex.join(
            [
                "sudo",
                "--non-interactive",
                "/usr/bin/systemd-run",
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "--expand-environment=no",
                f"--unit={self.action_unit}",
                "--service-type=exec",
                "--property=ExitType=cgroup",
                "--property=KillMode=control-group",
                "--property=UMask=0077",
                *self.action_argv(token, cmd),
            ]
        )
        result: tuple[int, bytes, bytes] = super().exec_command(
            guarded, in_data=in_data, sudoable=sudoable
        )
        return result

    def _file_transport_command(
        self, in_path: str, out_path: str, sftp_action: str
    ) -> tuple[int, bytes, bytes]:
        if self.get_option("ssh_transfer_method") != "piped":
            raise AnsibleConnectionFailure("successor transfers require the leased pipe")
        result: tuple[int, bytes, bytes] = super()._file_transport_command(
            in_path, out_path, sftp_action
        )
        return result
