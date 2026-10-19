"""Concrete GET-only terminal collector using existing CLI/controller identities.

No dispatch, provider client, child credential delivery or cleanup is exposed.
Native snapshots bracket six authenticated GitHub GETs. Exact raw artifacts,
source programs, invocation bindings and all original facts are retained private.
An operator subsequently selects these immutable bytes in the local effect plan.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import select
import subprocess
import time
from pathlib import Path
from typing import BinaryIO, cast

from scripts import m3_11_frozen_github as github
from scripts.m3_11_frozen_budget import COLLECT_SECONDS, GITHUB_CALL_SECONDS, SNAPSHOT_CALL_SECONDS
from scripts.m3_11_frozen_context import require
from scripts.m3_11_frozen_failure import document
from scripts.m3_11_frozen_terminal_bundle import FILES, verify
from scripts.m3_11_frozen_transport import require_operation
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import (
    CHUNK,
    RetirementError,
    digest,
    directory,
    fingerprint,
    preserve,
    record,
    sync,
)
from scripts.m3_11_unattended.state import LeaseState


class CommandError(RetirementError):
    def __init__(self, status: int) -> None:
        super().__init__("terminal native read command failed")
        self.status = status


def read_command(
    arguments: list[str],
    *,
    environment: dict[str, str],
    deadline: float,
    maximum: int,
    stdin: bytes | None = None,
) -> bytes:
    """Fixed callers only; bound wall time and bytes before returning any output."""
    require(time.monotonic() < deadline, "terminal collection operational deadline ended")
    process = subprocess.Popen(  # noqa: S603 - fixed source-owned commands, no shell
        arguments,
        env=environment,
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    try:
        if stdin is not None:
            from scripts.m3_11_frozen_frames import send  # noqa: PLC0415

            require(process.stdin is not None, "terminal native input unavailable")
            send(
                cast(BinaryIO, process.stdin),
                cast(dict[str, object], json.loads(stdin)),
                deadline=deadline,
            )
            cast(BinaryIO, process.stdin).close()
        require(process.stdout is not None, "terminal native output unavailable")
        result = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "terminal native read deadline ended")
            require(
                bool(select.select([cast(BinaryIO, process.stdout)], [], [], remaining)[0]),
                "terminal native read deadline ended",
            )
            block = os.read(
                cast(BinaryIO, process.stdout).fileno(), min(CHUNK, maximum + 1 - len(result))
            )
            if not block:
                break
            result.extend(block)
            require(len(result) <= maximum, "terminal native response exceeds its byte bound")
        status = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        if status:
            raise CommandError(status)
        return bytes(result)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        if process.stdout is not None:
            process.stdout.close()
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()


class Collector:
    def __init__(
        self,
        *,
        environment: dict[str, str],
        controller: str,
        program: str,
        bundle: str,
        plan: dict[str, object],
    ) -> None:
        require(re.fullmatch(r"[a-f0-9]{64}", controller), "terminal controller ID is invalid")
        require(
            environment.get("DOCKER_HOST", "").startswith("unix:///")
            and not environment.get("DOCKER_CONTEXT"),
            "terminal daemon binding differs",
        )
        require_operation(program, bundle, operation="terminal-snapshot", plan_sha256=digest(plan))
        require(
            cast(dict[str, object], plan["controller_identity"])["id"] == controller,
            "terminal collector selected another controller",
        )
        self.environment, self.controller = environment, controller
        self.program, self.bundle, self.plan = program, bundle, plan
        self.deadline = time.monotonic() + COLLECT_SECONDS
        self.calls: list[dict[str, object]] = []
        self.raw_responses: list[bytes] = []
        self.output: Path | None = None
        self.phase = "terminal-capture"

    def call(
        self,
        arguments: list[str],
        *,
        phase: str,
        deadline: float,
        maximum: int,
        stdin: bytes | None = None,
    ) -> bytes:
        started = time.monotonic()
        self.phase = phase
        try:
            return read_command(
                arguments,
                environment=self.environment,
                deadline=deadline,
                maximum=maximum,
                stdin=stdin,
            )
        except BaseException as error:
            if self.output is not None:
                report = document(error, started=started, phase=phase)
                report.update(
                    command_exit_status=error.status if isinstance(error, CommandError) else None,
                    command_attempt=1,
                    completed_reads=len(self.calls),
                    response_bodies_and_stderr_exposed=False,
                    provider_mutations=0,
                )
                record(self.output / "failure.json", report)
            raise

    def response(self, raw: bytes, row: dict[str, object], started: float) -> None:
        index = len(self.raw_responses)
        row.update(
            response_sha256=hashlib.sha256(raw).hexdigest(),
            response_file=f"response-{index}.bin",
            elapsed_seconds=max(0.0, time.monotonic() - started),
            attempt_count=1,
        )
        self.calls.append(row)
        self.raw_responses.append(raw)
        if self.output is not None:
            preserve(
                self.output / f"response-{index}.bin",
                (raw[i : i + CHUNK] for i in range(0, len(raw), CHUNK)),
                len(raw),
                hashlib.sha256(raw).hexdigest(),
            )
            record(self.output / f"call-{index}.json", row)

    def snapshot(self) -> dict[str, object]:
        now = time.monotonic()
        require(
            self.deadline - now >= SNAPSHOT_CALL_SECONDS + 60,
            "terminal collection lacks the whole snapshot startup/child/report allowance",
        )
        raw = self.call(
            [
                "docker",
                "exec",
                "-i",
                "-w",
                "/work/source",
                self.controller,
                "uv",
                "run",
                "--no-sync",
                "--frozen",
                "python",
                "-I",
                "-B",
                "-c",
                self.program,
            ],
            phase="terminal-snapshot",
            deadline=now + SNAPSHOT_CALL_SECONDS,
            maximum=github.MAX_BODY,
            stdin=json.dumps({"bundle": self.bundle, "authorization": {}}).encode(),
        )
        self.response(raw, {"operation": "terminal-snapshot"}, now)
        value = fields(
            json.loads(raw), {"status", "snapshot", "plan_sha256", "bundle_sha256", "provenance"}
        )
        require(
            value["status"] == "observed-terminal-facts"
            and value["plan_sha256"] == digest(self.plan)
            and value["bundle_sha256"] == hashlib.sha256(self.bundle.encode()).hexdigest(),
            "terminal native snapshot source binding differs",
        )
        require(
            value["provenance"]
            == {
                key: self.plan[key]
                for key in ("controller_identity", "request_sha256", "consumer_binding")
            },
            "terminal collector original native provenance differs",
        )
        require(isinstance(value["snapshot"], dict), "terminal native snapshot is missing")
        return cast(dict[str, object], value["snapshot"])

    def github_get(self, endpoint: str) -> bytes:
        require(
            re.fullmatch(
                r"repos/lowerduckpond-net/lowerduckpond\.net/actions/(runs/[1-9][0-9]*(/attempts/1(/jobs\?per_page=100)?|/artifacts\?per_page=100)?|artifacts/[1-9][0-9]*/zip)",
                endpoint,
            ),
            "terminal collector endpoint escaped its exact GET surface",
        )
        now = time.monotonic()
        require(
            self.deadline - now >= GITHUB_CALL_SECONDS + 60,
            "terminal collection lacks the whole native GET/report allowance",
        )
        raw = self.call(
            ["gh", "api", "--hostname", "github.com", "--method", "GET", endpoint],
            phase="terminal-github-get",
            deadline=now + GITHUB_CALL_SECONDS,
            maximum=github.MAX_ZIP,
        )
        self.response(raw, {"operation": "github-get", "endpoint": endpoint}, now)
        return raw

    def capture(
        self, *, output: Path, run_id: int, contract: dict[str, object], lease: LeaseState
    ) -> dict[str, object]:
        started = time.monotonic()
        try:
            return self._capture(output=output, run_id=run_id, contract=contract, lease=lease)
        except BaseException as error:
            if self.output == output and not (output / "failure.json").exists():
                record(output / "failure.json", document(error, started=started, phase=self.phase))
            raise

    def _capture(
        self, *, output: Path, run_id: int, contract: dict[str, object], lease: LeaseState
    ) -> dict[str, object]:
        directory(output.parent)
        output.mkdir(mode=0o700)
        self.output = output
        sync(output.parent)
        require(
            lease.manifest().lease_id == self.plan["lease_id"]
            and lease.manifest().sha256 == self.plan["manifest_sha256"],
            "terminal capture original manifest binding differs",
        )
        invocation = {
            "format": "lowerduckpond-m3-11-terminal-native-invocation-v1",
            "controller": self.controller,
            "plan": self.plan,
            "program_sha256": hashlib.sha256(self.program.encode()).hexdigest(),
            "bundle_sha256": hashlib.sha256(self.bundle.encode()).hexdigest(),
            "maximum_seconds": COLLECT_SECONDS,
            "operation": "GET-only-terminal-capture",
        }
        record(output / "invocation.json", invocation)
        for name, data in (("program.txt", self.program), ("bundle.txt", self.bundle)):
            raw = data.encode()
            preserve(
                output / name,
                (raw[i : i + CHUNK] for i in range(0, len(raw), CHUNK)),
                len(raw),
                hashlib.sha256(raw).hexdigest(),
            )
        write_private(output / "before.json", self.snapshot(), maximum=github.MAX_BODY)
        github.capture(self.github_get, run_id, output / "github", contract, lease.manifest())
        write_private(output / "after.json", self.snapshot(), maximum=github.MAX_BODY)
        for index, raw in enumerate(self.raw_responses):
            preserve(
                output / f"response-{index}.bin",
                (raw[i : i + CHUNK] for i in range(0, len(raw), CHUNK)),
                len(raw),
                hashlib.sha256(raw).hexdigest(),
            )
        record(output / "native-calls.json", {"calls": self.calls})
        selection: dict[str, object] = {
            "directory": str(output),
            "files": {name: fingerprint(output / name, github.MAX_ZIP) for name in FILES},
            "github_contract": contract,
            "collector_sha256": digest(invocation),
        }
        result = verify(selection, lease)
        require(
            time.monotonic() < self.deadline,
            "terminal collection exhausted its verification/report allowance",
        )
        record(output / "selection.json", selection)
        record(output / "verified.json", result)
        return selection
