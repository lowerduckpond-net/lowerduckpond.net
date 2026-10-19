"""Bound read-only cleanup refresh for the staged caller, never a dispatch.

The separately reviewed native collector and host observer keep their original
full verifiers and deadlines. Each call selects native scheduled evidence anew,
retains the exact invocation/files, then runs the isolated local proof child.
The caller seals this configuration and every executable/transitive dependency.
Neither an arbitrary command nor a previous projected receipt is accepted.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from scripts.m3_11_frozen_budget import REFRESH_SECONDS
from scripts.m3_11_frozen_collect import read_command
from scripts.m3_11_frozen_context import require
from scripts.m3_11_frozen_failure import document
from scripts.m3_11_frozen_local import cleanup
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import digest, directory, fingerprint, record, sync
from scripts.m3_11_unattended.model import instant

INVENTORY_SECONDS = 120
INDEPENDENT_SECONDS = 1800
HOST_SECONDS = 600
LOCAL_SECONDS = 600
MAX_JSON = 4 * 1024 * 1024
ENDPOINT = (
    "repos/lowerduckpond-net/lowerduckpond.net/actions/workflows/"
    "m3-11-credential-cleanup.yml/runs?event=schedule&per_page=20"
)


class Refresh:
    def __init__(self, configuration: object, *, environment: dict[str, str]) -> None:
        self.config = fields(
            configuration,
            {
                "format",
                "pins",
                "python",
                "python_realpath",
                "python_configuration",
                "collector",
                "host_observer",
                "local_validator",
                "readiness_directory",
                "evidence",
                "output_parent",
                "evidence_sha256",
            },
        )
        require(
            self.config["format"] == "lowerduckpond-m3-11-staged-proof-refresh-v1",
            "cleanup refresh configuration differs",
        )
        self.environment = environment
        self.phase = "terminal-capture"

    def pinned(self) -> None:
        pins = self.config["pins"]
        require(isinstance(pins, dict), "cleanup refresh lacks reviewed file bindings")
        for key in (
            "python_realpath",
            "python_configuration",
            "collector",
            "host_observer",
            "local_validator",
            "evidence",
        ):
            require(
                str(self.config[key]) in cast(dict[str, object], pins),
                "cleanup refresh executable/input is not bound",
            )
        python = Path(str(self.config["python"]))
        require(
            python.is_absolute()
            and python.resolve(strict=True) == Path(str(self.config["python_realpath"]))
            and python.parent.name == "bin"
            and python.parent.parent / "pyvenv.cfg"
            == Path(str(self.config["python_configuration"])),
            "cleanup refresh interpreter or virtual environment changed",
        )
        for name, wanted in cast(dict[str, object], pins).items():
            path = Path(name)
            require(
                path.is_absolute() and path.resolve(strict=True) == path,
                "cleanup refresh pinned path changed",
            )
            # Executables/source need not have private-evidence mode. Their
            # exact bytes are authorized by the independently reviewed seal.
            require(
                hashlib.sha256(path.read_bytes()).hexdigest() == wanted,
                "cleanup refresh reviewed executable/input changed",
            )

    def __call__(self) -> dict[str, object]:  # noqa: PLR0915 - ordered complete native proof transaction
        started = time.monotonic()
        deadline = started + REFRESH_SECONDS
        self.pinned()
        parent = Path(str(self.config["output_parent"]))
        directory(parent)
        output = parent / ("refresh-" + uuid.uuid7().hex)
        output.mkdir(mode=0o700)
        sync(parent)
        record(output / "configuration.json", self.config)

        def invoke(label: str, args: list[str], seconds: int) -> dict[str, object]:
            self.phase = "terminal-github-get" if label == "inventory" else "terminal-capture"
            self.pinned()
            require(
                deadline - time.monotonic() >= seconds + 120,
                "cleanup refresh lacks the whole child and reporting allowance",
            )
            call_start = time.monotonic()
            record(
                output / (label + "-intent.json"),
                {
                    "arguments": args,
                    "timeout_seconds": seconds,
                    "attempt_count": 1,
                    "configuration_sha256": digest(self.config),
                },
            )
            raw = read_command(
                args, environment=self.environment, deadline=call_start + seconds, maximum=MAX_JSON
            )
            value = json.loads(raw)
            require(isinstance(value, dict), "cleanup refresh native result is not an object")
            record(output / (label + ".json"), value)
            record(
                output / (label + "-elapsed.json"),
                {"elapsed_seconds": time.monotonic() - call_start, "attempt_count": 1},
            )
            return cast(dict[str, object], value)

        try:
            inventory = invoke(
                "inventory",
                ["gh", "api", "--hostname", "github.com", "--method", "GET", ENDPOINT],
                INVENTORY_SECONDS,
            )
            evidence = read_private(Path(str(self.config["evidence"])))
            require(
                digest(evidence) == self.config["evidence_sha256"],
                "cleanup refresh original evidence changed",
            )
            contract = cast(dict[str, object], evidence["cleanup_contract"])
            rows = inventory.get("workflow_runs")
            require(isinstance(rows, list), "native scheduled inventory is unavailable")
            now = datetime.now(UTC)
            eligible = [
                row
                for row in cast(list[dict[str, object]], rows)
                if type(row.get("id")) is int
                and cast(int, row["id"]) > 0
                and row.get("event") == "schedule"
                and row.get("run_attempt") == 1
                and row.get("head_sha") == contract["native_workflow"]
                and row.get("status") == "completed"
                and row.get("conclusion") == "success"
                and timedelta() <= now - instant(row["created_at"]) < timedelta(seconds=5400)
            ]
            require(
                eligible, "no eligible completed scheduled cleanup proof; no dispatch or waiting"
            )
            selected = max(eligible, key=lambda row: instant(row["created_at"]))
            run_id = selected["id"]
            python = str(self.config["python"])
            independent = invoke(
                "independent",
                [python, "-I", "-B", str(self.config["collector"]), str(run_id)],
                INDEPENDENT_SECONDS,
            )
            require(
                independent.get("status")
                == "verified-scheduled-cleanup-separate-native-helper-binding"
                and independent.get("run_id") == run_id
                and independent.get("run_attempt") == 1,
                "cleanup refresh independent full verifier failed",
            )
            readiness = Path(str(self.config["readiness_directory"]))
            native = Path(str(independent["review_directory"]))
            require(
                native.parent == readiness
                and re.fullmatch(
                    r"fresh-independent-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}",
                    native.name,
                ),
                "cleanup refresh independent output escaped its reviewed directory",
            )
            proof = native / "verified.json"
            require(
                fingerprint(proof, MAX_JSON)["sha256"] == independent["verified_sha256"],
                "cleanup refresh independent original bytes differ",
            )
            host = invoke(
                "host",
                [
                    python,
                    "-I",
                    "-B",
                    str(self.config["host_observer"]),
                    "observe",
                    str(proof),
                    str(independent["verified_sha256"]),
                ],
                HOST_SECONDS,
            )
            host_root = Path(str(host["evidence_directory"]))
            require(
                host.get("status") == "verified-new-host-cleanup"
                and host_root.parent == readiness
                and re.fullmatch(r"host-handoff-read-[a-f0-9]{32}", host_root.name),
                "cleanup refresh host full verifier failed",
            )
            selection = {
                name: {"path": str(path), **fingerprint(path, MAX_JSON)}
                for name, path in (
                    ("host", host_root / "host-verified.json"),
                    ("independent", proof),
                    ("collection", native / "collection-result.json"),
                )
            }
            # Preserve every verifier artifact as an immutable file binding.
            files = {
                str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                for root in (native, host_root)
                for path in root.rglob("*")
                if path.is_file()
            }
            record(output / "verifier-files.json", dict(files))
            record(output / "selection.json", dict(selection))
            expiry = cleanup(selection, contract, now=datetime.now(UTC))
            result = invoke(
                "local",
                [
                    python,
                    "-I",
                    "-B",
                    str(self.config["local_validator"]),
                    str(self.config["evidence"]),
                    str(output / "selection.json"),
                    str(output / "local-proof"),
                ],
                LOCAL_SECONDS,
            )
            require(
                result.get("evidence_sha256") == self.config["evidence_sha256"]
                and result.get("status") == "native-files-and-cleanup-verified"
                and instant(result["proof_valid_until"]) == expiry,
                "cleanup refresh local verification changed native proof origin",
            )
            cleanup(selection, contract, now=datetime.now(UTC))
            for name, expected in files.items():
                require(
                    hashlib.sha256(Path(name).read_bytes()).hexdigest() == expected,
                    "cleanup refresh verifier evidence changed during local proof",
                )
            require(time.monotonic() < deadline, "cleanup refresh reporting allowance ended")
            record(
                output / "verified.json",
                {
                    "result": result,
                    "native_run_id": run_id,
                    "configuration_sha256": digest(self.config),
                    "elapsed_seconds": time.monotonic() - started,
                    "provider_calls": 0,
                    "dispatches": 0,
                    "live_mutations": 0,
                },
            )
            return result
        except BaseException as error:
            record(output / "failure.json", document(error, started=started, phase=self.phase))
            raise
