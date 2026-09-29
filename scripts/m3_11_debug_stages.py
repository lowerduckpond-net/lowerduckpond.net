"""Individual bounded stages of a retained, non-qualifying reconstruction."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import os
import sys
import traceback
from pathlib import Path
from types import SimpleNamespace
from typing import cast

from lowerduckpond_m3_archive.storage import assert_storage_empty

from scripts import qualification_restore as owned
from scripts.m3_11_debug_dns import retire as retire_dns
from scripts.m3_11_debug_files import fingerprint, replace_private
from scripts.m3_11_debug_fixture import attach, history
from scripts.m3_11_debug_types import Fixture
from scripts.m3_11_dns_witness import DnsWitness
from scripts.m3_11_owned_teardown import Teardown
from scripts.m3_11_private_inputs import read_private, read_private_bytes, write_private
from scripts.m3_11_qualification_evidence import ZERO_ACCOUNTING
from scripts.qualification_case import owned_containers
from scripts.qualification_context import ARCHIVE_ENV
from scripts.qualification_retirement import uninstalled_storage_absence
from scripts.qualification_storage_lease import require_inherited


def public_recovery(
    root: Path, fixture: Fixture, *, retire_stale_dns: bool = False
) -> dict[str, object]:
    module = importlib.import_module("public_ca_recovery")
    public = module.PublicRecovery(fixture, fixture.live_storage, root, diagnostic=True)
    value = {
        "context_sha256": public.context_sha256,
        "binary": fixture.binary,
        "binary_sha256": public.context["caddy_binary_sha256"],
        "nonce": public.names["nonce"],
        "files": {
            name: base64.b64encode(read_private_bytes(path, maximum=1024 * 1024)).decode()
            for name, path in public.original.items()
        },
        "token": public.token,
    }
    prepared = public.call("diagnostic_prepare", value=value)
    interrupted = False
    try:
        retirement = retire_dns(public.witness, public.call) if retire_stale_dns else None
        public.call("diagnostic_start")
        public.peer(opened=False)
        while True:
            observation = public.witness.sample("activity")
            ready = public.call("ready")
            if ready["ready"]:
                break
            if observation.record_count and not interrupted:
                before = public.call("diagnostic_interrupt")
                fixture.reboot()
                after = public.call("diagnostic_interrupt")
                public.peer(opened=False)
                if before != after:
                    raise ValueError("diagnostic public reboot changed retained account bytes")
                public.call("diagnostic_start")
                interrupted = True
            public._wait()
        public.witness.require_absent("cleanup")
        public.peer(opened=False)
        public.call("diagnostic_open", expected=ready["tls"])
        public.peer(opened=True)
        public.call(
            "diagnostic_finish",
            expected=ready["tls"],
            audit_rotation=fixture.target["auditRotationEnabled"],
        )
        result = {
            "context_sha256": public.context_sha256,
            "cold": prepared["cold"],
            "interrupted": interrupted,
            "public_tls": True,
            "dns_retirement": retirement,
            "zones_observed": len(public.witness.observed_zones),
            "coverage_gaps": ["cold-interruption-or-two-zone-observation"]
            if prepared["cold"] and (not interrupted or len(public.witness.observed_zones) != 2)  # noqa: PLR2004 - both configured zones
            else [],
        }
        replace_private(root / "diagnostic-public-result.json", result)
        return result
    except BaseException:
        try:
            public.call("diagnostic_stop_failed")
        except Exception:
            traceback.print_exc()
        raise


def accounting(root: Path, fixture: Fixture) -> dict[str, object]:

    module = importlib.import_module("combined_accounting")
    public = SimpleNamespace(fixture=fixture, directory=root)
    before = module._source_inputs(public)
    pair = owned.paired_proof(fixture.environment)
    original = read_private(root / "diagnostic-origin.json")["original_run"]
    rotation = read_private(Path(str(original)) / "combined-phases/protected-rotation.json")[
        "observations"
    ]
    protection = module._protection(public, rotation)
    _, observer = fixture.live_storage.target.clients(fixture.live_storage.environment)
    assert_storage_empty(observer, bucket=fixture.live_storage.target.archive_bucket)
    if module._source_inputs(public) != before or owned.paired_proof(fixture.environment) != pair:
        raise ValueError("diagnostic paired accounting changed during provider observation")
    value = {
        "context_sha256": hashlib.sha256(
            read_private_bytes(root / "combined-context.json")
        ).hexdigest(),
        "identities": pair,
        "source_pending_inputs": before,
        "protected_history": protection,
        "accounting": {
            **dict.fromkeys(ZERO_ACCOUNTING, 0),
            "source_state": "fenced",
            "source_fence_sha256": hashlib.sha256(fixture.fence).hexdigest(),
            "source_pending_inputs_sha256": before["sha256"],
            "destination_quarantine": False,
        },
    }
    replace_private(root / "paired-accounting.json", value)
    return {"paired_accounting": "observed"}


def run(  # noqa: PLR0911, PLR0912 - fixed stage dispatch
    root: Path, attempt: Path, stage: str
) -> dict[str, object]:

    require_inherited(os.environ)
    fixture = attach(root)
    if stage == "repair":
        expected = read_private(attempt / "controller.json")["repair_sha256"]
        path = attempt / "repair.py"
        if fingerprint(path) != expected:
            raise ValueError("diagnostic repair differs from its captured branch script")
        module = importlib.import_module("test_export_import")
        script = read_private_bytes(path).decode()
        program = module._selected_python(
            fixture.destination, f"exec(compile({script!r}, 'diagnostic-repair.py', 'exec'))"
        )
        output = fixture.command(
            "docker",
            "exec",
            fixture.destination_id,
            "timeout",
            "--signal=TERM",
            "--kill-after=10s",
            "270s",
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            program,
            timeout=290,
        )
        print(output.decode(errors="replace"))
        return {"repair_sha256": expected, "qualification_authority": "none"}
    saved = history(root, fixture)
    scenarios = importlib.import_module("restore_scenarios")
    if stage == "restore":
        status = fixture.status()
        if status["phase"] != "complete":
            scenarios.gate_closed(fixture)
        if fixture.destination.run("systemctl stop lowerduckpond-host-restore.service").rc:
            raise ValueError("diagnostic coordinator did not stop")
        fixture.fault("none")
        fixture.start()
        fixture.wait({"complete"})
        return {"restore": "complete"}
    if stage == "reconstruction":
        scenarios.verify_reconstruction(fixture, saved["replay"])
        return {"reconstruction": "checked"}
    if stage == "reboot":
        journal = fixture.destination.file(
            "/var/lib/lowerduckpond/recovery/host-restore.json"
        ).content
        fixture.reboot()
        fixture.start()
        fixture.wait({"complete"})
        if (
            fixture.destination.file("/var/lib/lowerduckpond/recovery/host-restore.json").content
            != journal
        ):
            raise ValueError("diagnostic reboot changed completed restore evidence")
        return {"reboot": "checked"}
    if stage == "replay":
        return cast(
            "dict[str, object]",
            scenarios.replay_and_retire(
                fixture, saved["tenants"], saved["replay"], operator_directory=attempt / "operator"
            ),
        )
    if stage == "public-ca":
        return public_recovery(
            root,
            fixture,
            retire_stale_dns=read_private(attempt / "controller.json").get("retire_stale_dns")
            is True,
        )
    if stage == "accounting":
        return accounting(root, fixture)
    if stage == "teardown-check":
        witness = DnsWitness.begin(root, fixture.live_storage, diagnostic=True)
        teardown = Teardown(
            root, fixture.live_storage, lambda: witness.require_absent("teardown").sha256
        )
        owned.paired_proof(fixture.environment)
        uninstalled_storage_absence(
            fixture.environment, owned_containers(fixture.environment)[ARCHIVE_ENV]
        )
        teardown._archive_absent()
        teardown._dns_absent()
        teardown._pair_receipts()
        if not teardown._image():
            raise ValueError("diagnostic teardown lost the original image")
        # Exercise prefix ownership and inventory without deleting protected backup evidence.
        fixture.live_storage.require_owner()
        return {"teardown_prerequisites": "checked", "resources": "retained"}
    raise ValueError("unknown diagnostic stage")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("attempt", type=Path)
    parser.add_argument("stage")
    args = parser.parse_args()
    if args.stage not in {
        "restore",
        "reconstruction",
        "reboot",
        "replay",
        "public-ca",
        "accounting",
        "teardown-check",
        "repair",
    }:
        parser.error("unknown diagnostic stage")
    if args.attempt.parent != args.workspace / "attempts" or args.attempt.resolve() != args.attempt:
        parser.error("diagnostic stage needs its original attempt directory")
    try:
        result = run(args.workspace, args.attempt, args.stage)
        write_private(args.attempt / (args.stage + ".details.json"), result)
        return 0
    except Exception as error:
        traceback.print_exc()
        write_private(
            args.attempt / (args.stage + ".error.json"),
            {
                "exception": type(error).__name__,
                "locations": [
                    {"file": Path(frame.filename).name, "line": frame.lineno}
                    for frame in traceback.extract_tb(error.__traceback__)
                ][-12:],
            },
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
