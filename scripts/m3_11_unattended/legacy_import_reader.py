"""Opt-in import bridge for the exact installed legacy cleanup helper.

Run this file with the legacy interpreter, without changing the legacy checkout.
Only the approved import is separated from legacy events. Physical inventory and
snapshot checks still include it. No client policy, checkpoint or ACK is changed.
"""

# ruff: noqa: ANN401 - the pinned legacy class is absent from the current runtime
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import runpy
import sys
from collections.abc import Callable
from contextlib import suppress
from copy import deepcopy
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path
from types import ModuleType
from typing import Any

LEGACY_REVISION = "0b5b198bf06443e61f01b1f7259fea827f79fc23"
LEDGER_SHA256 = "5a52d59b3e9315b90b877506a564fa5d9230c18a0b112dfccaa3670c3b25c4a3"
IMPORT_TAG = "ldp-m3-11-legacy-import-v1"
FORMAT = "lowerduckpond-m3-11-legacy-import-reader-v1"
PROGRAM = "/opt/import-bridge/legacy_import_reader.py"


def watchdog_command(vault: str, expected: str) -> list[str]:
    return [
        "uv",
        "run",
        "--no-sync",
        "--frozen",
        "python",
        PROGRAM,
        "--legacy-root",
        "/opt/lifecycle",
        "--journal-vault",
        vault,
        "--migration-sha256",
        expected,
        "--actor",
        "watchdog",
        "--receipt",
        "/evidence/import-reader.json",
        "--",
        "--config",
        "/cleanup/cleanup.json",
        "--actor",
        "watchdog",
        "--watch",
        "--runs",
        "/evidence/runs",
    ]


def install(  # noqa: PLR0915 - keep the bound legacy algorithm together for comparison
    module: ModuleType,
    *,
    vault: str,
    expected: str,
    observe: Callable[[dict[str, object]], None] = lambda _value: None,
) -> None:
    """Install before either legacy host or independent journal is imported."""
    if (
        re.fullmatch(r"[a-z0-9]{26}", vault) is None
        or re.fullmatch(r"[0-9a-f]{64}", expected) is None
        or module.__file__ is None
        or hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest() != LEDGER_SHA256
        or getattr(module, "import_bridge_installed", False)
    ):
        raise ValueError("legacy import bridge binding differs")
    original = module.ConnectLedger
    title = "m3-11-import-" + expected

    def inventory(self: Any) -> dict[str, dict[str, object]]:  # noqa: PLR0912 - closed legacy/import metadata checks
        if self.vault != vault:
            raise module.LifecycleError("legacy import bridge vault differs")
        with self._reading():
            response = self.client.request("GET", "/v1/vaults/" + self.vault + "/items")
        if (
            response.status != HTTPStatus.OK
            or not isinstance(response.body, list)
            or len(response.body) > module.MAX_EVENTS
        ):
            raise module.LifecycleError("Connect journal inventory is partial or unavailable")
        result: dict[str, dict[str, object]] = {}
        imports = []
        for listed in response.body:
            if not isinstance(listed, dict):
                raise module.LifecycleError("Connect journal inventory is invalid")
            item_id = module._item_identity(listed.get("id"))
            if item_id in result:
                raise module.LifecycleError("Connect journal inventory has duplicate items")
            is_import = listed.get("title") == title
            match = module.TITLE.fullmatch(str(listed.get("title")))
            if (
                listed.get("category") != "SECURE_NOTE"
                or listed.get("tags") != ([IMPORT_TAG] if is_import else [module.TAG])
                or listed.get("state") is not None
                or type(listed.get("version")) is not int
                or listed["version"] < 1
                or not isinstance(listed.get("vault"), dict)
                or listed["vault"].get("id") != self.vault
                or (not is_import and match is None)
            ):
                raise module.LifecycleError("Connect journal inventory item metadata is invalid")
            if match is not None:
                module.identity(match[1])
            module.account_identity(listed.get("lastEditedBy"))
            module.instant(listed.get("createdAt"))
            module.instant(listed.get("updatedAt"))
            result[item_id] = {key: listed.get(key) for key in module.ITEM_BINDING}
            if is_import:
                imports.append(item_id)
        if len(imports) > 1:
            raise module.LifecycleError("approved legacy import has duplicate items")
        pin = self.spool / ("import-reader-" + expected + ".json")
        if imports:
            item_id = imports[0]
            with self._reading():
                full = self.client.item(self.vault, item_id)
            metadata = result[item_id]
            raw = module._note_content(full.get("fields"))
            value = json.loads(raw)
            if (
                any(full.get(key) != metadata[key] for key in module.ITEM_BINDING)
                or full.get("id") != item_id
                or full.get("version") != 1
                or full.get("createdAt") != full.get("updatedAt")
                or not isinstance(value, dict)
                or value.get("format") != "lowerduckpond-m3-11-legacy-import-v2"
                or module.canonical_bytes(value).decode() != raw
                or hashlib.sha256(raw.encode()).hexdigest() != expected
            ):
                raise module.LifecycleError("approved legacy import content or metadata changed")
            binding = {"id": item_id, "metadata": metadata, "migration_sha256": expected}
            if not pin.exists():
                module.write_private(pin, binding)
            if module.read_private(pin) != binding:
                raise module.LifecycleError("approved legacy import identity changed")
        elif pin.exists():
            raise module.LifecycleError("previously observed legacy import disappeared")
        self._bridge_import_visible = bool(imports)
        self._bridge_physical_count = len(result)
        return result

    def records(self: Any) -> list[dict[str, object]]:
        # This is the pinned records() algorithm with two explicit inventories:
        # physical rows drive stability/counts; legacy rows drive events/ACKs.
        self._observed_records = None
        before = self._vault_state()
        physical = self._inventory()
        legacy = {key: row for key, row in physical.items() if row["title"] != title}
        self._remember_inventory(legacy)
        events: dict[str, dict[str, object]] = {}
        metadata: dict[str, list[dict[str, object]]] = {}
        items: dict[str, str] = {}
        with self._details(legacy) as details:
            for item_id, (record, item) in details:
                if any(legacy[item_id].get(key) != item.get(key) for key in module.ITEM_BINDING):
                    raise module.LifecycleError("Connect journal changed during readback")
                event_id = module.identity(record["event_id"])
                if event_id in events and events[event_id] != record:
                    raise module.LifecycleError(
                        "Connect journal contains conflicting event identities"
                    )
                record_sha256 = module.digest(record)
                if event_id in self._known and self._known[event_id] != record_sha256:
                    raise module.LifecycleError("an immutable Connect journal event changed")
                if item_id == self.anchor and record_sha256 != self.anchor_sha256:
                    raise module.LifecycleError("Connect journal anchor changed")
                items[event_id] = item_id
                metadata.setdefault(event_id, []).append(item)
                events[event_id] = record
                self._known[event_id] = record_sha256
                self._cached_items[item_id] = record, item
        after = self._inventory()
        if any(after[key] != physical[key] for key in after.keys() & physical.keys()):
            raise module.LifecycleError(
                "immutable Connect journal metadata changed during readback"
            )
        self._remember_inventory({key: row for key, row in after.items() if row["title"] != title})
        if (
            len(physical) < before[0]
            or self.anchor not in legacy
            or not self._known.keys() <= items.keys()
            or after != physical
            or self._vault_state() != before
        ):
            raise module.SnapshotChangedError(
                "Connect journal is not synchronized with its retained checkpoint"
            )
        self._metadata, self._items = metadata, items
        self._cached_items = {key: self._cached_items[key] for key in legacy}
        self._observed_records = sorted(events.values(), key=lambda row: str(row["event_id"]))
        if self._staging:
            self._stage_records = deepcopy(self._observed_records)
            self._stage_until = module.time.monotonic() + module.STAGING_OBSERVATION_SECONDS
        return list(self._observed_records)

    def observed_records(self: Any) -> list[dict[str, object]]:
        observation: dict[str, object] = {
            "format": FORMAT,
            "legacy_revision": LEGACY_REVISION,
            "bridge_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "journal_vault": vault,
            "migration_sha256": expected,
            "observed_at": datetime.now(UTC).isoformat(),
            "status": "unresolved",
        }
        try:
            result = records(self)
            observation.update(
                status="snapshot-verified",
                legacy_records=len(result),
                physical_items=self._bridge_physical_count,
                import_visible=self._bridge_import_visible,
            )
            return result
        finally:
            with suppress(OSError, ValueError, RuntimeError):
                # A missing fresh diagnostic blocks handoff, not original cleanup.
                observe(observation)

    module.__dict__["ConnectLedger"] = type(
        "ImportCompatibleLedger",
        (original,),
        {"_inventory": inventory, "records": observed_records},
    )
    module.__dict__["import_bridge_installed"] = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-root", type=Path, required=True)
    parser.add_argument("--journal-vault", required=True)
    parser.add_argument("--migration-sha256", required=True)
    parser.add_argument("--actor", choices=("watchdog", "github"), required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        root = args.legacy_root.resolve(strict=True)
        if any(name == "scripts" or name.startswith("scripts.") for name in sys.modules):
            raise ValueError("run the bridge as a standalone file with the legacy interpreter")
        os.chdir(root)
        sys.path.insert(0, str(root))
        module = importlib.import_module("scripts.m3_11_unattended.connect_ledger")
        if module.__file__ is None or Path(module.__file__).resolve() != (
            root / "scripts/m3_11_unattended/connect_ledger.py"
        ):
            raise ValueError("legacy reader came from another helper")
        if args.actor == "github" and os.environ.get("M3_11_HELPER_REVISION") != LEGACY_REVISION:
            raise ValueError("independent helper pin differs")
        state = importlib.import_module("scripts.m3_11_unattended.state")
        args.receipt.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        module.private_directory(args.receipt.parent)
        install(
            module,
            vault=args.journal_vault,
            expected=args.migration_sha256,
            observe=lambda value: state.replace_private(args.receipt, value),
        )
        arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
        if args.actor == "watchdog" and (
            "--actor" not in arguments
            or arguments[arguments.index("--actor") + 1 :][:1] != ["watchdog"]
        ):
            raise ValueError("bridge accepts cleanup-only watchdog arguments")
        if args.actor == "github" and arguments:
            raise ValueError("independent bridge accepts the original private stdin contract")
    except OSError, ValueError, ImportError:
        parser.exit(1, "Legacy import reader binding failed; preserve original cleanup.\n")
    sys.argv = ["legacy-cleanup", *arguments]
    runpy.run_module(
        "scripts.m3_11_unattended." + ("cleanup" if args.actor == "watchdog" else "connect_action"),
        run_name="__main__",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
