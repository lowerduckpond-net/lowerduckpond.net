"""Verify staged authority generations before explicitly approved delivery."""

from __future__ import annotations

import argparse
from pathlib import Path

from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_renewal import handover
from scripts.m3_11_unattended.inventory import ConnectInventory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--replacement", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        previous, replacement = (
            LeaseConfiguration.load(path) for path in (args.previous, args.replacement)
        )
        inventory = ConnectInventory(
            previous.generations[previous.active_generation]["cleanup"].reader(),
            previous.journal_vault,
            spool=args.evidence / "pending",
        )
        result = handover(previous, replacement, inventory, root=args.evidence / "leases")
        write_private(args.evidence / "handover.json", result)
    except RuntimeError, OSError, ValueError, KeyError, TypeError:
        parser.exit(1, "Authority handover is unresolved; retain original cleanup access.\n")
    print("Handover evidence retained; delivery and old access removal remain explicit operations.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
