"""Cleanup-only rollback of a versioned controller bundle; never restore old issuance."""

from __future__ import annotations

import argparse
from pathlib import Path

from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_unattended.config import LeaseConfiguration


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = LeaseConfiguration.load(args.configuration)
        write_private(args.output, config.document(cleanup_only=True))
    except RuntimeError, OSError, ValueError, KeyError, TypeError:
        parser.exit(1, "Cleanup-only rollback is unavailable; retain original access.\n")
    print("Cleanup-only bundle retained; no issuance or authority extension is enabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
