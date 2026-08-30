"""Command-line entry point for the trusted static operator."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from lowerduckpond_static_contracts import ContractError, ProtocolError

from lowerduckpond_static_operator.client import OperatorClientError, print_result, submit


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Submit one static-publication operation")
    parser.add_argument("--host", required=True)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--export", dest="export_path", type=Path)
    options = parser.parse_args(arguments)
    try:
        result = submit(
            host=options.host,
            identity_path=options.identity,
            request_path=options.request,
            artifact_path=options.artifact,
            export_path=options.export_path,
        )
    except (OSError, ContractError, ProtocolError, OperatorClientError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print_result(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
