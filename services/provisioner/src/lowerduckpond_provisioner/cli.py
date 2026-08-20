"""Unprivileged Milestone 0 command boundary for the provisioner."""

import argparse
from collections.abc import Sequence

from lowerduckpond_provisioner import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build the command parser without performing host operations."""
    parser = argparse.ArgumentParser(
        prog="lowerduckpond-provisioner",
        description="Reconcile Lower Duck Pond tenant manifests.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    """Parse foundation arguments and exit without privileged side effects."""
    build_parser().parse_args(arguments)
    return 0
