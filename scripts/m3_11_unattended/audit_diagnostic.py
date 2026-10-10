"""The historical permission-grant workflow is retired; restoration remains in cleanup."""

from scripts.m3_11_unattended.model import LifecycleError


def main() -> int:
    raise LifecycleError(
        "obsolete audit grants are permanently disabled; use cleanup reconciliation"
    )


if __name__ == "__main__":
    raise SystemExit(main())
