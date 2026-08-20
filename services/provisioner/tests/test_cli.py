"""Provisioner foundation tests."""

import pytest
from lowerduckpond_provisioner import __version__
from lowerduckpond_provisioner.cli import main


def test_version_is_available_without_host_access(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out == f"lowerduckpond-provisioner {__version__}\n"


def test_empty_invocation_has_no_side_effects() -> None:
    assert main([]) == 0
