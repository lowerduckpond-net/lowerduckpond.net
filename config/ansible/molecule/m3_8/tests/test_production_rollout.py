"""Real playbooks, SSH leases and capture recovery on one dark disposable host."""

import pytest
from production_rollout_fixture import Fixture
from testinfra.host import Host


def test_installed_production_rollout_preserves_original_evidence(
    host: Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert host.run("systemctl is-active caddy.service").rc == 0
    fixture = Fixture(monkeypatch)
    namespace = fixture.run("namespace")
    assert namespace[-1][0] == "namespace"
    capture = fixture.run("backup")
    assert capture[: len(namespace)] == namespace
    assert capture[-1][0] == "backup-verified.started"
    retained = fixture.retained_capture()
    completed = fixture.run()
    assert completed[: len(capture)] == capture
    assert fixture.retained_capture() == retained
    assert fixture.run() == completed
    assert fixture.retained_capture() == retained
