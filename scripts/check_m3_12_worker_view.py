"""Exercise the installed publication worker in one owned offline systemd guest."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid7

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from scripts.m3_12_contracts import require
from scripts.qualification_disposable_cleanup import LABEL, daemon_id

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "config/ansible/roles/static_host_agent"
INSTALL = "/opt/lowerduckpond/static-host-agent"
LIBEXEC = "/usr/local/libexec/lowerduckpond"
STATE = "/var/lib/lowerduckpond/static"
RELEASES = "/srv/lowerduckpond/sites"
PROBE = f"{LIBEXEC}/m3-12-worker-view-probe"
JOB = "00000000-0000-7000-8000-000000000003"
GATE = f"{LIBEXEC}/static-publication-gate"
VIEW = "/var/lib/lowerduckpond/convergence/m3-12/droplet-publication"
STAGING = "/worker-view-staging"
WITNESS = f"{STATE}/worker-view-witness"
STOP_PROBE = f"{LIBEXEC}/m3-12-worker-view-stop"
WORKER_DROPIN = f"""[Service]
StandardError=file:{WITNESS}/stderr
ExecStopPost=!{STOP_PROBE}
"""
PROBE_SOURCE = f"""#!/usr/bin/python3 -I
import os
import sys
from pathlib import Path
assert os.geteuid() == 0
assert not os.path.lexists("/.dockerenv")
assert not os.path.lexists("/var/lib/lowerduckpond/convergence/m3-12/controller-only-witness")
assert not os.path.lexists("/etc/ssh/ssh_host_ed25519_key")
assert os.statvfs("{VIEW}").f_flag & os.ST_RDONLY
for path in (
    "/etc/machine-id",
    "/sys/devices/virtual/dmi/id/product_uuid",
    "/etc/ssh/ssh_host_ed25519_key.pub",
):
    if os.path.lexists(path):
        assert os.statvfs(path).f_flag & os.ST_RDONLY
root = Path("{WITNESS}")
with (root / "entered").open("x") as entered:
    entered.write((root / "request").read_text())
os.execv("{GATE}", ["{GATE}", "worker", sys.argv[1]])
"""
STOP_SOURCE = f"""#!/usr/bin/python3 -I
import json
import os
from pathlib import Path
root = Path("{WITNESS}")
nonce = (root / "request").read_text()
entered = root / "entered"
with (root / "receipt.json").open("x") as result:
    json.dump(
        {{
            "request": nonce,
            "entered": entered.is_file() and entered.read_text() == nonce,
            "invocation": os.environ.get("INVOCATION_ID"),
            "result": os.environ.get("SERVICE_RESULT"),
            "code": os.environ.get("EXIT_CODE"),
            "status": os.environ.get("EXIT_STATUS"),
        }},
        result,
    )
"""
SETUP = f"""set -eu
stage=guest-users
trap 'printf "worker-view setup stage=%s\\n" "$stage" >&2' ERR
digest=$1
groupadd caddy
useradd --system --user-group ldp-provisioner
install -d -m 0700 {INSTALL} {STATE} {RELEASES} /etc/lowerduckpond
install -d -m 0755 {LIBEXEC} /run/caddy /etc/caddy /etc/ssh
stage=artifact-extraction
tar -xf {STAGING}/worker-artifact.tar -C {INSTALL}
mv {INSTALL}/artifact {INSTALL}/"$digest"
ln -s {INSTALL}/"$digest" {INSTALL}/current
stage=unit-install
install -m 0755 {STAGING}/static-publication-gate {GATE}
install -m 0755 {STAGING}/host-restore-gate {LIBEXEC}/host-restore-gate
install -m 0755 {STAGING}/verify-static-host-agent-artifact {LIBEXEC}/
install -m 0755 {STAGING}/m3-12-worker-view-probe {PROBE}
install -m 0755 {STAGING}/m3-12-worker-view-stop {STOP_PROBE}
install -m 0644 {STAGING}/lowerduckpond-static-worker@.service /etc/systemd/system/
install -d -m 0755 /etc/systemd/system/lowerduckpond-static-worker@.service.d
install -m 0644 {STAGING}/worker-view-receipt.conf \
    /etc/systemd/system/lowerduckpond-static-worker@.service.d/worker-view-receipt.conf
sudo_rule="ldp-provisioner ALL=(root:caddy) NOPASSWD: {PROBE} {JOB}"
printf '%s\\n' "$sudo_rule" > /etc/sudoers.d/worker-view
chmod 0440 /etc/sudoers.d/worker-view
cat > /etc/lowerduckpond/static-publication.json <<'JSON'
{{"format":"lowerduckpond-static-publication-gate-v1","static_publication_enabled":true}}
JSON
chmod 0400 /etc/lowerduckpond/static-publication.json
stage=artifact-verify
{LIBEXEC}/verify-static-host-agent-artifact {INSTALL}/"$digest"
stage=unit-reload
systemctl daemon-reload
"""


def docker(
    *arguments: str, data: str | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed CLI and owned local container
        ["/usr/bin/docker", *arguments], input=data, capture_output=True, text=True, check=check
    )


def artifact_and_unit(directory: Path) -> str:
    built = subprocess.run(  # noqa: S603 - locked repository artifact builder
        [str(ROOT / "scripts/build-static-host-agent"), str(directory / "worker-artifact.tar")],
        check=True,
        capture_output=True,
        text=True,
    )
    digest = built.stdout.strip()
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "invalid artifact digest")
    environment = Environment(
        loader=FileSystemLoader(ROLE / "templates"),
        undefined=StrictUndefined,
        autoescape=False,  # noqa: S701 - fixed systemd unit syntax
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    template = environment.get_template("lowerduckpond-static-worker@.service.j2")
    values = {
        "provisioner_user": "ldp-provisioner",
        "provisioner_group": "ldp-provisioner",
        "static_host_agent_install_root": INSTALL,
        "static_host_agent_executor": PROBE,
        "static_host_agent_state_root": STATE,
        "static_host_agent_release_root": RELEASES,
        "static_host_agent_archive_lifecycle_enabled": False,
    }
    environment.filters["bool"] = bool
    ordinary = template.render(
        **values, static_host_agent_droplet_publication={"stat": {"exists": False}}
    )
    enrolled = template.render(
        **values, static_host_agent_droplet_publication={"stat": {"exists": True}}
    )
    expected_mounts = {
        "# Expose only the enrolled publication view and the public host identity inputs.",
        f"BindReadOnlyPaths=-{VIEW}",
        "BindReadOnlyPaths=-/etc/machine-id",
        "BindReadOnlyPaths=-/sys/devices/virtual/dmi/id/product_uuid",
        "BindReadOnlyPaths=-/etc/ssh/ssh_host_ed25519_key.pub",
    }
    require(
        set(enrolled.splitlines()) - set(ordinary.splitlines()) == expected_mounts
        and set(ordinary.splitlines()) <= set(enrolled.splitlines()),
        "worker template changed outside the read-only view",
    )
    (directory / "lowerduckpond-static-worker@.service").write_text(enrolled)
    (directory / "m3-12-worker-view-probe").write_text(PROBE_SOURCE)
    (directory / "m3-12-worker-view-stop").write_text(STOP_SOURCE)
    (directory / "worker-view-receipt.conf").write_text(WORKER_DROPIN)
    return digest


def install(container: str, directory: Path, digest: str) -> None:
    # Docker's archive API cannot rely on the running guest's /tmp tmpfs.
    docker("exec", container, "/usr/bin/install", "-d", "-m", "0700", STAGING)
    files = (
        directory / "worker-artifact.tar",
        directory / "lowerduckpond-static-worker@.service",
        directory / "m3-12-worker-view-probe",
        directory / "m3-12-worker-view-stop",
        directory / "worker-view-receipt.conf",
        ROLE / "files/static-publication-gate",
        ROLE / "files/verify-static-host-agent-artifact",
        ROOT / "config/ansible/roles/host_recovery/files/host-restore-gate",
    )
    for path in files:
        docker("cp", str(path), f"{container}:{STAGING}/{path.name}")
    result = docker(
        "exec", "-i", container, "/bin/bash", "-s", "--", digest, data=SETUP, check=False
    )
    if result.returncode:
        known = re.search(
            r"^worker-view setup stage=(guest-users|artifact-extraction|unit-install|"
            r"artifact-verify|unit-reload)$",
            result.stderr,
            re.MULTILINE,
        )
        stage = "transport" if known is None else known.group(1)
        detail = (
            f"; systemctl daemon-reload stderr={result.stderr.strip()[:1000]!r}"
            if stage == "unit-reload"
            else ""
        )
        raise ValueError(
            f"offline witness setup failed at {stage} (exit {result.returncode}){detail}"
        )


def wait_for_systemd(container: str) -> None:
    while True:
        status = docker(
            "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", container
        ).stdout.strip()
        if status != "running 0":
            messages = docker("logs", container, check=False)
            if "Failed to create /init.scope control group" in messages.stderr + messages.stdout:
                raise ValueError("the offline guest cannot mount its systemd cgroup")
            raise ValueError(f"the offline systemd guest stopped ({status})")
        socket_ready = docker(
            "exec", container, "/usr/bin/test", "-S", "/run/systemd/private", check=False
        )
        if socket_ready.returncode == 0:
            result = docker(
                "exec",
                container,
                "/usr/bin/systemctl",
                "show",
                "--property=SystemState",
                "--value",
                check=False,
            )
            state = result.stdout.strip()
            if result.returncode == 0 and state in {"running", "degraded"}:
                return
            if result.returncode or state not in {"initializing", "starting"}:
                raise ValueError(
                    "/usr/bin/systemctl show --property=SystemState --value "
                    f"exit={result.returncode} manager={state[:80]!r} "
                    f"stderr={result.stderr.strip()[:1000]!r}"
                )
        time.sleep(0.1)


def witness(image: str, directory: Path) -> None:
    env = dict(os.environ)
    endpoint = env.get("DOCKER_HOST", "")
    if (
        not endpoint.startswith("unix:///")
        or not Path(endpoint[7:]).is_socket()
        or env.get("DOCKER_CONTEXT")
    ):
        raise ValueError("worker view requires the verified workspace-local Unix Docker socket")
    daemon = daemon_id(env)
    cached = docker("image", "inspect", image, "--format", "{{.Id}}").stdout.strip()
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", cached) is not None, "invalid cached image")
    digest = artifact_and_unit(directory)
    run = uuid7().hex
    container = docker(
        "create",
        "--pull",
        "never",
        "--network",
        "none",
        "--privileged",
        "--cgroupns",
        "private",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/run/lock",
        "--tmpfs",
        "/tmp",  # noqa: S108 - tmpfs in the isolated container
        "--label",
        f"{LABEL}={run}",
        "--name",
        f"ldp-m3-12-worker-view-{run}",
        cached,
        "/sbin/init",
    ).stdout.strip()
    require(re.fullmatch(r"[0-9a-f]{64}", container) is not None, "invalid container identity")
    try:
        docker("start", container)
        wait_for_systemd(container)
        install(container, directory, digest)
        code = (ROOT / "config/ansible/molecule/m3_8/m3_12_worker_view.py").read_text()
        observed = docker(
            "exec",
            "-i",
            container,
            "/usr/bin/python3",
            "-I",
            "-B",
            "-",
            digest,
            data=code,
            check=False,
        )
        print(observed.stdout, end="", flush=True)
        if observed.returncode:
            print(observed.stderr, file=sys.stderr, end="")
            raise ValueError("installed worker view did not satisfy the witness")
    finally:
        require(daemon_id(env) == daemon, "Docker daemon identity changed")
        actual = docker(
            "inspect",
            "--format",
            '{{.Id}} {{index .Config.Labels "' + LABEL + '"}}',
            container,
        ).stdout.strip()
        require(actual == f"{container} {run}", "worker fixture ownership changed")
        removal = docker("rm", "--force", container, check=False)
        if removal.returncode:
            reason = (
                "daemon did not receive an exit event"
                if "did not receive an exit event" in removal.stderr
                else f"Docker removal exited {removal.returncode}"
            )
            raise ValueError(f"owned worker fixture {container} retained: {reason}")
        print("owned offline worker fixture removed", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="cached Ubuntu 26.04 Molecule systemd image")
    args = parser.parse_args()
    with TemporaryDirectory(prefix="ldp-m3-12-worker-view-") as work:
        witness(args.image, Path(work))


if __name__ == "__main__":
    main()
