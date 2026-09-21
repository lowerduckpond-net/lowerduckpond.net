"""Owned installed audit fixtures at the unchanged production segment bound."""

from __future__ import annotations

import json
import shlex

import test_backup_identity as identity
import test_lifecycle as support
from testinfra.host import Host

ROOT = support.STATE_ROOT
SOURCE = "/var/cache/lowerduckpond-backup/audit/snapshot"
VERIFY_UNIT = "lowerduckpond-audit-verify.service"
MAINTENANCE_UNIT = "lowerduckpond-backup-maintenance.service"
PREFIX = f"{ROOT}/audit/archive"


def root_agent(host: Host, body: str) -> str:
    """The diagnostic alters only fixture data or the named failure callback."""
    code = (
        """
import fcntl, json, os, subprocess, sys
from pathlib import Path
selection = os.open('/opt/lowerduckpond/static-host-agent/selection.lock', os.O_RDONLY)
fcntl.flock(selection, fcntl.LOCK_SH)
selected = Path('/opt/lowerduckpond/static-host-agent/current').resolve(strict=True)
subprocess.run(['/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact',
                str(selected)], check=True, capture_output=True)
sys.path.insert(0, str(selected / 'site-packages'))
from lowerduckpond_static_host_agent.backup_restic import inherit_restic_leases
"""
        + body
    )
    result = host.run(
        "/bin/bash -c %s",
        "set -euo pipefail; umask 077; "
        "exec 9</var/cache/lowerduckpond-backup/repository.lock; flock --exclusive 9; "
        "set -a; source /etc/lowerduckpond/backup.env; set +a; "
        f"/usr/bin/python3 -I -B -c {shlex.quote(code)}",
    )
    assert result.rc == 0, result.stderr
    return result.stdout


def stage_closed_segment(host: Host) -> dict[str, object]:
    # Root-authored failed-create entries fill exactly one real 8-MiB segment.
    # No production limit, artifact, worker or public command is modified. The
    # existing successful tenant prefix remains byte-identical and lineage-bound.
    output = root_agent(
        host,
        f"""
from lowerduckpond_static_contracts import canonical_json_bytes, audit_entry_digest
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent.audit_archive_local import archive_transaction, observe_archive
from lowerduckpond_static_host_agent.audit import DEFAULT_AUDIT_LIMITS, inspect_audit_readonly
from lowerduckpond_static_host_agent.backup_identity import decode_lineage, framed_digest
from lowerduckpond_static_host_agent.durable import DurableDirectory
root_path = Path({ROOT!r})
with archive_transaction(root_path, 0) as root:
    lineage = decode_lineage((root_path / 'platform/audit-lineage.json').read_bytes())
    current = observe_archive(root, lineage, 0)
    assert current.audit.segment_count == 1 and current.audit.entry_count > 0
    path = root_path / 'audit/segment-00000000000000000000.jsonl'
    original = path.read_bytes()
    segment = bytearray(original)
    template = json.loads(original.splitlines()[-1])
    template.update(operation='create', tenantId=None, resultStatus='failed',
        operatorPrincipal='fixture.audit.padding.' + 'x' * 100,
        resultDigest={{'format':'lowerduckpond-result-v1','algorithm':'sha256','value':'0' * 64}})
    template.pop('deletionEvidence', None)
    sequence, previous = current.audit.entry_count, current.audit.terminal_digest
    while True:
        entry = {{**template, 'sequence': sequence, 'previousEntryDigest': previous,
                  'correlationId': f'0198d17f-6f4a-7000-8001-{{sequence:012x}}'}}
        raw = canonical_json_bytes(entry)
        if len(segment) + len(raw) > DEFAULT_AUDIT_LIMITS.maximum_segment_bytes:
            break
        segment.extend(raw)
        previous = audit_entry_digest(entry).to_dict()
        sequence += 1
    assert bytes(segment).startswith(original)
    root.replace(('audit', path.name), bytes(segment))
    root.create_immutable(('audit', 'segment-00000000000000000001.jsonl'), raw)
    checked = inspect_audit_readonly(root, expected_owner=0,
        expected_directory_mode=0o700, expected_record_mode=0o600)
    assert checked.segment_count == 2 and checked.entry_count == sequence + 1
    evidence = formats.inspect_segment(bytes(segment))
    record = {{
        'schema':formats.ROTATION_SCHEMA, 'rotationId':'0198d17f-6f4a-7000-8000-000000000077',
        'lineageId':lineage['lineageId'], 'repositoryBinding':lineage['repositoryBinding'],
        'createdAt':'2026-09-21T12:00:00Z', 'segmentNumber':0, 'segmentName':path.name,
        'firstSequence':0, 'lastSequence':sequence-1, 'entryCount':sequence,
        'segmentBytes':len(segment),
        'segmentSha256':__import__('hashlib').sha256(segment).hexdigest(),
        'predecessorEntryDigest':None, 'terminalEntryDigest':previous,
        'previousDescriptorDigest':None, 'witnessFormat':formats.WITNESS_FORMAT,
        'witnessBytes':len(evidence.witness),
        'witnessDigest':framed_digest(formats.WITNESS_FORMAT,evidence.witness),
    }}
    encoded = canonical_json_bytes(record)
    formats.decode_rotation(encoded)
    with DurableDirectory.open(Path({SOURCE!r}), expected_owner=0,
                               expected_directory_mode=0o700) as stage:
        stage.create_immutable(('descriptor.json',), encoded)
        stage.create_immutable(('segment.jsonl',), bytes(segment))
    print(json.dumps({{'bytes':len(segment), 'entries':sequence,
                      'tags':list(formats.required_archive_tags(record)),
                      'node':lineage['repository']['nodeName']}}))
""",
    )
    result = json.loads(output)
    assert type(result) is dict
    return result


def snapshot(host: Host, metadata: dict[str, object], timestamp: str) -> str:
    tags = metadata["tags"]
    assert type(tags) is list
    flags = " ".join("--tag " + shlex.quote(tag) for tag in tags)
    output = identity._restic(
        host,
        f"backup --json --quiet --host {shlex.quote(str(metadata['node']))} "
        f"--time {shlex.quote(timestamp)} {flags} {SOURCE}",
    )
    return str(json.loads(output.splitlines()[-1])["snapshot_id"])


def snapshots(host: Host) -> dict[str, dict[str, object]]:
    return {entry["id"]: entry for entry in json.loads(identity._restic(host, "snapshots --json"))}


def run_unit(host: Host, unit: str, *, succeeds: bool = True) -> None:
    result = host.run("systemctl start %s", unit)
    assert (result.rc == 0) is succeeds, host.run("journalctl -u %s --no-pager -n 15", unit).stdout


def ordinary_snapshot(host: Host, node: str, timestamp: str) -> str:
    output = identity._restic(
        host,
        f"backup --json --quiet --host {shlex.quote(node)} --tag scheduled "
        f"--time {shlex.quote(timestamp)} "
        "/var/cache/lowerduckpond-backup/audit/ordinary-fixture",
    )
    return str(json.loads(output.splitlines()[-1])["snapshot_id"])


def interrupt_after_forget(host: Host) -> None:
    # Exercise real Restic and actual durable writes, with a test-process exit
    # immediately after the forgotten phase is renamed. It is not a CLI option.
    root_agent(
        host,
        f"""
from lowerduckpond_static_host_agent.audit_archive_coordinator import (
    ProtectionPaths, maintain_archive,
)
from lowerduckpond_static_host_agent.durable import DurabilityBoundary
pid = os.fork()
if pid == 0:
    def terminate(name, boundary):
        if name == 'maintenance-intent.json' and boundary == DurabilityBoundary.RENAME:
            intent = json.loads(Path({PREFIX + "/maintenance-intent.json"!r}).read_bytes())
            if intent['phase'] == 'forgotten':
                os._exit(73)
    try:
        with inherit_restic_leases((9, selection)):
            maintain_archive(ProtectionPaths(), os.environ, expected_owner=0,
                expected_group=0, failure_hook=terminate)
    except BaseException:
        os._exit(74)
    os._exit(75)
_, status = os.waitpid(pid, 0)
assert os.waitstatus_to_exitcode(status) == 73
print('interrupted-after-forget')
""",
    )


def health(host: Host, *, succeeds: bool) -> str:
    result = host.run(
        "/bin/bash -c %s",
        "set -euo pipefail; source /etc/lowerduckpond/backup.env; "
        "/usr/bin/env --ignore-environment PATH=/usr/bin:/bin "
        'RESTIC_REPOSITORY="${RESTIC_REPOSITORY}" '
        'LOWERDUCKPOND_BACKUP_NODE_NAME="${LOWERDUCKPOND_BACKUP_NODE_NAME}" '
        "/usr/local/libexec/lowerduckpond/check-audit-protection",
    )
    assert (result.rc == 0) is succeeds
    return result.stdout
