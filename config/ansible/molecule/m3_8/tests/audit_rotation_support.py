"""Owned full-size history and process-termination injection for installed rotation."""

from __future__ import annotations

import json

import audit_protection_support as audits
from testinfra.host import Host

UNIT = "lowerduckpond-audit-rotate.service"
TIMER = "lowerduckpond-audit-rotate.timer"
_RESOURCE_MESSAGE = "ae8f7b866b0347b9af31fe1c80b127c0"


def run_bounded_rotation(host: Host) -> None:
    # The inactive unit may be garbage-collected before a later MemoryPeak
    # property read. Keep the actual invocation's PID-1 resource record instead;
    # the installed command and its service limits remain unchanged.
    latest = host.run("journalctl --no-pager --output=json --lines=1")
    assert latest.rc == 0
    cursor = json.loads(latest.stdout)["__CURSOR"]
    assert type(cursor) is str and cursor
    audits.run_unit(host, UNIT)
    assert host.run("journalctl --sync").rc == 0
    outcome = host.run(
        "journalctl --no-pager --output=json --lines=2 "
        "--output-fields=UNIT,MESSAGE_ID,MEMORY_PEAK,_PID "
        "--after-cursor=%s UNIT=%s MESSAGE_ID=%s _PID=1",
        cursor,
        UNIT,
        _RESOURCE_MESSAGE,
    )
    assert outcome.rc == 0
    records = [json.loads(line) for line in outcome.stdout.splitlines()]
    assert len(records) == 1, "rotation invocation lacks unique resource accounting"
    record = records[0]
    assert record["UNIT"] == UNIT and record["MESSAGE_ID"] == _RESOURCE_MESSAGE
    assert record["_PID"] == "1"
    peak = record["MEMORY_PEAK"]
    assert type(peak) is str and peak.isdigit() and 0 < int(peak) <= 256 * 1024 * 1024


def close_full_segment(host: Host) -> dict[str, object]:
    # Retain all real operator history and fill only the active segment using
    # valid root-authored failed-create entries. Production limits are unchanged.
    output = audits.root_agent(
        host,
        f"""
from lowerduckpond_static_contracts import canonical_json_bytes, audit_entry_digest
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent.audit_archive_local import archive_transaction, observe_archive
from lowerduckpond_static_host_agent.audit import DEFAULT_AUDIT_LIMITS
from lowerduckpond_static_host_agent.backup_identity import decode_lineage
root_path = Path({audits.ROOT!r})
with archive_transaction(root_path, 0) as root:
    lineage = decode_lineage((root_path / 'platform/audit-lineage.json').read_bytes())
    current = observe_archive(root, lineage, 0)
    number = len(current.prefix.segments)
    assert current.audit.segment_count == number + 1 and current.audit.entry_count > 0
    assert current.prefix.rotation_intent is None
    name = formats.segment_name(number)
    original = (root_path / 'audit' / name).read_bytes()
    segment = bytearray(original)
    template = json.loads(original.splitlines()[-1])
    template.update(operation='create', tenantId=None, resultStatus='failed',
        operatorPrincipal='fixture.rotation.padding.' + 'x' * 100,
        resultDigest={{'format':'lowerduckpond-result-v1','algorithm':'sha256','value':'0' * 64}})
    template.pop('deletionEvidence', None)
    sequence, previous = current.audit.entry_count, current.audit.terminal_digest
    while True:
        entry = {{**template, 'sequence': sequence, 'previousEntryDigest': previous,
                  'correlationId': f'0198d17f-6f4a-7000-8002-{{sequence:012x}}'}}
        raw = canonical_json_bytes(entry)
        if len(segment) + len(raw) > DEFAULT_AUDIT_LIMITS.maximum_segment_bytes:
            break
        segment.extend(raw)
        previous = audit_entry_digest(entry).to_dict()
        sequence += 1
    assert bytes(segment).startswith(original)
    root.replace(('audit', name), bytes(segment))
    root.create_immutable(('audit', formats.segment_name(number + 1)), raw)
    checked = observe_archive(root, lineage, 0)
    assert checked.audit.segment_count == number + 2 and checked.audit.entry_count == sequence + 1
    print(json.dumps({{'number':number, 'bytes':len(segment), 'entries':sequence,
        'sha256':__import__('hashlib').sha256(segment).hexdigest()}}))
""",
    )
    result = json.loads(output)
    assert type(result) is dict and type(result["bytes"]) is int
    assert 8 * 1024 * 1024 - 16384 < result["bytes"] <= 8 * 1024 * 1024
    return result


def interrupt_rotation(host: Host, *, point: str, number: int) -> None:
    assert point in {"prepared", "lost-response", "witness", "index", "head", "unlink"}
    # Only this owned test process supplies hooks. Production commands expose
    # no alternate limits, fixture paths, faults, or destructive selectors.
    audits.root_agent(
        host,
        f"""
from lowerduckpond_static_host_agent import audit_rotation_coordinator as rotation
from lowerduckpond_static_host_agent.durable import DurabilityBoundary
pid = os.fork()
if pid == 0:
    create = rotation.create_rotation_snapshot
    def lose_response(record, environment):
        create(record, environment)
        os._exit(73)
    if {point!r} == 'lost-response':
        rotation.create_rotation_snapshot = lose_response
    def terminate(name, boundary):
        targets = {{
            'witness': ('witness-{number:020d}.json', DurabilityBoundary.RENAME),
            'index': ('index-{number:020d}.json', DurabilityBoundary.RENAME),
            'head': ('head.json', DurabilityBoundary.RENAME),
            'unlink': ('segment-{number:020d}.jsonl', DurabilityBoundary.REMOVE),
        }}
        if ({point!r} == 'prepared' and name == 'rotation-intent.json'
                and boundary == DurabilityBoundary.DIRECTORY_SYNC):
            intent = json.loads(Path({audits.PREFIX + "/rotation-intent.json"!r}).read_bytes())
            if intent['phase'] == 'prepared':
                os._exit(73)
        if targets.get({point!r}) == (name, boundary):
            os._exit(73)
    try:
        with inherit_restic_leases((9, selection)):
            rotation.rotate_archive(rotation.RotationPaths(), os.environ,
                expected_owner=0, expected_group=0, failure_hook=terminate)
    except BaseException:
        os._exit(74)
    os._exit(75)
_, status = os.waitpid(pid, 0)
assert os.waitstatus_to_exitcode(status) == 73
print('interrupted-' + {point!r})
""",
    )


def archived_digests(host: Host) -> list[str]:
    result = audits.root_agent(
        host,
        f"""
from lowerduckpond_static_host_agent.audit_archive_local import archive_transaction
from lowerduckpond_static_host_agent.audit_archive_store import read_archive_prefix
with archive_transaction(Path({audits.ROOT!r}), 0) as root:
    prefix = read_archive_prefix(root, expected_owner=0)
    print(json.dumps([item.descriptor['segmentSha256'] for item in prefix.segments]))
""",
    )
    digests = json.loads(result)
    assert type(digests) is list and all(type(value) is str for value in digests)
    return digests
