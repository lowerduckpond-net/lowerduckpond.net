"""Build a reviewed in-memory overlay for an unchanged retained controller.

This avoids installing packages or changing the controller's immutable checkout.
Only changed scripts are overlaid; native packages must match the retained
runtime revision exactly. The resulting program and its payload need review and
separate destructive-action approval before any caller may submit it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import zlib
from pathlib import Path

from scripts.production_qualification_inputs import git, revision

MAX_PROGRAM = 100_000
MAX_BUNDLE = 512 * 1024
STARTUP_SECONDS = 180

BOOTSTRAP = """import signal, time
def startup_expired(*args): raise TimeoutError('retirement startup budget ended')
signal.signal(signal.SIGALRM, startup_expired)
signal.setitimer(signal.ITIMER_REAL, 180)
startup_deadline = time.monotonic() + 180
import sys, json, os, select, hashlib, base64, zlib, importlib.abc, importlib.util
sys.dont_write_bytecode = True
raw = bytearray()
while len(raw) <= 1048576:
 remaining = startup_deadline - time.monotonic()
 if remaining <= 0 or not select.select([sys.stdin.buffer], [], [], remaining)[0]:
  raise TimeoutError('retirement initial frame deadline ended')
 part = os.read(sys.stdin.fileno(), 1)
 if not part: raise ValueError('retirement initial frame incomplete')
 raw += part
 if part == b'\\n': break
else: raise ValueError('retirement initial frame exceeds byte bound')
initial = json.loads(raw)
if not isinstance(initial, dict) or set(initial) != {'bundle', 'authorization'}:
 raise ValueError('retirement initial frame differs')
data = initial['bundle']
if not isinstance(data, str) or len(data) > 524288:
 raise ValueError('retirement bundle exceeds byte bound')
if hashlib.sha256(data.encode()).hexdigest() != EXPECTED_DATA_SHA256:
 raise ValueError('retirement bundle checksum differs')
bundle = json.loads(zlib.decompress(base64.b85decode(data)))
sys.path.insert(0, '/work/source')
class Overlay(importlib.abc.MetaPathFinder, importlib.abc.Loader):
 def find_spec(self, fullname, path=None, target=None):
  if fullname in bundle['modules']:
   return importlib.util.spec_from_loader(fullname, self)
 def create_module(self, spec): return None
 def exec_module(self, module):
  name = module.__name__
  module.__file__ = '/reviewed-memory-overlay/' + name.replace('.', '/') + '.py'
  exec(compile(bundle['modules'][name], module.__file__, 'exec'), module.__dict__)
sys.meta_path.insert(0, Overlay())
from scripts.m3_11_frozen_entry import run
signal.setitimer(signal.ITIMER_REAL, 0)
signal.signal(signal.SIGALRM, signal.SIG_DFL)
raise SystemExit(run({**bundle['payload'], 'authorization': initial['authorization']}))
"""


def build(repository: Path, payload: dict[str, object]) -> dict[str, object]:
    if set(payload) != {"plan", "fixture", "runtime_revision", "operation"}:
        raise ValueError("retirement overlay inputs must exclude future approval")
    if git(repository, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("retirement implementation checkout is not clean")
    head = revision(git(repository, "rev-parse", "HEAD").decode().strip())
    runtime = revision(str(payload["runtime_revision"]))
    plan = payload["plan"]
    if not isinstance(plan, dict) or plan.get("implementation_revision") != head:
        raise ValueError("retirement plan differs from its exact implementation revision")
    if git(
        repository,
        "diff",
        "--name-only",
        runtime,
        head,
        "--",
        "packages",
        "tools",
        "services",
        "uv.lock",
    ):
        raise ValueError("retained native dependencies differ; a new runtime needs separate review")
    names = (
        git(repository, "diff", "--name-only", runtime, head, "--", "scripts").decode().splitlines()
    )
    modules, hashes = {}, {}
    for name in names:
        if not name.startswith("scripts/") or not name.endswith(".py"):
            continue
        path = repository / name
        if not path.is_file() or path.resolve() != path or path.name == "__init__.py":
            raise ValueError("retirement overlay contains an unsupported module transition")
        raw = path.read_bytes()
        modules[name.removesuffix(".py").replace("/", ".")] = raw.decode()
        hashes[name] = hashlib.sha256(raw).hexdigest()
    if "scripts.m3_11_frozen_entry" not in modules:
        raise ValueError("retirement overlay lacks its reviewed entrypoint")
    compressed = base64.b85encode(
        zlib.compress(
            json.dumps({"modules": modules, "payload": payload}, sort_keys=True).encode(), level=9
        )
    ).decode()
    if len(compressed.encode()) > MAX_BUNDLE:
        raise ValueError("retirement bundle exceeds the reviewed frame allowance")
    bundle_sha256 = hashlib.sha256(compressed.encode()).hexdigest()
    program = "EXPECTED_DATA_SHA256 = " + repr(bundle_sha256) + "\n" + BOOTSTRAP
    if len(program.encode()) > MAX_PROGRAM:
        raise ValueError("retirement program exceeds the existing exec argument bound")
    return {
        "program": program,
        "bundle": compressed,
        "bundle_sha256": bundle_sha256,
        "program_sha256": hashlib.sha256(program.encode()).hexdigest(),
        "implementation_revision": head,
        "runtime_revision": runtime,
        "modules": hashes,
    }
