"""Explicit isolation for component tests of standalone Molecule helpers."""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType

import pytest


@pytest.fixture
def installed_module(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Callable[[str], ModuleType]]:
    # Molecule's independently collected modules use flat imports. Some share
    # names with component tests already collected by the repository-wide run.
    # Isolate the complete helper graph, including transitive cached imports,
    # and restore the original modules after each requesting test.
    root = Path(__file__).resolve().parents[2] / "config/ansible/molecule/m3_8/tests"
    names = {path.stem for path in root.glob("*.py")} - {"conftest"}
    original = {name: sys.modules[name] for name in names if name in sys.modules}
    for name in names:
        sys.modules.pop(name, None)
    monkeypatch.syspath_prepend(str(root))
    try:
        yield importlib.import_module
    finally:
        for name in names:
            sys.modules.pop(name, None)
        sys.modules.update(original)
