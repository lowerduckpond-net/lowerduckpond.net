from __future__ import annotations

import ast
from pathlib import Path

SOURCE_ROOT = Path(__file__).parents[1] / "src/lowerduckpond_static_domain"
FORBIDDEN_IMPORTS = frozenset(
    {
        "asyncio",
        "io",
        "os",
        "pathlib",
        "random",
        "secrets",
        "shutil",
        "socket",
        "sqlite3",
        "subprocess",
        "tempfile",
        "time",
    }
)
FORBIDDEN_CALLS = frozenset(
    {
        "open",
        "read_bytes",
        "read_text",
        "unlink",
        "write_bytes",
        "write_text",
    }
)


def test_root_domain_package_has_no_ambient_io_or_persistence_dependency() -> None:
    violations: list[str] = []
    for path in sorted(SOURCE_ROOT.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                violations.extend(
                    f"{path.name}:{node.lineno}:import:{alias.name}"
                    for alias in node.names
                    if alias.name.split(".", maxsplit=1)[0] in FORBIDDEN_IMPORTS
                )
            if (
                isinstance(node, ast.ImportFrom)
                and node.module is not None
                and node.module.split(".", maxsplit=1)[0] in FORBIDDEN_IMPORTS
            ):
                violations.append(f"{path.name}:{node.lineno}:import:{node.module}")
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else None
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                if name in FORBIDDEN_CALLS:
                    violations.append(f"{path.name}:{node.lineno}:call:{name}")

    assert violations == []
