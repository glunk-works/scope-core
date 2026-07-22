"""Import-boundary assertion, re-aimed from loop-orchestrator's
`tests/tools/scope_validator/test_boundary.py` (SC Task 1).

That file pinned "no runtime import edge onto `tools/inventory_db`" -- a
property specific to sharing a repo with `inventory_db`. In `scope-core`
that edge is impossible by construction (`inventory_db` does not exist
here), so the guard as written could never go RED -- exactly the failure
mode loop-orchestrator's own BL-15 warns about (a guard that cannot fail is
not a guard).

The property that still matters and can still break, now that this package
is a standalone dependency pulled into two other repos' environments:
**`scope_core` imports nothing outside the standard library and pydantic.**
A new runtime dependency here is a supply-chain surface added to every
consumer silently. Detector is verified to go RED via planted imports below
before being trusted.
"""

import ast
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "scope_core"
ALLOWED_TOP_LEVEL_MODULES = frozenset(sys.stdlib_module_names) | {"pydantic", "scope_core"}


def _top_level(module: str) -> str:
    return module.split(".", 1)[0]


def _dynamic_import_targets(tree: ast.Module) -> list[str]:
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_import_module = (
            isinstance(func, ast.Attribute)
            and func.attr == "import_module"
            and isinstance(func.value, ast.Name)
            and func.value.id == "importlib"
        )
        is_dunder_import = isinstance(func, ast.Name) and func.id == "__import__"
        if not (is_import_module or is_dunder_import):
            continue
        if (
            node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            found.append(node.args[0].value)
    return found


def _imported_modules(tree: ast.Module) -> list[str]:
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # A relative import (level > 0) can only resolve inside this
            # package's own tree, so it is never a third-party edge.
            if node.level == 0 and node.module:
                found.append(node.module)
    found.extend(_dynamic_import_targets(tree))
    return found


def _disallowed_imports(tree: ast.Module) -> list[str]:
    return [m for m in _imported_modules(tree) if _top_level(m) not in ALLOWED_TOP_LEVEL_MODULES]


def test_scope_core_imports_nothing_outside_stdlib_and_pydantic() -> None:
    for path in SRC_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        found = _disallowed_imports(tree)
        assert not found, f"{path} imports outside stdlib+pydantic: {found}"


def test_detector_flags_a_planted_disallowed_import() -> None:
    planted = ast.parse("import requests\n")
    assert _disallowed_imports(planted) == ["requests"]


def test_detector_flags_a_planted_disallowed_import_from() -> None:
    planted = ast.parse("from boto3 import client\n")
    assert _disallowed_imports(planted) == ["boto3"]


def test_detector_flags_a_dynamic_import_of_a_disallowed_module() -> None:
    via_importlib = ast.parse('import importlib\nimportlib.import_module("requests")\n')
    assert _disallowed_imports(via_importlib) == ["requests"]
    via_dunder = ast.parse('__import__("requests")\n')
    assert _disallowed_imports(via_dunder) == ["requests"]


def test_detector_allows_stdlib_and_pydantic_imports() -> None:
    allowed = ast.parse(
        "import re\nimport unicodedata\n"
        "from typing import Protocol\nfrom pydantic import BaseModel\n"
    )
    assert _disallowed_imports(allowed) == []


def test_detector_allows_internal_scope_core_imports() -> None:
    absolute = ast.parse("from scope_core.rules import ScopeRules\n")
    assert _disallowed_imports(absolute) == []
    relative = ast.parse("from .rules import ScopeRules\n")
    assert _disallowed_imports(relative) == []
