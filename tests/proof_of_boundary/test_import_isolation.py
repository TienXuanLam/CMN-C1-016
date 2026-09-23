"""PB-4 — Import isolation: no Level 0 (agenticstar) imports in src/."""

import ast
import pathlib


def test_pb4_no_level0_imports():
    violations = []
    for py_file in pathlib.Path("src").rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("agenticstar"):
                        violations.append(f"{py_file}:{node.lineno}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").startswith("agenticstar"):
                    violations.append(f"{py_file}:{node.lineno}: from {node.module} import ...")

    assert violations == [], "Level 0 (agenticstar SDK) imports detected — import isolation violation:\n" + "\n".join(
        violations
    )
