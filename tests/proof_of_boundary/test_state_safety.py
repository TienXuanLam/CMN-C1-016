"""State Safety — CMN-C1-016

CodeGenerationState must use only primitives (msgpack-safe).
_PROHIBITED includes 'dict' — bare dict annotation violates msgpack-safe rule.
"""

import ast
import importlib
import os
import re
import pytest

_CREDENTIAL_RE = re.compile(r"(?:^|_)(api_key|secret|password|credential|jwt|bearer|token)(?:_|$)", re.IGNORECASE)
_PROHIBITED = ["BaseModel", "InvocationContext", "dict"]


def _state_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src", "schemas", "state.py"))


def _parse():
    with open(_state_path()) as f:
        return ast.parse(f.read())


def _get_class(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "CodeGenerationState":
            return node
    pytest.fail("CodeGenerationState not found in src/schemas/state.py")


def _fields(cls):
    return [
        (item.target.id, item)
        for item in cls.body
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
    ]


class TestNoCredentialFields:
    def test_no_credential_names(self):
        cls = _get_class(_parse())
        violations = [f"  {n}" for n, _ in _fields(cls) if _CREDENTIAL_RE.search(n)]
        assert not violations, "Credential-like field names:\n" + "\n".join(violations)


class TestMsgpackSafe:
    def test_no_prohibited_types(self):
        cls = _get_class(_parse())
        violations = []
        for name, item in _fields(cls):
            if item.annotation:
                names = {n.id for n in ast.walk(item.annotation) if isinstance(n, ast.Name)}
                for p in _PROHIBITED:
                    if p in names:
                        violations.append(f"  {name} uses {p}")
        assert not violations, "Prohibited types:\n" + "\n".join(violations)


class TestRequiredFields:
    _REQUIRED = {
        "validated_spec",
        "parsed_spec",
        "raw_code",
        "generated_code",
        "formatted_output",
    }

    def test_all_required_fields(self):
        cls = _get_class(_parse())
        declared = {n for n, _ in _fields(cls)}
        missing = self._REQUIRED - declared
        assert not missing, f"Missing fields: {sorted(missing)}"


class TestRuntimeSafety:
    def test_state_is_not_pydantic(self):
        mod = importlib.import_module("src.schemas.state")
        cls = getattr(mod, "CodeGenerationState")
        assert hasattr(cls, "__annotations__")
        try:
            from pydantic import BaseModel

            assert not issubclass(cls, BaseModel)
        except ImportError:
            pass

    def test_state_inherits_from_agent_state(self):
        mod = importlib.import_module("src.schemas.state")
        cls = getattr(mod, "CodeGenerationState")
        from framework.schemas.agent_state import AgentState

        missing = set(AgentState.__annotations__) - set(cls.__annotations__)
        assert not missing, f"Missing AgentState fields: {sorted(missing)}"

    def test_formatted_output_is_optional_str(self):
        mod = importlib.import_module("src.schemas.state")
        cls = getattr(mod, "CodeGenerationState")
        hints = cls.__annotations__
        assert "formatted_output" in hints, "formatted_output must be declared in state"
        hint = hints["formatted_output"]
        args = getattr(hint, "__args__", (hint,))
        for arg in args:
            if arg is type(None):
                continue
            assert arg is str, f"formatted_output must be Optional[str], not Optional[{arg}]"
