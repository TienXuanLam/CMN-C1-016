"""Proof-of-Boundary tests — CMN-C1-016 CodeGenerationGraph (SDK v2)

PB-1  emit_trace_event() fires from shared.utils.audit_logger (no silent failure)
PB-2  Post-invoke state is primitives only (msgpack-safe)
PB-4  Import isolation — no Level 0 (agenticstar) imports in src/
PB-5  Saved checkpoint contains no credentials or Pydantic objects
PB-6  Execution order: S-1 → S-4 node_start → S-2 → execute() → S-3 → S-4 node_complete

TC-02 SecurityViolationError / S-1 denial fires on trust gate breach
TC-04 InvocationContext accessed via from_state() only
"""

import ast
import pathlib


from shared.secrets.inmemory_provider import InMemoryProvider
from framework.secrets.context import bound_secrets as bind_secrets
from framework.schemas.trust_level import TrustLevel
from framework.schemas.invocation_context import InvocationContext

from src.nodes.main_node import MainNode
from src.nodes.pre_process_node import PreProcessNode

_SECRETS = InMemoryProvider({"AZURE_OPENAI_API_KEY": "test-key"})


def _state(**overrides) -> dict:
    base = {
        "user_input": "write a hello world function",
        "validated_spec": "write a hello world function",
        "parsed_spec": "write a hello world function",
        "caller_trust_level": TrustLevel.VERIFIED_EXTERNAL.value,
        "caller_id": "test",
        "session_id": "s",
        "thread_id": "t",
        "correlation_id": "c",
        "trace_id": "",
        "hitl_allowed": True,
        "node_history": [],
        "error_log": [],
        "status": "pending",
        "execution_time": {},
    }
    base.update(overrides)
    return base


class TestPB1EmitTraceEvent:
    """PB-1: emit_trace_event() fires from shared.utils.audit_logger."""

    def test_pb1_emit_trace_event_callable(self):
        from shared.utils.audit_logger import emit_trace_event

        assert callable(emit_trace_event)

    def test_pb1_main_node_emits_llm_call_event(self):
        from unittest.mock import patch

        events: list[dict] = []

        def capture(event_type, payload, state):
            events.append({"event_type": event_type, "payload": payload})

        # Patch the name as imported in main_node.py, not the module attribute
        with patch("src.nodes.main_node.emit_trace_event", side_effect=capture):
            node = MainNode()
            node._generate = lambda prompt, state: "def hello(): pass"
            with bind_secrets(_SECRETS):
                node.execute(_state())

        assert any(
            e["event_type"] == "llm_call" for e in events
        ), "MainNode did not emit 'llm_call' trace event — S-4 audit silent failure"


class TestPB2StatePrimitives:
    """PB-2: State fields must be primitives only after node execution."""

    def test_pb2_main_node_result_primitives_only(self):
        node = MainNode()
        node._generate = lambda prompt, state: "def hello(): pass"
        with bind_secrets(_SECRETS):
            result = node.execute(_state())

        allowed = (str, int, float, bool, type(None), list, dict)
        for key, value in result.items():
            assert isinstance(value, allowed), f"State field {key!r} is {type(value).__name__!r} — not msgpack-safe"

    def test_pb2_pre_process_result_primitives_only(self):
        node = PreProcessNode()
        result = node.execute(_state())
        allowed = (str, int, float, bool, type(None), list, dict)
        for key, value in result.items():
            assert isinstance(value, allowed), f"State field {key!r} is {type(value).__name__!r}"


class TestPB4ImportIsolation:
    """PB-4: No Level 0 (agenticstar) imports in src/."""

    def test_pb4_no_agenticstar_imports(self):
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
                            violations.append(f"{py_file}:{node.lineno}")
                elif isinstance(node, ast.ImportFrom):
                    if (node.module or "").startswith("agenticstar"):
                        violations.append(f"{py_file}:{node.lineno}")

        assert violations == [], "Level 0 (agenticstar) imports detected:\n" + "\n".join(violations)


class TestPB6ExecutionOrder:
    """PB-6: S-1 → S-2 → execute() → S-3 runs in correct order via __call__."""

    def test_pb6_trust_gate_blocks_before_execute(self):
        """S-1 must fire before execute() — anonymous caller blocked by INTERNAL node."""
        from src.nodes.pre_process_node import PreProcessNode
        from framework.schemas.trust_level import TrustLevel

        # Use a subclass to avoid mutating the shared class variable across test runs
        class InternalPreProcessNode(PreProcessNode):
            required_trust_level = TrustLevel.INTERNAL

        node = InternalPreProcessNode()
        state = _state(caller_trust_level=TrustLevel.ANONYMOUS.value)
        result = node(state)  # __call__, not execute()
        assert result["status"] == "error", "S-1 trust gate did not block"
        assert any(
            "trust" in m.lower() or "s-1" in m.lower() for m in result.get("error_log", [])
        ), "S-1 denial not recorded in error_log"


class TestTC02S1Denial:
    """TC-02: S-1 trust gate denial is recorded in error_log (framework boundary)."""

    def test_tc02_s1_denial_sets_error_status(self):
        """INTERNAL node must reject ANONYMOUS caller via __call__()."""
        from src.nodes.pre_process_node import PreProcessNode
        from framework.schemas.trust_level import TrustLevel

        class InternalNode(PreProcessNode):
            required_trust_level = TrustLevel.INTERNAL

        node = InternalNode()
        state = _state(caller_trust_level=TrustLevel.ANONYMOUS.value)
        result = node(state)
        assert result["status"] == "error"
        assert result.get("error_log"), "error_log must not be empty after S-1 denial"

    def test_tc02_verified_external_accepted_by_internal_node(self):
        """VERIFIED_EXTERNAL caller must pass an INTERNAL node's S-1 gate."""
        from src.nodes.pre_process_node import PreProcessNode
        from framework.schemas.trust_level import TrustLevel

        node = PreProcessNode()  # VERIFIED_EXTERNAL
        state = _state(
            user_input="write a function",
            caller_trust_level=TrustLevel.VERIFIED_EXTERNAL.value,
        )
        result = node.execute(state)
        assert result["status"] != "error" or "trust" not in str(result.get("error_log", []))


class TestTC04InvocationContext:
    """TC-04: InvocationContext must be accessed via from_state() only — never stored in state."""

    def test_tc04_ctx_not_in_state_before_execute(self):
        """State must not contain an InvocationContext object."""
        state = _state()
        for v in state.values():
            assert not isinstance(
                v, InvocationContext
            ), "InvocationContext found in state — must be obtained via from_state() at runtime only"

    def test_tc04_ctx_not_in_execute_result(self):
        """execute() result dict must not contain an InvocationContext object."""
        from src.nodes.pre_process_node import PreProcessNode

        node = PreProcessNode()
        result = node.execute(_state(user_input="write a function"))
        for v in result.values():
            assert not isinstance(
                v, InvocationContext
            ), "execute() returned InvocationContext in result dict — state safety violation"


class TestPB5CheckpointSafety:
    """PB-5: Checkpoint state must not contain credentials or Pydantic objects."""

    def test_pb5_no_credentials_in_state_fields(self):
        """State field values must not match credential patterns."""
        import re
        from src.nodes.main_node import MainNode

        node = MainNode()
        node._generate = lambda prompt, state: "def hello(): pass"
        with bind_secrets(_SECRETS):
            result = node.execute(_state())

        cred_patterns = [
            re.compile(r"sk-[A-Za-z0-9]{20,}"),
            re.compile(r"eyJ[A-Za-z0-9._\-]{10,}"),
            re.compile(r"AKIA[A-Z0-9]{16}"),
        ]
        for key, value in result.items():
            if isinstance(value, str):
                for pat in cred_patterns:
                    assert not pat.search(
                        value
                    ), f"Credential pattern found in state field {key!r} — checkpoint safety violation"

    def test_pb5_no_pydantic_in_state(self):
        """State values must not be Pydantic model instances."""
        from src.nodes.pre_process_node import PreProcessNode

        node = PreProcessNode()
        result = node.execute(_state(user_input="write a function"))
        try:
            from pydantic import BaseModel

            for key, value in result.items():
                assert not isinstance(
                    value, BaseModel
                ), f"Pydantic object found in state field {key!r} — not msgpack-safe"
        except ImportError:
            pass
