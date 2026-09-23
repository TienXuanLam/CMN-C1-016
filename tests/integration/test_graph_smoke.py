"""Integration smoke tests — CMN-C1-016 CodeGenerationGraph

SMOKE-001  Graph compiles
SMOKE-002  Full pipeline success
SMOKE-003  Output contains generated code
SMOKE-004  Empty input returns actionable guidance (no LLM call)
SMOKE-005  Fences in LLM output are stripped
SMOKE-006  Credential in input returns ERROR
"""

from shared.secrets.inmemory_provider import InMemoryProvider
from framework.secrets.context import bound_secrets as bind_secrets
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from shared.services.events import EventEmitter, bound_emitter
from shared.services.events.types import EventType

from src.graph.graph import CodeGenerationGraph

_SECRETS = InMemoryProvider({"AZURE_OPENAI_API_KEY": "test-key"})


def _ctx() -> InvocationContext:
    return InvocationContext(
        session_id="test-session",
        caller_trust_level=TrustLevel.VERIFIED_EXTERNAL,
        caller_id="test",
    )


def _agent(llm_return: str) -> CodeGenerationGraph:
    agent = CodeGenerationGraph()
    agent.compile()
    agent._nodes["main"]._generate = lambda prompt, state: llm_return
    return agent


def _invoke(agent, user_input: str = "write a hello world function"):
    with bind_secrets(_SECRETS):
        return agent.invoke(
            user_input,
            ctx=_ctx(),
        )


class _RecordingEmitter(EventEmitter):
    def __init__(self):
        self.events = []

    def emit_event(self, *, event_type, message, metadata=None, sub_event_type=None):
        self.events.append(
            {
                "event_type": event_type,
                "message": message,
                "metadata": metadata,
                "sub_event_type": sub_event_type,
            }
        )


class TestSmoke:
    def test_smoke_001_graph_compiles(self):
        agent = CodeGenerationGraph()
        agent.compile()
        assert agent._compiled is not None

    def test_smoke_002_full_pipeline_success(self):
        agent = _agent("def hello(): pass")
        result = _invoke(agent)
        assert result["status"] == "success"

    def test_smoke_003_output_contains_code(self):
        agent = _agent("def hello(): pass")
        result = _invoke(agent)
        output = result.get("output")
        assert isinstance(output, str)
        assert output.startswith("# Generated code")
        assert "def hello(): pass" in output
        assert not output.lstrip().startswith("{")
        assert "write a hello world function" not in output

    def test_smoke_004_empty_input_returns_error(self):
        agent = _agent("def f(): pass")
        result = _invoke(agent, user_input="")
        assert result["status"] == "success"
        assert "Code generation request required" in result.get("output", "")

    def test_smoke_005_fences_stripped(self):
        agent = _agent("```python\ndef f(): pass\n```")
        result = _invoke(agent)
        assert result["status"] == "success"
        output = result.get("output")
        assert isinstance(output, str)
        assert "```python" not in output
        assert "def f(): pass" in output

    def test_smoke_006_credential_in_input_blocked(self):
        agent = _agent("should not reach here")
        with bind_secrets(_SECRETS):
            result = agent.invoke(
                "api_key=sk-abcdefghijklmnop12345678",
                ctx=_ctx(),
            )
        assert result["status"] == "error"

    def test_smoke_007_emits_only_progress_events(self):
        agent = _agent("def hello(): pass")
        progress = _RecordingEmitter()

        with bound_emitter(progress):
            result = _invoke(agent)

        assert result["status"] == "success"
        assert [event["metadata"]["stage"] for event in progress.events] == [
            "input_validation",
            "code_generation",
            "output_assembly",
        ]
        assert all(event["event_type"] is EventType.PROGRESS_UPDATE for event in progress.events)
        assert all(
            event["event_type"] not in {EventType.COMPLETION_SUCCESS, EventType.COMPLETION_FAILURE}
            for event in progress.events
        )
