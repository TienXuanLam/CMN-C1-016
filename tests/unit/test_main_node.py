"""Unit tests — MainNode (CMN-C1-016)"""

from shared.secrets.inmemory_provider import InMemoryProvider
from framework.secrets.context import bound_secrets as bind_secrets
from framework.schemas.trust_level import TrustLevel
from framework.schemas.agent_status import AgentStatus

from src.nodes.main_node import MainNode

_SECRETS = InMemoryProvider(
    {
        "AZURE_OPENAI_API_KEY": "test-key",
        "AZURE_OPENAI_ENDPOINT": "https://example.services.ai.azure.com",
        "AZURE_OPENAI_DEPLOYMENT": "test-deployment",
    }
)


def _base_state(**overrides) -> dict:
    base = {
        "user_input": "write a hello world function",
        "validated_spec": "write a hello world function",
        "parsed_spec": "write a hello world function",
        "caller_trust_level": TrustLevel.VERIFIED_EXTERNAL.value,
        "caller_id": "test",
        "session_id": "test-session",
        "thread_id": "test-thread",
        "correlation_id": "test-corr",
        "trace_id": "",
        "hitl_allowed": True,
        "node_history": [],
        "error_log": [],
        "status": "pending",
        "execution_time": {},
    }
    base.update(overrides)
    return base


class TestMainNodeTrustLevel:
    def test_trust_level_is_anonymous(self):
        assert MainNode.required_trust_level == TrustLevel.ANONYMOUS

    def test_tc08_higher_trust_level_does_not_block(self):
        """TC-08: ANONYMOUS node must accept VERIFIED_EXTERNAL and INTERNAL callers."""
        node = MainNode()
        node._generate = lambda prompt, state: "def hello(): pass"
        for level in (TrustLevel.VERIFIED_EXTERNAL, TrustLevel.INTERNAL):
            state = _base_state(caller_trust_level=level.value)
            with bind_secrets(_SECRETS):
                result = node(state)  # via __call__ — exercises S-1 gate
            assert result.get("status") != "error" or "trust" not in str(
                result.get("error_log", [])
            ), f"S-1 gate incorrectly blocked caller with trust level {level.name}"

    def test_tc08_no_trust_lower_than_anonymous_exists(self):
        """TC-08: ANONYMOUS is the lowest level — any caller is accepted."""
        node = MainNode()
        node._generate = lambda prompt, state: "x = 1"
        state = _base_state(caller_trust_level=TrustLevel.ANONYMOUS.value)
        with bind_secrets(_SECRETS):
            result = node(state)
        # ANONYMOUS callers must not be blocked by S-1 on an ANONYMOUS node
        assert "s-1" not in str(result.get("error_log", [])).lower()


class TestMainNodeSuccess:
    def _node_with_fake_llm(self, return_value: str) -> MainNode:
        node = MainNode()
        node._generate = lambda prompt, state: return_value
        return node

    def test_success_sets_generated_code(self):
        node = self._node_with_fake_llm("def hello(): pass")
        with bind_secrets(_SECRETS):
            result = node.execute(_base_state())
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["generated_code"] == "def hello(): pass"

    def test_fences_are_stripped(self):
        node = self._node_with_fake_llm("```python\ndef f(): pass\n```")
        with bind_secrets(_SECRETS):
            result = node.execute(_base_state())
        assert result["status"] == AgentStatus.SUCCESS.value
        assert "```" not in result["generated_code"]
        assert result["generated_code"] == "def f(): pass"

    def test_raw_code_retains_fences(self):
        node = self._node_with_fake_llm("```python\ndef f(): pass\n```")
        with bind_secrets(_SECRETS):
            result = node.execute(_base_state())
        assert "```" in result["raw_code"]

    def test_plain_text_spec_reaches_fixed_prompt(self):
        captured: list[str] = []
        node = MainNode()

        def generate(prompt: str, state: dict) -> str:
            captured.append(prompt)
            return "func main() {}"

        node._generate = generate
        spec = "Write an idiomatic Go service using Gin and include unit tests."
        with bind_secrets(_SECRETS):
            result = node.execute(_base_state(user_input=spec, validated_spec=spec, parsed_spec=spec))

        assert result["status"] == AgentStatus.SUCCESS.value
        assert len(captured) == 1
        assert spec in captured[0]
        assert "infer the requested programming language" in captured[0]

    def test_shared_azure_client_uses_invocation_secrets(self, monkeypatch):
        captured: dict = {}

        class FakeAzureOpenAIClient:
            def __init__(self, config):
                captured.update(config)

            def complete(self, messages):
                assert messages[0]["role"] == "user"
                return {"content": "def hello(): pass"}

        monkeypatch.setattr("src.nodes.main_node.AzureOpenAIClient", FakeAzureOpenAIClient)
        node = MainNode(llm_temperature=0.3, llm_max_tokens=2048, timeout_s=20, max_retry=2)

        with bind_secrets(_SECRETS):
            result = node.execute(_base_state())

        assert result["status"] == AgentStatus.SUCCESS.value
        assert captured == {
            "api_key": "test-key",
            "azure_endpoint": "https://example.services.ai.azure.com",
            "azure_deployment": "test-deployment",
            "temperature": 0.3,
            "max_tokens": 2048,
            "timeout": 20,
            "max_retries": 2,
        }


class TestMainNodeErrors:
    def _node_with_fake_llm(self, return_value: str) -> MainNode:
        node = MainNode()
        node._generate = lambda prompt, state: return_value
        return node

    def test_empty_parsed_spec_returns_error(self):
        node = self._node_with_fake_llm("def f(): pass")
        with bind_secrets(_SECRETS):
            result = node.execute(_base_state(parsed_spec=""))
        assert result["status"] == AgentStatus.ERROR.value

    def test_empty_llm_response_returns_error(self):
        node = self._node_with_fake_llm("")
        with bind_secrets(_SECRETS):
            result = node.execute(_base_state())
        assert result["status"] == AgentStatus.ERROR.value
        assert any("empty" in msg.lower() for msg in result["error_log"])

    def test_refusal_prefix_returns_error(self):
        node = self._node_with_fake_llm("I cannot generate that")
        with bind_secrets(_SECRETS):
            result = node.execute(_base_state())
        assert result["status"] == AgentStatus.ERROR.value
        assert any("refusal" in msg.lower() for msg in result["error_log"])

    def test_prose_only_returns_error(self):
        node = self._node_with_fake_llm("This function calculates fibonacci numbers")
        with bind_secrets(_SECRETS):
            result = node.execute(_base_state())
        assert result["status"] == AgentStatus.ERROR.value

    def test_provider_failure_returns_structured_error_without_exception_details(self):
        node = MainNode()

        def fail(_prompt: str, _state: dict) -> str:
            raise RuntimeError("secret provider detail")

        node._generate = fail
        with bind_secrets(_SECRETS):
            result = node.execute(_base_state())

        assert result["status"] == AgentStatus.ERROR.value
        assert result["error_log"] == ["Azure OpenAI code generation failed."]
        assert "secret provider detail" not in str(result)
