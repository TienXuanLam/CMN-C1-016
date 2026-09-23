# The server provisions invocation-scoped secrets. MainNode constructs the
# AgentCore shared AzureOpenAIClient only when a real invocation reaches it.

import importlib

import pytest
from pydantic import ValidationError


_AZURE_SECRETS = {
    "AZURE_OPENAI_API_KEY": "dummy-test-key",
    "AZURE_OPENAI_ENDPOINT": "https://example.services.ai.azure.com",
    "AZURE_OPENAI_DEPLOYMENT": "test-deployment",
}


class TestServerBootsWithoutAzureOpenAiSecrets:
    def test_server_imports_and_app_constructs_with_no_key(self, monkeypatch):
        for key in _AZURE_SECRETS:
            monkeypatch.delenv(key, raising=False)

        import src.api.server as server

        importlib.reload(server)

        assert server.app is not None
        assert server.agent is not None
        assert not hasattr(server, "_llm")


class TestPlainTextRequestContract:
    def test_request_accepts_only_input_and_session_id(self):
        from src.api.server import InvokeRequest

        request = InvokeRequest(input="Write a Rust CLI and include tests.", session_id="plain-text-001")

        assert request.input == "Write a Rust CLI and include tests."
        assert request.session_id == "plain-text-001"

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("language", "python"),
            ("style_guide", "pep8"),
            ("framework_constraints", "fastapi"),
            ("test_generation", True),
        ],
    )
    def test_legacy_structured_fields_are_rejected(self, field, value):
        from src.api.server import InvokeRequest

        with pytest.raises(ValidationError):
            InvokeRequest(input="Write code.", **{field: value})


class TestServerProvisionsInvocationSecrets:
    def test_configured_provider_reaches_standalone_secret_provider(self, monkeypatch):
        from shared.secrets.inmemory_provider import InMemoryProvider

        # server.py's InMemoryProvider construction prefers os.environ.get(key)
        # over the configured provider (see server.py's Azure secrets merge) --
        # a real Azure credential left in the test-runner's own environment
        # (e.g. exported for a manual Stage 5 rehearsal in the same shell)
        # would otherwise silently win over this test's mock provider and
        # falsify the assertion below without indicating a real code bug.
        for key in _AZURE_SECRETS:
            monkeypatch.delenv(key, raising=False)

        monkeypatch.setattr(
            "shared.secrets.factory",
            lambda namespace, agent_name: InMemoryProvider(_AZURE_SECRETS),
        )

        import src.api.server as server

        importlib.reload(server)

        assert {key: server._secrets_provider.require(key) for key in _AZURE_SECRETS} == _AZURE_SECRETS
        assert not hasattr(server.agent._nodes["main"], "_llm")

    def test_process_environment_reaches_standalone_secret_provider(self, monkeypatch):
        for key, value in _AZURE_SECRETS.items():
            monkeypatch.setenv(key, value)

        import src.api.server as server

        importlib.reload(server)

        assert {key: server._secrets_provider.require(key) for key in _AZURE_SECRETS} == _AZURE_SECRETS


class TestStandaloneTrustPromotion:
    def test_external_bearer_never_promotes_to_internal(self):
        import src.api.server as server
        from framework.schemas.trust_level import TrustLevel

        assert (
            server._resolve_standalone_trust(TrustLevel.ANONYMOUS, "Bearer external", "external", "runner")
            is TrustLevel.VERIFIED_EXTERNAL
        )

    def test_runner_bearer_promotes_to_internal(self):
        import src.api.server as server
        from framework.schemas.trust_level import TrustLevel

        assert (
            server._resolve_standalone_trust(TrustLevel.ANONYMOUS, "Bearer runner", "external", "runner")
            is TrustLevel.INTERNAL
        )

    def test_wrong_or_missing_bearer_is_rejected_when_auth_is_enabled(self):
        import pytest
        import src.api.server as server
        from fastapi import HTTPException
        from framework.schemas.trust_level import TrustLevel

        for authorization in ("", "Bearer wrong"):
            with pytest.raises(HTTPException) as exc:
                server._resolve_standalone_trust(TrustLevel.ANONYMOUS, authorization, "external", "runner")
            assert exc.value.status_code == 401
