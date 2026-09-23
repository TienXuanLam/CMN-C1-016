"""AgentCore Platform v1.0"""

# Standalone HTTP entry point for the agent.
# Entry points are adapters only — no business logic here.

import os
import secrets
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.context import bound_secrets
from framework.utils.config_loader import load_config
from shared.secrets import factory as secrets_factory
from shared.secrets.inmemory_provider import InMemoryProvider
from src.graph.graph import CodeGenerationGraph

app = FastAPI(title="CodeGenerationAgent")

# Finding #6 (2026-08-18, Medium): this file never loaded config/config.yaml,
# so the deployment's own max_spec_length/llm_model/llm_temperature never
# reached CodeGenerationGraph -- register_nodes() always saw self.config == {}.
_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"
_config = load_config(str(_CONFIG_PATH)) if _CONFIG_PATH.exists() else {}

# Standalone Podman/Docker runs inject secrets through process environment,
# while the configured provider covers platform-managed execution. Merge both
# channels into the invocation-scoped provider without exposing secret values
# to state or telemetry. MainNode resolves them through InvocationContext.
_configured_secrets_provider = secrets_factory(namespace="cmn", agent_name="cmn-c1-016")
_azure_secret_keys = (
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_DEPLOYMENT",
)
_secrets_provider = InMemoryProvider(
    {
        key: value
        for key in _azure_secret_keys
        if (value := os.environ.get(key) or _configured_secrets_provider.get(key)) is not None
    },
    namespace="cmn",
    agent_name="cmn-c1-016",
)
agent = CodeGenerationGraph(config=_config)
agent.compile()
agent.provision_secrets(_secrets_provider)


class InvokeRequest(BaseModel):
    """Public contract: the user's complete intent lives in plain-text input."""

    model_config = ConfigDict(extra="forbid")

    input: str
    session_id: str = ""


def _bearer_matches(supplied: str, expected: str) -> bool:
    """Constant-time bearer comparison that is safe for non-ASCII header input."""
    return secrets.compare_digest(supplied.encode(), f"Bearer {expected}".encode())


def _resolve_standalone_trust(
    current: TrustLevel, authorization: str, invoke_auth_token: str | None, internal_runner_token: str | None
) -> TrustLevel:
    """Authenticate standalone callers without allowing external-token elevation.

    Finding #1 (2026-08-18, High): this template had no equivalent of this
    resolver at all -- request.state.trust_level was read directly with no
    middleware ever setting it, so /invoke always 401'd, including for the
    Stage-5 deploy-stg runner and local-stg rehearsal, both of which present
    a bearer token expecting it to establish trust.

    STG_INTERNAL_RUNNER_TOKEN is a distinct, CI-generated deployment credential.
    It is considered only for an anonymous caller and maps exactly to INTERNAL;
    INVOKE_AUTH_TOKEN remains VERIFIED_EXTERNAL. Middleware-established trust is
    never changed.
    """
    if current is not TrustLevel.ANONYMOUS:
        return current
    if internal_runner_token and _bearer_matches(authorization, internal_runner_token):
        return TrustLevel.INTERNAL
    if invoke_auth_token and _bearer_matches(authorization, invoke_auth_token):
        return TrustLevel.VERIFIED_EXTERNAL
    if internal_runner_token or invoke_auth_token:
        raise HTTPException(status_code=401, detail="Token is invalid or expired.")
    return TrustLevel.ANONYMOUS


@app.post("/invoke")
async def invoke(req: InvokeRequest, request: Request) -> dict[str, Any]:
    trust = _resolve_standalone_trust(
        getattr(request.state, "trust_level", TrustLevel.ANONYMOUS),
        request.headers.get("authorization", ""),
        os.environ.get("INVOKE_AUTH_TOKEN"),
        os.environ.get("STG_INTERNAL_RUNNER_TOKEN"),
    )

    ctx = InvocationContext(
        session_id=req.session_id or str(uuid4()),
        caller_trust_level=trust,
        caller_id=getattr(request.state, "caller_id", ""),
    )

    with bound_secrets(agent._secrets_provider):
        return cast(
            "dict[str, Any]",
            agent.invoke(req.input, ctx=ctx),
        )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "agent": "cmn-c1-016"}
