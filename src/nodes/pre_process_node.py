"""AgentCore Platform v1.0"""

import re
from typing import Any

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.services.events import emitter
from shared.services.events.types import EventType
from shared.utils.audit_logger import emit_trace_event

from src.nodes._security_patterns import INJECTION_PATTERNS, scan_for_credentials, scan_for_pii
from src.schemas.state import CodeGenerationState

_MAX_SPEC_LENGTH = 4000


def _guidance_message(message: str) -> str:
    return (
        "# Code generation request required\n\n"
        f"I could not process the input: {message}\n\n"
        "Describe the code you want in plain text, including the language, behavior, and tests.\n\n"
        "**Example**\n\n"
        "Write a Python function that calculates Fibonacci numbers iteratively, "
        "with type hints, a docstring, and pytest tests."
    )


class PreProcessNode(FunctionNode):
    """pre_process slot: S-2 PII masking + input validation + spec parsing.

    The framework calls _extra_security_gate_input() before execute(). The hook
    performs fail-closed raw-input checks; execute() retains the same checks so
    direct node tests and non-framework callers receive the same domain errors.
    PII masking stays in execute() because it transforms the specification that
    is passed to the LLM.

    max_spec_length is deployment configuration, threaded from
    config/config.yaml via CodeGenerationGraph.register_nodes(). Language,
    framework, style, and test requirements remain part of the sanitized
    plain-text specification and are inferred by the LLM.
    """

    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def __init__(self, max_spec_length: int = _MAX_SPEC_LENGTH) -> None:
        super().__init__()
        self._max_spec_length = max_spec_length

    @staticmethod
    def _reject(state: CodeGenerationState, message: str) -> CodeGenerationState:
        """Mutate state into the hook's fail-closed error shape."""
        state["status"] = AgentStatus.ERROR.value
        state["error_log"] = [message]
        return state

    @staticmethod
    def _guide(state: CodeGenerationState, message: str) -> CodeGenerationState:
        """Handle an ordinary validation error without failing the invocation."""
        state["status"] = AgentStatus.SUCCESS.value
        state["input_validation_failed"] = "true"
        state["formatted_output"] = _guidance_message(message)
        state["error_log"] = [message]
        return state

    def _extra_security_gate_input(self, state: CodeGenerationState) -> CodeGenerationState:
        """Reject invalid raw input before execute() performs transformations."""
        if state.get("status") == AgentStatus.ERROR.value:
            return state

        # Framework contract/proof harnesses may call a node with only shared
        # metadata to verify lifecycle ordering. Domain validation belongs to
        # a real invocation, where InitializeNode always supplies user_input.
        if "user_input" not in state:
            return state

        spec = state.get("user_input", "")
        if not isinstance(spec, str) or not spec.strip():
            return self._guide(state, "The request must not be empty or whitespace-only.")
        if len(spec) > self._max_spec_length:
            return self._guide(
                state,
                f"The request exceeds the maximum length of {self._max_spec_length} characters.",
            )

        cred_types = scan_for_credentials(spec)
        if cred_types:
            emit_trace_event(
                event_type="s2_credential_blocked",
                payload={"violation": cred_types[0]},
                state=state,
            )
            return self._reject(
                state,
                f"S-2: credential pattern detected in user_input ({cred_types[0]}).",
            )

        for pattern in INJECTION_PATTERNS:
            if pattern.search(spec):
                emit_trace_event(
                    event_type="s2_injection_blocked",
                    payload={},
                    state=state,
                )
                return self._reject(
                    state,
                    "S-2: prompt injection pattern detected in user_input. Input rejected.",
                )

        return state

    def execute(self, state: CodeGenerationState) -> dict[str, Any]:
        if state.get("input_validation_failed"):
            return {
                "status": AgentStatus.SUCCESS.value,
                "input_validation_failed": "true",
                "formatted_output": str(state.get("formatted_output") or "Invalid input."),
                "error_log": list(state.get("error_log") or []),
            }

        spec = state.get("user_input", "")

        # 1. Reject empty input
        if not spec or not spec.strip():
            return {
                "status": AgentStatus.SUCCESS.value,
                "input_validation_failed": "true",
                "formatted_output": _guidance_message("The request must not be empty or whitespace-only."),
                "error_log": ["The request must not be empty or whitespace-only."],
            }

        # 2. Length check FIRST, on the raw untrimmed input (finding #7,
        # 2026-08-18, Medium). The previous order ran PII/credential/
        # injection regex scans on the full raw string, THEN collapsed
        # whitespace, THEN checked length against the *normalized* length --
        # a 1,000,010-char payload of mostly whitespace normalized down to 10
        # chars and sailed through a max_spec_length=20 limit, having already
        # forced every regex scan above to walk the full million-char string.
        # This defeats the ingress size limit as a DoS control and wastes
        # the regex-scan cost on attacker-controlled padding. Checking the
        # raw length up front bounds the work every later step can do.
        if len(spec) > self._max_spec_length:
            return {
                "status": AgentStatus.SUCCESS.value,
                "input_validation_failed": "true",
                "formatted_output": _guidance_message(
                    f"The request exceeds the maximum length of {self._max_spec_length} characters."
                ),
                "error_log": [f"user_input exceeds max length of {self._max_spec_length} chars (got {len(spec)})."],
            }

        # 3. S-2: PII masking (mask, not reject — specs may contain sample data)
        spec, pii_detected = scan_for_pii(spec)

        # 4. S-2: Credential scan (reject — credentials must not reach LLM)
        cred_types = scan_for_credentials(spec)
        if cred_types:
            emit_trace_event(
                event_type="s2_credential_blocked",
                payload={"violation": cred_types[0]},
                state=state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [f"S-2: credential pattern detected in user_input ({cred_types[0]})."],
            }

        if pii_detected:
            emit_trace_event(
                event_type="s2_pii_masked",
                payload={"types": pii_detected},
                state=state,
            )

        # 5. S-2: Prompt injection detection (block, not mask)
        for pat in INJECTION_PATTERNS:
            if pat.search(spec):
                emit_trace_event(
                    event_type="s2_injection_blocked",
                    payload={},
                    state=state,
                )
                return {
                    "status": AgentStatus.ERROR.value,
                    "error_log": ["S-2: prompt injection pattern detected in user_input. Input rejected."],
                }

        # 6. Normalize whitespace (post-length-check; see finding #7 above)
        spec = re.sub(r"\s+", " ", spec).strip()

        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Code generation request validated.",
            metadata={"stage": "input_validation"},
        )

        emit_trace_event(
            event_type="pre_process_ok",
            payload={
                "spec_length": len(spec),
                "pii_masked": len(pii_detected) > 0,
            },
            state=state,
        )

        return {
            "validated_spec": spec,
            "parsed_spec": spec,
            "status": AgentStatus.SUCCESS.value,
        }
