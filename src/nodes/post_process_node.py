"""AgentCore Platform v1.0"""

from typing import Any, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.services.events import emitter
from shared.services.events.types import EventType
from shared.utils.audit_logger import emit_trace_event

from src.nodes._security_patterns import scan_for_credentials
from src.schemas.state import CodeGenerationState


class PostProcessNode(FunctionNode):
    """post_process slot: output assembly + S-3 domain credential scan.

    Packages generated_code into a Markdown string for Marketplace UI rendering.
    S-3 domain scan runs via _run_output_gate() private helper.
    Domain S-3 logic stays inline so the graph preserves its explicit error
    contract rather than returning the framework's generic hook error shape.
    """

    required_trust_level = TrustLevel.ANONYMOUS

    def _run_output_gate(self, code: str) -> Optional[str]:
        """S-3: scan generated_code for credential patterns. Returns violation or None."""
        found = scan_for_credentials(code)
        return found[0] if found else None

    def execute(self, state: CodeGenerationState) -> dict[str, Any]:
        if state.get("input_validation_failed"):
            emit_trace_event(
                event_type="input_guidance_returned",
                payload={},
                state=state,
            )
            return {
                "formatted_output": str(state.get("formatted_output") or "Invalid input."),
                "input_validation_failed": None,
                "error_log": [],
                "status": AgentStatus.SUCCESS.value,
            }

        generated_code = state.get("generated_code", "")

        if not generated_code:
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["generated_code is empty — main node did not produce output."],
            }

        # S-3 domain gate
        violation = self._run_output_gate(generated_code)
        if violation:
            emit_trace_event(
                event_type="s3_blocked",
                payload={"reason": violation},
                state=state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [f"S-3 domain gate blocked: {violation} detected in generated code."],
            }

        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Formatting and validating generated code.",
            metadata={"stage": "output_assembly"},
        )

        formatted_output = f"# Generated code\n\n```\n{generated_code}\n```"

        emit_trace_event(
            event_type="code_generation_complete",
            payload={
                "code_length": len(generated_code),
            },
            state=state,
        )

        return {
            "formatted_output": formatted_output,
            "status": AgentStatus.SUCCESS.value,
        }
