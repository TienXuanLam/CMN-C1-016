"""AgentCore Platform v1.0"""

from typing import Optional

from framework.schemas.agent_state import AgentState


class CodeGenerationState(AgentState):
    """Flat TypedDict state for CMN-C1-016 CodeGenerationAgent.

    All fields are primitives (str, None) — msgpack-safe.
    Agent-specific fields only; shared fields (user_input, status,
    session_id, node_history, error_log, etc.) are inherited from AgentState.
    """

    validated_spec: Optional[str]  # pre_process: sanitized, length-checked spec
    parsed_spec: Optional[str]  # pre_process: structured prompt fragment
    raw_code: Optional[str]  # main: raw LLM output (fences NOT stripped)
    generated_code: Optional[str]  # main: fence-stripped, normalized code
    formatted_output: Optional[str]  # post_process: Markdown code block — SDK result["output"]
    input_validation_failed: Optional[str]  # "true" while returning validation guidance
