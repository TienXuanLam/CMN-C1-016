"""AgentCore Platform v1.0"""

import os
import re
from typing import Any, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from shared.services.events import emitter
from shared.services.events.types import EventType
from shared.services.llm.azure_openai_client import AzureOpenAIClient
from shared.utils.audit_logger import emit_trace_event

from src.nodes._security_patterns import scan_for_credentials
from src.schemas.state import CodeGenerationState

# Strip markdown code fences (LF and CRLF)
_FENCE_PATTERN = re.compile(r"^```[a-zA-Z]*\r?\n?|^[ \t]*```\s*$", re.MULTILINE)
_EXCESS_BLANK_LINES = re.compile(r"\n{3,}")

_REFUSAL_PREFIXES = (
    "i cannot",
    "i'm sorry",
    "i am unable",
    "as an ai",
    "i apologize",
)
_CODE_PUNCTUATION = set("()=:{}[];|&$#")
# The prose guard needs a language-neutral vocabulary: valid Bash ("echo
# hello") or SQL ("SELECT 1") can contain no punctuation. Keep common leading
# tokens across mainstream languages so plain-text requests are not forced
# through a language allowlist merely to validate the response.
_CODE_KEYWORDS = frozenset(
    {
        # Python
        "pass",
        "break",
        "continue",
        "return",
        "yield",
        "raise",
        "del",
        "assert",
        "import",
        "from",
        "if",
        "elif",
        "else",
        "while",
        "for",
        "with",
        "lambda",
        "def",
        "class",
        "try",
        "except",
        "finally",
        # Bash
        "echo",
        "cd",
        "export",
        "source",
        "cat",
        "grep",
        "sed",
        "awk",
        "chmod",
        "mkdir",
        "rm",
        "cp",
        "mv",
        "ls",
        "curl",
        "wget",
        "sudo",
        "function",
        # SQL
        "select",
        "insert",
        "update",
        "delete",
        "create",
        "alter",
        "drop",
        "where",
        "join",
        "into",
        "values",
        "table",
        # Go / Rust / Java / Kotlin / Swift
        "func",
        "package",
        "fn",
        "let",
        "mut",
        "impl",
        "struct",
        "trait",
        "public",
        "private",
        "static",
        "void",
        "var",
        "val",
        "fun",
    }
)
_BARE_LITERALS = frozenset({"true", "false", "none", "null", "undefined"})

# Fixed project-owned instructions; never accept caller-supplied templates.
_PROMPT_PREFIX = (
    "You are a code generation assistant.\n"
    "Read the user's software specification and infer the requested programming "
    "language, framework, coding style, and testing requirements from the text. "
    "When a detail is not specified, use a sensible, idiomatic default.\n"
    "Generate code that satisfies the specification. Output only the code, "
    "with no explanations or commentary.\n\n"
    "User specification:\n"
)


class MainNode(FunctionNode):
    """main slot: LLM code generation + output formatting.

    The AgentCore shared AzureOpenAIClient is constructed per invocation from
    InvocationContext secrets. Client objects and credentials never enter the
    public request or serializable graph state.

    Prompt instructions are a fixed, non-caller-controlled string. The prior
    design accepted input_context["prompt_template"] and rendered it with a
    non-sandboxed template engine, creating an SSTI surface. The public
    contract now accepts only plain-text user_input; no template override or
    template engine is used.

    S-4: emits 'llm_call' trace event for every LLM invocation.
    S-3 credential scan is handled by PostProcessNode (canonical S-3 slot).
    MainNode performs an early LLM output validity check (ERR_LLM_CREDENTIAL)
    to catch obvious credential leaks before they reach state — this is NOT
    the S-3 gate; it uses a distinct error code.
    """

    required_trust_level = TrustLevel.ANONYMOUS

    def __init__(
        self,
        llm_temperature: float = 0.2,
        llm_max_tokens: int = 4096,
        timeout_s: int = 30,
        max_retry: int = 3,
    ) -> None:
        super().__init__()
        self._llm_temperature = llm_temperature
        self._llm_max_tokens = llm_max_tokens
        self._timeout_s = timeout_s
        self._max_retry = max_retry

    def _check_llm_credential_leak(self, raw: str, code: str) -> Optional[dict[str, Any]]:
        """Early LLM output check — not S-3 gate. Distinct error code ERR_LLM_CREDENTIAL."""
        for field_name, text in (("raw_code", raw), ("generated_code", code)):
            if scan_for_credentials(text):
                return {
                    "status": AgentStatus.ERROR.value,
                    "error_log": [
                        f"ERR_LLM_CREDENTIAL: credential pattern detected in LLM output "
                        f"({field_name!r}). Output rejected before state write."
                    ],
                }
        return None

    def execute(self, state: CodeGenerationState) -> dict[str, Any]:
        if state.get("input_validation_failed"):
            return {}

        parsed_spec = state.get("parsed_spec", "")
        if not parsed_spec:
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["parsed_spec is empty — pre_process did not run correctly."],
            }

        # Prompt instructions are fixed and caller-controlled text is appended
        # only as the specification. No template engine or template override is
        # exposed to the caller.
        prompt = f"{_PROMPT_PREFIX}{parsed_spec}"

        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Generating code with Azure OpenAI.",
            metadata={"stage": "code_generation"},
        )

        try:
            raw = self._generate(prompt, state)
        except Exception as exc:  # noqa: BLE001
            emit_trace_event(
                event_type="llm_call_failed",
                payload={"provider": "azure_openai", "reason": type(exc).__name__},
                state=state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["Azure OpenAI code generation failed."],
            }

        # S-4: audit LLM call (emitted after call so result metadata is available)
        emit_trace_event(
            event_type="llm_call",
            payload={
                "spec_length": len(parsed_spec),
                "response_length": len(raw) if raw else 0,
            },
            state=state,
        )

        if not raw or not raw.strip():
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["LLM returned an empty response. Check model config and prompt template."],
            }

        # Fence stripping + normalization
        code = _FENCE_PATTERN.sub("", raw).strip()
        code = _EXCESS_BLANK_LINES.sub("\n\n", code)

        if not code:
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["LLM returned empty output after fence stripping."],
            }

        # Refusal prefix guard
        code_lower = code.lower()
        for prefix in _REFUSAL_PREFIXES:
            if code_lower.startswith(prefix):
                return {
                    "status": AgentStatus.ERROR.value,
                    "error_log": [f"LLM returned a non-code response (refusal prefix {prefix!r} detected)."],
                }

        # Prose guard
        non_blank = [ln for ln in code.splitlines() if ln.strip()]
        if non_blank and not any(self._line_looks_like_code(ln) for ln in non_blank):
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [
                    "LLM returned a non-code response " "(no line contains code punctuation or a recognized keyword)."
                ],
            }

        # Early credential check (ERR_LLM_CREDENTIAL — not S-3 gate)
        cred_error = self._check_llm_credential_leak(raw, code)
        if cred_error is not None:
            return cred_error

        return {
            "raw_code": raw,
            "generated_code": code,
            "result": code,
            "status": AgentStatus.SUCCESS.value,
        }

    def _generate(self, prompt: str, state: CodeGenerationState) -> str:
        """Call AgentCore's shared Azure client using invocation-scoped secrets."""
        # STG_MOCK_MODE is the scaffold's standard Stage 5 provisional-deploy
        # toggle (set "true" by the shared deploy-stg CI job every template
        # includes). This CI-only structural toggle is never enabled for a real
        # invocation; there is no real Azure OpenAI secret provisioned for
        # the provisional smoke deploy, so without this branch the smoke
        # invoke fails closed on MissingSecret every time.
        if os.environ.get("STG_MOCK_MODE") == "true":
            emit_trace_event(
                "llm_call_mocked",
                {"reason": "STG_MOCK_MODE=true"},
                {},
            )
            return (
                "def stg_mock():\n"
                "    # This is a mocked code generation result used only for the\n"
                "    # provisional Stage 5 deploy-stg smoke invoke, which has no real\n"
                "    # Azure OpenAI secrets provisioned. Not returned in any real invocation.\n"
                "    return None\n"
            )
        ctx = InvocationContext.from_state(state)
        llm = AzureOpenAIClient(
            {
                "api_key": ctx.secrets.require("AZURE_OPENAI_API_KEY"),
                "azure_endpoint": ctx.secrets.require("AZURE_OPENAI_ENDPOINT"),
                "azure_deployment": ctx.secrets.require("AZURE_OPENAI_DEPLOYMENT"),
                "temperature": self._llm_temperature,
                "max_tokens": self._llm_max_tokens,
                "timeout": self._timeout_s,
                "max_retries": self._max_retry,
            }
        )
        response = llm.complete([{"role": "user", "content": prompt}])
        content = response.get("content", "") if isinstance(response, dict) else str(response)
        return str(content)

    @staticmethod
    def _line_looks_like_code(line: str) -> bool:
        if not line.strip():
            return True
        if any(ch in line for ch in _CODE_PUNCTUATION):
            return True
        tokens = line.lower().split()
        if tokens[0] in _CODE_KEYWORDS:
            return True
        if len(tokens) == 1 and tokens[0] in _BARE_LITERALS:
            return True
        return False
