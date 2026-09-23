# CMN-C1-016 CodeGenerationAgent — Design Specification

| Field | Value |
|---|---|
| L1 Base | `AgentBaseGraph` |
| Category | Cat 1 |
| Industry | CMN (Common / Cross-Industry) |

## 1. Purpose

CodeGenerationAgent converts one plain-text natural-language software
specification into source code for developer review. The user expresses the
language, framework, style, and test requirements in the text itself.

The agent does not execute generated code, call external tools, or perform side
effects. Its only external dependency is the configured LLM provider.

## 2. Public Contract

Standalone HTTP request:

```json
{
  "input": "Write a FastAPI service in Python, follow PEP 8, and include unit tests.",
  "session_id": "codegen-001"
}
```

`language`, `style_guide`, `framework_constraints`, `test_generation`, LLM
clients, and prompt templates are not public request fields.

The successful output is a Markdown string, not a JSON envelope. It is a
`# Generated code` heading followed by the generated source wrapped in a
fenced code block, built as
`f"# Generated code\n\n` + "```" + `\n{generated_code}\n` + "```"`. No `spec`
field is ever returned to the caller. When input validation fails, the same
`formatted_output` field instead carries Markdown guidance text (see
`_guidance_message()` in `pre_process_node.py`).

## 3. Architecture

```text
initialize → pre_process → main → post_process → finalize
```

| Slot | Node | Responsibility | Trust |
|---|---|---|---|
| `pre_process` | `PreProcessNode` | Length validation, PII masking, credential and injection blocking | `VERIFIED_EXTERNAL` |
| `main` | `MainNode` | Fixed prompt assembly, LLM call, code normalization and early output guards | `ANONYMOUS` |
| `post_process` | `PostProcessNode` | Final credential scan and output envelope | `ANONYMOUS` |

The standalone server merges process-environment secrets with the configured
secret provider and provisions it on the graph. For each invocation, `MainNode`
obtains that provider through `InvocationContext.from_state(state)` and creates
AgentCore's shared `AzureOpenAIClient`. The client and credentials are never
stored in graph state or supplied by the caller.

The shared client uses Azure OpenAI's v1-compatible endpoint through
`langchain-openai==1.2.1`. It requires a bare resource endpoint and converts it
internally to `<endpoint>/openai/v1/`.

## 4. Processing Rules

### Pre-process

- Reject empty or oversized input.
- Mask detected PII before prompt construction.
- Reject credentials and prompt-injection markers.
- Normalize whitespace.
- Preserve the sanitized text as both `validated_spec` and `parsed_spec`.

### Main

- Append `parsed_spec` to fixed, project-owned prompt instructions.
- Ask the LLM to infer language, framework, style, and testing requirements.
- Call AgentCore's shared Azure client exactly once through `complete()`.
- Strip Markdown code fences and excessive blank lines.
- Reject empty, refusal, prose-only, or credential-bearing output.

### Post-process

- Scan generated code for credentials again.
- Wrap the generated code in a Markdown code fence under a `# Generated code`
  heading as `formatted_output`; no sanitized specification is returned.
- Never execute or validate the generated program at runtime.

## 5. Security Invariants

- Caller must reach the graph with `VERIFIED_EXTERNAL` trust.
- PII and credentials must not reach the LLM.
- Caller-controlled templates are prohibited; no template engine is used.
- LLM/client objects must not enter state.
- Generated credentials must be blocked before output.
- Provider failure, empty output, refusal, or non-code output must fail closed.
- Audit events contain lengths and categories, not raw input or code.

## 6. Runtime Configuration

`config/config.yaml` owns deployment values:

- `max_spec_length`
- `llm_temperature`
- `llm_max_tokens`
- retry, timeout, memory, and HITL settings

Per-request specialization belongs entirely in the plain-text `input`.

## 7. State

`CodeGenerationState` adds only primitive, serializable fields:

- `validated_spec`
- `parsed_spec`
- `raw_code`
- `generated_code`
- `formatted_output`

No credential, provider client, Pydantic model, or invocation context is stored.
