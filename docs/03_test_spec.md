# CMN-C1-016 CodeGenerationAgent — Test Specification

## 1. Objective

Tests prove the plain-text request contract, fixed graph pipeline, security
boundaries, output contract, and provider injection without requiring a live LLM
in the unit-test job.

## 2. Required Coverage

### Public request

- `input` and optional `session_id` are accepted.
- Legacy structured fields are rejected.
- Language, framework, style, and test instructions are carried inside `input`.

### Pre-process

- Empty and oversized text are rejected.
- Clean text is preserved after whitespace normalization.
- PII is masked.
- Credentials and prompt injection are blocked.
- Arbitrary programming-language requirements are not rejected by an allowlist.

### Main

- The sanitized specification reaches the fixed prompt.
- The LLM is called exactly once.
- Markdown fences are removed from `generated_code` but retained in `raw_code`.
- Empty, refusal, prose-only, and credential-bearing output fail closed.

### Post-process

- Output contains `code` and sanitized `spec`.
- Output does not claim a language derived from removed structured fields.
- Final credential scan blocks unsafe output.

### Framework boundaries

- Graph compiles and runs the canonical node order.
- State remains primitive and msgpack-safe.
- Trust gates run before node execution.
- No Level 0 imports occur in `src/`.
- LLM client is constructor-injected and never stored in state.

## 3. Mock Strategy

Unit and integration tests replace `MainNode._generate(prompt)` with a fixed
callable. This isolates business and security logic from network availability.
Real-provider acceptance is performed separately after build and must run with
all mock flags disabled and the three Azure OpenAI secrets provisioned.

## 4. Commands

```bash
python -m pytest tests/ -v --tb=short
python -m pytest tests/proof_of_boundary/ -v --tb=short
ruff check src tests
ruff format --check src tests
mypy src
```

## 5. Real-LLM Acceptance

Use requests that encode every requirement in text, for example:

```text
Write a REST API in Python using FastAPI and Pydantic, follow PEP 8, and include unit tests.
```

Acceptance requires non-empty code, correct constraints, no explanatory prose,
no mock marker, no credential leakage, and the complete success node path.

## 6. Invalid-input guidance

An empty, whitespace-only, or oversized request must return `status=success` with Markdown beginning `# Code generation request required` and must not call Azure OpenAI. Prompt injection, credentials, LLM failures, and output-gate violations must remain `status=error`.
