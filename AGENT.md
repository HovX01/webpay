# AGENT.md - Self Spec Driving (Repository Root)

## Mission

Build and maintain WebPay SDKs across multiple languages with consistent
behavior and runtime-native developer experience.

## Scope

- Root-level orchestration and standards
- Cross-runtime API parity and spec governance
- Runtime folders: `node/`, `php/`, `python/`, `java/`, `csharp/`

## Source of Truth

Before implementing or changing runtime code, define/update a short spec:

- feature goal
- in-scope runtimes
- API surface (methods, models, errors)
- acceptance criteria
- compatibility and migration notes
- external API docs reference: `https://devwebpayment.kesspay.io/docs`

Keep shared contracts discoverable (recommended path: `specs/`).
Current documented currency values in API fields are `USD` and `KHR`.

## Self Spec Driving Workflow

1. Understand
   - Read current runtime implementation and tests.
   - Identify parity gaps across runtimes.
2. Specify
   - Write a concise implementation spec for the change.
   - State non-goals to prevent scope drift.
3. Implement
   - Deliver minimal, focused runtime changes.
   - Preserve public API compatibility unless explicitly versioned.
4. Verify
   - Run language-appropriate checks per touched runtime.
   - Add/update tests for behavior changes.
5. Report
   - Summarize changed files and decisions.
   - Include test evidence and known follow-ups.

## Cross-Runtime Guardrails

- Keep signing and auth behavior functionally equivalent.
- Keep gateway service naming and payload conventions aligned.
- Keep error classes/categories aligned conceptually.
- Document unavoidable runtime differences explicitly.
- Never commit secrets, credentials, or local keys.

## Runtime Validation Matrix

Use this baseline when a runtime exists:

- Node: `npm run typecheck && npm test`
- PHP: static analysis + unit tests
- Python: type/lint + pytest
- Java: compile + test
- C#: build + test

## Definition of Done

- Spec acceptance criteria are met.
- Tests pass for all touched runtimes.
- Docs are updated at root and runtime level.
- Public API impact is clear.
