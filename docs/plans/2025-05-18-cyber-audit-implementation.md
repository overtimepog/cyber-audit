# Cyber Audit — Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build an 8-stage vulnerability-discovery agent pipeline (modeled on Cloudflare's Project Glasswing / evilsocket/audit) that uses DeepSeek API + OpenAI models instead of Claude subscription.

**Architecture:** Multi-provider LLM abstraction → custom agent loop with tool execution → SQLite state store → 8-stage pipeline → CLI. Each stage is a system prompt + JSON schema. Models disagree deliberately (different models for Hunt vs Validate). The agent loop handles tool calls (Read, Grep, Glob, Bash) natively without the Claude Agent SDK.

**Tech Stack:** Python 3.11+, DeepSeek API (via existing Hermes config), OpenAI API, Click CLI, SQLite, jsonschema, PyYAML, pytest with asyncio

---

## Project Structure

```
cyber-audit/
├── pyproject.toml
├── README.md
├── config/
│   └── stages.yaml              # Per-stage model + concurrency + tools
├── prompts/                      # 8 stage prompts (markdown)
│   ├── 01-recon.md
│   ├── 02-hunt.md
│   ├── 03-validate.md
│   ├── 04-gapfill.md
│   ├── 05-dedupe.md
│   ├── 06-trace.md
│   ├── 07-feedback.md
│   └── 08-report.md
├── schemas/                      # JSON schemas for every agent output
│   ├── recon_output.schema.json
│   ├── hunt_task.schema.json
│   ├── finding.schema.json
│   ├── validation.schema.json
│   ├── gapfill_output.schema.json
│   ├── dedupe_output.schema.json
│   ├── trace.schema.json
│   ├── feedback_output.schema.json
│   └── report.schema.json
├── cyber_audit/                  # Python package
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                    # Click CLI
│   ├── config.py                 # stages.yaml loader
│   ├── llm.py                    # Multi-provider LLM client
│   ├── agent.py                  # Agent loop: prompt → tools → schema validate
│   ├── tools.py                  # Read, Grep, Glob, Bash implementations
│   ├── json_utils.py             # extract_json, validate_schema
│   ├── state.py                  # SQLite StateDB
│   ├── orchestrator.py           # Pipeline driver
│   └── stages/                   # One module per stage
│       ├── __init__.py
│       ├── _common.py            # StageContext
│       ├── recon.py
│       ├── hunt.py
│       ├── validate.py
│       ├── gapfill.py
│       ├── dedupe.py
│       ├── trace.py
│       ├── feedback.py
│       └── report.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_llm.py
│   ├── test_agent.py
│   ├── test_tools.py
│   ├── test_json_utils.py
│   ├── test_config.py
│   ├── test_state.py
│   ├── test_orchestrator.py
│   ├── test_stages/
│   │   ├── test_recon.py
│   │   ├── test_hunt.py
│   │   ├── test_validate.py
│   │   └── ...
│   └── fixtures/
│       └── vulnerable_app/
│           ├── app.py
│           └── README.md
└── work/                         # Per-hunt-task scratch dirs (gitignored)
```

---

## Core Architecture: Agent Loop

The agent loop replaces `claude-agent-sdk`'s `ClaudeSDKClient`:

```
1. Send system_prompt + user_input to LLM (DeepSeek or OpenAI)
2. Parse response:
   a. If tool_call → execute tool → append result → go to 1
   b. If text response → try to extract JSON
3. Validate JSON against schema
4. If invalid and repair_attempts remain → send repair prompt → go to 1
5. Return validated payload + cost/token metadata
```

Tool calls use a structured format the model is instructed to use:
```json
{"tool": "Read", "path": "/abs/path/to/file.py", "offset": 1, "limit": 50}
{"tool": "Grep", "pattern": "eval\\(", "path": "/abs/path"}
{"tool": "Glob", "pattern": "**/*.py", "path": "/abs/path"}
{"tool": "Bash", "command": "python3 -c 'print(1+1)'", "workdir": "/abs/path"}
```

The model emits tool calls in fenced JSON blocks; we parse, execute, and feed results back as the next user message.

---

## Model Strategy

Per the Cloudflare blog's "deliberate disagreement" principle, Hunt and Validate MUST use different models:

| Stage    | Provider  | Model              | Rationale                        |
|----------|-----------|--------------------|----------------------------------|
| Recon    | deepseek  | deepseek-v4-pro    | Deep reasoning for architecture  |
| Hunt     | openai    | gpt-4o             | Fast, many parallel tasks        |
| Validate | deepseek  | deepseek-v4-pro    | Different from Hunt (disagreement)|
| Gapfill  | openai    | gpt-4o-mini        | Cheap re-queue analysis          |
| Dedupe   | openai    | gpt-4o-mini        | Pattern matching                 |
| Trace    | deepseek  | deepseek-v4-pro    | "The stage that matters most"    |
| Feedback | openai    | gpt-4o-mini        | Task generation                  |
| Report   | openai    | gpt-4o              | Structured output                |

---

## Task Breakdown

### Task 1: Create GitHub repo + project scaffold

Create repo `cyber-audit`, set up `pyproject.toml`, directory structure, `.gitignore`.

### Task 2: Build LLM client (cyber_audit/llm.py)

Multi-provider async HTTP client supporting DeepSeek and OpenAI APIs. Handles API keys, streaming responses, tool call parsing, token counting.

### Task 3: Build tool execution (cyber_audit/tools.py)

Implement Read (file reader), Grep (regex search), Glob (file glob), Bash (shell execution in scratch dir). Each tool has input validation and safety constraints.

### Task 4: Build JSON utilities (cyber_audit/json_utils.py)

`extract_json()` — extract JSON from model output (handles markdown fences, trailing text). `validate_schema()` — validate against JSON Schema, return error list.

### Task 5: Build agent loop (cyber_audit/agent.py)

The `run_agent()` function: system prompt + user input → LLM call → parse tool calls or JSON → schema validate → repair if needed → return AgentResult.

### Task 6: Build StateDB (cyber_audit/state.py)

SQLite database for runs, tasks, findings, traces, dedupe groups, costs, artifacts.

### Task 7: Build config system (cyber_audit/config.py)

Load `stages.yaml`, provide per-stage model/concurrency/tool settings.

### Task 8: Build StageContext + Recon stage (stage 1)

StageContext provides paths. Recon maps repo, emits initial hunt tasks.

### Task 9: Build Hunt + Validate stages (stages 2-3)

Hunt runs tasks concurrently, emits findings. Validate adversarially re-reads findings.

### Task 10: Build remaining stages (4-8)

Gapfill, Dedupe, Trace, Feedback, Report.

### Task 11: Build orchestrator

Pipeline driver that sequences stages, handles budget, supports resume.

### Task 12: Build CLI

Click CLI: `cyber-audit run`, `cyber-audit status`, `cyber-audit report`.

### Task 13: Create vulnerable test fixture + E2E test

A Flask app with known vulnerabilities (SQLi, command injection, path traversal). Run full pipeline against it.

---

## TDD Rules (Iron Law)

```
NO PRODUCTION CODE WITHOUT A FAILING TEST FIRST
```

Every module: write test → watch it fail → write minimal code → watch it pass.

## Commit Convention

`feat: <description>` for features, `test: <description>` for tests, `fix: <description>` for fixes.
