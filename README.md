# Cyber Audit

An 8-stage vulnerability-discovery agent pipeline powered by **DeepSeek** and **OpenAI** models. Built on the architecture described in Cloudflare's [Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/) blog post and inspired by [evilsocket/audit](https://github.com/evilsocket/audit).

## What makes this different

- **Multi-provider**: Uses your DeepSeek API key + OpenAI models — no Claude subscription required
- **8-stage pipeline**: Recon → Hunt → Validate → Gapfill → Dedupe → Trace → Feedback → Report
- **Deliberate disagreement**: Hunt and Validate use different models to catch noise
- **Custom agent loop**: Tool execution (Read, Grep, Glob, Bash) built in, no external SDK needed
- **Schema-validated**: Every agent output validates against JSON Schema with auto-repair

## Architecture

The pipeline stages (from Cloudflare's Project Glasswing):

| # | Stage    | Purpose |
|---|----------|---------|
| 1 | Recon    | Map the repo, emit narrowly-scoped Hunt tasks |
| 2 | Hunt     | One attack class per agent; compile/run PoCs |
| 3 | Validate | Adversarial re-read; tries to **disprove** |
| 4 | Gapfill  | Re-queue under-covered areas |
| 5 | Dedupe   | Cluster findings by root cause |
| 6 | Trace    | Prove attacker-controlled input reaches the sink |
| 7 | Feedback | Turn reachable traces into new Hunt tasks |
| 8 | Report   | Schema-validated structured report |

## Quickstart

```bash
# Install
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Configure
export DEEPSEEK_API_KEY="sk-..."
export OPENAI_API_KEY="sk-..."

# Run
cyber-audit run --repo /path/to/target --run-id my-run
cyber-audit status --run-id my-run
cyber-audit report --run-id my-run --format md > report.md
```

## Configuration

Edit `config/stages.yaml` to change models, concurrency, or tools per stage. Default uses DeepSeek for deep reasoning stages (Recon, Validate, Trace) and OpenAI for high-throughput stages (Hunt, Gapfill, Dedupe, Report).

## Safety

Hunt agents compile and run PoC code. Run inside a disposable VM or container when auditing untrusted source code.

## License

MIT. Based on the architecture from Cloudflare's Project Glasswing blog post.
