# SentinelCore

**AI Threat Gateway** — an open-source security layer for LLM, RAG, and agentic AI systems.

SentinelCore sits between an AI application and the models, tools, and data it touches. It inspects prompts, retrieved context, tool calls, and model outputs for security threats, calculates risk, and enforces configurable policies (allow / warn / sanitize / block).

Part of the [CipherAI](https://cipherai.in) platform.

## Why this exists

Modern AI apps expose models to untrusted user input, external documents, tools, and other AI systems — a security boundary traditional AppSec tools don't cover. SentinelCore aims to be that layer: model-independent, modular, and measurable.

## Authenticity Policy

We never fabricate accuracy, precision, recall, F1, latency, or detection-rate numbers. Every claim in this repo reflects what is actually implemented and tested — not the long-term vision. Planned and experimental capabilities are always labeled as such.

## Current Status — v0.1.0-dev (Day 1-2)

| Component | Status |
|---|---|
| Repo scaffold | Done |
| FastAPI skeleton + health endpoint | Done |
| Security finding schema (Pydantic) | Done |
| Detector plugin interface + registry | Done |
| Prompt injection detector | Not started |
| Obfuscation detector | Not started |
| Risk engine | Not started |
| Policy engine | Not started |
| `/api/v1/scan` endpoint | Not started |
| Evaluation / benchmarks | Not started |
| Attack Replay Lab | Not started |

**No detection capability exists yet.** This is infrastructure only — an honest baseline, not a demo dressed up to look further along than it is.

## Quickstart

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Visit `http://localhost:8000/api/v1/health`.

Run tests:

```bash
pytest --cov=app tests/ -v
```

## Architecture (target)

```
AI APPLICATION -> SentinelCore Threat Gateway
                     |-- Input Guard
                     |-- Context Guard
                     `-- Output Guard
                           |
                     Risk Engine -> Policy Engine -> ALLOW / WARN / SANITIZE / BLOCK
```

Full design docs land in `docs/architecture/` as each phase ships.

## Adding a detector

Detectors are self-contained plugins — no core files need to change. See `CONTRIBUTING.md`.

## Roadmap

Ten-phase roadmap, currently in Phase 1 (Foundation). Phase 2 (prompt injection + obfuscation detectors) is next.

## License

MIT — see `LICENSE`.
