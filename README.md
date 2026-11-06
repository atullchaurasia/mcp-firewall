# MCP Firewall

An agent-agnostic prompt-injection defense for the Model Context Protocol (MCP).

MCP Firewall is a proxy that sits between any AI agent and the MCP servers it uses. It labels tools,
tracks the provenance of untrusted data, enforces policies before every tool call (allow / ask / block),
scans tool descriptions for poisoning, pins them against rug pulls, and logs every decision.

> Status: early development (Phase 0). Quickstart and demo coming with `v0.1.0`.

## Development

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux
pip install -e ".[dev]"
pytest -q
```

## License

MIT
