# AgentAuth Identity (layer 1)

Attested agent credentials: JWT-SVID identity, Biscuit capability tokens,
proof-of-possession, and optional hosted FastAPI identity service.

## Quickstart

```bash
pip install -e ".[dev]"
python examples/01_quickstart.py
```

```python
from agentauth.identity import AgentAuth
```

## Run identity service

```bash
uvicorn agentauth.backend.main:app --reload
```

Layer 2 (dynamic capabilities): [agentauth-capabilities](https://github.com/pberlizov/agentauth-capabilities)
Layer 3 (receipts + verify): [agentauth-receipts](https://github.com/pberlizov/agentauth-receipts)
