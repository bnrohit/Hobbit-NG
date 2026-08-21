# Hobbit-NG Security Assessment Framework

Hobbit-NG is an **authorized-use-only** security assessment and posture-analysis framework. It combines bounded asynchronous discovery, TCP exposure checks, conservative service identification, defensive finding correlation, compliance scaffolding, supply-chain/SBOM parsing, and plan-only purple-team/Zero Trust workflows.

> **Legal and ethical use:** Run active scans only against systems you own or have explicit written permission to assess. The CLI requires `--ack-authorized` before active network scanning. The API requires `authorized=true` for the same reason.

## What this baseline intentionally does not do

Hobbit-NG does not include credential brute forcing, exploit delivery, persistence, destructive actions, automatic lateral movement, secret harvesting, or automatic remediation execution. Purple-team mode is validation-plan-only. Deception mode is plan-only.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python hobbit.py --help
python hobbit.py -t 192.168.1.0/24 --ack-authorized --scan-depth quick -o report.json
```

For a single host:

```bash
python hobbit.py -t 10.0.0.10 --ack-authorized --modules portscan,service_detect,vulnscan,webscan
```

## API

Set a strong JWT secret and start Redis first. Development login is disabled unless explicitly enabled.

```bash
export JWT_SECRET="replace-with-a-long-random-secret"
uvicorn src.api.server:app --host 127.0.0.1 --port 8000
```

## Docker Compose

```bash
export JWT_SECRET="replace-with-a-long-random-secret"
docker compose -f infrastructure/docker/docker-compose.yml up --build
```

The worker intentionally does **not** mount `/var/run/docker.sock`.

## Security design

- Explicit authorization acknowledgement for active scans
- Bounded CIDR expansion and concurrency
- No hard-coded JWT, database, or provider API secrets
- Development authentication disabled by default
- Namespace-scoped Kubernetes RBAC with no Secret read permission
- Non-root containers
- Automatic remediation execution disabled
- HTML report fields escaped before rendering

## Structure

- `hobbit.py` — CLI
- `src/core` — scan orchestration
- `src/modules` — bounded active checks and defensive modules
- `src/api` — FastAPI service
- `src/workers` — Celery scan worker
- `src/ai_engine` — deduplication/planning scaffolding
- `src/threat_intel`, `src/graph_analysis`, `src/supply_chain` — enrichment scaffolding
- `src/remediation`, `src/compliance`, `src/deception` — defensive workflows
- `infrastructure` — Docker and Kubernetes deployment manifests
- `tests` — baseline safety and engine tests

## Status

Version 3.0.0 is a production-oriented **baseline**, not a claim of complete enterprise pentest automation. Several enrichment integrations intentionally remain adapters/scaffolds until provider credentials, schemas, storage, and test fixtures are supplied.

## License

MIT. See `LICENSE`.
