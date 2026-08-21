# Hobbit-NG Security Assessment Framework

Hobbit-NG is an **authorized-use-only** security assessment, exposure monitoring, and posture-analysis framework. Version 3.1 turns the original point-in-time scanner into a lightweight continuous-security platform by adding asset inventory, deterministic finding correlation, baseline comparison, and security drift detection.

> **Legal and ethical use:** Run active scans only against systems you own or have explicit written permission to assess. The CLI requires `--ack-authorized` before active network scanning. The API requires `authorized=true`.

## Why Hobbit-NG is useful

A one-time port scan answers **what is reachable now**. Hobbit-NG can also answer **what changed since the last approved scan**:

- Which assets are new or missing?
- Which ports opened or closed?
- Which findings are new, persistent, or resolved?
- Did the overall risk score increase?
- Which assets have the highest exposure score?
- Did a change introduce a security regression that should fail CI or trigger review?

This makes it useful for recurring network-security checks, change validation, exposure monitoring, and remediation verification.

## Core capabilities

- Bounded asynchronous host discovery and TCP exposure checks
- Conservative service identification and banner collection
- Defensive exposure findings with evidence and remediation guidance
- Stable finding fingerprints for correlation across scans
- Asset inventory with per-host exposure scoring
- Baseline and drift analysis
- New/resolved finding tracking
- New/removed host tracking
- Opened/closed port tracking
- CI-friendly regression exit code
- Target allowlist/denylist policy controls
- HTML and JSON reporting
- Redis + Celery distributed scan worker
- FastAPI service with tenant checks and result retrieval
- Supply-chain/SBOM parsing scaffolding
- Compliance, Zero Trust, attack-graph, threat-intelligence, and remediation scaffolding
- Plan-only purple-team and deception workflows

## Safety boundaries

Hobbit-NG intentionally does **not** include credential brute forcing, exploit delivery, persistence, destructive actions, automatic lateral movement, secret harvesting, or automatic remediation execution. Purple-team mode is validation-plan-only. Deception mode is plan-only.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python hobbit.py --help
```

Authorized quick scan:

```bash
python hobbit.py \
  -t 192.168.1.0/24 \
  --ack-authorized \
  --scan-depth quick \
  -o reports/current.json
```

Single host:

```bash
python hobbit.py \
  -t 10.0.0.10 \
  --ack-authorized \
  --modules portscan,service_detect,vulnscan,webscan
```

## Continuous-security workflow

### 1. Create a known-good baseline

```bash
python hobbit.py \
  -t 10.20.0.0/24 \
  --ack-authorized \
  --scan-depth standard \
  -o reports/day-1.json \
  --save-baseline baselines/site-a.json
```

### 2. Compare a later scan with that baseline

```bash
python hobbit.py \
  -t 10.20.0.0/24 \
  --ack-authorized \
  --baseline baselines/site-a.json \
  -o reports/day-2.json
```

The report gains a `drift` section containing new/resolved findings, host changes, port changes, and risk delta.

### 3. Fail a pipeline when security regresses

```bash
python hobbit.py \
  -t 10.20.0.0/24 \
  --ack-authorized \
  --baseline baselines/site-a.json \
  --fail-on-regression \
  -o reports/current.json
```

Exit code `2` means the comparison found a new host, newly opened port, or new finding.

### 4. Compare two existing reports without scanning

This mode is passive and performs no network activity:

```bash
python hobbit.py --compare-reports reports/day-1.json reports/day-2.json
```

Use `--fail-on-regression` with the same command for CI/change-control workflows.

## Asset inventory

Every scan report contains `asset_inventory`, including:

- asset count
- total observed open ports
- services per asset
- finding counts and severity breakdown
- sensitive-service observations
- exposure score per asset

Write the inventory separately when needed:

```bash
python hobbit.py \
  -t 10.20.0.0/24 \
  --ack-authorized \
  --inventory-output reports/site-a-inventory.json
```

## Target scope policy

For production use, enable the allowlist in `config/default.yaml` or a site-specific config:

```yaml
target_policy:
  enforce_allowlist: true
  allowed_networks:
    - "10.20.0.0/16"
    - "10.30.40.0/24"
  denied_networks:
    - "10.20.250.0/24"
  allowed_hostnames:
    - "*.lab.example.org"
  denied_hostnames:
    - "sensitive.lab.example.org"
```

When allowlist enforcement is enabled, an out-of-scope target is rejected before any active scan begins.

## API

Set a strong JWT secret and start Redis first. Development login is disabled unless explicitly enabled.

```bash
export JWT_SECRET="replace-with-a-long-random-secret"
uvicorn src.api.server:app --host 127.0.0.1 --port 8000
```

Important endpoints:

- `POST /scans`
- `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/results`
- `POST /remediate` (dry-run only in the baseline)
- `GET /health`

Interactive API documentation is available at `/docs` while the API is running.

## Docker Compose

```bash
export JWT_SECRET="replace-with-a-long-random-secret"
docker compose -f infrastructure/docker/docker-compose.yml up --build
```

The worker intentionally does **not** mount `/var/run/docker.sock`.

## Security design

- Explicit authorization acknowledgement for active scans
- Optional target allowlist/denylist enforcement
- Bounded per-target and total host expansion
- Shared connection concurrency limits
- Per-host failure isolation
- No hard-coded JWT, database, or provider API secrets
- Development authentication disabled by default
- Namespace-scoped Kubernetes RBAC with no Secret read permission
- Non-root containers
- Automatic remediation execution disabled
- HTML report fields escaped before rendering
- Stable fingerprints instead of unstable random finding IDs

## Structure

- `hobbit.py` — CLI and offline report comparison
- `src/core/engine.py` — scan orchestration
- `src/core/baseline.py` — finding fingerprints and drift analysis
- `src/core/inventory.py` — asset inventory and exposure scoring
- `src/core/policy.py` — target-scope enforcement
- `src/modules` — bounded active checks and defensive modules
- `src/api` — FastAPI service
- `src/workers` — Celery scan worker
- `src/ai_engine` — deterministic correlation and planning scaffolding
- `src/threat_intel`, `src/graph_analysis`, `src/supply_chain` — enrichment scaffolding
- `src/remediation`, `src/compliance`, `src/deception` — defensive workflows
- `infrastructure` — Docker and Kubernetes deployment manifests
- `docs/OPERATIONS.md` — practical recurring-use workflow
- `tests` — safety, drift, policy, inventory, and engine tests

## Status

Version 3.1.0 is a production-oriented defensive baseline. Some enrichment integrations remain adapters/scaffolds until provider credentials, persistence schemas, and representative test fixtures are supplied.

## License

MIT. See `LICENSE`.
