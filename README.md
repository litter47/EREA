# EVA-Agent

**Exploit Verification Agent** — An HTTP + Containerized Runtime + LLM Agent + SSH Verification platform for exploit execution and verification.

> **Important**: This system is designed **only** for:
> - Docker-based target environments (labs/ranges)
> - Local experimental environments
> - Authorized security research
>
> It does **not** generate attack payloads. It is an **execution and verification framework** for user-provided exploits.

---

## Architecture

```
HTTP API (FastAPI)
    ↓
Task Manager (async queue)
    ↓
Execution Worker (orchestrator)
    ↓
┌─────────────────────────────────────────┐
│  1. SandboxExecutor (Docker container)  │
│  2. SSHVerificationAgent (asyncssh)     │
│  3. EvidenceBuilder                     │
│  4. RuleEngine (YAML rules)             │
│  5. LLM Judge (optional)                │
│  6. ReportGenerator (JSON + Markdown)   │
└─────────────────────────────────────────┘
```

- **Controller/Worker** pattern
- **Rule-first**: YAML rules work independently of LLM
- **LLM optional**: Hot-swappable LLM backend (OpenAI-compatible)

---

## Supported Verify Types

| Type | Description | Verification |
|------|-------------|-------------|
| `rce` | Remote Code Execution | Process, file, network side effects |
| `info_leak` | Information Leak | Sensitive file/content exposure |
| `priv_esc` | Privilege Escalation | UID/GID changes, sudo access |
| `auth_bypass` | Authentication Bypass | HTTP 401/403 → 200 transitions |

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+

### 1. Clone and configure

```bash
cp .env.example .env
```

### 2. Start the service

```bash
docker compose up --build
```

The API will be available at `http://localhost:8000`. OpenAPI docs at `http://localhost:8000/docs`.

### 3. Submit an exploit

```bash
curl -X POST http://localhost:8000/submit \
  -F "exploit_file=@exp.py" \
  -F "execute_cmd=python exp.py" \
  -F "target_ip=192.168.1.10" \
  -F "target_port=22" \
  -F "verify_type=rce" \
  -F "ssh_user=root" \
  -F "ssh_password=toor"
```

### 4. Check task status

```bash
curl http://localhost:8000/task/{task_id}
```

### 5. Get results

```bash
curl http://localhost:8000/result/{task_id}
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/submit` | Submit exploit for execution |
| `GET` | `/task/{task_id}` | Check task status |
| `GET` | `/result/{task_id}` | Get verification results |
| `GET` | `/docs` | OpenAPI documentation |

### POST /submit

**Content-Type**: `multipart/form-data`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `exploit_file` | file | Yes | Exploit file (.py, .jar, .go, .c, .cpp, .sh) |
| `execute_cmd` | string | Yes | Execution command (e.g., `python exp.py`) |
| `target_ip` | string | Yes | Target IP address |
| `target_port` | integer | Yes | SSH port (usually 22) |
| `verify_type` | string | Yes | `rce` / `info_leak` / `priv_esc` / `auth_bypass` |
| `ssh_user` | string | Yes | SSH username |
| `ssh_password` | string | No | SSH password |
| `ssh_key` | string | No | SSH private key content |

---

## LLM Configuration

LLM configuration is **completely decoupled from Docker images**. Change providers without rebuilding.

### Configuration Priority

```
Environment Variables  >  config/llm.yaml  >  Defaults
```

### LLM Provider Examples

#### OpenAI

```bash
# .env
EVA_LLM_PROVIDER=openai
EVA_LLM_BASE_URL=https://api.openai.com/v1
EVA_LLM_API_KEY=sk-your-key
EVA_LLM_MODEL=gpt-4.1
EVA_LLM_ENABLED=true
```

#### vLLM (self-hosted)

```bash
# .env
EVA_LLM_PROVIDER=openai
EVA_LLM_BASE_URL=http://your-vllm-server:8000/v1
EVA_LLM_API_KEY=not-needed
EVA_LLM_MODEL=meta-llama/Meta-Llama-3-70B-Instruct
EVA_LLM_ENABLED=true
```

#### Ollama (local)

```bash
# .env
EVA_LLM_PROVIDER=ollama
EVA_LLM_BASE_URL=http://host.docker.internal:11434/v1
EVA_LLM_API_KEY=not-needed
EVA_LLM_MODEL=qwen2.5
EVA_LLM_ENABLED=true
```

After changing `.env`:

```bash
docker compose restart
```

No image rebuild required.

### Disabling LLM

Set `EVA_LLM_ENABLED=false` (default). The rule engine alone provides the final verdict.

---

## Rule Engine

Verification rules are defined in YAML under `config/rules/`. Each verify type has its own rule file:

```yaml
# config/rules/rce.yaml
verify_type: rce
logic:
  operator: AND
  threshold: 0.5
checks:
  - name: exp_exit_code_zero
    type: exit_code
    params:
      expected: 0
    weight: 0.3
  - name: file_side_effect
    type: ssh_check
    params:
      check_name: file_side_effect
    weight: 0.3
  - name: process_running
    type: ssh_check
    params:
      check_name: process_running
    weight: 0.2
  - name: network_listening
    type: ssh_check
    params:
      check_name: network_listening
    weight: 0.2
```

Supported check types:
- `exit_code` — Check EXP exit code
- `ssh_check` — Match against SSH verification results
- `content_match` — Search stdout/stderr for patterns

Logic operators: `AND`, `OR` with optional `threshold`.

---

## Development

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run locally

```bash
python -m eva_agent.main
```

### Run tests

```bash
pytest tests/ -v
```

### Build runtime image

```bash
docker build -t eva-runtime:latest -f docker/runtime/Dockerfile docker/runtime/
```

---

## Project Structure

```
EREA/
├── eva_agent/            # Main application package
│   ├── main.py           # FastAPI entry point
│   ├── api/              # HTTP API (routes, models)
│   ├── task/             # Task manager + worker
│   ├── sandbox/          # Docker sandbox executor
│   ├── ssh/              # SSH verification agent
│   │   └── verifiers/    # Per-type verifiers
│   ├── evidence/         # Evidence builder
│   ├── rules/            # YAML rule engine
│   ├── llm/              # LLM client abstraction
│   ├── report/           # Report generator
│   └── config/           # Settings
├── config/               # Configuration files
│   ├── llm.yaml          # LLM provider config
│   └── rules/            # YAML verification rules
├── docker/
│   └── runtime/          # EXP runtime Docker image
├── tests/                # Test suite
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## Security

- API keys are **never** hardcoded — always injected via environment variables
- No privileged containers
- Resource limits enforced (512MB memory, 1 CPU)
- `no-new-privileges` security option
- Default task timeout: 300 seconds
- System is an **execution framework only** — does not generate attack payloads

---

## License

This project is for authorized security research and education only.
