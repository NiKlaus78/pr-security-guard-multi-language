# PR Security Guard — Multi-Language Edition

Enterprise-grade AI agent that intercepts pull requests across **Java, JavaScript/Node.js,
and Python** repositories, scans for security violations, runs a self-reflection critique
loop, and blocks merges on confirmed threats.

## What's new in this version

The agent now detects and scans THREE dependency manifest formats in the same PR:

| Manifest | Ecosystem | Language |
|---|---|---|
| `pom.xml` | Maven | Java |
| `package.json` | npm | JavaScript / TypeScript / Node.js |
| `requirements.txt` | PyPI | Python |

This works even in a single PR touching multiple languages (monorepo scenario) —
all three manifests are detected and scanned in parallel.

The secret-detection regex and Mistral Codestral semantic analysis already worked
across any language; this update adds proper CVE/dependency scanning for npm and PyPI
ecosystems to match what already existed for Maven.

## Architecture

```
GitHub PR Event (any language)
      |
      v
Spring Boot Webhook Service
      |  detects pom.xml / package.json / requirements.txt in diff
      |  fetches FULL content of each detected manifest
      v
Python LangGraph Agent
  +-- Stage 1: Regex Pre-filter           (language-agnostic secrets)
  +-- Stage 2: CVE Scanner                (Maven + npm + PyPI via OSV API)
  +-- Stage 3: Mistral Codestral Analyzer (language-aware semantic analysis)
  +-- Stage 4: Self-Reflection Critique
  +-- Stage 5: Gate Decision -> GitHub Status API
      |
      v
PostgreSQL (audit log) + LangSmith (tracing)
```

## Project Structure

```
pr-security-guard/
├── webhook-service/              # Spring Boot — receives GitHub webhooks
│   └── src/main/java/com/security/guard/
│       ├── controller/           # WebhookController, FindingsController
│       ├── service/              # Orchestrator, DiffExtractor, GitHubComment
│       ├── model/                # Request/response/entity models
│       └── config/               # Security + WebClient config
├── agent/                        # Python LangGraph agent
│   ├── main.py                   # FastAPI entry point
│   ├── graph.py                  # LangGraph pipeline definition
│   ├── nodes.py                  # Pipeline stage implementations
│   ├── prompts/                  # Language-agnostic LLM prompts
│   └── tools/
│       └── cve_checker.py        # Multi-ecosystem CVE scanning (Maven/npm/PyPI)
├── samples/                      # Sample vulnerable projects for testing
│   ├── nodejs-payment-service/   # JavaScript/Node.js test project
│   └── python-fraud-detection/   # Python test project
├── docker/
│   ├── Dockerfile.webhook
│   ├── Dockerfile.agent
│   └── docker-compose.yml
└── .github/workflows/
```

## Quick Start

### Prerequisites
- Java 17+, Maven 3.8+
- Docker & Docker Compose
- Mistral AI API key (console.mistral.ai)
- LangSmith API key (free tier — smith.langchain.com)
- GitHub Personal Access Token with `repo` + `write:discussion` scopes

### 1. Set environment variables

```bash
cp .env.example docker/.env
# Fill in: MISTRAL_API_KEY, LANGSMITH_API_KEY, GITHUB_TOKEN, GITHUB_WEBHOOK_SECRET
```

### 2. Start with Docker Compose

```bash
cd docker
docker-compose up --build
```

### 3. Expose locally with a tunnel

```bash
cloudflared tunnel --url http://localhost:8080
```

### 4. Test against each language

**Java:** use your existing webhook-service repo (already has pom.xml).

**JavaScript/Node.js:**
1. Create a new GitHub repo, e.g. `nodejs-payment-service-test`
2. Push the contents of `samples/nodejs-payment-service/` as the initial commit
3. Register the webhook on this repo (same payload URL, same secret)
4. Open a PR with a small change — the existing hardcoded secrets and
   vulnerable npm dependencies should get flagged automatically

**Python:**
1. Create a new GitHub repo, e.g. `python-fraud-detection-test`
2. Push the contents of `samples/python-fraud-detection/` as the initial commit
3. Register the webhook on this repo
4. Open a PR — hardcoded secrets, eval()/pickle.loads() risks, and
   vulnerable PyPI dependencies (flask, pyyaml, jinja2, etc.) should get flagged

See each sample folder's README.md for the exact expected findings.

## Environment Variables

| Variable | Description |
|---|---|
| `MISTRAL_API_KEY` | Your Mistral API key |
| `LANGSMITH_API_KEY` | LangSmith tracing key |
| `LANGSMITH_PROJECT` | LangSmith project name |
| `GITHUB_TOKEN` | GitHub token for posting comments |
| `GITHUB_WEBHOOK_SECRET` | Secret for validating webhook signatures |
| `DATABASE_URL` | PostgreSQL connection string |
| `AGENT_SERVICE_URL` | Internal URL of the Python agent service |
| `CONFIDENCE_THRESHOLD` | Min confidence to block merge (default: 0.85) |

## How multi-language detection works

1. Spring Boot's `PrScanOrchestrator` checks the diff for the presence of
   `pom.xml`, `package.json`, or `requirements.txt` — any combination, even
   all three at once in a monorepo PR
2. For each detected manifest, it extracts the real repo-relative path
   (handles subdirectories like `backend/pom.xml` or `frontend/package.json`)
   and fetches the FULL file content via the GitHub Contents API
3. All manifest contents are sent to the Python agent in one request
4. The agent's `cve_scanner_node` runs the appropriate extractor for each:
   - `extract_dependencies_from_full_pom()` — resolves Spring Boot BOM versions too
   - `extract_dependencies_from_package_json()` — strips npm semver prefixes (^, ~)
   - `extract_dependencies_from_requirements_txt()` — parses pinned `==` versions
5. All dependencies across all ecosystems are batched into a single OSV API
   query, deduplicated per dependency, and merged into the final findings list
