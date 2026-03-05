# Architecture & Design

## System Overview

The Security Intelligence Engine is an LLM-powered analysis layer for Wazuh SIEM. It translates natural language questions into structured Wazuh alert queries, runs automated pattern detection, and produces professional SOC analyst reports — using any OpenAI-compatible LLM provider.

---

## Data Flow

```
User Query (natural language)
        │
        ▼
┌─── FastAPI Server (/query endpoint) ────────────────────────┐
│                                                              │
│  Step 1: INTERPRET                                           │
│  ┌──────────────────────────┐                                │
│  │  LLM Provider (any)      │  "Detect brute force attacks"  │
│  │  interpret_query()        │──→ {intent: pattern_detection, │
│  │  temp=0.1, 512 tokens     │     hours: 24,                │
│  └──────────────────────────┘     run_patterns: true,        │
│                                    pattern_types: [brute...]} │
│  Step 2: SEARCH                                              │
│  ┌──────────────────────────┐                                │
│  │  AlertProcessor           │  Load alerts.json             │
│  │  search_alerts()          │──→ Filter by time, level,     │
│  │                           │     agent, keywords           │
│  └──────────────────────────┘──→ 4,500 → 2,800 filtered     │
│                                                              │
│  Step 3: STATISTICS                                          │
│  ┌──────────────────────────┐                                │
│  │  AlertProcessor           │  Severity distribution        │
│  │  compute_stats()          │──→ Top rules, agents          │
│  │                           │     MITRE ATT&CK mapping      │
│  └──────────────────────────┘                                │
│                                                              │
│  Step 4: PATTERNS (conditional)                              │
│  ┌──────────────────────────┐                                │
│  │  PatternDetector          │  Brute force: 3 findings      │
│  │  run_pattern_detection()  │──→ Port scan: 0               │
│  │  6 algorithms             │     Priv esc: 1 finding       │
│  └──────────────────────────┘                                │
│                                                              │
│  Step 5: ANALYZE                                             │
│  ┌──────────────────────────┐                                │
│  │  LLM Provider (any)      │  Professional SOC report:      │
│  │  analyze_results()        │──→ Threat Assessment           │
│  │  SOC analyst persona      │     Key Findings              │
│  │  temp=0.4, 3000 tokens    │     Attack Patterns           │
│  └──────────────────────────┘     Recommendations            │
│                                                              │
└──────────────────────────────────────────────────────────────┘
        │
        ▼
  JSON Response → Dashboard / API consumer
```

---

## Module Dependency Graph

```
api_server.py (FastAPI backend)
  ├── modules/ai_query_engine.py    (LLM query/analysis)
  │     └── modules/llm_providers.py  (provider registry)
  ├── modules/llm_providers.py      (provider listing for dashboard)
  ├── modules/alert_processor.py    (data layer)
  ├── modules/pattern_detector.py   (detection algorithms)
  └── modules/wazuh_client.py       (Wazuh REST API)

dashboard.py (Streamlit web UI)
  ├── HTTP → api_server.py (:8000)
  └── modules/report_exporter.py    (HTML/PDF export)

analyze.py (CLI tool)
  ├── modules/alert_processor.py
  └── modules/pattern_detector.py

modules/action_broker.py (response actions)
  └── modules/incident_reporter.py

modules/incident_reporter.py (report generation)
  ├── modules/alert_processor.py    (lazy import, CLI mode)
  └── modules/pattern_detector.py   (lazy import, CLI mode)

modules/wazuh_links.py (standalone — no module dependencies)
modules/report_exporter.py (standalone — no module dependencies)
```

---

## LLM Integration Design

### Multi-Provider Architecture

All modern LLM APIs follow the OpenAI chat/completions format. The platform uses a single generic HTTP client (`llm_chat()` in `ai_query_engine.py`) that talks to any registered provider via the `PROVIDER_REGISTRY` in `llm_providers.py`.

```
┌─────────────────────────────────────────────────┐
│              llm_chat()                          │
│  Resolves provider → builds request → retries   │
└──────────────────────┬──────────────────────────┘
                       │ POST (OpenAI-compatible)
         ┌─────────────┼─────────────────────┐
         ▼             ▼                     ▼
    ┌─────────┐  ┌──────────┐  ┌──────────────────┐
    │  Groq   │  │  Ollama  │  │ OpenRouter/OpenAI │
    │  (cloud)│  │  (local) │  │ Claude/Gemini/HF  │
    └─────────┘  └──────────┘  └──────────────────┘
```

### Registered Providers

| Provider | Key | Protocol | Notes |
|----------|-----|----------|-------|
| Groq | `GROQ_API_KEY` | OpenAI-compatible | Default. Free tier: 30 req/min |
| Ollama | `OLLAMA_API_KEY` | OpenAI-compatible | Self-hosted, no rate limits |
| OpenRouter | `OPENROUTER_API_KEY` | OpenAI-compatible | 100+ models, free tiers available |
| OpenAI | `OPENAI_API_KEY` | Native | GPT-4o, GPT-4o-mini |
| Anthropic | `ANTHROPIC_API_KEY` | OpenAI-compatible | Claude Sonnet 4, Claude Haiku 4 |
| Google Gemini | `GOOGLE_API_KEY` | OpenAI-compatible | Gemini 2.0 Flash, 1.5 Pro |
| HuggingFace | `HUGGINGFACE_API_KEY` | OpenAI-compatible | Llama 3.3 70B, Mixtral, etc. |

Providers auto-appear in the dashboard when their API key is set. The user selects the active provider and model from the sidebar at runtime.

### Two LLM Calls Per Query

1. **Query Interpretation** (`interpret_query`)
   - Temperature: 0.1 (deterministic)
   - Max tokens: 512
   - Output: Structured JSON with search parameters
   - Purpose: Convert "detect brute force" → `{intent: "pattern_detection", run_patterns: true, ...}`

2. **Result Analysis** (`analyze_results`)
   - Temperature: 0.4 (slightly creative for report writing)
   - Max tokens: 3000
   - Output: Markdown report with sections
   - System prompt: Tier 2 SOC analyst persona (see `prompts/soc_analyst_system.md`)

### Rate Limit Handling

The `llm_chat()` client tracks rate-limit headers (where supported) and implements exponential backoff with up to 3 retries. Rate limit state is exposed via `get_rate_limit_info()` for dashboard display.

---

## Alert Processing Pipeline

### Data Source

Wazuh writes every alert as a JSON line to `/var/ossec/logs/alerts/alerts.json`. This file is:
- Append-only, owned by `root:wazuh`
- Contains all alerts from all agents
- Grows continuously (no rotation by default within a day)

### Processing Steps

1. **Load**: Read all lines from alerts.json, parse as JSON
2. **Filter**: Apply time range, severity, agent, keyword filters
3. **Enrich**: Extract MITRE ATT&CK, compliance mappings, source info
4. **Aggregate**: Compute stats (severity distribution, top rules, agent breakdown)
5. **Detect**: Run pattern detection algorithms on filtered set
6. **Format**: Output as summary, Markdown, JSON, or AI-ready package

---

## Pattern Detection Algorithms

Each detector follows the same pattern:
1. Filter alerts for relevant rule IDs/groups
2. Group by source (IP, user, or agent)
3. Apply sliding window for burst detection
4. Score severity and confidence
5. Return structured findings list

| Algorithm | What It Detects | Key Parameters |
|-----------|----------------|----------------|
| `detect_brute_force()` | Repeated auth failures from same source | threshold=5, window=10min |
| `detect_port_scan()` | Rapid port change events per agent | threshold=10, window=5min |
| `detect_privilege_escalation()` | sudo/su abuse, MITRE T1548 indicators | threshold=3, window=30min |
| `detect_lateral_movement()` | Same source IP across multiple agents | min_agents=2, window=30min |
| `detect_alert_bursts()` | Sudden spikes in alert volume | threshold=20, window=5min |
| `detect_compliance_failures()` | SCA check failures per agent | per-agent summary |

### Confidence Scoring

```
Base confidence: 0.5–0.6
+ Event count bonus: count × 0.02–0.03
+ Diversity bonus: unique commands × 0.04
+ Cross-agent bonus: +0.15 (lateral movement indicator)
Cap: 0.85–0.95
```

---

## Report Export Pipeline

`report_exporter.py` converts analysis output into distributable formats:

1. **Markdown** — raw `.md` (always available)
2. **Branded HTML** — styled report with header, embedded charts (via matplotlib), MITRE tables
3. **PDF** — via WeasyPrint or pdfkit (optional system dependencies)

The dashboard imports `report_exporter` directly for download buttons. Charts are generated as base64-encoded PNGs embedded in the HTML.

---

## Security Controls

### Read-Only Default

- `WazuhClient`: Enforces `read_only=True` — blocks PUT/POST/DELETE
- `AlertProcessor`: Only reads alerts.json, never writes
- `PatternDetector`: Pure analysis, no side effects

### Action Safety Gates

The `ActionBroker` has four layers:
1. **Validation**: Check required fields, rate limits
2. **Simulation**: Dry-run showing what *would* happen
3. **Approval**: Interactive prompt requiring explicit consent
4. **Audit**: Every action (approved or denied) logged to `logs/action_audit.jsonl`

### Actions by Risk Level

| Risk | Actions | Approval |
|------|---------|----------|
| LOW | Generate report, CDB entry, rule tuning | Simple y/N |
| MODERATE | Custom rules, agent group changes | y/N + justification |
| HIGH | Firewall block, service restart, disable user | Type "APPROVE" |

---

## Configuration

All config via `.env` file (never committed). See `.env.example` for the full reference.

### Wazuh Connection

| Variable | Purpose | Default |
|----------|---------|---------|
| `WAZUH_API_URL` | Wazuh REST API | `https://localhost:55000` |
| `WAZUH_API_USER` | API username | `wazuh` |
| `WAZUH_API_PASSWORD` | API password | (required) |
| `WAZUH_VERIFY_SSL` | SSL verification | `False` |
| `WAZUH_ALERT_FILE` | Alert JSON path | `/var/ossec/logs/alerts/alerts.json` |
| `WAZUH_DASHBOARD_URL` | For clickable report links | `https://localhost` |

### LLM Providers

Set any provider's API key to enable it. The first available provider becomes the default.

| Variable | Provider |
|----------|----------|
| `GROQ_API_KEY` | Groq Cloud (default) |
| `OLLAMA_API_URL` | Ollama (self-hosted) |
| `OPENROUTER_API_KEY` | OpenRouter |
| `OPENAI_API_KEY` | OpenAI |
| `ANTHROPIC_API_KEY` | Anthropic (Claude) |
| `GOOGLE_API_KEY` | Google Gemini |
| `HUGGINGFACE_API_KEY` | HuggingFace Inference |

---

## Deployment

### Ports

| Port | Service | Access |
|------|---------|--------|
| 8000 | FastAPI API server | LAN |
| 8501 | Streamlit dashboard | LAN |
| 55000 | Wazuh REST API | localhost only |

### sudo Requirements

The alert file `/var/ossec/logs/alerts/alerts.json` is owned by `root:wazuh`. The API server needs sudo to read it. The dashboard communicates with the API server over HTTP and does not need elevated privileges.

### Process Management

- **Development**: `bash start_dashboard.sh` — starts API + dashboard with health checks and clean shutdown
- **Production**: `sudo bash systemd/install-services.sh` — installs and enables `ai-soc-api.service` and `ai-soc-dashboard.service` for auto-start on boot
