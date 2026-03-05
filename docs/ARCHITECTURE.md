# AI-SOC Architecture & Design

## System Overview

AI-SOC is an LLM-powered security analysis platform that sits on top of Wazuh SIEM. It combines traditional alert processing and pattern detection with cloud LLM analysis to provide natural-language security querying.

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
│  │  Groq LLM API            │  "Detect brute force attacks"  │
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
│  │  Groq LLM API            │  Professional SOC report:      │
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
api_server.py
  ├── modules/ai_query_engine.py    (Groq LLM)
  ├── modules/alert_processor.py    (data layer)
  ├── modules/pattern_detector.py   (analysis)
  └── modules/wazuh_client.py       (API client)

dashboard.py
  └── HTTP → api_server.py (:8000)

analyze.py (CLI)
  ├── modules/alert_processor.py
  └── modules/pattern_detector.py

modules/action_broker.py
  └── modules/incident_reporter.py

modules/incident_reporter.py
  ├── modules/alert_processor.py
  └── modules/pattern_detector.py
```

---

## LLM Integration Design

### Provider: Groq Cloud API

| Property | Value |
|----------|-------|
| Endpoint | `https://api.groq.com/openai/v1/chat/completions` |
| Model | `llama-3.3-70b-versatile` |
| Protocol | OpenAI-compatible REST API |
| Auth | Bearer token (API key) |
| Free tier | 30 req/min, 14,400 req/day |
| Typical latency | 0.5–1.5 seconds |

### Why Groq (not local Ollama)

We originally tried **Ollama with llama3.2:3b** running locally on CPU. Results:
- Inference took **>120 seconds** per query on CPU-only hardware
- Consistently timed out even with 300s timeout + streaming
- 3B parameter model produced mediocre security analysis

Groq cloud provides:
- **Sub-second** inference (700ms typical)
- Access to **70B parameter** model (much better analysis quality)
- Free tier is sufficient for SOC analyst usage patterns
- Ollama remains installed as potential offline fallback

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

---

## Alert Processing Pipeline

### Data Source

Wazuh writes every alert as a JSON line to `/var/ossec/logs/alerts/alerts.json`. This file is:
- Append-only, owned by root
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

### Confidence Scoring

```
Base confidence: 0.5–0.6
+ Event count bonus: count × 0.02–0.03
+ Diversity bonus: unique commands × 0.04
+ Cross-agent bonus: +0.15 (lateral movement indicator)
Cap: 0.85–0.95
```

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
4. **Audit**: Every action (approved or denied) logged to JSONL

### Actions by Risk Level

| Risk | Actions | Approval |
|------|---------|----------|
| LOW | Generate report, CDB entry, rule tuning | Simple y/N |
| MODERATE | Custom rules, agent group changes | y/N + justification |
| HIGH | Firewall block, service restart, disable user | Type "APPROVE" |

---

## Configuration

All config via `.env` file (never committed):

| Variable | Purpose | Default |
|----------|---------|---------|
| `WAZUH_API_URL` | Wazuh REST API | `https://localhost:55000` |
| `WAZUH_API_USER` | API username | `wazuh` |
| `WAZUH_API_PASSWORD` | API password | (required) |
| `WAZUH_VERIFY_SSL` | SSL verification | `False` |
| `WAZUH_ALERT_FILE` | Alert JSON path | `/var/ossec/logs/alerts/alerts.json` |
| `GROQ_API_KEY` | Groq API key | (required) |
| `GROQ_MODEL` | LLM model name | `llama-3.3-70b-versatile` |

---

## Deployment Notes

### Ports

| Port | Service | Access |
|------|---------|--------|
| 8000 | FastAPI API server | LAN |
| 8501 | Streamlit dashboard | LAN |
| 55000 | Wazuh REST API | localhost only |

### sudo Requirements

The alert file `/var/ossec/logs/alerts/alerts.json` is owned by `root:wazuh`. The API server and CLI tools need sudo to read it. The dashboard itself does not — it communicates with the API server over HTTP.

### Process Management

Currently managed via `start_dashboard.sh` which:
1. Starts API server as background process
2. Waits for health check on :8000
3. Starts Streamlit as background process
4. Waits for health check on :8501
5. Traps Ctrl+C to clean shutdown both

For production, consider systemd units or supervisord.

---

*Architecture document — AI-SOC Integration Project — February 2026*
