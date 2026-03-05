#!/usr/bin/env python3
"""
AllysecLabs Security Intelligence Platform - API Backend
AI-powered threat detection and analysis engine

Run with: uvicorn api_server:app --reload --port 8000
Or: python api_server.py
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import uvicorn
import json
import sys
import logging
from datetime import datetime, timedelta
from pathlib import Path

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.wazuh_client import WazuhClient
from modules.alert_processor import AlertProcessor
from modules.pattern_detector import PatternDetector
from modules.ai_query_engine import (
    interpret_query,
    analyze_results,
    check_ollama_status,
    check_llm_status,
    llm_chat,
    quick_threat_assessment,
    get_rate_limit_info,
)
from modules.llm_providers import (
    get_available_providers,
    get_provider_config,
    get_default_provider,
    discover_models,
    check_provider_health,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════
# Initialize FastAPI
# ══════════════════════════════════════════════════════

app = FastAPI(
    title="AllysecLabs Security Intelligence API",
    description="AI-Powered Threat Detection & Analysis for Wazuh SIEM",
    version="2.0.0"
)

# CORS middleware for browser access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ══════════════════════════════════════════════════════
# Pydantic Models
# ══════════════════════════════════════════════════════

class QueryRequest(BaseModel):
    query: str
    options: Optional[Dict[str, Any]] = {}
    report_depth: Optional[str] = "summary"  # "summary" (default fast view) or "full" (enterprise professional report)
    provider: Optional[str] = None   # LLM provider ID (e.g., "groq", "ollama"). None = default.
    model: Optional[str] = None      # Specific model to use. None = provider's default.

class QueryResponse(BaseModel):
    success: bool
    query: str
    interpretation: Dict[str, Any]
    alert_count: int
    stats: Optional[Dict[str, Any]] = None
    patterns: Optional[Dict[str, Any]] = None
    pattern_count: Optional[int] = 0
    ai_analysis: Optional[str] = None
    threat_level: Optional[str] = None
    recommendations: Optional[List[str]] = None
    timestamp: str

# ══════════════════════════════════════════════════════
# Constants & Helpers
# ══════════════════════════════════════════════════════

ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"

def parse_wazuh_timestamp(timestamp_str: str) -> Optional[datetime]:
    """Parse Wazuh timestamp robustly"""
    if not timestamp_str:
        return None
    for fmt in ['%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z',
                '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S']:
        try:
            dt = datetime.strptime(timestamp_str, fmt)
            if dt.tzinfo is not None:
                dt = dt.replace(tzinfo=None)
            return dt
        except (ValueError, AttributeError):
            continue
    return None


def search_alerts(params: Dict[str, Any]) -> tuple:
    """Search and filter alerts based on LLM-interpreted parameters"""
    processor = AlertProcessor(alert_file=ALERT_FILE)
    all_alerts = processor.load_alerts()

    hours = int(params.get("hours", 24))
    min_level = int(params.get("min_level", 0))
    max_level = int(params.get("max_level", 15))
    agent_name = params.get("agent_name")
    rule_keywords = params.get("rule_keywords", [])
    os_filter = params.get("os_context", "unknown")  # NEW: OS filtering

    threshold_time = datetime.now() - timedelta(hours=hours)

    filtered = []
    for alert in all_alerts:
        alert_time = parse_wazuh_timestamp(alert.get('timestamp', ''))
        if alert_time and alert_time < threshold_time:
            continue

        alert_level = alert.get('rule', {}).get('level', 0)
        if not (min_level <= alert_level <= max_level):
            continue

        if agent_name:
            alert_agent = alert.get('agent', {}).get('name', '')
            if agent_name.lower() not in alert_agent.lower():
                continue

        # NEW: OS-based filtering
        if os_filter and os_filter not in ("unknown", "both", "all"):
            if not _alert_matches_os(alert, os_filter):
                continue

        if rule_keywords:
            rule_desc = alert.get('rule', {}).get('description', '').lower()
            rule_groups = ' '.join(alert.get('rule', {}).get('groups', [])).lower()
            full_text = f"{rule_desc} {rule_groups}"
            matched_kw = [kw for kw in rule_keywords if kw.lower() in full_text]
            if not matched_kw:
                continue
            # Store relevance score for smarter sampling (more keyword matches = higher relevance)
            alert['_relevance'] = len(matched_kw) / len(rule_keywords)

        filtered.append(alert)

    return filtered, len(all_alerts)


# ══════════════════════════════════════════════════════
# OS Detection for Agents
# ══════════════════════════════════════════════════════

# Known agent-to-OS mapping (customize for your environment)
AGENT_OS_MAP = {
    # Linux agents
    "wazuhserver": "linux",
    "server": "linux",
    "ubuntu": "linux",
    "centos": "linux",
    "debian": "linux",
    "rhel": "linux",
    "fedora": "linux",
    "cloudoffice": "linux",
    # Windows agents
    "desktop": "windows",
    "win": "windows",
    "windows": "windows",
    "allyshipgloballtd": "windows",  # Based on user's environment
    # macOS agents
    "mac": "macos",
    "macos": "macos",
    "macbook": "macos",
    "imac": "macos",
}

# Rule groups that indicate OS
LINUX_RULE_GROUPS = {
    "syslog", "pam", "sshd", "ssh", "sudo", "authentication_success", 
    "authentication_failed", "adduser", "linux", "unix", "dpkg", "apt",
    "yum", "systemd", "cron", "postfix", "dovecot", "nginx", "apache",
    "iptables", "firewalld", "audit", "auditd", "centos", "ubuntu",
    "debian", "rhel", "fedora", "ossec"
}

WINDOWS_RULE_GROUPS = {
    "windows", "win_eventlog", "win_application", "win_security", 
    "win_system", "sysmon", "powershell", "windows_audit", "wmi",
    "active_directory", "ad", "ms", "microsoft", "iis", "mssql",
    "windows_defender", "defender", "rdp", "cis_win", "sca_win"
}

MACOS_RULE_GROUPS = {
    "macos", "osx", "apple", "darwin"
}


def _detect_agent_os(agent_name: str) -> str:
    """Detect OS from agent name using known mappings and heuristics"""
    if not agent_name:
        return "unknown"
    
    name_lower = agent_name.lower()
    
    # Check exact or partial matches in our map
    for pattern, os_type in AGENT_OS_MAP.items():
        if pattern in name_lower:
            return os_type
    
    # Heuristics based on common naming patterns
    if any(x in name_lower for x in ["desktop-", "pc-", "laptop-", "workstation"]):
        return "windows"  # Most desktops are Windows
    if any(x in name_lower for x in ["srv", "server", "vm-", "node"]):
        return "linux"  # Most servers are Linux
    
    return "unknown"


def _detect_rule_os(rule_groups: list) -> str:
    """Detect OS from rule groups"""
    if not rule_groups:
        return "unknown"
    
    groups_set = set(g.lower() for g in rule_groups)
    
    linux_matches = len(groups_set & LINUX_RULE_GROUPS)
    windows_matches = len(groups_set & WINDOWS_RULE_GROUPS)
    macos_matches = len(groups_set & MACOS_RULE_GROUPS)
    
    if windows_matches > linux_matches and windows_matches > macos_matches:
        return "windows"
    elif linux_matches > windows_matches and linux_matches > macos_matches:
        return "linux"
    elif macos_matches > 0:
        return "macos"
    
    # Check for CIS benchmarks which are OS-specific
    groups_str = ' '.join(rule_groups).lower()
    if 'cis microsoft windows' in groups_str or 'win' in groups_str:
        return "windows"
    if 'cis centos' in groups_str or 'cis ubuntu' in groups_str or 'cis debian' in groups_str:
        return "linux"
    if 'cis apple' in groups_str or 'macos' in groups_str:
        return "macos"
    
    return "unknown"


def _alert_matches_os(alert: dict, target_os: str) -> bool:
    """
    Check if an alert matches the target OS.
    Uses multiple detection methods for accuracy.
    """
    target_os = target_os.lower()
    
    # Handle macOS aliases
    if target_os in ("macos", "mac", "osx", "darwin"):
        target_os = "macos"
    
    # Method 1: Check agent name
    agent_name = alert.get('agent', {}).get('name', '')
    agent_os = _detect_agent_os(agent_name)
    
    if agent_os != "unknown" and agent_os == target_os:
        return True
    if agent_os != "unknown" and agent_os != target_os:
        return False
    
    # Method 2: Check rule groups
    rule_groups = alert.get('rule', {}).get('groups', [])
    rule_os = _detect_rule_os(rule_groups)
    
    if rule_os != "unknown" and rule_os == target_os:
        return True
    if rule_os != "unknown" and rule_os != target_os:
        return False
    
    # Method 3: Check rule description for OS keywords
    rule_desc = alert.get('rule', {}).get('description', '').lower()
    
    if target_os == "windows":
        if any(x in rule_desc for x in ['windows', 'microsoft', 'powershell', 'registry', 'uac', 'eventlog']):
            return True
    elif target_os == "linux":
        if any(x in rule_desc for x in ['linux', 'unix', 'ssh', 'sudo', 'pam', 'syslog', 'dpkg', 'apt', 'yum']):
            return True
    elif target_os == "macos":
        if any(x in rule_desc for x in ['macos', 'mac os', 'osx', 'apple', 'darwin']):
            return True
    
    # If we can't determine OS, include the alert (avoid false negatives)
    # But only if target_os detection is uncertain
    return agent_os == "unknown" and rule_os == "unknown"


# ══════════════════════════════════════════════════════
# Stratified Alert Sampling
# ══════════════════════════════════════════════════════

def stratified_sample(alerts: list, max_samples: int = 20) -> list:
    """
    Intelligently sample alerts to maximize diversity for LLM analysis.
    Prevents the LLM from seeing 20 identical low-severity alerts while
    critical high-severity events are buried deeper in the dataset.

    Strategy:
    1. One representative from each unique high-severity rule (level >= 10)
    2. One representative from each remaining unique rule ID
    3. Additional high-severity alerts (up to half budget)
    4. Diversify by source IP to avoid repetition
    5. Fill remaining with relevance-scored alerts
    6. Sort result by severity (highest first)
    """
    if not alerts:
        return []
    if len(alerts) <= max_samples:
        return sorted(alerts, key=lambda a: a.get('rule', {}).get('level', 0), reverse=True)

    selected = []
    selected_indices = set()
    seen_rules = set()

    # Phase 1: One representative from EACH unique high-severity rule (level >= 10)
    for i, alert in enumerate(alerts):
        level = alert.get('rule', {}).get('level', 0)
        rule_id = alert.get('rule', {}).get('id', '')
        if level >= 10 and rule_id not in seen_rules:
            selected.append(alert)
            selected_indices.add(i)
            seen_rules.add(rule_id)
            if len(selected) >= max_samples:
                break

    # Phase 2: One representative from each remaining unique rule ID
    for i, alert in enumerate(alerts):
        if len(selected) >= max_samples:
            break
        if i in selected_indices:
            continue
        rule_id = alert.get('rule', {}).get('id', '')
        if rule_id not in seen_rules:
            selected.append(alert)
            selected_indices.add(i)
            seen_rules.add(rule_id)

    # Phase 3: Additional high-severity alerts (up to half of budget) for depth
    high_budget = max_samples // 2
    high_count = sum(1 for a in selected if a.get('rule', {}).get('level', 0) >= 10)
    for i, alert in enumerate(alerts):
        if len(selected) >= max_samples or high_count >= high_budget:
            break
        if i in selected_indices:
            continue
        level = alert.get('rule', {}).get('level', 0)
        if level >= 10:
            selected.append(alert)
            selected_indices.add(i)
            high_count += 1

    # Phase 4: Diversify by source IP — avoid showing same attacker repeatedly
    seen_src_ips = {a.get('data', {}).get('srcip', '') for a in selected} - {''}
    for i, alert in enumerate(alerts):
        if len(selected) >= max_samples:
            break
        if i in selected_indices:
            continue
        src_ip = alert.get('data', {}).get('srcip', '')
        if src_ip and src_ip not in seen_src_ips:
            selected.append(alert)
            selected_indices.add(i)
            seen_src_ips.add(src_ip)

    # Phase 5: Prefer higher-relevance alerts (from keyword matching scores)
    remaining = [(i, a) for i, a in enumerate(alerts) if i not in selected_indices]
    remaining.sort(key=lambda x: x[1].get('_relevance', 0.5), reverse=True)

    for i, alert in remaining:
        if len(selected) >= max_samples:
            break
        selected.append(alert)
        selected_indices.add(i)

    # Sort by severity (highest first) so LLM sees critical items first
    selected.sort(
        key=lambda a: (a.get('rule', {}).get('level', 0), a.get('_relevance', 0.5)),
        reverse=True
    )
    return selected


def run_pattern_detection(alerts: list, pattern_types: list = None) -> Dict[str, List]:
    """Run requested pattern detection algorithms"""
    detector = PatternDetector()
    if not pattern_types:
        pattern_types = ["brute_force", "port_scan", "privilege_escalation",
                         "lateral_movement", "compliance", "alert_bursts"]

    type_to_method = {
        "brute_force": detector.detect_brute_force,
        "port_scan": detector.detect_port_scan,
        "privilege_escalation": detector.detect_privilege_escalation,
        "lateral_movement": detector.detect_lateral_movement,
        "compliance": detector.detect_compliance_failures,
        "alert_bursts": detector.detect_alert_bursts,
    }

    results = {}
    for ptype in pattern_types:
        method = type_to_method.get(ptype)
        if method:
            try:
                results[ptype] = method(alerts)
            except Exception as e:
                logger.warning(f"Pattern detection '{ptype}' failed: {e}")
                results[ptype] = []
    return results

# ══════════════════════════════════════════════════════
# API Routes
# ══════════════════════════════════════════════════════

@app.on_event("startup")
async def startup_event():
    """Initialize on server start"""
    print("🚀 Starting AllysecLabs Security Intelligence API...")
    
    # Check all configured providers
    available = get_available_providers()
    default_pid = get_default_provider()
    print(f"🔌 LLM Providers: {len(available)} configured (default: {default_pid})")
    for p in available:
        print(f"   {p.get('icon', '•')} {p['name']} — {p['default_model']}")
    
    ai_status = check_llm_status(default_pid)
    if ai_status["status"] == "online":
        print(f"✅ Default AI online — {ai_status.get('provider_name', default_pid)} ({ai_status['model']})")
    elif ai_status["status"] == "not_configured":
        print(f"⚠️  Default AI not configured — set API key in .env")
    else:
        print(f"⚠️  Default AI: {ai_status.get('error', 'offline')}")

    try:
        WazuhClient().get_manager_info()
        print("✅ Wazuh API connected")
    except Exception as e:
        print(f"⚠️  Wazuh API: {e}")

    if Path(ALERT_FILE).exists():
        print(f"✅ Alert file: {ALERT_FILE}")
    else:
        print(f"⚠️  Alert file not found: {ALERT_FILE}")

@app.get("/")
async def root():
    return {
        "service": "AllysecLabs Security Intelligence API",
        "version": "2.0.0",
        "organization": "AllysecLabs",
        "ai_engine": "Multi-Provider LLM (Groq, Ollama, OpenRouter, ...)",
        "endpoints": {
            "POST /query": "AI-powered natural language security query",
            "GET /status": "System status",
            "GET /providers": "Available LLM providers",
            "GET /providers/{id}/models": "Available models for a provider",
            "GET /providers/{id}/health": "Check provider connectivity",
            "GET /docs": "Interactive API documentation",
        }
    }

# ══════════════════════════════════════════════════════
# Provider Management Endpoints
# ══════════════════════════════════════════════════════

@app.get("/providers")
async def list_providers():
    """List all available LLM providers (those with API keys configured)."""
    providers = get_available_providers()
    default = get_default_provider()
    return {
        "providers": providers,
        "default": default,
        "count": len(providers),
    }

@app.get("/providers/{provider_id}/models")
async def list_provider_models(provider_id: str):
    """Discover available models for a specific provider."""
    config = get_provider_config(provider_id)
    if not config:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found")
    
    models = discover_models(provider_id)
    return {
        "provider": provider_id,
        "provider_name": config.get("name", provider_id),
        "models": models,
        "default_model": config.get("default_model", ""),
    }

@app.get("/providers/{provider_id}/health")
async def provider_health_check(provider_id: str):
    """Check if a specific provider is online and responding."""
    health = check_provider_health(provider_id)
    return {
        "provider": provider_id,
        **health,
    }

@app.get("/status")
async def get_status():
    """Get full system status including active provider info"""
    wazuh_status = "unknown"
    try:
        WazuhClient().get_manager_info()
        wazuh_status = "connected"
    except:
        wazuh_status = "disconnected"

    # Check default provider status
    default_provider = get_default_provider()
    ai_status = check_llm_status(default_provider)
    
    # Get all available providers
    available = get_available_providers()

    rate_info = get_rate_limit_info()

    return {
        "status": "online",
        "wazuh_status": wazuh_status,
        "ai_engine": ai_status.get("provider", "unknown") if ai_status["status"] == "online" else ai_status.get("status", "offline"),
        "ai_provider": ai_status.get("provider", default_provider),
        "ai_provider_name": ai_status.get("provider_name", ""),
        "ai_model": ai_status.get("model", "none"),
        "ai_model_available": ai_status.get("model_available", False),
        "available_providers": [p["id"] for p in available],
        "provider_count": len(available),
        "rate_limit": rate_info,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/query")
async def process_query(request: QueryRequest):
    """
    LLM-powered natural language security query.

    The LLM:
    1. Interprets your natural language query into structured search parameters
    2. Decides which modules to run (alerts, patterns, etc.)
    3. Searches Wazuh alerts intelligently
    4. Analyzes the results like a professional Tier 2 SOC analyst
    5. Returns findings with actionable recommendations
    """

    user_query = request.query.strip()
    if not user_query:
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    logger.info(f"📥 Query: {user_query}")

    try:
        # ── Resolve provider/model ──
        selected_provider = request.provider or get_default_provider()
        selected_model = request.model  # None = use provider's default
        
        provider_config = get_provider_config(selected_provider)
        provider_name = provider_config.get("name", selected_provider) if provider_config else selected_provider
        provider_model_name = selected_model or (provider_config.get("default_model", "?") if provider_config else "?")
        
        logger.info(f"🔌 Provider: {provider_name} / {provider_model_name}")

        # ── Step 1: LLM interprets the query ──
        logger.info("🧠 Step 1: AI interpreting query...")
        params = interpret_query(user_query, provider_id=selected_provider, model=selected_model)
        os_filter = params.get('os_context', 'unknown')
        logger.info(f"   Intent: {params['intent']}, Hours: {params['hours']}, "
                     f"Keywords: {params['rule_keywords']}, Patterns: {params['run_patterns']}")
        if os_filter and os_filter not in ('unknown', 'both'):
            logger.info(f"   🖥️  OS Filter: {os_filter.upper()} only")
        if params.get('os_mismatch_note'):
            logger.info(f"   ⚠️  OS Note: {params['os_mismatch_note'][:80]}...")

        # ── Step 2: Search alerts ──
        logger.info("🔍 Step 2: Searching alerts...")
        if not Path(ALERT_FILE).exists():
            raise HTTPException(status_code=404, detail="Alerts file not found")

        filtered_alerts, total_alerts = search_alerts(params)
        logger.info(f"   Found {len(filtered_alerts)} matching alerts (of {total_alerts} total)")
        if os_filter and os_filter not in ('unknown', 'both'):
            logger.info(f"   (Filtered to {os_filter.upper()} agents/rules only)")

        # ── Step 3: Compute statistics ──
        logger.info("📊 Step 3: Computing statistics...")
        processor = AlertProcessor(alert_file=ALERT_FILE)
        stats = processor.compute_stats(filtered_alerts)

        # ── Step 4: Pattern detection (if LLM decides it's needed) ──
        patterns = None
        pattern_count = 0
        if params.get("run_patterns"):
            logger.info(f"🔎 Step 4: Running pattern detection: {params.get('pattern_types', 'all')}...")
            patterns = run_pattern_detection(
                filtered_alerts,
                params.get("pattern_types") or None
            )
            pattern_count = sum(len(v) for v in patterns.values() if isinstance(v, list))
            logger.info(f"   Detected {pattern_count} patterns")
        else:
            logger.info("⏭️  Step 4: Pattern detection not needed for this query")

        # ── Step 5: LLM analyzes results like a SOC analyst ──
        ai_analysis = None
        threat_level = quick_threat_assessment(stats, patterns)

        if params.get("needs_ai_analysis", True):
            # Check if full professional report is requested
            report_depth = request.report_depth or "summary"
            full_report_mode = report_depth.lower() == "full"
            
            logger.info(f"🤖 Step 5: AI analyzing results... (Report Mode: {report_depth.upper()}, Provider: {provider_name})")
            # Use stratified sampling for diverse, high-quality LLM context
            sample_size = 30 if full_report_mode else 20
            sample_alerts = stratified_sample(filtered_alerts, max_samples=sample_size)
            try:
                ai_analysis = analyze_results(
                    user_query=user_query,
                    stats=stats,
                    patterns=patterns,
                    sample_alerts=sample_alerts,
                    alert_count=len(filtered_alerts),
                    full_report=full_report_mode,  # Enterprise-grade comprehensive report
                    interpretation=params,  # Pass query interpretation for OS context awareness
                    provider_id=selected_provider,
                    model=selected_model,
                )
                logger.info("   ✅ AI analysis complete")
            except Exception as e:
                logger.warning(f"   ⚠️ AI analysis failed: {e}")
                ai_analysis = f"**AI Analysis Unavailable:** {str(e)}\n\nCheck your LLM provider configuration and try again."
        else:
            logger.info("⏭️  Step 5: AI analysis not requested for this query")

        # ── Build response ──
        interpretation = {
            "intent": params["intent"],
            "time_range": f"last {params['hours']} hours",
            "hours": params["hours"],
            "severity_range": f"{params['min_level']}-{params['max_level']}",
            "agent_filter": params.get("agent_name"),
            "keywords": params.get("rule_keywords", []),
            "patterns_requested": params.get("run_patterns", False),
            "ai_analysis_requested": params.get("needs_ai_analysis", True),
            "search_description": params.get("search_description", user_query),
            "os_context": params.get("os_context", "unknown"),
            "os_mismatch_note": params.get("os_mismatch_note"),
            "provider": selected_provider,
            "provider_name": provider_name,
            "model": provider_model_name,
            "filters": {
                "min_level": params["min_level"],
                "max_level": params["max_level"],
            }
        }

        response = QueryResponse(
            success=True,
            query=user_query,
            interpretation=interpretation,
            alert_count=len(filtered_alerts),
            stats=stats,
            patterns=patterns,
            pattern_count=pattern_count,
            ai_analysis=ai_analysis,
            threat_level=threat_level,
            recommendations=[],
            timestamp=datetime.now().isoformat()
        )

        logger.info(f"✅ Query complete: {len(filtered_alerts)} alerts, {pattern_count} patterns")
        return response

    except HTTPException:
        raise
    except RuntimeError as e:
        error_msg = str(e)
        if error_msg.startswith("RATE_LIMIT:"):
            logger.warning(f"⏳ Rate limited: {error_msg}")
            raise HTTPException(
                status_code=429,
                detail=error_msg,
                headers={"Retry-After": "60"},
            )
        logger.error(f"❌ Runtime error: {e}")
        raise HTTPException(status_code=503, detail=error_msg)
    except Exception as e:
        logger.error(f"❌ Query processing error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ══════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════

if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════════════════════════╗
║      AllysecLabs Security Intelligence Platform       ║
║      AI-Powered Threat Detection & Analysis          ║
╚═══════════════════════════════════════════════════════════╝

Starting server on http://localhost:8000
API Documentation: http://localhost:8000/docs

Press Ctrl+C to stop
""")
    
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
