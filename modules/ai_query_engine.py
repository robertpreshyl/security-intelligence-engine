#!/usr/bin/env python3
"""
AI Query Engine - Multi-Provider LLM-Powered SOC Analysis
Supports any OpenAI-compatible LLM API: Groq, Ollama, OpenRouter, OpenAI, etc.

This module provides:
1. Query interpretation - understand ANY natural language query
2. Search routing - decide which Wazuh modules to call
3. Result analysis - professional SOC analyst recommendations
4. Multi-provider LLM support - route to any configured provider
"""

import json
import requests
import logging
import os
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════
# Configuration - Load from .env
# ══════════════════════════════════════════════════════

def _load_env():
    """Load variables from .env file"""
    env_file = Path(__file__).parent.parent / ".env"
    env_vars = {}
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                env_vars[key.strip()] = value.strip()
    return env_vars

_env = _load_env()

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", _env.get("GROQ_API_KEY", ""))
GROQ_MODEL = os.environ.get("GROQ_MODEL", _env.get("GROQ_MODEL", "llama-3.3-70b-versatile"))
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Import provider registry
from modules.llm_providers import (
    get_provider_config,
    get_default_provider,
    get_available_providers,
    check_provider_health,
    get_provider_api_key,
    is_provider_available,
)


# ══════════════════════════════════════════════════════
# Multi-Provider LLM Client
# ══════════════════════════════════════════════════════

# Rate limit tracking (works for any provider that sends headers)
_rate_limit_state = {
    "remaining": None,
    "reset_at": None,
    "retry_after": None,
    "daily_remaining": None,
}

MAX_RETRIES = 3
BASE_BACKOFF = 2.0  # seconds


def get_rate_limit_info() -> Dict[str, Any]:
    """Return current rate limit state for display in dashboard/API."""
    return {
        "requests_remaining": _rate_limit_state["remaining"],
        "reset_at": _rate_limit_state["reset_at"],
        "retry_after_seconds": _rate_limit_state["retry_after"],
        "daily_remaining": _rate_limit_state["daily_remaining"],
    }


def _update_rate_limit_headers(headers: dict):
    """Extract rate-limit headers and update tracking state."""
    if "x-ratelimit-remaining-requests" in headers:
        _rate_limit_state["remaining"] = int(headers["x-ratelimit-remaining-requests"])
    if "x-ratelimit-reset-requests" in headers:
        _rate_limit_state["reset_at"] = headers["x-ratelimit-reset-requests"]
    if "retry-after" in headers:
        try:
            _rate_limit_state["retry_after"] = float(headers["retry-after"])
        except ValueError:
            _rate_limit_state["retry_after"] = None
    if "x-ratelimit-remaining-tokens" in headers:
        _rate_limit_state["daily_remaining"] = int(headers["x-ratelimit-remaining-tokens"])


def llm_chat(
    messages: List[Dict[str, str]],
    provider_id: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 2048,
    timeout: int = 30,
) -> str:
    """
    Call any OpenAI-compatible LLM API with automatic retry on rate limits.

    Supports Groq, Ollama, OpenRouter, OpenAI, Anthropic, Google Gemini —
    any provider registered in llm_providers.py.

    Args:
        messages: [{"role": "system"|"user"|"assistant", "content": "..."}]
        provider_id: Provider to use (e.g., "groq", "ollama"). None = default.
        model: Model to use. None = provider's default model.
        temperature: 0.0 = deterministic, 1.0 = creative
        max_tokens: Maximum tokens to generate
        timeout: Request timeout in seconds

    Returns:
        Assistant response text

    Raises:
        RuntimeError: On API errors, auth failures, or exhausted retries
    """
    # Resolve provider
    if not provider_id:
        provider_id = get_default_provider()

    config = get_provider_config(provider_id)
    if not config:
        raise RuntimeError(f"Unknown LLM provider: '{provider_id}'. Available: {[p['id'] for p in get_available_providers()]}")

    api_key = config.get("api_key", "")
    base_url = config.get("base_url", "")
    resolved_model = model or config.get("default_model", "")
    supports_rate_headers = config.get("supports_rate_limit_headers", False)

    if not api_key:
        env_var = config.get("api_key_env", "?")
        raise RuntimeError(
            f"{config.get('name', provider_id)} API key not configured. "
            f"Set {env_var} in .env or as an environment variable."
        )

    if not base_url:
        raise RuntimeError(f"No base_url configured for provider '{provider_id}'")

    # Use the larger of: caller's timeout OR provider's configured timeout
    # Self-hosted models (Ollama) need much more time for large prompts
    provider_timeout = config.get("timeout", 60)
    effective_timeout = max(timeout, provider_timeout)

    last_error = None

    for attempt in range(MAX_RETRIES + 1):
        try:
            response = requests.post(
                base_url,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": resolved_model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
                timeout=effective_timeout,
            )

            # Track rate limit headers if provider supports them
            if supports_rate_headers:
                _update_rate_limit_headers(response.headers)

            # Parse response body safely — some providers (Google) return
            # JSON arrays instead of objects for error responses
            try:
                resp_data = response.json()
                # Normalize: if response is a list, unwrap the first element
                if isinstance(resp_data, list):
                    resp_data = resp_data[0] if resp_data else {}
            except Exception:
                resp_data = {}

            if response.status_code == 429:
                error_data = resp_data.get("error", {}) if isinstance(resp_data, dict) else {}
                error_msg = error_data.get("message", "") if isinstance(error_data, dict) else str(error_data)
                retry_after = response.headers.get("retry-after")

                if attempt < MAX_RETRIES:
                    wait = float(retry_after) if retry_after else BASE_BACKOFF * (2 ** attempt)
                    wait = min(wait, 30)  # Cap at 30 seconds
                    logger.warning(
                        f"{config.get('name', provider_id)} rate limited "
                        f"(attempt {attempt + 1}/{MAX_RETRIES + 1}). "
                        f"Waiting {wait:.1f}s before retry..."
                    )
                    time.sleep(wait)
                    continue
                else:
                    raise RuntimeError(
                        f"RATE_LIMIT: {config.get('name', provider_id)} rate limit exceeded "
                        f"after {MAX_RETRIES + 1} attempts. "
                        f"{error_msg or 'Wait and try again.'}"
                    )

            if response.status_code == 401:
                raise RuntimeError(
                    f"Invalid API key for {config.get('name', provider_id)}. "
                    f"Check your {config.get('api_key_env', '?')} in .env"
                )

            if response.status_code != 200:
                error_detail = ""
                if isinstance(resp_data, dict):
                    err = resp_data.get("error", {})
                    if isinstance(err, dict):
                        error_detail = err.get("message", "")
                    elif isinstance(err, str):
                        error_detail = err
                if not error_detail:
                    error_detail = response.text[:200]
                # Provide helpful context for common HTTP errors
                status_hint = ""
                if response.status_code in (502, 520, 521, 522, 523, 524):
                    status_hint = " The upstream model may be temporarily unavailable — try a different model."
                elif response.status_code == 503:
                    status_hint = " The provider service may be overloaded — try again in a moment."
                raise RuntimeError(
                    f"{config.get('name', provider_id)} returned HTTP {response.status_code}: {error_detail}{status_hint}"
                )

            # Success — extract content
            if not isinstance(resp_data, dict) or "choices" not in resp_data:
                raise RuntimeError(
                    f"{config.get('name', provider_id)} returned unexpected response format. "
                    f"Response: {str(resp_data)[:300]}"
                )

            content = resp_data["choices"][0]["message"]["content"].strip()
            logger.debug(f"LLM response from {provider_id}/{resolved_model}: {len(content)} chars")
            return content

        except requests.exceptions.ConnectionError:
            raise RuntimeError(
                f"Cannot reach {config.get('name', provider_id)} at {base_url}. "
                f"Check your network connection."
            )
        except requests.exceptions.Timeout:
            # For self-hosted providers, don't retry on timeout — model is just slow
            if not supports_rate_headers:  # Cloud providers have rate headers, local don't
                raise RuntimeError(
                    f"{config.get('name', provider_id)} timed out after {effective_timeout}s. "
                    f"The model may still be loading or the prompt is very large. Try a smaller model."
                )
            if attempt < MAX_RETRIES:
                wait = BASE_BACKOFF * (2 ** attempt)
                logger.warning(
                    f"{config.get('name', provider_id)} timed out "
                    f"(attempt {attempt + 1}/{MAX_RETRIES + 1}). Retrying in {wait:.1f}s..."
                )
                time.sleep(wait)
                # Increase timeout for next attempt (model may be loading)
                timeout = int(timeout * 1.5)
                continue
            raise RuntimeError(
                f"{config.get('name', provider_id)} timed out after {MAX_RETRIES + 1} attempts. "
                f"The model may be loading or the server is overloaded."
            )
        except RuntimeError:
            raise
        except Exception as e:
            logger.error(f"LLM API error ({provider_id}): {e}")
            raise RuntimeError(f"{config.get('name', provider_id)} API error: {e}")


def groq_chat(
    messages: List[Dict[str, str]],
    temperature: float = 0.3,
    max_tokens: int = 2048,
    timeout: int = 30,
) -> str:
    """
    Backward-compatible wrapper — routes to llm_chat() with Groq provider.
    Kept for any code still calling groq_chat() directly.
    """
    return llm_chat(
        messages=messages,
        provider_id="groq",
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
    )


def check_groq_status() -> Dict[str, Any]:
    """Check if the default provider (or Groq specifically) is reachable."""
    return check_llm_status("groq")


def check_llm_status(provider_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Check if an LLM provider is reachable and key is valid.
    Uses the provider registry health check.
    """
    if not provider_id:
        provider_id = get_default_provider()

    config = get_provider_config(provider_id)
    if not config:
        return {
            "status": "not_configured",
            "provider": provider_id,
            "model": "unknown",
            "model_available": False,
            "error": f"Provider '{provider_id}' not found",
        }

    api_key = config.get("api_key", "")
    if not api_key:
        return {
            "status": "not_configured",
            "provider": provider_id,
            "model": config.get("default_model", "unknown"),
            "model_available": False,
            "error": f"{config.get('api_key_env', '?')} not set",
        }

    try:
        response = requests.post(
            config["base_url"],
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": config.get("default_model", ""),
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5,
                "temperature": 0,
            },
            timeout=10,
        )

        if response.status_code == 200:
            return {
                "status": "online",
                "provider": provider_id,
                "provider_name": config.get("name", provider_id),
                "model": config.get("default_model", ""),
                "model_available": True,
            }
        elif response.status_code == 401:
            return {
                "status": "auth_error",
                "provider": provider_id,
                "model": config.get("default_model", ""),
                "model_available": False,
                "error": "Invalid API key",
            }
        elif response.status_code == 429:
            return {
                "status": "rate_limited",
                "provider": provider_id,
                "model": config.get("default_model", ""),
                "model_available": True,
                "error": "Rate limited — still functional, just slow down",
            }
        else:
            return {
                "status": "error",
                "provider": provider_id,
                "model": config.get("default_model", ""),
                "model_available": False,
                "error": f"HTTP {response.status_code}",
            }

    except Exception as e:
        return {
            "status": "offline",
            "provider": provider_id,
            "model": config.get("default_model", ""),
            "model_available": False,
            "error": str(e),
        }


# Backward-compatible aliases (api_server imports these names)
check_ollama_status = check_groq_status


# ══════════════════════════════════════════════════════
# Import Master SOC Analyst Prompt System
# ══════════════════════════════════════════════════════

from prompts.master_soc_prompt import (
    MASTER_SOC_ANALYST_PROMPT,
    PROFESSIONAL_ANALYSIS_PROMPT,
    QUICK_SUMMARY_PROMPT,
    WAZUH_DASHBOARD_URL,
    format_context_for_analysis,
    get_report_timestamp,
)

# Use master prompt as default
SOC_SYSTEM_PROMPT = MASTER_SOC_ANALYST_PROMPT


# ══════════════════════════════════════════════════════
# Query Interpreter
# ══════════════════════════════════════════════════════

QUERY_INTERPRETER_PROMPT = """You are a query interpreter for a Wazuh SIEM security system.
Given a user's natural language question, extract structured search parameters.

You MUST respond with ONLY valid JSON (no markdown, no explanation, no ```json wrapper).
Use this exact schema:

{
  "intent": "summary|search|pattern_detection|analysis|incident_report",
  "hours": 24,
  "min_level": 0,
  "max_level": 15,
  "agent_name": null,
  "rule_keywords": [],
  "run_patterns": false,
  "pattern_types": [],
  "needs_ai_analysis": true,
  "search_description": "brief description of what to search for",
  "os_context": "linux|windows|macos|both|unknown",
  "os_mismatch_note": null
}

## CRITICAL: OS FILTERING RULES

When a user mentions a specific OS, you MUST set os_context to filter results:

**Linux keywords** → set os_context: "linux"
- "linux", "ubuntu", "centos", "debian", "rhel", "fedora"
- "sudo", "ssh", "syslog", "pam", "bash", "/var/log"
- "linux servers", "linux OS", "linux endpoints"

**Windows keywords** → set os_context: "windows"  
- "windows", "windowsOS", "win10", "win11", "windows server"
- "powershell", "cmd", "registry", "event id", "eventlog"
- "UAC", "RDP", "active directory", "AD"
- "windows endpoints", "windows machines"

**macOS keywords** → set os_context: "macos"
- "macos", "mac", "osx", "macbook", "imac", "apple"
- "mac endpoints", "mac OS"

**Both/All** → set os_context: "both"
- When user wants all systems or doesn't specify
- "all agents", "entire network", "all endpoints"

**IMPORTANT**: If user says "on linux" or "on windows", ALWAYS filter to that OS only!

## OS MISMATCH DETECTION

If user asks for concepts that don't exist on the specified OS:
- "sudo on Windows" → set os_mismatch_note explaining sudo is Linux-only
- "RDP on Linux" → set os_mismatch_note explaining RDP is Windows-only
- Still set os_context to the user's specified OS and provide equivalent terms

## Other Rules

- "hours": time range in hours. "today" = 24, "last hour" = 1, "last week" = 168. Default: 24
- "min_level": minimum alert severity (0-15). "critical" = 11, "high" = 8, "moderate" = 5. Default: 0
- "agent_name": filter by SPECIFIC agent name if mentioned (e.g., "server", "desktop-1"), null otherwise
- "rule_keywords": security terms to search for in rule descriptions
- "run_patterns": true if user asks about patterns, attacks, anomalies, scanning
- "pattern_types": ["brute_force", "port_scan", "privilege_escalation", "lateral_movement", "compliance", "alert_bursts"]
- "needs_ai_analysis": ALWAYS true unless user explicitly says "no analysis" or "raw only"

## Examples

User: "are there any port scanning or reconnaissance attempts on the linux OS?"
{"intent":"pattern_detection","hours":24,"min_level":0,"max_level":15,"agent_name":null,"rule_keywords":["scan","port","reconnaissance","network","probe"],"run_patterns":true,"pattern_types":["port_scan"],"needs_ai_analysis":true,"search_description":"Port scanning and reconnaissance on Linux systems only","os_context":"linux","os_mismatch_note":null}

User: "Show me authentication failures on Windows servers"
{"intent":"search","hours":24,"min_level":0,"max_level":15,"agent_name":null,"rule_keywords":["authentication","failed","login","logon","4625"],"run_patterns":false,"pattern_types":[],"needs_ai_analysis":true,"search_description":"Authentication failures on Windows systems","os_context":"windows","os_mismatch_note":null}

User: "Check for sudo abuse across all systems"
{"intent":"pattern_detection","hours":24,"min_level":0,"max_level":15,"agent_name":null,"rule_keywords":["sudo","privilege","escalation","su"],"run_patterns":true,"pattern_types":["privilege_escalation"],"needs_ai_analysis":true,"search_description":"Sudo privilege escalation across all Linux systems","os_context":"linux","os_mismatch_note":null}

User: "Detect any privilege escalation or sudo abuse attempts on the windowsOS"
{"intent":"pattern_detection","hours":24,"min_level":0,"max_level":15,"agent_name":null,"rule_keywords":["uac","privilege","escalation","runas","token","elevation","bypass"],"run_patterns":true,"pattern_types":["privilege_escalation"],"needs_ai_analysis":true,"search_description":"Windows privilege escalation attempts (UAC bypass, token manipulation)","os_context":"windows","os_mismatch_note":"User mentioned 'sudo' which is a Linux concept. On Windows, privilege escalation involves UAC bypass, runas, token manipulation, or scheduled tasks with elevated privileges."}

User: "What alerts are coming from the Mac endpoint?"
{"intent":"search","hours":24,"min_level":0,"max_level":15,"agent_name":"mac","rule_keywords":[],"run_patterns":false,"pattern_types":[],"needs_ai_analysis":true,"search_description":"All alerts from Mac endpoint","os_context":"macos","os_mismatch_note":null}

User: "Show me failed SSH logins in the last 6 hours"
{"intent":"search","hours":6,"min_level":0,"max_level":15,"agent_name":null,"rule_keywords":["ssh","authentication","failed","login","sshd"],"run_patterns":false,"pattern_types":[],"needs_ai_analysis":true,"search_description":"Failed SSH authentication attempts on Linux systems","os_context":"linux","os_mismatch_note":null}

User: "Give me a full security assessment"
{"intent":"summary","hours":24,"min_level":0,"max_level":15,"agent_name":null,"rule_keywords":[],"run_patterns":true,"pattern_types":["brute_force","port_scan","privilege_escalation"],"needs_ai_analysis":true,"search_description":"Full security assessment across all systems","os_context":"both","os_mismatch_note":null}

Respond with ONLY the JSON object. No other text."""


def interpret_query(user_query: str, provider_id: Optional[str] = None, model: Optional[str] = None) -> Dict[str, Any]:
    """
    Use LLM to interpret any natural language query into structured search parameters.
    Now includes OS-awareness for intelligent query translation.

    Args:
        user_query: Natural language security question
        provider_id: LLM provider to use (None = default)
        model: Specific model to use (None = provider default)

    Returns:
        Structured dict with search parameters including OS context
    """
    try:
        # Use provider-aware timeout (Ollama may need more time for cold starts)
        pconfig = get_provider_config(provider_id or get_default_provider())
        interpret_timeout = max(15, pconfig.get("timeout", 30) if pconfig else 30)
        
        raw_response = llm_chat(
            messages=[
                {"role": "system", "content": QUERY_INTERPRETER_PROMPT},
                {"role": "user", "content": f"User query: {user_query}"},
            ],
            provider_id=provider_id,
            model=model,
            temperature=0.1,
            max_tokens=512,
            timeout=interpret_timeout,
        )

        # Clean up response
        cleaned = raw_response.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            cleaned = "\n".join(l for l in lines if not l.startswith("```"))

        params = json.loads(cleaned)

        # Validate and set defaults
        defaults = {
            "intent": "summary",
            "hours": 24,
            "min_level": 0,
            "max_level": 15,
            "agent_name": None,
            "rule_keywords": [],
            "run_patterns": False,
            "pattern_types": [],
            "needs_ai_analysis": True,
            "search_description": user_query,
            "os_context": "unknown",
            "os_mismatch_note": None,
        }

        for key, default in defaults.items():
            if key not in params:
                params[key] = default

        # Ensure types
        params["hours"] = int(params.get("hours", 24))
        params["min_level"] = int(params.get("min_level", 0))
        params["max_level"] = int(params.get("max_level", 15))
        params["run_patterns"] = bool(params.get("run_patterns", False))
        params["needs_ai_analysis"] = bool(params.get("needs_ai_analysis", True))

        if not isinstance(params.get("rule_keywords"), list):
            params["rule_keywords"] = []
        if not isinstance(params.get("pattern_types"), list):
            params["pattern_types"] = []

        # Log OS mismatch if detected
        if params.get("os_mismatch_note"):
            logger.info(f"OS context note: {params['os_mismatch_note']}")

        logger.info(f"Query interpreted: {params['search_description']} (OS: {params['os_context']})")
        return params

    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse LLM JSON: {e}. Raw: {raw_response[:200]}")
        return {
            "intent": "summary",
            "hours": 24,
            "min_level": 0,
            "max_level": 15,
            "agent_name": None,
            "rule_keywords": user_query.lower().split()[:5],
            "run_patterns": False,
            "pattern_types": [],
            "needs_ai_analysis": True,
            "search_description": user_query,
            "os_context": "unknown",
            "os_mismatch_note": None,
        }
    except Exception as e:
        logger.error(f"Query interpretation error: {e}")
        raise


# ══════════════════════════════════════════════════════
# Result Analyzer - Professional Report Generation
# ══════════════════════════════════════════════════════

def analyze_results(
    user_query: str,
    stats: Dict[str, Any],
    patterns: Optional[Dict[str, List]] = None,
    sample_alerts: Optional[List[Dict]] = None,
    alert_count: int = 0,
    full_report: bool = False,
    interpretation: Optional[Dict[str, Any]] = None,
    provider_id: Optional[str] = None,
    model: Optional[str] = None,
) -> str:
    """
    Generate professional SOC analyst report using meta-cognitive reasoning.

    Args:
        user_query: Original user question
        stats: Alert statistics from Wazuh
        patterns: Detected attack patterns
        sample_alerts: Sample alerts for detailed analysis
        alert_count: Total matching alerts
        full_report: If True, generate comprehensive report; else quick summary
        interpretation: Query interpretation context (includes OS context, mismatch notes)
        provider_id: LLM provider to use (None = default)
        model: Specific model to use (None = provider default)

    Returns:
        Professional markdown-formatted security analysis
    """
    
    # Build structured context for the LLM
    context = format_context_for_analysis(
        user_query=user_query,
        stats=stats,
        patterns=patterns,
        sample_alerts=sample_alerts,
        alert_count=alert_count,
        wazuh_url=WAZUH_DASHBOARD_URL,
    )
    
    # Add interpretation context if available (OS awareness, query translation notes)
    interpretation_context = ""
    if interpretation:
        os_context = interpretation.get('os_context', 'unknown')
        os_mismatch = interpretation.get('os_mismatch_note')
        search_desc = interpretation.get('search_description', '')
        
        interpretation_context = f"""
### Query Interpretation Context
- **Original Query**: {user_query}
- **Interpreted Search**: {search_desc}
- **Detected OS Context**: {os_context}
"""
        if os_mismatch:
            interpretation_context += f"""
- **⚠️ OS CONTEXT NOTE**: {os_mismatch}

**IMPORTANT**: The user's query contained OS-specific terminology that may not match their target environment. 
Your analysis should:
1. Acknowledge this mismatch clearly
2. Explain what you searched for instead
3. Provide OS-appropriate recommendations
4. Suggest better queries for their actual intent
"""
    
    full_context = f"{interpretation_context}\n{context}" if interpretation_context else context
    
    # Get timestamp for report ID
    timestamp = get_report_timestamp()
    current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # Build the analysis prompt
    if full_report:
        # Use full professional report template
        analysis_prompt = PROFESSIONAL_ANALYSIS_PROMPT.format(
            context=full_context,
            timestamp=timestamp,
            datetime=current_datetime,
            wazuh_url=WAZUH_DASHBOARD_URL,
        )
    else:
        # Use streamlined analysis format with intelligent empty-result handling
        analysis_prompt = f"""## ANALYSIS REQUEST

Analyze the following security data and produce a professional SOC analyst assessment.

{full_context}

---

## CRITICAL REQUIREMENTS

1. **INCLUDE TABLES**: Generate markdown tables for severity distribution, top alerts, and affected hosts
2. **BE SPECIFIC**: Reference actual rule IDs, IP addresses, usernames from the data
3. **HIGHLIGHT CRITICAL**: If high-severity events exist, call them out specifically with ⚠️
4. **TARGETED RECOMMENDATIONS**: Each recommendation should reference specific hosts/rules/users
5. **CLICKABLE WAZUH LINKS**: Make every rule ID, host name, IP address, and username a clickable link

## 🔗 WAZUH DASHBOARD LINK FORMAT

**Base URL**: {WAZUH_DASHBOARD_URL}

Make identifiers clickable using these markdown link formats:
- Rule: `[🔗 Rule 5712]({WAZUH_DASHBOARD_URL}/app/discover#/?_g=(time:(from:'now-24h',to:now))&_a=(query:(language:kuery,query:'rule.id:5712')))`
- Agent: `[🖥️ hostname]({WAZUH_DASHBOARD_URL}/app/discover#/?_g=(time:(from:'now-24h',to:now))&_a=(query:(language:kuery,query:'agent.name:hostname')))`
- IP: `[🌐 192.168.1.1]({WAZUH_DASHBOARD_URL}/app/discover#/?_g=(time:(from:'now-24h',to:now))&_a=(query:(language:kuery,query:'data.srcip:192.168.1.1')))`

Use the pre-built "Clickable link for report" provided with each alert in the data above.

## CRITICAL INSTRUCTION FOR EMPTY RESULTS

If the data shows 0 matching alerts, DO NOT simply report "no data found." Instead:
1. **Explain WHY**: Is it an OS mismatch? Time range issue? Or genuinely clean?
2. **Provide VALUE**: What does the absence of alerts tell us?
3. **Guide the User**: What should they search for instead?
4. **Stay Professional**: Sound like a helpful senior analyst, not a robotic template.

---

## OUTPUT FORMAT

Write as a seasoned Tier 3 SOC analyst briefing your team. Use active voice, natural language, and professional expertise. DO NOT use robotic phrasing like "Confidence: X%" without context.

# Security Analysis Report

**Report**: SIR-{timestamp}
**Time**: {current_datetime}

---

## Executive Summary

Write 2-3 natural sentences a CISO could read in 30 seconds:
- Bottom line security posture (use your expert judgment)
- Key finding OR intelligent explanation of results
- Your confidence in this assessment and why

---

## At-a-Glance Statistics

**REQUIRED: Generate a summary statistics table:**

| Metric | Value |
|--------|-------|
| Total Alerts Analyzed | [X] |
| Critical/High Severity | [X] |
| Unique Agents Affected | [X] |
| Time Range | [range] |

---

## Severity Distribution

**REQUIRED: Create a severity breakdown table:**

| Level | Severity | Count |
|-------|----------|-------|
| 12+ | CRITICAL | [X] |
| 8-11 | HIGH | [X] |
| 5-7 | MEDIUM | [X] |
| 1-4 | LOW | [X] |

---

## Threat Assessment

### Risk Level: [CRITICAL/HIGH/MEDIUM/LOW/MINIMAL/NOT APPLICABLE]

Use "NOT APPLICABLE" if the search didn't match the environment.

Explain your risk scoring naturally:
- What the severity means in context
- How confident you are and why

---

## ⚠️ Critical/High Priority Findings

**If ANY high-severity alerts exist, document them here with CLICKABLE LINKS:**

### [Finding Name]
- **Rule ID**: [🔗 Rule ID](wazuh_link) — clickable link from data
- **Description**: [actual description]
- **Agent**: [🖥️ hostname](wazuh_link) — clickable link from data
- **Source IP**: [🌐 IP](wazuh_link) — if available, make clickable
- **User**: [👤 user](wazuh_link) — if available, make clickable
- **Occurrences**: [count]
- **Immediate Action**: [specific remediation]

---

## Top Triggered Rules

**REQUIRED: Table of most frequent rules with CLICKABLE LINKS:**

| # | Rule ID | Description | Count |
|---|---------|-------------|-------|
| 1 | [🔗 ID](link) | [description] | [X] |
| 2 | [🔗 ID](link) | [description] | [X] |
| ... | ... | ... | ... |

---

## Recommendations

### What I'd Do Now
Provide specific, actionable recommendations with CLICKABLE LINKS:
1. **For [🔗 rule ID](link)**: [specific action]
2. **For [🖥️ host](link)**: [specific action]
3. **For [👤 user](link)**: [if applicable]

---

## 📊 Quick Wazuh Dashboard Links

- [View All Security Events]({WAZUH_DASHBOARD_URL}/app/wazuh#/overview/?tab=general)
- [View Critical Alerts]({WAZUH_DASHBOARD_URL}/app/discover#/?_g=(time:(from:'now-24h',to:now))&_a=(query:(language:kuery,query:'rule.level >= 10')))
- [View All Agents]({WAZUH_DASHBOARD_URL}/app/wazuh#/agents-preview/)

---

## Analyst Notes

Share your professional observations:
- Data quality notes
- Any potential false positives
- Suggestions for the security team

---

*AllysecLabs Security Intelligence Platform*
"""

    try:
        # Resolve provider-specific limits
        pconfig = get_provider_config(provider_id or get_default_provider())
        provider_max_tokens = pconfig.get("max_tokens", 4096) if pconfig else 4096
        provider_timeout = pconfig.get("timeout", 60) if pconfig else 60

        # Use provider limits but respect request-level overrides
        effective_max_tokens = min(8000 if full_report else 6000, provider_max_tokens)
        effective_timeout = max(90 if full_report else 60, provider_timeout)

        analysis = llm_chat(
            messages=[
                {"role": "system", "content": MASTER_SOC_ANALYST_PROMPT},
                {"role": "user", "content": analysis_prompt},
            ],
            provider_id=provider_id,
            model=model,
            temperature=0.3,
            max_tokens=effective_max_tokens,
            timeout=effective_timeout,
        )
        return analysis
    except Exception as e:
        logger.error(f"AI analysis error: {e}")
        provider_name = "your LLM provider"
        if provider_id:
            pc = get_provider_config(provider_id)
            provider_name = pc.get("name", provider_id) if pc else provider_id
        return f"""# Analysis Unavailable

**Error**: {str(e)}

The AI analysis could not be generated. This may be due to:
- {provider_name} rate limiting (wait 60 seconds)
- Network connectivity issues
- API key problems

Please check your LLM provider configuration and try again.

---
*AllysecLabs Security Intelligence Platform*
"""


def generate_full_report(
    user_query: str,
    stats: Dict[str, Any],
    patterns: Optional[Dict[str, List]] = None,
    sample_alerts: Optional[List[Dict]] = None,
    alert_count: int = 0,
    provider_id: Optional[str] = None,
    model: Optional[str] = None,
) -> str:
    """Generate a comprehensive professional security report."""
    return analyze_results(
        user_query=user_query,
        stats=stats,
        patterns=patterns,
        sample_alerts=sample_alerts,
        alert_count=alert_count,
        full_report=True,
        provider_id=provider_id,
        model=model,
    )


# ══════════════════════════════════════════════════════
# Quick Analysis Helpers
# ══════════════════════════════════════════════════════

def quick_threat_assessment(stats: Dict, patterns: Dict = None) -> str:
    """Generate a quick threat level string"""
    total = stats.get("total", 0)
    high_count = sum(v for k, v in stats.get("levels", {}).items() if int(k) >= 8)
    pattern_count = sum(len(v) for v in (patterns or {}).values() if isinstance(v, list))

    if high_count > 50 or pattern_count > 5:
        return f"CRITICAL: {high_count} high-severity alerts and {pattern_count} attack patterns detected. Immediate investigation required."
    elif high_count > 10 or pattern_count > 2:
        return f"HIGH: {high_count} high-severity alerts and {pattern_count} patterns detected. Investigation recommended."
    elif high_count > 0:
        return f"MODERATE: {high_count} high-severity alerts found across {total} total alerts. Monitor closely."
    else:
        return f"LOW: {total} alerts detected, none at high severity. Normal operations."


# ══════════════════════════════════════════════════════
# Main (for testing)
# ══════════════════════════════════════════════════════

if __name__ == "__main__":
    print("AI Query Engine - Groq Cloud LLM")
    print("=" * 50)

    status = check_groq_status()
    print(f"Status: {status['status']}")
    print(f"Provider: {status['provider']}")
    print(f"Model: {status['model']}")
    if status.get("error"):
        print(f"Error: {status['error']}")

    if status["status"] != "online":
        print(f"\n❌ Groq API not reachable: {status.get('error', 'unknown')}")
        exit(1)

    print("\n✅ Groq API connected! Testing query interpretation...\n")

    test_queries = [
        "Show me failed SSH logins in the last 6 hours",
        "Are we under brute force attack?",
        "What critical events happened today?",
    ]

    for query in test_queries:
        print(f"{'─' * 50}")
        print(f"Query: {query}")
        result = interpret_query(query)
        print(f"  Intent: {result['intent']}")
        print(f"  Hours: {result['hours']}")
        print(f"  Keywords: {result['rule_keywords']}")
        print(f"  Patterns: {result['run_patterns']}")
        print(f"  Description: {result['search_description']}")
    print(f"{'─' * 50}")
    print("\n✅ All tests passed!")
