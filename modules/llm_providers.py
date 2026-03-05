#!/usr/bin/env python3
"""
LLM Provider Registry — Multi-Provider Support for AllysecLabs

Supports any OpenAI-compatible API endpoint:
- Groq (default, cloud)
- Ollama (self-hosted)
- OpenRouter, OpenAI, Claude, Google Gemini (future)

Each provider is defined by:
- base_url: Chat completions endpoint
- api_key: Auth key (from .env or hardcoded for local)
- models: Available model IDs
- default_model: Preferred model
- max_tokens: Max output tokens supported
- timeout: Request timeout in seconds

Architecture: All modern LLM APIs follow OpenAI's chat/completions format,
so a single generic client can talk to any provider.
"""

import os
import logging
import requests
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════
# Load .env
# ══════════════════════════════════════════════════════

def _load_env() -> dict:
    """Load variables from .env file."""
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

def _get_config(key: str, default: str = "") -> str:
    """Get config from environment or .env file."""
    return os.environ.get(key, _env.get(key, default))


# ══════════════════════════════════════════════════════
# Provider Definitions
# ══════════════════════════════════════════════════════

# Each provider entry: static config + optional dynamic model discovery
PROVIDER_REGISTRY: Dict[str, Dict[str, Any]] = {
    "groq": {
        "name": "Groq Cloud",
        "icon": "☁️",
        "base_url": "https://api.groq.com/openai/v1/chat/completions",
        "models_url": "https://api.groq.com/openai/v1/models",
        "api_key_env": "GROQ_API_KEY",
        "default_model": "llama-3.3-70b-versatile",
        "models": [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "meta-llama/llama-4-scout-17b-16e-instruct",
            "qwen/qwen3-32b",
        ],
        "max_tokens": 8000,
        "timeout": 60,
        "supports_rate_limit_headers": True,
        "description": "Ultra-fast cloud inference. Best quality with 70B models.",
    },
    "ollama": {
        "name": "Ollama (Self-Hosted)",
        "icon": "🏠",
        "base_url": _get_config("OLLAMA_API_URL", "http://localhost:11434/v1/chat/completions"),
        "models_url": _get_config("OLLAMA_API_URL", "http://localhost:11434/v1").rstrip("/chat/completions").rstrip("/") + "/models",
        "api_key_env": "OLLAMA_API_KEY",
        "api_key_default": "ollama",  # Ollama doesn't need auth
        "default_model": "qwen2.5:3b",
        "models": [
            "qwen2.5:3b",
            "llama3.2:3b",
            "qwen2.5:7b-instruct-q4_K_M",
            "llama3:8b",
        ],
        "max_tokens": 4096,
        "timeout": 300,  # Self-hosted ARM is slow with large prompts — 5 min
        "supports_rate_limit_headers": False,
        "description": "Self-hosted on OCI ARM. Private, no rate limits, slower.",
    },
    # ── Future Providers (add API key to .env to enable) ──
    "openrouter": {
        "name": "OpenRouter",
        "icon": "🌐",
        "base_url": "https://openrouter.ai/api/v1/chat/completions",
        "models_url": "https://openrouter.ai/api/v1/models",
        "api_key_env": "OPENROUTER_API_KEY",
        "default_model": "meta-llama/llama-3.3-70b-instruct:free",
        "models": [
            "meta-llama/llama-3.3-70b-instruct:free",
            "deepseek/deepseek-r1-0528:free",
            "google/gemma-3-27b-it:free",
            "mistralai/mistral-small-3.1-24b-instruct:free",
            "nousresearch/hermes-3-llama-3.1-405b:free",
            "qwen/qwen3-coder:free",
            "meta-llama/llama-3.3-70b-instruct",
            "anthropic/claude-sonnet-4",
            "openai/gpt-4o",
            "google/gemini-2.0-flash-001",
        ],
        "max_tokens": 8000,
        "timeout": 90,
        "supports_rate_limit_headers": False,
        "description": "Unified access to 100+ models from all providers.",
    },
    "openai": {
        "name": "OpenAI",
        "icon": "🤖",
        "base_url": "https://api.openai.com/v1/chat/completions",
        "models_url": "https://api.openai.com/v1/models",
        "api_key_env": "OPENAI_API_KEY",
        "default_model": "gpt-4o",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
        "max_tokens": 8000,
        "timeout": 90,
        "supports_rate_limit_headers": True,
        "description": "OpenAI's GPT models. Requires paid API key.",
    },
    "anthropic_openai": {
        "name": "Anthropic (Claude)",
        "icon": "🧠",
        "base_url": "https://api.anthropic.com/v1/chat/completions",
        "api_key_env": "ANTHROPIC_API_KEY",
        "default_model": "claude-sonnet-4-20250514",
        "models": ["claude-sonnet-4-20250514", "claude-haiku-4-20250514"],
        "max_tokens": 8000,
        "timeout": 90,
        "supports_rate_limit_headers": False,
        "description": "Anthropic's Claude models. Excellent for analysis.",
    },
    "google": {
        "name": "Google Gemini",
        "icon": "💎",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "api_key_env": "GOOGLE_API_KEY",
        "default_model": "gemini-2.0-flash",
        "models": ["gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-1.5-pro"],
        "max_tokens": 8000,
        "timeout": 90,
        "supports_rate_limit_headers": False,
        "description": "Google's Gemini models via OpenAI-compatible endpoint.",
    },
    "huggingface": {
        "name": "HuggingFace Inference",
        "icon": "🤗",
        "base_url": "https://router.huggingface.co/v1/chat/completions",
        "models_url": "https://router.huggingface.co/v1/models",
        "api_key_env": "HUGGINGFACE_API_KEY",
        "default_model": "meta-llama/Llama-3.3-70B-Instruct",
        "models": [
            "meta-llama/Llama-3.3-70B-Instruct",
            "Qwen/Qwen2.5-72B-Instruct",
            "mistralai/Mixtral-8x7B-Instruct-v0.1",
            "microsoft/Phi-3-mini-4k-instruct",
        ],
        "max_tokens": 8000,
        "timeout": 90,
        "supports_rate_limit_headers": False,
        "description": "HuggingFace serverless inference. Free tier available.",
    },
}


# ══════════════════════════════════════════════════════
# Provider Manager
# ══════════════════════════════════════════════════════

def get_provider_api_key(provider_id: str) -> str:
    """Get the API key for a provider from env/.env."""
    provider = PROVIDER_REGISTRY.get(provider_id)
    if not provider:
        return ""
    
    env_key = provider.get("api_key_env", "")
    key = _get_config(env_key, provider.get("api_key_default", ""))
    return key


def is_provider_available(provider_id: str) -> bool:
    """Check if a provider has a valid API key configured."""
    key = get_provider_api_key(provider_id)
    return bool(key)


def get_available_providers() -> List[Dict[str, Any]]:
    """
    Return list of providers that have API keys configured.
    Each entry includes: id, name, icon, models, default_model, description, status.
    """
    available = []
    for pid, pconfig in PROVIDER_REGISTRY.items():
        if is_provider_available(pid):
            available.append({
                "id": pid,
                "name": pconfig["name"],
                "icon": pconfig.get("icon", "🔌"),
                "models": pconfig.get("models", []),
                "default_model": pconfig.get("default_model", ""),
                "description": pconfig.get("description", ""),
                "max_tokens": pconfig.get("max_tokens", 4096),
                "timeout": pconfig.get("timeout", 60),
            })
    return available


def get_provider_config(provider_id: str) -> Optional[Dict[str, Any]]:
    """Get full config for a specific provider. Returns None if not found."""
    config = PROVIDER_REGISTRY.get(provider_id)
    if not config:
        return None
    # Include resolved API key
    result = dict(config)
    result["api_key"] = get_provider_api_key(provider_id)
    return result


def get_default_provider() -> str:
    """Return the ID of the first available provider (Groq preferred)."""
    for pid in ["groq", "ollama", "openrouter", "openai", "anthropic_openai", "google"]:
        if is_provider_available(pid):
            return pid
    return "groq"  # fallback


def discover_models(provider_id: str) -> List[str]:
    """
    Dynamically discover available models from a provider's API.
    Falls back to static list on failure.
    """
    config = PROVIDER_REGISTRY.get(provider_id)
    if not config:
        return []
    
    models_url = config.get("models_url")
    if not models_url:
        return config.get("models", [])
    
    api_key = get_provider_api_key(provider_id)
    
    try:
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        response = requests.get(models_url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict) and "data" in data:
                model_ids = [m.get("id", "") for m in data["data"] if m.get("id")]
                if model_ids:
                    logger.info(f"Discovered {len(model_ids)} models from {provider_id}")
                    return model_ids
        
        logger.debug(f"Model discovery failed for {provider_id} ({response.status_code}), using static list")
    except Exception as e:
        logger.debug(f"Model discovery error for {provider_id}: {e}")
    
    return config.get("models", [])


def check_provider_health(provider_id: str) -> Dict[str, Any]:
    """
    Check if a provider is online and responsive.
    Returns: {status, latency_ms, model, error}
    """
    config = PROVIDER_REGISTRY.get(provider_id)
    if not config:
        return {"status": "unknown", "error": "Provider not found"}
    
    api_key = get_provider_api_key(provider_id)
    if not api_key:
        return {"status": "not_configured", "error": f"Set {config.get('api_key_env', '?')} in .env"}
    
    import time
    start = time.time()
    
    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        
        response = requests.post(
            config["base_url"],
            headers=headers,
            json={
                "model": config["default_model"],
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5,
                "temperature": 0,
            },
            timeout=10,
        )
        
        latency = int((time.time() - start) * 1000)
        
        if response.status_code == 200:
            return {
                "status": "online",
                "latency_ms": latency,
                "model": config["default_model"],
            }
        elif response.status_code == 401:
            return {"status": "auth_error", "error": "Invalid API key"}
        elif response.status_code == 429:
            return {"status": "rate_limited", "model": config["default_model"]}
        else:
            return {"status": "error", "error": f"HTTP {response.status_code}"}
    
    except requests.exceptions.ConnectionError:
        return {"status": "offline", "error": "Cannot connect"}
    except requests.exceptions.Timeout:
        return {"status": "timeout", "error": "Connection timed out"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
