#!/usr/bin/env python3
"""
AllysecLabs Security Intelligence Platform
AI-Powered Threat Detection & Analysis Dashboard

Run with: streamlit run dashboard.py
Access at: http://localhost:8501
"""

import streamlit as st
import requests
import json
from datetime import datetime
import pandas as pd
from pathlib import Path

# Import report exporter for PDF/Markdown export
try:
    from modules.report_exporter import get_report_as_bytes, markdown_to_html
    EXPORT_AVAILABLE = True
except ImportError:
    EXPORT_AVAILABLE = False

# Configure page
st.set_page_config(
    page_title="AllysecLabs | Security Intelligence Platform",
    page_icon="branding/AllyShipSec-favicon.png",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API endpoint (FastAPI backend)
API_URL = "http://localhost:8000"

# ──────────────────────────────────────────────────────
# STYLING
# ──────────────────────────────────────────────────────

st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #FF4B4B;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #888;
        margin-bottom: 2rem;
    }
    .threat-critical {
        background: linear-gradient(135deg, #ff0000, #cc0000);
        color: white; padding: 12px 20px; border-radius: 8px;
        font-size: 1.3rem; font-weight: bold; text-align: center;
    }
    .threat-high {
        background: linear-gradient(135deg, #ff6600, #cc5500);
        color: white; padding: 12px 20px; border-radius: 8px;
        font-size: 1.3rem; font-weight: bold; text-align: center;
    }
    .threat-moderate {
        background: linear-gradient(135deg, #ffb800, #cc9500);
        color: white; padding: 12px 20px; border-radius: 8px;
        font-size: 1.3rem; font-weight: bold; text-align: center;
    }
    .threat-low {
        background: linear-gradient(135deg, #00aa00, #008800);
        color: white; padding: 12px 20px; border-radius: 8px;
        font-size: 1.3rem; font-weight: bold; text-align: center;
    }
    .threat-info {
        background: linear-gradient(135deg, #0066cc, #004499);
        color: white; padding: 12px 20px; border-radius: 8px;
        font-size: 1.3rem; font-weight: bold; text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────────────
# HEADER
# ──────────────────────────────────────────────────────

# Display logo if available
logo_path = Path("branding/asl-logo-full.png")
if logo_path.exists():
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.image(str(logo_path), width=400)
else:
    st.markdown('<div class="main-header">AllysecLabs</div>', unsafe_allow_html=True)

st.markdown('<div class="sub-header">Security Intelligence Platform • AI-Powered Threat Detection & Analysis</div>', unsafe_allow_html=True)

# ──────────────────────────────────────────────────────
# SIDEBAR - Quick Actions
# ──────────────────────────────────────────────────────

with st.sidebar:
    st.header("⚡ Quick Queries")
    
    # ═══════════════════════════════════════════════════
    # DAILY ESSENTIALS - What analysts check every day
    # ═══════════════════════════════════════════════════
    with st.expander("📊 Daily Essentials", expanded=True):
        daily_queries = {
            "🔍 24h Overview": "Give me a complete security overview of the last 24 hours",
            "🚨 Critical Alerts": "Show me all critical and high severity alerts from today",
            "📈 Top Threats Today": "What are the top 10 most triggered security rules in the last 24 hours?",
            "🖥️ Agent Health": "Show health status and recent alerts for all Wazuh agents",
            "⚠️ New High Severity": "Show any new high severity alerts in the last 4 hours",
        }
        for label, q in daily_queries.items():
            if st.button(label, key=f"daily_{label}", use_container_width=True):
                st.session_state['query_input'] = q
                st.rerun()
    
    # ═══════════════════════════════════════════════════
    # THREAT DETECTION - Active threat hunting
    # ═══════════════════════════════════════════════════
    with st.expander("🎯 Threat Detection", expanded=False):
        threat_queries = {
            "🔓 Brute Force": "Detect any brute force or authentication attack patterns",
            "🎯 Privilege Esc.": "Detect any privilege escalation attempts on Linux or Windows",
            "📡 Port Scans": "Are there any port scanning or reconnaissance activities?",
            "🌐 Lateral Movement": "Check for lateral movement indicators across agents",
            "🔎 All Patterns": "Run full pattern detection — brute force, port scans, privilege escalation, lateral movement",
            "🦠 Malware Alerts": "Show any malware or virus detection alerts",
            "💀 Ransomware IoCs": "Check for ransomware indicators - mass file encryption, shadow copy deletion",
            "🕵️ Suspicious Procs": "Show alerts for suspicious process execution or command line activity",
            "🔗 C2 Indicators": "Detect potential command and control (C2) communication patterns",
        }
        for label, q in threat_queries.items():
            if st.button(label, key=f"threat_{label}", use_container_width=True):
                st.session_state['query_input'] = q
                st.rerun()
    
    # ═══════════════════════════════════════════════════
    # AUTHENTICATION & ACCESS - Identity security
    # ═══════════════════════════════════════════════════
    with st.expander("🔐 Authentication & Access", expanded=False):
        auth_queries = {
            "🔑 Failed Logins": "Show all failed authentication attempts across all systems",
            "🚪 SSH Activity": "Show all SSH login events - successful and failed on Linux",
            "🖥️ RDP Sessions": "Show Remote Desktop (RDP) login events on Windows systems",
            "👤 Root/Admin Use": "Show all root or administrator privilege usage",
            "🔄 Password Changes": "Show password change events and account modifications",
            "👥 New Accounts": "Detect any new user account creation events",
            "🔓 Account Lockouts": "Show account lockout events across all systems",
            "🌍 Geo Anomalies": "Check for logins from unusual geographic locations or IPs",
        }
        for label, q in auth_queries.items():
            if st.button(label, key=f"auth_{label}", use_container_width=True):
                st.session_state['query_input'] = q
                st.rerun()
    
    # ═══════════════════════════════════════════════════
    # NETWORK SECURITY - Network-based threats
    # ═══════════════════════════════════════════════════
    with st.expander("🌐 Network Security", expanded=False):
        network_queries = {
            "🔥 Firewall Blocks": "Show firewall blocked connections and dropped packets",
            "🚫 IDS/IPS Alerts": "Show intrusion detection and prevention system alerts",
            "📊 Top Talkers": "What are the most active source IPs communicating with our systems?",
            "🔌 Unusual Ports": "Detect connections on unusual or suspicious ports",
            "🌐 DNS Anomalies": "Show suspicious DNS queries or DNS tunneling indicators",
            "📡 Network Scans": "Detect network scanning activity targeting our infrastructure",
            "🔗 Outbound Suspici": "Check for suspicious outbound connections to unknown IPs",
        }
        for label, q in network_queries.items():
            if st.button(label, key=f"net_{label}", use_container_width=True):
                st.session_state['query_input'] = q
                st.rerun()
    
    # ═══════════════════════════════════════════════════
    # ENDPOINT SECURITY - Host-based security
    # ═══════════════════════════════════════════════════
    with st.expander("🖥️ Endpoint Security", expanded=False):
        endpoint_queries = {
            "📁 File Integrity": "Show file integrity monitoring (FIM) alerts - changed or deleted files",
            "🔧 System Changes": "Show system configuration changes and modifications",
            "🐛 Rootkit Checks": "Show rootkit detection scan results",
            "⚙️ Service Changes": "Detect new or modified system services and daemons",
            "📜 Script Execution": "Show PowerShell, bash, or script execution events",
            "📦 Software Install": "Detect new software installations or package changes",
            "🔒 AV/EDR Alerts": "Show antivirus or endpoint protection alerts",
            "💾 USB Activity": "Detect USB device connections and removable media events",
        }
        for label, q in endpoint_queries.items():
            if st.button(label, key=f"ep_{label}", use_container_width=True):
                st.session_state['query_input'] = q
                st.rerun()
    
    # ═══════════════════════════════════════════════════
    # MITRE ATT&CK - Framework-based hunting
    # ═══════════════════════════════════════════════════
    with st.expander("🎯 MITRE ATT&CK", expanded=False):
        mitre_queries = {
            "🚀 Initial Access": "Show alerts mapped to MITRE Initial Access tactics",
            "⚡ Execution": "Show alerts for MITRE Execution techniques",
            "🔄 Persistence": "Detect MITRE Persistence mechanisms - scheduled tasks, registry, services",
            "🔑 Cred Access": "Show MITRE Credential Access attempts - dumping, keylogging",
            "🔍 Discovery": "Detect MITRE Discovery techniques - system enumeration",
            "↔️ Lateral Move": "Show MITRE Lateral Movement indicators",
            "📤 Exfiltration": "Detect potential MITRE Exfiltration activity",
            "💥 Impact": "Show MITRE Impact techniques - encryption, destruction",
        }
        for label, q in mitre_queries.items():
            if st.button(label, key=f"mitre_{label}", use_container_width=True):
                st.session_state['query_input'] = q
                st.rerun()
    
    # ═══════════════════════════════════════════════════
    # VULNERABILITY & COMPLIANCE
    # ═══════════════════════════════════════════════════
    with st.expander("📋 Compliance & Vuln", expanded=False):
        compliance_queries = {
            "📋 SCA Results": "Show Security Configuration Assessment (SCA) failures",
            "🔓 CVE Alerts": "Show vulnerability detection alerts with CVE references",
            "🛡️ CIS Benchmark": "Show CIS benchmark compliance check results",
            "📊 Compliance Sum": "Give me a compliance summary across all agents",
            "⚠️ Critical Vulns": "Show critical severity vulnerabilities detected",
            "🔄 Patch Status": "Show systems with outdated packages or missing patches",
        }
        for label, q in compliance_queries.items():
            if st.button(label, key=f"comp_{label}", use_container_width=True):
                st.session_state['query_input'] = q
                st.rerun()
    
    # ═══════════════════════════════════════════════════
    # XDR CORRELATION - Cross-system analysis
    # ═══════════════════════════════════════════════════
    with st.expander("🔗 XDR Correlation", expanded=False):
        xdr_queries = {
            "🔗 Attack Chain": "Correlate alerts to identify potential attack chains across multiple hosts",
            "⏱️ Timeline Attack": "Create a timeline of events for the most affected host today",
            "🎯 Targeted Host": "Which host has the most security alerts and what's happening?",
            "👤 User Risk": "Which user accounts have the most suspicious activity?",
            "🌐 IP Correlation": "Show all events associated with the top suspicious source IP",
            "📊 Multi-Agent": "Correlate events across all agents for coordinated attack detection",
        }
        for label, q in xdr_queries.items():
            if st.button(label, key=f"xdr_{label}", use_container_width=True):
                st.session_state['query_input'] = q
                st.rerun()
    
    # ═══════════════════════════════════════════════════
    # OS-SPECIFIC QUERIES
    # ═══════════════════════════════════════════════════
    with st.expander("💻 OS-Specific", expanded=False):
        os_queries = {
            "🐧 Linux Security": "Show all security events from Linux agents only",
            "🪟 Windows Events": "Show all security events from Windows agents only",
            "🍎 macOS Activity": "Show all security events from macOS agents",
            "🐧 Linux Auth": "Show SSH and PAM authentication events on Linux",
            "🪟 Win Logons": "Show Windows logon events (4624, 4625, 4634)",
            "🪟 Win PowerShell": "Show PowerShell execution events on Windows",
            "🐧 Sudo Activity": "Show sudo command usage and privilege escalation on Linux",
            "🪟 UAC Events": "Show User Account Control (UAC) events on Windows",
        }
        for label, q in os_queries.items():
            if st.button(label, key=f"os_{label}", use_container_width=True):
                st.session_state['query_input'] = q
                st.rerun()
    
    # ═══════════════════════════════════════════════════
    # APPLICATION SECURITY
    # ═══════════════════════════════════════════════════
    with st.expander("📱 Application Security", expanded=False):
        app_queries = {
            "🌐 Web Server": "Show web server security events - Apache, Nginx, IIS",
            "🗄️ Database": "Show database security events - MySQL, PostgreSQL, MSSQL",
            "📧 Email Server": "Show email server security events - Postfix, Exchange",
            "🔐 VPN Activity": "Show VPN connection and authentication events",
            "☁️ Cloud Events": "Show cloud-related security events - AWS, Azure, GCP",
            "🐳 Container": "Show Docker or Kubernetes security events",
        }
        for label, q in app_queries.items():
            if st.button(label, key=f"app_{label}", use_container_width=True):
                st.session_state['query_input'] = q
                st.rerun()

    st.divider()

    st.header("⚙️ Settings")
    
    # ── LLM Provider & Model Selection ──
    st.subheader("🤖 AI Provider")
    
    # Fetch available providers from API
    try:
        providers_resp = requests.get(f"{API_URL}/providers", timeout=3)
        if providers_resp.status_code == 200:
            providers_data = providers_resp.json()
            providers_list = providers_data.get("providers", [])
            default_provider = providers_data.get("default", "groq")
        else:
            providers_list = []
            default_provider = "groq"
    except:
        providers_list = []
        default_provider = "groq"
    
    if providers_list:
        # Build display labels: "☁️ Groq Cloud", "🏠 Ollama (Self-Hosted)"
        provider_labels = {
            p["id"]: f"{p.get('icon', '🔌')} {p['name']}" 
            for p in providers_list
        }
        provider_ids = list(provider_labels.keys())
        
        # Default selection index
        default_idx = provider_ids.index(default_provider) if default_provider in provider_ids else 0
        
        selected_provider = st.selectbox(
            "Provider",
            options=provider_ids,
            format_func=lambda x: provider_labels.get(x, x),
            index=default_idx,
            key="selected_provider",
            help="Choose which AI engine processes your queries",
        )
        
        # Fetch models for selected provider
        try:
            models_resp = requests.get(f"{API_URL}/providers/{selected_provider}/models", timeout=3)
            if models_resp.status_code == 200:
                models_data = models_resp.json()
                model_list = models_data.get("models", [])
                default_model = models_data.get("default_model", "")
            else:
                model_list = []
                default_model = ""
        except:
            # Fallback to static model list from provider data
            pinfo = next((p for p in providers_list if p["id"] == selected_provider), {})
            model_list = pinfo.get("models", [])
            default_model = pinfo.get("default_model", "")
        
        if model_list:
            default_model_idx = model_list.index(default_model) if default_model in model_list else 0
            selected_model = st.selectbox(
                "Model",
                options=model_list,
                index=default_model_idx,
                key="selected_model",
                help="Choose which model to use for analysis",
            )
        else:
            selected_model = None
            st.caption("No models available")
        
        # Show provider info
        pinfo = next((p for p in providers_list if p["id"] == selected_provider), {})
        st.caption(pinfo.get("description", ""))
    else:
        selected_provider = None
        selected_model = None
        st.warning("No AI providers configured")
    
    st.divider()
    
    # Report depth selection
    report_mode = st.radio(
        "📄 Report Depth",
        options=["summary", "full"],
        format_func=lambda x: "⚡ Quick Summary" if x == "summary" else "📊 Full Professional Report",
        index=0,
        help="Quick Summary: Fast, concise analysis\nFull Report: Enterprise-grade detailed analysis for board meetings",
        key="report_mode"
    )
    
    if report_mode == "full":
        st.caption("*Full reports include comprehensive tables, MITRE mapping, and detailed recommendations.*")
    
    show_raw_data = st.checkbox("Show raw JSON data", value=False)

    st.divider()

    st.header("📊 System Status")
    try:
        status_response = requests.get(f"{API_URL}/status", timeout=3)
        if status_response.status_code == 200:
            status = status_response.json()
            st.success("✅ Backend: Online")

            ai_status = status.get('ai_engine', 'offline')
            model = status.get('ai_model', 'none')
            model_ready = status.get('ai_model_available', False)
            provider_name = status.get('ai_provider_name', '')
            provider_count = status.get('provider_count', 0)

            if model_ready:
                st.success(f"🤖 AI: {provider_name or ai_status} ({model})")
            elif ai_status == "rate_limited":
                st.warning(f"🤖 {provider_name or 'AI'}: Rate limited")
            elif ai_status == "auth_error":
                st.error(f"🤖 {provider_name or 'AI'}: Invalid API key")
            else:
                st.error(f"🤖 AI: {ai_status}")
            
            if provider_count > 1:
                st.caption(f"🔌 {provider_count} providers available")

            wazuh = status.get('wazuh_status', 'unknown')
            if wazuh == "connected":
                st.success("📡 Wazuh: Connected")
            else:
                st.warning(f"📡 Wazuh: {wazuh}")

            # Rate limit info
            rate = status.get('rate_limit', {})
            remaining = rate.get('requests_remaining')
            if remaining is not None:
                if remaining <= 3:
                    st.warning(f"⏳ Rate limit: {remaining} req left")
                else:
                    st.caption(f"Rate limit: {remaining} req remaining")
        else:
            st.error("❌ Backend: Error")
    except:
        st.error("❌ Backend: Unreachable")
        st.caption("Start with: `bash start_dashboard.sh`")

# ──────────────────────────────────────────────────────
# MAIN INTERFACE - Query Input
# ──────────────────────────────────────────────────────

st.markdown("### 💬 Natural Language Security Query")
st.caption("Powered by advanced AI — ask any security question in plain language and receive professional SOC analyst insights.")

col1, col2 = st.columns([5, 1])

with col1:
    query = st.text_area(
        "Type your query in natural language:",
        height=100,
        placeholder="Examples:\n• What's happening on my network right now?\n• Any brute force attacks in the last 12 hours?\n• Show me suspicious activity from any agent\n• Are there signs of lateral movement?",
        key="query_input",
        label_visibility="collapsed"
    )

with col2:
    st.write("")
    st.write("")
    analyze_button = st.button("🚀 Analyze", type="primary", use_container_width=True)
    clear_button = st.button("🗑️ Clear", use_container_width=True)

if clear_button:
    st.session_state['query_input'] = ''
    if 'last_result' in st.session_state:
        del st.session_state['last_result']
    st.rerun()

# Example queries
with st.expander("💡 Example Queries — click to expand"):
    st.markdown("""
    **General Analysis:**
    - "Give me a full security assessment of the last 24 hours"
    - "What's the most concerning activity right now?"
    - "Summarize today's alerts and tell me what to prioritize"

    **Threat Hunting:**
    - "Detect brute force attacks in the last 12 hours"
    - "Are there any port scanning or reconnaissance attempts?"
    - "Check for privilege escalation or unauthorized sudo use"
    - "Is there lateral movement between agents?"

    **Specific Investigations:**
    - "Show me all level 10+ critical alerts"
    - "What's happening with authentication failures?"
    - "Find all Postfix or email-related security events"
    - "Show me SCA compliance failures"

    **Agent-Specific:**
    - "What alerts are coming from the server agent?"
    - "Analyze activity from AllyshipGlobalLtd"
    """)

# ──────────────────────────────────────────────────────
# QUERY PROCESSING
# ──────────────────────────────────────────────────────

if analyze_button and query:
    status_text = st.empty()
    
    # Get report mode from session state (set by sidebar radio)
    current_report_mode = st.session_state.get('report_mode', 'summary')
    
    # Get provider/model from session state (set by sidebar selector)
    current_provider = st.session_state.get('selected_provider', None)
    current_model = st.session_state.get('selected_model', None)

    with st.spinner(""):
        mode_label = "Enterprise Report" if current_report_mode == "full" else "Quick Analysis"
        provider_label = ""
        if current_provider:
            provider_label = f" via {current_provider}"
            if current_model:
                provider_label = f" via {current_model}"
        status_text.markdown(f"**🧠 Step 1/5:** AI is interpreting your query... ({mode_label}{provider_label})")
        try:
            # Build request payload with provider selection
            payload = {
                "query": query, 
                "report_depth": current_report_mode,
            }
            if current_provider:
                payload["provider"] = current_provider
            if current_model:
                payload["model"] = current_model
            
            # Adjust timeout based on provider type
            is_self_hosted = current_provider in ("ollama",)
            if is_self_hosted:
                api_timeout = 360  # 6 minutes for self-hosted ARM inference
            elif current_report_mode == "full":
                api_timeout = 180  # 3 minutes for full reports on cloud providers
            else:
                api_timeout = 120  # 2 minutes for quick summaries (OpenRouter free models can be slow)
            
            response = requests.post(
                f"{API_URL}/query",
                json=payload,
                timeout=api_timeout,
            )

            if response.status_code == 200:
                result = response.json()
                st.session_state['last_result'] = result
                st.session_state['last_query'] = query
                status_text.empty()
            elif response.status_code == 429:
                status_text.empty()
                st.warning(
                    "**⏳ Rate Limit Reached** — The AI provider's rate limit has been exceeded.\n\n"
                    "The AI engine retried automatically but the limit persists. "
                    "Wait ~60 seconds and try again, or switch to a different provider in Settings. "
                    "Your alert data is still being processed — "
                    "only the AI analysis step is rate-limited."
                )
                result = None
            else:
                status_text.empty()
                error_detail = response.text
                try:
                    error_detail = response.json().get('detail', response.text)
                except:
                    pass
                st.error(f"❌ API Error ({response.status_code}): {error_detail}")
                result = None

        except requests.exceptions.ConnectionError:
            status_text.empty()
            st.error("❌ Cannot connect to backend API. Run `bash start_dashboard.sh` to start.")
            result = None
        except requests.exceptions.Timeout:
            status_text.empty()
            st.error("❌ Query timed out. The AI analysis may be taking too long. Try a simpler query.")
            result = None
        except Exception as e:
            status_text.empty()
            st.error(f"❌ Error: {str(e)}")
            result = None

# ──────────────────────────────────────────────────────
# RESULTS DISPLAY
# ──────────────────────────────────────────────────────

if 'last_result' in st.session_state:
    result = st.session_state['last_result']

    st.markdown("---")

    # ── Threat Level Banner ──
    threat_level = result.get('threat_level', 'UNKNOWN')
    threat_class = {
        'CRITICAL': 'threat-critical',
        'HIGH': 'threat-high',
        'MODERATE': 'threat-moderate',
        'LOW': 'threat-low',
    }.get(threat_level.upper() if threat_level else '', 'threat-info')

    threat_emoji = {
        'CRITICAL': '🔴', 'HIGH': '🟠', 'MODERATE': '🟡', 'LOW': '🟢',
    }.get(threat_level.upper() if threat_level else '', 'ℹ️')

    st.markdown(
        f'<div class="{threat_class}">{threat_emoji} Threat Level: {threat_level}</div>',
        unsafe_allow_html=True
    )
    st.write("")

    # ── Top-level Metrics ──
    mcol1, mcol2, mcol3, mcol4 = st.columns(4)
    with mcol1:
        st.metric("📋 Alerts Found", result.get('alert_count', 0))
    with mcol2:
        st.metric("🔎 Patterns Found", result.get('pattern_count', 0))
    with mcol3:
        interp = result.get('interpretation', {})
        st.metric("⏰ Time Range", interp.get('time_range', 'N/A'))
    with mcol4:
        st.metric("🎯 Intent", interp.get('intent', 'Unknown'))

    # ── AI Interpretation ──
    with st.expander("🧠 How AI Interpreted Your Query", expanded=False):
        interp = result.get('interpretation', {})
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Intent:** {interp.get('intent', 'N/A')}")
            st.markdown(f"**Time Range:** {interp.get('time_range', 'N/A')}")
            st.markdown(f"**Severity Range:** {interp.get('severity_range', 'all')}")
            st.markdown(f"**Agent Filter:** {interp.get('agent_filter') or 'None (all agents)'}")
        with col2:
            keywords = interp.get('keywords', [])
            st.markdown(f"**Keywords:** {', '.join(keywords) if keywords else 'None'}")
            st.markdown(f"**Patterns Requested:** {'Yes' if interp.get('patterns_requested') else 'No'}")
            st.markdown(f"**AI Analysis:** {'Yes' if interp.get('ai_analysis_requested') else 'No'}")
            provider_display = interp.get('provider_name', interp.get('provider', ''))
            model_display = interp.get('model', '')
            if provider_display:
                st.markdown(f"**AI Provider:** {provider_display}")
            if model_display:
                st.markdown(f"**Model:** {model_display}")
            if interp.get('search_description'):
                st.markdown(f"**Search Description:** {interp['search_description']}")

    # ── Tabs (AI Analysis first!) ──
    tab1, tab2, tab3, tab4 = st.tabs([
        "🤖 AI Analysis",
        "📊 Alert Summary",
        "🔍 Patterns",
        "📄 Raw Data"
    ])
    
    # ── Tab 1: AI Analysis (first!) ──
    with tab1:
        if result.get('ai_analysis'):
            st.markdown(result['ai_analysis'])
            
            # ── Report Export Section ──
            st.markdown("---")
            st.markdown("#### 📥 Export Report")
            
            if EXPORT_AVAILABLE:
                # Get the analysis content
                analysis_content = result.get('ai_analysis', '')
                original_query = st.session_state.get('last_query', 'Security Analysis')
                current_report_mode = st.session_state.get('report_mode', 'summary')
                
                # Add metadata header to export
                report_type = "Executive Summary" if current_report_mode == "summary" else "Full Professional Report"
                export_header = f"""# Security Intelligence Report
**Platform:** AllysecLabs Security Intelligence Platform  
**Report Type:** {report_type}  
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Query:** {original_query}  
**Threat Level:** {result.get('threat_level', 'N/A')}  
**Alerts Analyzed:** {result.get('alert_count', 0)}  

---

"""
                full_export_content = export_header + analysis_content
                
                # Build metadata for enhanced PDF/HTML rendering (cover page, charts)
                _report_stats = result.get('stats')
                _report_metadata = {
                    'query': original_query,
                    'threat_level': result.get('threat_level', 'N/A'),
                    'alert_count': result.get('alert_count', 0),
                    'report_depth': current_report_mode,
                }
                
                # Show info about current report type
                if current_report_mode == "summary":
                    st.info("📋 **Currently viewing: Quick Summary** — Use sidebar toggle for Full Professional Report mode")
                else:
                    st.success("📊 **Currently viewing: Full Professional Report** — Enterprise-grade analysis suitable for board meetings")
                
                # Export row 1: Download current report
                st.markdown("##### Download Current Report")
                export_cols = st.columns(4)
                
                with export_cols[0]:
                    # Markdown download
                    md_bytes, md_mime, md_filename = get_report_as_bytes(full_export_content, "md", stats=_report_stats, report_metadata=_report_metadata)
                    st.download_button(
                        label="📄 Markdown",
                        data=md_bytes,
                        file_name=md_filename,
                        mime=md_mime,
                        use_container_width=True,
                        key="export_md_current"
                    )
                
                with export_cols[1]:
                    # HTML download
                    html_bytes, html_mime, html_filename = get_report_as_bytes(full_export_content, "html", stats=_report_stats, report_metadata=_report_metadata)
                    st.download_button(
                        label="🌐 HTML",
                        data=html_bytes,
                        file_name=html_filename,
                        mime=html_mime,
                        use_container_width=True,
                        key="export_html_current"
                    )
                
                with export_cols[2]:
                    # PDF download (if available)
                    try:
                        pdf_bytes, pdf_mime, pdf_filename = get_report_as_bytes(full_export_content, "pdf", stats=_report_stats, report_metadata=_report_metadata)
                        st.download_button(
                            label="📑 PDF Report",
                            data=pdf_bytes,
                            file_name=pdf_filename,
                            mime=pdf_mime,
                            use_container_width=True,
                            key="export_pdf_current"
                        )
                    except Exception as e:
                        st.button("📑 PDF", disabled=True, use_container_width=True,
                                  help="Install weasyprint for PDF export", key="pdf_disabled")
                
                with export_cols[3]:
                    # JSON export for raw data
                    json_export = json.dumps({
                        "query": original_query,
                        "timestamp": datetime.now().isoformat(),
                        "threat_level": result.get('threat_level'),
                        "alert_count": result.get('alert_count'),
                        "stats": result.get('stats'),
                        "ai_analysis": analysis_content
                    }, indent=2)
                    st.download_button(
                        label="📦 JSON",
                        data=json_export.encode(),
                        file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True,
                        key="export_json"
                    )
                
                # Generate Full Report button (if currently in summary mode)
                if current_report_mode == "summary":
                    st.markdown("---")
                    st.markdown("##### 📊 Need a Full Enterprise Report?")
                    st.caption("Generate a comprehensive board-ready report with detailed tables, MITRE ATT&CK mapping, timeline analysis, and executive recommendations.")
                    
                    col1, col2, col3 = st.columns([1, 2, 1])
                    with col2:
                        if st.button("🏢 Generate Full Enterprise Report", type="primary", use_container_width=True, key="gen_full_report"):
                            # Re-run query with full report mode
                            with st.spinner("Generating comprehensive enterprise report..."):
                                try:
                                    full_response = requests.post(
                                        f"{API_URL}/query",
                                        json={"query": original_query, "report_depth": "full"},
                                        timeout=120
                                    )
                                    if full_response.status_code == 200:
                                        full_result = full_response.json()
                                        st.session_state['full_report_content'] = full_result.get('ai_analysis', '')
                                        st.success("✅ Full report generated! Download options below.")
                                    else:
                                        st.error(f"Failed to generate full report: {full_response.status_code}")
                                except Exception as e:
                                    st.error(f"Error: {str(e)}")
                    
                    # Show full report download if generated
                    if 'full_report_content' in st.session_state and st.session_state['full_report_content']:
                        full_report_header = f"""# Security Intelligence Report — Full Enterprise Edition
**Platform:** AllysecLabs Security Intelligence Platform  
**Report Type:** Full Professional Report  
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Query:** {original_query}  
**Threat Level:** {result.get('threat_level', 'N/A')}  
**Alerts Analyzed:** {result.get('alert_count', 0)}  

---

"""
                        full_report_export = full_report_header + st.session_state['full_report_content']
                        
                        # Full report metadata for cover page and charts
                        _full_meta = {
                            'query': original_query,
                            'threat_level': result.get('threat_level', 'N/A'),
                            'alert_count': result.get('alert_count', 0),
                            'report_depth': 'full',
                        }
                        
                        st.markdown("##### Download Full Enterprise Report")
                        full_cols = st.columns(3)
                        
                        with full_cols[0]:
                            md_full, _, md_fn = get_report_as_bytes(full_report_export, "md", stats=_report_stats, report_metadata=_full_meta)
                            st.download_button(
                                label="📄 Full Report (MD)",
                                data=md_full,
                                file_name=f"SIR_FULL_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                                mime="text/markdown",
                                use_container_width=True,
                                key="export_full_md"
                            )
                        
                        with full_cols[1]:
                            html_full, _, _ = get_report_as_bytes(full_report_export, "html", stats=_report_stats, report_metadata=_full_meta)
                            st.download_button(
                                label="🌐 Full Report (HTML)",
                                data=html_full,
                                file_name=f"SIR_FULL_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                                mime="text/html",
                                use_container_width=True,
                                key="export_full_html"
                            )
                        
                        with full_cols[2]:
                            try:
                                pdf_full, _, _ = get_report_as_bytes(full_report_export, "pdf", stats=_report_stats, report_metadata=_full_meta)
                                st.download_button(
                                    label="📑 Full Report (PDF)",
                                    data=pdf_full,
                                    file_name=f"SIR_FULL_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                                    mime="application/pdf",
                                    use_container_width=True,
                                    key="export_full_pdf"
                                )
                            except:
                                st.button("📑 PDF", disabled=True, use_container_width=True, key="full_pdf_disabled")
                        
                        # Expandable preview of full report
                        with st.expander("📖 Preview Full Enterprise Report", expanded=False):
                            st.markdown(st.session_state['full_report_content'])
                            
            else:
                st.info("Export functionality not available. Check that modules/report_exporter.py exists.")
        else:
            st.info("AI analysis was not generated for this query.")
            st.caption("This can happen if Groq is unreachable or the query didn't require analysis.")

        if result.get('recommendations'):
            st.markdown("---")
            st.markdown("#### 📝 Additional Recommendations")
            for rec in result['recommendations']:
                st.markdown(f"- {rec}")

    # ── Tab 2: Alert Summary ──
    with tab2:
        st.subheader("Alert Statistics")

        if result.get('stats'):
            stats = result['stats']

            # Metrics row
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Alerts", stats.get('total', 0))
            with col2:
                levels = stats.get('levels', {})
                high = sum(v for k, v in levels.items() if int(k) >= 8)
                st.metric("High Severity (8+)", high,
                          delta="⚠️ Needs attention" if high > 0 else None,
                          delta_color="inverse" if high > 0 else "off")
            with col3:
                st.metric("Agents", len(stats.get('by_agent', {})))
            with col4:
                st.metric("Unique Rules", len(stats.get('top_rules', [])))

            # Severity distribution chart
            if stats.get('levels'):
                st.markdown("#### Severity Distribution")
                severity_data = []
                for level, count in sorted(stats['levels'].items(), key=lambda x: int(x[0]), reverse=True):
                    lvl = int(level)
                    tier = ("CRITICAL" if lvl >= 11 else "HIGH" if lvl >= 8
                            else "MODERATE" if lvl >= 5 else "LOW")
                    severity_data.append({'Level': f"L{level}", 'Count': count, 'Tier': tier})

                df = pd.DataFrame(severity_data)
                st.bar_chart(df.set_index('Level')['Count'])

            # Top rules table
            if stats.get('top_rules'):
                st.markdown("#### Top Triggered Rules")
                rule_data = [{'Rule ID': r['rule_id'], 'Description': r['description'][:80], 'Count': r['count'], 'Level': r.get('level', '?')}
                             for r in stats['top_rules'][:15] if isinstance(r, dict)]
                st.dataframe(pd.DataFrame(rule_data), use_container_width=True, hide_index=True)

            # Agents table
            if stats.get('by_agent'):
                st.markdown("#### Alert Distribution by Agent")
                agent_data = [{'Agent': agent, 'Alerts': count}
                              for agent, count in sorted(stats['by_agent'].items(),
                                                         key=lambda x: x[1], reverse=True)]
                st.dataframe(pd.DataFrame(agent_data), use_container_width=True, hide_index=True)
        else:
            st.info("No statistics available.")
    
    # ── Tab 3: Pattern Detection ──
    with tab3:
        if result.get('patterns'):
            patterns = result['patterns']
            total_patterns = sum(len(v) for v in patterns.values() if isinstance(v, list))

            if total_patterns > 0:
                st.success(f"🔍 Detected **{total_patterns}** security pattern(s)")

                for pattern_type, findings in patterns.items():
                    if not findings or not isinstance(findings, list):
                        continue

                    st.markdown(f"#### {pattern_type.replace('_', ' ').title()}")

                    for i, finding in enumerate(findings, 1):
                        if isinstance(finding, dict) and 'error' in finding:
                            st.error(f"Error: {finding['error']}")
                            continue

                        if not isinstance(finding, dict):
                            continue

                        severity = finding.get('severity', 'UNKNOWN')
                        emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MODERATE': '🟡',
                                 'LOW': '⚪'}.get(severity, '⚪')

                        title = finding.get('pattern', pattern_type)
                        with st.expander(f"{emoji} #{i}: {title} — {severity}"):
                            cols = st.columns(2)
                            with cols[0]:
                                for key, value in finding.items():
                                    if key in ('pattern', 'severity', 'confidence'):
                                        continue
                                    if isinstance(value, (list, dict)):
                                        st.write(f"**{key}:** {len(value)} items")
                                    else:
                                        st.write(f"**{key}:** {value}")
                            with cols[1]:
                                conf = finding.get('confidence', 0)
                                st.metric("Confidence", f"{conf:.0%}" if isinstance(conf, float) else str(conf))
                                if finding.get('count'):
                                    st.metric("Event Count", finding['count'])
            else:
                st.info("✅ No attack patterns detected. Security posture appears normal.")
        else:
            st.info("Pattern detection was not requested for this query. "
                     "Try asking: *'Run full pattern detection on recent alerts'*")
    
    # ── Tab 4: Raw Data ──
    with tab4:
        if show_raw_data:
            st.json(result)
        else:
            st.info("Enable **'Show raw JSON data'** in the sidebar to view the full API response.")

# ──────────────────────────────────────────────────────
# FOOTER
# ──────────────────────────────────────────────────────

st.markdown("---")
col1, col2, col3 = st.columns([2, 2, 1])
with col1:
    st.caption("© 2026 AllysecLabs | Security Intelligence Platform")
with col2:
    st.caption("Powered by Groq AI + Wazuh SIEM | Built with Streamlit")
with col3:
    st.caption("v2.0.0")
