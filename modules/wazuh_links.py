"""
Wazuh Dashboard Link Generator

Generates clickable URLs that open Wazuh dashboard filtered to specific events,
rules, agents, or time ranges. These links are embedded in AI-generated reports
for direct correlation between analysis findings and Wazuh data.
"""

import urllib.parse
import json
import os
from datetime import datetime, timedelta
from typing import Optional, Union

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

# Base URL for Wazuh dashboard - can be overridden via environment variable
WAZUH_DASHBOARD_URL = os.getenv("WAZUH_DASHBOARD_URL", "https://localhost")

# Default time range for links (in hours, looking back)
DEFAULT_TIME_RANGE_HOURS = 24


class WazuhLinkGenerator:
    """
    Generates clickable links to Wazuh dashboard for specific security events.
    
    URL Structure Reference (OpenSearch Dashboards):
    - Discover app: /app/discover#/?_g=(...)&_a=(...)
    - Wazuh security events: /app/wazuh#/overview/?tab=general
    - Time range in _g (global state): time:(from:'now-24h',to:'now')
    - Query in _a (app state): query:(language:kuery,query:'rule.id:5712')
    """
    
    def __init__(self, base_url: str = None):
        """
        Initialize the link generator.
        
        Args:
            base_url: Wazuh dashboard base URL (e.g., "https://your-wazuh-host")
                     Defaults to WAZUH_DASHBOARD_URL environment variable.
        """
        self.base_url = (base_url or WAZUH_DASHBOARD_URL).rstrip('/')
    
    # ─────────────────────────────────────────────────────────────────────────
    # MAIN LINK GENERATORS
    # ─────────────────────────────────────────────────────────────────────────
    
    def rule_events_link(
        self, 
        rule_id: Union[str, int], 
        time_range: str = "24h",
        agent_name: str = None
    ) -> str:
        """
        Generate link to view all events for a specific Wazuh rule ID.
        
        Args:
            rule_id: Wazuh rule ID (e.g., 5712, 110002)
            time_range: Time range like "24h", "7d", "1h"
            agent_name: Optional - filter to specific agent
            
        Returns:
            Full URL to Wazuh Discover filtered by rule ID
        """
        query_parts = [f"rule.id:{rule_id}"]
        if agent_name:
            query_parts.append(f"agent.name:{agent_name}")
        
        query = " AND ".join(query_parts)
        return self._build_discover_url(query, time_range)
    
    def agent_events_link(
        self, 
        agent_name: str, 
        time_range: str = "24h",
        min_severity: int = None
    ) -> str:
        """
        Generate link to view all events from a specific agent.
        
        Args:
            agent_name: Wazuh agent name (e.g., "wazuhserver", "DESKTOP-53AEN5S")
            time_range: Time range like "24h", "7d"
            min_severity: Optional - minimum rule level (e.g., 8 for high+)
            
        Returns:
            Full URL to Wazuh Discover filtered by agent
        """
        query_parts = [f"agent.name:{agent_name}"]
        if min_severity:
            query_parts.append(f"rule.level >= {min_severity}")
        
        query = " AND ".join(query_parts)
        return self._build_discover_url(query, time_range)
    
    def severity_events_link(
        self, 
        min_level: int, 
        max_level: int = None,
        time_range: str = "24h"
    ) -> str:
        """
        Generate link to view events by severity level.
        
        Args:
            min_level: Minimum severity level (1-15)
            max_level: Optional maximum level
            time_range: Time range like "24h", "7d"
            
        Returns:
            Full URL filtered by severity
        """
        if max_level:
            query = f"rule.level >= {min_level} AND rule.level <= {max_level}"
        else:
            query = f"rule.level >= {min_level}"
        
        return self._build_discover_url(query, time_range)
    
    def ip_events_link(
        self, 
        ip_address: str, 
        ip_type: str = "src",
        time_range: str = "24h"
    ) -> str:
        """
        Generate link to view events involving a specific IP address.
        
        Args:
            ip_address: IP address to search for
            ip_type: "src" for source IP, "dst" for destination, "any" for both
            time_range: Time range
            
        Returns:
            Full URL filtered by IP
        """
        if ip_type == "src":
            query = f"data.srcip:{ip_address}"
        elif ip_type == "dst":
            query = f"data.dstip:{ip_address}"
        else:  # any
            query = f"(data.srcip:{ip_address} OR data.dstip:{ip_address})"
        
        return self._build_discover_url(query, time_range)
    
    def user_events_link(
        self, 
        username: str, 
        time_range: str = "24h"
    ) -> str:
        """
        Generate link to view events involving a specific user.
        
        Args:
            username: Username to search for (in srcuser or dstuser fields)
            time_range: Time range
            
        Returns:
            Full URL filtered by username
        """
        # Search both source and destination user fields
        query = f"(data.srcuser:{username} OR data.dstuser:{username})"
        return self._build_discover_url(query, time_range)
    
    def mitre_technique_link(
        self, 
        technique_id: str, 
        time_range: str = "24h"
    ) -> str:
        """
        Generate link to view events mapped to a MITRE ATT&CK technique.
        
        Args:
            technique_id: MITRE technique ID (e.g., "T1110", "T1566.001")
            time_range: Time range
            
        Returns:
            Full URL filtered by MITRE technique
        """
        query = f"rule.mitre.id:{technique_id}"
        return self._build_discover_url(query, time_range)
    
    def custom_query_link(
        self, 
        query: str, 
        time_range: str = "24h"
    ) -> str:
        """
        Generate link with a custom Kuery/KQL query.
        
        Args:
            query: Custom query string (e.g., "rule.groups:sshd AND agent.name:server")
            time_range: Time range
            
        Returns:
            Full URL with custom query
        """
        return self._build_discover_url(query, time_range)
    
    # ─────────────────────────────────────────────────────────────────────────
    # SPECIALIZED LINKS
    # ─────────────────────────────────────────────────────────────────────────
    
    def authentication_failures_link(self, time_range: str = "24h") -> str:
        """Link to authentication failure events."""
        query = '(rule.groups:"authentication_failed" OR rule.groups:"authentication_failures")'
        return self._build_discover_url(query, time_range)
    
    def brute_force_link(self, time_range: str = "24h") -> str:
        """Link to brute force detection events."""
        query = 'rule.groups:"authentication_failures" AND rule.level >= 8'
        return self._build_discover_url(query, time_range)
    
    def file_integrity_link(self, agent_name: str = None, time_range: str = "24h") -> str:
        """Link to file integrity monitoring events."""
        query_parts = ['rule.groups:"syscheck"']
        if agent_name:
            query_parts.append(f"agent.name:{agent_name}")
        return self._build_discover_url(" AND ".join(query_parts), time_range)
    
    def vulnerability_link(self, agent_name: str = None, time_range: str = "7d") -> str:
        """Link to vulnerability detection events."""
        query_parts = ['rule.groups:"vulnerability-detector"']
        if agent_name:
            query_parts.append(f"agent.name:{agent_name}")
        return self._build_discover_url(" AND ".join(query_parts), time_range)
    
    def critical_alerts_link(self, time_range: str = "24h") -> str:
        """Link to critical/high severity alerts (level 10+)."""
        return self.severity_events_link(10, time_range=time_range)
    
    def security_events_overview_link(self) -> str:
        """Link to Wazuh security events overview page."""
        return f"{self.base_url}/app/wazuh#/overview/?tab=general"
    
    def agents_overview_link(self) -> str:
        """Link to Wazuh agents overview page."""
        return f"{self.base_url}/app/wazuh#/agents-preview/"
    
    # ─────────────────────────────────────────────────────────────────────────
    # INTERNAL URL BUILDING
    # ─────────────────────────────────────────────────────────────────────────
    
    def _build_discover_url(self, query: str, time_range: str = "24h") -> str:
        """
        Build a complete Discover app URL with query and time range.
        
        The URL structure follows OpenSearch Dashboards format:
        - _g: Global state (time range, refresh interval)
        - _a: App state (query, columns, filters)
        """
        # Parse time range to proper format
        time_from = self._parse_time_range(time_range)
        
        # Build the Rison-encoded state parameters
        # Note: Wazuh uses wazuh-alerts-* index pattern
        
        # Global state: time range
        global_state = f"(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'{time_from}',to:now))"
        
        # App state: query and index
        # Escape the query for URL
        encoded_query = query.replace("'", "\\'").replace('"', '\\"')
        app_state = f"(columns:!(_source),filters:!(),index:'wazuh-alerts-*',interval:auto,query:(language:kuery,query:'{encoded_query}'),sort:!())"
        
        # Build the full URL
        url = f"{self.base_url}/app/discover#/?_g={global_state}&_a={app_state}"
        
        return url
    
    def _parse_time_range(self, time_range: str) -> str:
        """
        Convert time range string to OpenSearch Dashboards format.
        
        Args:
            time_range: Time range like "24h", "7d", "1h", "30m"
            
        Returns:
            Format like "now-24h" for OpenSearch
        """
        time_range = time_range.lower().strip()
        
        # Already in correct format
        if time_range.startswith("now-"):
            return time_range
        
        # Parse common formats
        if time_range.endswith('h'):
            hours = int(time_range[:-1])
            return f"now-{hours}h"
        elif time_range.endswith('d'):
            days = int(time_range[:-1])
            return f"now-{days}d"
        elif time_range.endswith('m'):
            minutes = int(time_range[:-1])
            return f"now-{minutes}m"
        elif time_range.endswith('w'):
            weeks = int(time_range[:-1])
            return f"now-{weeks}w"
        else:
            # Default to 24 hours
            return "now-24h"


# ══════════════════════════════════════════════════════════════════════════════
# MARKDOWN LINK GENERATORS
# These return formatted markdown/HTML links for embedding in reports
# ══════════════════════════════════════════════════════════════════════════════

class WazuhReportLinks:
    """
    Generates formatted markdown links for embedding in AI-generated reports.
    These links open in new tabs and take users directly to filtered Wazuh views.
    """
    
    def __init__(self, base_url: str = None):
        self.generator = WazuhLinkGenerator(base_url)
    
    def rule_link_markdown(
        self, 
        rule_id: Union[str, int], 
        rule_description: str = None,
        time_range: str = "24h"
    ) -> str:
        """
        Generate markdown link for a rule ID.
        
        Example output: [Rule 5712](https://your-wazuh-host/app/discover#/...)
        """
        url = self.generator.rule_events_link(rule_id, time_range)
        label = f"Rule {rule_id}"
        if rule_description:
            label = f"{rule_description} (Rule {rule_id})"
        return f"[🔗 {label}]({url})"
    
    def agent_link_markdown(
        self, 
        agent_name: str, 
        time_range: str = "24h"
    ) -> str:
        """Generate markdown link for an agent."""
        url = self.generator.agent_events_link(agent_name, time_range)
        return f"[🖥️ {agent_name}]({url})"
    
    def ip_link_markdown(
        self, 
        ip_address: str, 
        time_range: str = "24h"
    ) -> str:
        """Generate markdown link for an IP address."""
        url = self.generator.ip_events_link(ip_address, "any", time_range)
        return f"[🌐 {ip_address}]({url})"
    
    def user_link_markdown(
        self, 
        username: str, 
        time_range: str = "24h"
    ) -> str:
        """Generate markdown link for a username."""
        url = self.generator.user_events_link(username, time_range)
        return f"[👤 {username}]({url})"
    
    def severity_link_markdown(
        self, 
        level_label: str,  # e.g., "CRITICAL", "HIGH"
        min_level: int,
        time_range: str = "24h"
    ) -> str:
        """Generate markdown link for a severity level."""
        url = self.generator.severity_events_link(min_level, time_range=time_range)
        return f"[⚠️ View all {level_label} alerts]({url})"
    
    def mitre_link_markdown(
        self, 
        technique_id: str, 
        technique_name: str = None,
        time_range: str = "24h"
    ) -> str:
        """Generate markdown link for a MITRE technique."""
        url = self.generator.mitre_technique_link(technique_id, time_range)
        label = f"{technique_id}"
        if technique_name:
            label = f"{technique_id} - {technique_name}"
        return f"[🎯 {label}]({url})"
    
    def view_all_link_markdown(self) -> str:
        """Generate link to security events overview."""
        url = self.generator.security_events_overview_link()
        return f"[📊 View All Security Events]({url})"


# ══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

# Default instance for easy import
_default_generator = WazuhLinkGenerator()
_default_report_links = WazuhReportLinks()


def get_rule_link(rule_id: Union[str, int], time_range: str = "24h") -> str:
    """Get URL for a specific rule ID."""
    return _default_generator.rule_events_link(rule_id, time_range)


def get_agent_link(agent_name: str, time_range: str = "24h") -> str:
    """Get URL for a specific agent."""
    return _default_generator.agent_events_link(agent_name, time_range)


def get_ip_link(ip_address: str, time_range: str = "24h") -> str:
    """Get URL for events involving an IP."""
    return _default_generator.ip_events_link(ip_address, "any", time_range)


def get_critical_alerts_link(time_range: str = "24h") -> str:
    """Get URL for critical severity alerts."""
    return _default_generator.critical_alerts_link(time_range)


def format_alert_with_links(alert: dict, time_range: str = "24h") -> dict:
    """
    Take an alert dict and add Wazuh dashboard links for key fields.
    
    Returns a dict with additional *_link keys for rule, agent, IPs, etc.
    """
    links = {}
    
    rule = alert.get('rule', {})
    agent = alert.get('agent', {})
    data = alert.get('data', {})
    
    # Rule link
    if rule.get('id'):
        links['rule_link'] = _default_report_links.rule_link_markdown(
            rule['id'], 
            rule.get('description'),
            time_range
        )
    
    # Agent link
    if agent.get('name'):
        links['agent_link'] = _default_report_links.agent_link_markdown(
            agent['name'],
            time_range
        )
    
    # IP links
    if data.get('srcip'):
        links['srcip_link'] = _default_report_links.ip_link_markdown(
            data['srcip'],
            time_range
        )
    if data.get('dstip'):
        links['dstip_link'] = _default_report_links.ip_link_markdown(
            data['dstip'],
            time_range
        )
    
    # User link
    if data.get('srcuser'):
        links['srcuser_link'] = _default_report_links.user_link_markdown(
            data['srcuser'],
            time_range
        )
    
    # MITRE links
    mitre = rule.get('mitre', {})
    if mitre.get('id'):
        technique_ids = mitre.get('id', [])
        technique_names = mitre.get('technique', [])
        links['mitre_links'] = []
        for i, tech_id in enumerate(technique_ids[:3]):
            tech_name = technique_names[i] if i < len(technique_names) else None
            links['mitre_links'].append(
                _default_report_links.mitre_link_markdown(tech_id, tech_name, time_range)
            )
    
    return links


# ══════════════════════════════════════════════════════════════════════════════
# LINK TEMPLATES FOR AI PROMPT
# These are provided to the LLM so it can generate links in reports
# ══════════════════════════════════════════════════════════════════════════════

def get_link_instructions_for_prompt(base_url: str = None) -> str:
    """
    Generate instructions for the AI on how to create Wazuh dashboard links.
    This is injected into the analysis prompt.
    """
    url = (base_url or WAZUH_DASHBOARD_URL).rstrip('/')
    
    return f"""
## WAZUH DASHBOARD LINK GENERATION

**IMPORTANT**: For every specific event, rule, IP address, or agent you mention in the report, 
include a clickable link that opens the Wazuh dashboard filtered to show those exact events.

### Link Format Rules

1. **Rule IDs**: When mentioning a rule (e.g., Rule 5712), make it clickable:
   `[🔗 Rule 5712]({url}/app/discover#/?_g=(time:(from:'now-24h',to:now))&_a=(query:(language:kuery,query:'rule.id:5712')))`

2. **Agent Names**: When mentioning an agent/host, link to its events:
   `[🖥️ servername]({url}/app/discover#/?_g=(time:(from:'now-24h',to:now))&_a=(query:(language:kuery,query:'agent.name:servername')))`

3. **IP Addresses**: Link IPs to their related events:
   `[🌐 192.168.1.100]({url}/app/discover#/?_g=(time:(from:'now-24h',to:now))&_a=(query:(language:kuery,query:'data.srcip:192.168.1.100')))`

4. **Usernames**: Link users to their activity:
   `[👤 admin]({url}/app/discover#/?_g=(time:(from:'now-24h',to:now))&_a=(query:(language:kuery,query:'data.srcuser:admin')))`

5. **Severity Levels**: Link to all alerts of a severity:
   `[⚠️ View CRITICAL alerts]({url}/app/discover#/?_g=(time:(from:'now-24h',to:now))&_a=(query:(language:kuery,query:'rule.level >= 12')))`

6. **MITRE Techniques**: Link to MITRE-tagged events:
   `[🎯 T1110]({url}/app/discover#/?_g=(time:(from:'now-24h',to:now))&_a=(query:(language:kuery,query:'rule.mitre.id:T1110')))`

### Pre-Built Quick Links

Include these standard links at the end of every report:

**📊 Quick Dashboard Links:**
- [View All Security Events]({url}/app/wazuh#/overview/?tab=general)
- [View Critical Alerts (Level 10+)]({url}/app/discover#/?_g=(time:(from:'now-24h',to:now))&_a=(query:(language:kuery,query:'rule.level >= 10')))
- [View All Agents]({url}/app/wazuh#/agents-preview/)
- [Authentication Events]({url}/app/discover#/?_g=(time:(from:'now-24h',to:now))&_a=(query:(language:kuery,query:'rule.groups:authentication_success OR rule.groups:authentication_failed')))

### Link Usage Guidelines

- ✅ ALWAYS link rule IDs when you mention them (e.g., "Rule 5712 fired 15 times" → make "Rule 5712" clickable)
- ✅ ALWAYS link IP addresses that appear in alerts
- ✅ ALWAYS link agent/host names  
- ✅ ALWAYS link usernames involved in security events
- ✅ Use emoji prefixes for visual clarity (🔗 rules, 🖥️ hosts, 🌐 IPs, 👤 users)
- ❌ DON'T create broken links - only link values you actually see in the data
- ❌ DON'T link generic terms - only link specific identifiers from the alert data
"""


if __name__ == "__main__":
    # Test the link generator
    gen = WazuhLinkGenerator()
    links = WazuhReportLinks()
    
    print("Testing Wazuh Link Generator")
    print("=" * 60)
    
    # Test various link types
    print("\n1. Rule link:")
    print(gen.rule_events_link(5712))
    
    print("\n2. Agent link:")
    print(gen.agent_events_link("wazuhserver"))
    
    print("\n3. IP link:")
    print(gen.ip_events_link("192.168.1.100"))
    
    print("\n4. Critical alerts link:")
    print(gen.critical_alerts_link())
    
    print("\n5. Markdown rule link:")
    print(links.rule_link_markdown(5712, "SSHD authentication success"))
    
    print("\n6. Markdown agent link:")
    print(links.agent_link_markdown("wazuhserver"))
    
    print("\nLink Instructions for Prompt:")
    print("-" * 60)
    print(get_link_instructions_for_prompt()[:500] + "...")
