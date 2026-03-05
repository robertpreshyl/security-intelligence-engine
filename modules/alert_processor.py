#!/usr/bin/env python3
"""
Alert Processor - Phase 2: Structured Alert Analysis
Reads alerts from Wazuh alerts.json, filters, enriches, and formats them
for human and AI consumption.

Author: AI-SOC Integration Project
Created: February 15, 2026
"""

import os
import sys
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict

from dotenv import load_dotenv

load_dotenv()

# Configure logging
logger = logging.getLogger('ai_soc.alert_processor')

ALERT_FILE = os.getenv('WAZUH_ALERT_FILE', '/var/ossec/logs/alerts/alerts.json')
DEFAULT_MIN_LEVEL = int(os.getenv('WAZUH_MIN_ALERT_LEVEL', '3'))


class AlertProcessor:
    """
    Processes Wazuh alerts from alerts.json file.
    Provides filtering, enrichment, grouping, and formatted output.
    """

    def __init__(self, alert_file: str = None):
        self.alert_file = alert_file or ALERT_FILE
        self._alerts_cache = None
        self._cache_time = None
        self._cache_ttl = 60  # seconds

    # ─────────────────────────────────────────────
    # DATA LOADING
    # ─────────────────────────────────────────────

    def load_alerts(self, max_lines: int = None) -> List[Dict]:
        """
        Load alerts from the JSON alert file.

        Args:
            max_lines: Maximum number of alert lines to read (from end of file).
                       None = read all.

        Returns:
            List of alert dictionaries, newest first.
        """
        alerts = []
        try:
            with open(self.alert_file, 'r') as f:
                lines = f.readlines()

            if max_lines:
                lines = lines[-max_lines:]

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                    alerts.append(alert)
                except json.JSONDecodeError:
                    continue

        except PermissionError:
            logger.error(f"Permission denied reading {self.alert_file}. Run with sudo.")
            raise
        except FileNotFoundError:
            logger.error(f"Alert file not found: {self.alert_file}")
            raise

        # newest first
        alerts.reverse()
        self._alerts_cache = alerts
        self._cache_time = datetime.now()
        return alerts

    # ─────────────────────────────────────────────
    # FILTERING
    # ─────────────────────────────────────────────

    def filter_alerts(self, alerts: List[Dict],
                      min_level: int = None,
                      max_level: int = None,
                      hours: float = None,
                      agent_name: str = None,
                      agent_id: str = None,
                      rule_id: str = None,
                      groups: List[str] = None,
                      exclude_groups: List[str] = None,
                      search: str = None) -> List[Dict]:
        """
        Filter alerts by multiple criteria (all criteria are AND-ed).

        Args:
            min_level: Minimum rule level (inclusive)
            max_level: Maximum rule level (inclusive)
            hours: Only alerts from the last N hours
            agent_name: Filter by agent name (case-insensitive partial match)
            agent_id: Filter by exact agent ID
            rule_id: Filter by exact rule ID
            groups: Require alert to have at least one of these groups
            exclude_groups: Exclude alerts with any of these groups
            search: Text search in description and full_log

        Returns:
            Filtered list of alerts
        """
        filtered = []
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        for alert in alerts:
            rule = alert.get('rule', {})
            level = rule.get('level', 0)
            agent = alert.get('agent', {})
            alert_groups = rule.get('groups', [])

            # Level filter
            if min_level is not None and level < min_level:
                continue
            if max_level is not None and level > max_level:
                continue

            # Time filter
            if hours is not None:
                try:
                    ts = datetime.strptime(
                        alert['timestamp'][:19], '%Y-%m-%dT%H:%M:%S'
                    )
                    if (now - ts).total_seconds() > hours * 3600:
                        continue
                except (KeyError, ValueError):
                    continue

            # Agent filters
            if agent_name and agent_name.lower() not in agent.get('name', '').lower():
                continue
            if agent_id and agent.get('id') != agent_id:
                continue

            # Rule ID filter
            if rule_id and rule.get('id') != rule_id:
                continue

            # Group filters
            if groups:
                if not any(g in alert_groups for g in groups):
                    continue
            if exclude_groups:
                if any(g in alert_groups for g in exclude_groups):
                    continue

            # Text search
            if search:
                search_lower = search.lower()
                desc = rule.get('description', '').lower()
                full_log = alert.get('full_log', '').lower()
                if search_lower not in desc and search_lower not in full_log:
                    continue

            filtered.append(alert)

        return filtered

    # ─────────────────────────────────────────────
    # GROUPING & AGGREGATION
    # ─────────────────────────────────────────────

    def group_by_agent(self, alerts: List[Dict]) -> Dict[str, List[Dict]]:
        """Group alerts by agent name."""
        groups = defaultdict(list)
        for alert in alerts:
            name = alert.get('agent', {}).get('name', 'unknown')
            groups[name].append(alert)
        return dict(groups)

    def group_by_rule(self, alerts: List[Dict]) -> Dict[str, List[Dict]]:
        """Group alerts by rule ID."""
        groups = defaultdict(list)
        for alert in alerts:
            rule_id = alert.get('rule', {}).get('id', 'unknown')
            groups[rule_id].append(alert)
        return dict(groups)

    def group_by_level(self, alerts: List[Dict]) -> Dict[int, List[Dict]]:
        """Group alerts by severity level."""
        groups = defaultdict(list)
        for alert in alerts:
            level = alert.get('rule', {}).get('level', 0)
            groups[level].append(alert)
        return dict(groups)

    def group_by_mitre_tactic(self, alerts: List[Dict]) -> Dict[str, List[Dict]]:
        """Group alerts by MITRE ATT&CK tactic."""
        groups = defaultdict(list)
        for alert in alerts:
            mitre = alert.get('rule', {}).get('mitre', {})
            tactics = []
            if isinstance(mitre, dict):
                tactics = mitre.get('tactic', [])
            elif isinstance(mitre, list):
                for m in mitre:
                    if isinstance(m, dict):
                        tactics.extend(m.get('tactic', []))

            if not tactics:
                groups['No MITRE Mapping'].append(alert)
            else:
                for tactic in tactics:
                    groups[tactic].append(alert)

        return dict(groups)

    # ─────────────────────────────────────────────
    # ENRICHMENT
    # ─────────────────────────────────────────────

    def enrich_with_mitre(self, alert: Dict) -> Dict:
        """
        Extract and flatten MITRE ATT&CK information from an alert.

        Returns dict with: tactics, techniques, technique_ids
        """
        mitre = alert.get('rule', {}).get('mitre', {})
        result = {'tactics': [], 'techniques': [], 'technique_ids': []}

        if isinstance(mitre, dict):
            result['tactics'] = mitre.get('tactic', [])
            result['techniques'] = mitre.get('technique', [])
            result['technique_ids'] = mitre.get('id', [])
        elif isinstance(mitre, list):
            for m in mitre:
                if isinstance(m, dict):
                    result['tactics'].extend(m.get('tactic', []))
                    result['techniques'].extend(m.get('technique', []))
                    result['technique_ids'].extend(m.get('id', []))

        return result

    def enrich_with_compliance(self, alert: Dict) -> Dict:
        """Extract all compliance framework mappings from an alert."""
        rule = alert.get('rule', {})
        return {
            'pci_dss': rule.get('pci_dss', []),
            'nist_800_53': rule.get('nist_800_53', []),
            'gdpr': rule.get('gdpr', []),
            'hipaa': rule.get('hipaa', []),
            'gpg13': rule.get('gpg13', []),
            'tsc': rule.get('tsc', []),
        }

    def extract_source_info(self, alert: Dict) -> Dict:
        """Extract source user/IP/command details from alert data."""
        data = alert.get('data', {})
        return {
            'src_user': data.get('srcuser', ''),
            'dst_user': data.get('dstuser', ''),
            'src_ip': data.get('srcip', alert.get('data', {}).get('src_ip', '')),
            'dst_ip': data.get('dstip', ''),
            'command': data.get('command', ''),
            'tty': data.get('tty', ''),
            'pwd': data.get('pwd', ''),
        }

    # ─────────────────────────────────────────────
    # STATISTICS
    # ─────────────────────────────────────────────

    def compute_stats(self, alerts: List[Dict]) -> Dict:
        """
        Compute summary statistics for a set of alerts.

        Returns dict with counts, distributions, time range.
        """
        if not alerts:
            return {'total': 0}

        level_counts = Counter()
        rule_id_counts = Counter()
        rule_id_meta = {}  # rule_id -> {description, level}
        agent_counts = Counter()
        group_counts = Counter()
        mitre_tactic_counts = Counter()

        timestamps = []

        for alert in alerts:
            rule = alert.get('rule', {})
            level_counts[rule.get('level', 0)] += 1
            rule_id = rule.get('id', '?')
            rule_id_counts[rule_id] += 1
            if rule_id not in rule_id_meta:
                rule_id_meta[rule_id] = {
                    'description': rule.get('description', '?')[:60],
                    'level': rule.get('level', 0),
                }
            agent_counts[alert.get('agent', {}).get('name', '?')] += 1

            for g in rule.get('groups', []):
                group_counts[g] += 1

            mitre_info = self.enrich_with_mitre(alert)
            for t in mitre_info['tactics']:
                mitre_tactic_counts[t] += 1

            try:
                ts = datetime.strptime(alert['timestamp'][:19], '%Y-%m-%dT%H:%M:%S')
                timestamps.append(ts)
            except (KeyError, ValueError):
                pass

        time_range = {}
        if timestamps:
            time_range = {
                'earliest': min(timestamps).isoformat(),
                'latest': max(timestamps).isoformat(),
                'span_hours': round(
                    (max(timestamps) - min(timestamps)).total_seconds() / 3600, 1
                ),
            }

        return {
            'total': len(alerts),
            'levels': dict(sorted(level_counts.items(), reverse=True)),
            'top_rules': [
                {
                    'rule_id': rid,
                    'description': rule_id_meta.get(rid, {}).get('description', '?'),
                    'count': count,
                    'level': rule_id_meta.get(rid, {}).get('level', 0),
                }
                for rid, count in rule_id_counts.most_common(15)
            ],
            'by_agent': dict(agent_counts.most_common()),
            'top_groups': dict(group_counts.most_common(10)),
            'mitre_tactics': dict(mitre_tactic_counts.most_common()),
            'time_range': time_range,
        }

    # ─────────────────────────────────────────────
    # SEVERITY CLASSIFICATION
    # ─────────────────────────────────────────────

    @staticmethod
    def classify_severity(level: int) -> Tuple[str, str]:
        """
        Classify a Wazuh alert level into a severity tier.

        Returns (tier_name, emoji)

        Wazuh levels:
          0-4:   Informational / low
          5-7:   Moderate / notable
          8-10:  High / significant
          11-13: Critical / action needed
          14-15: Emergency / immediate response
        """
        if level >= 14:
            return 'EMERGENCY', '🔴'
        elif level >= 11:
            return 'CRITICAL', '🟠'
        elif level >= 8:
            return 'HIGH', '🟡'
        elif level >= 5:
            return 'MODERATE', '🔵'
        else:
            return 'LOW', '⚪'

    # ─────────────────────────────────────────────
    # FORMATTED OUTPUT
    # ─────────────────────────────────────────────

    def format_alert_summary(self, alert: Dict, include_full_log: bool = False) -> str:
        """Format a single alert as a concise readable line."""
        rule = alert.get('rule', {})
        agent = alert.get('agent', {})
        level = rule.get('level', 0)
        _, emoji = self.classify_severity(level)

        ts = alert.get('timestamp', '?')[:19]
        desc = rule.get('description', '?')
        rule_id = rule.get('id', '?')
        agent_name = agent.get('name', '?')

        line = f"{emoji} [{ts}] Level {level} | Rule {rule_id} | {agent_name} | {desc}"

        if include_full_log:
            full_log = alert.get('full_log', '')
            if full_log:
                line += f"\n   Log: {full_log[:200]}"

        return line

    def format_markdown_report(self, alerts: List[Dict],
                                title: str = "Alert Analysis Report",
                                include_details: bool = True) -> str:
        """
        Generate a full Markdown report from a set of alerts.

        Args:
            alerts: List of alert dictionaries
            title: Report title
            include_details: Include per-alert detail section

        Returns:
            Markdown-formatted report string
        """
        stats = self.compute_stats(alerts)
        lines = []

        # Header
        lines.append(f"# {title}")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
        lines.append(f"**Total Alerts:** {stats['total']}")
        if stats.get('time_range'):
            tr = stats['time_range']
            lines.append(f"**Time Range:** {tr.get('earliest', '?')} → {tr.get('latest', '?')} ({tr.get('span_hours', '?')}h)")
        lines.append("")

        # Severity breakdown
        lines.append("## Severity Breakdown")
        lines.append("")
        lines.append("| Level | Severity | Count |")
        lines.append("|-------|----------|-------|")
        for level in sorted(stats.get('levels', {}).keys(), reverse=True):
            count = stats['levels'][level]
            tier, emoji = self.classify_severity(level)
            lines.append(f"| {level} | {emoji} {tier} | {count} |")
        lines.append("")

        # Top rules
        lines.append("## Top Alert Rules")
        lines.append("")
        lines.append("| Count | Rule ID | Description | Severity |")
        lines.append("|-------|---------|-------------|----------|")
        for rule_info in stats.get('top_rules', []):
            if isinstance(rule_info, dict):
                lines.append(f"| {rule_info['count']} | {rule_info['rule_id']} | {rule_info['description']} | Level {rule_info.get('level', '?')} |")
        lines.append("")

        # By agent
        lines.append("## Alerts by Agent")
        lines.append("")
        lines.append("| Agent | Count |")
        lines.append("|-------|-------|")
        for agent, count in stats.get('by_agent', {}).items():
            lines.append(f"| {agent} | {count} |")
        lines.append("")

        # MITRE ATT&CK
        if stats.get('mitre_tactics'):
            lines.append("## MITRE ATT&CK Tactics Observed")
            lines.append("")
            lines.append("| Tactic | Count |")
            lines.append("|--------|-------|")
            for tactic, count in stats['mitre_tactics'].items():
                lines.append(f"| {tactic} | {count} |")
            lines.append("")

        # Notable alerts (level >= 7)
        high_alerts = [a for a in alerts if a.get('rule', {}).get('level', 0) >= 7]
        if high_alerts:
            lines.append(f"## Notable Alerts (Level 7+) — {len(high_alerts)} total")
            lines.append("")
            for alert in high_alerts[:30]:
                lines.append(f"- {self.format_alert_summary(alert)}")
            if len(high_alerts) > 30:
                lines.append(f"- ... and {len(high_alerts) - 30} more")
            lines.append("")

        # Detailed alert list
        if include_details:
            lines.append("## Alert Details")
            lines.append("")
            for i, alert in enumerate(alerts[:50], 1):
                rule = alert.get('rule', {})
                agent = alert.get('agent', {})
                level = rule.get('level', 0)
                tier, emoji = self.classify_severity(level)

                lines.append(f"### {emoji} Alert #{i} — Rule {rule.get('id', '?')}")
                lines.append(f"- **Time:** {alert.get('timestamp', '?')}")
                lines.append(f"- **Level:** {level} ({tier})")
                lines.append(f"- **Description:** {rule.get('description', '?')}")
                lines.append(f"- **Agent:** {agent.get('name', '?')} ({agent.get('id', '?')})")
                lines.append(f"- **Groups:** {', '.join(rule.get('groups', []))}")

                # MITRE
                mitre = self.enrich_with_mitre(alert)
                if mitre['tactics']:
                    lines.append(f"- **MITRE Tactics:** {', '.join(mitre['tactics'])}")
                    lines.append(f"- **MITRE Techniques:** {', '.join(mitre['techniques'])} ({', '.join(mitre['technique_ids'])})")

                # Compliance
                compliance = self.enrich_with_compliance(alert)
                comp_parts = []
                for framework, values in compliance.items():
                    if values:
                        comp_parts.append(f"{framework}: {', '.join(values)}")
                if comp_parts:
                    lines.append(f"- **Compliance:** {' | '.join(comp_parts)}")

                # Source info
                src = self.extract_source_info(alert)
                src_parts = []
                if src['src_user']:
                    src_parts.append(f"User: {src['src_user']}")
                if src['src_ip']:
                    src_parts.append(f"IP: {src['src_ip']}")
                if src['command']:
                    src_parts.append(f"Cmd: {src['command'][:100]}")
                if src_parts:
                    lines.append(f"- **Source:** {' | '.join(src_parts)}")

                # Full log (truncated)
                full_log = alert.get('full_log', '')
                if full_log:
                    lines.append(f"- **Log:** `{full_log[:200]}`")

                lines.append("")

            if len(alerts) > 50:
                lines.append(f"*... {len(alerts) - 50} additional alerts omitted.*")
                lines.append("")

        return '\n'.join(lines)

    def format_json_for_ai(self, alerts: List[Dict], context: str = "") -> str:
        """
        Format alerts as structured JSON suitable for LLM analysis.
        Strips unnecessary fields, flattens structure, adds context.

        Args:
            alerts: List of alert dictionaries
            context: Optional context string to prepend

        Returns:
            JSON string ready for AI consumption
        """
        stats = self.compute_stats(alerts)

        processed = []
        for alert in alerts[:100]:  # Cap at 100 for context window
            rule = alert.get('rule', {})
            agent = alert.get('agent', {})
            mitre = self.enrich_with_mitre(alert)
            src = self.extract_source_info(alert)

            processed.append({
                'timestamp': alert.get('timestamp', ''),
                'level': rule.get('level', 0),
                'severity': self.classify_severity(rule.get('level', 0))[0],
                'rule_id': rule.get('id', ''),
                'description': rule.get('description', ''),
                'agent': agent.get('name', ''),
                'agent_id': agent.get('id', ''),
                'groups': rule.get('groups', []),
                'mitre_tactics': mitre['tactics'],
                'mitre_techniques': mitre['techniques'],
                'mitre_ids': mitre['technique_ids'],
                'src_user': src['src_user'],
                'src_ip': src['src_ip'],
                'command': src['command'],
                'full_log': alert.get('full_log', '')[:300],
                'location': alert.get('location', ''),
            })

        output = {
            'analysis_request': {
                'generated_utc': datetime.now(timezone.utc).isoformat(),
                'context': context,
                'summary': stats,
                'alerts': processed,
            }
        }

        return json.dumps(output, indent=2, default=str)


def main():
    """CLI interface for alert processing."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Wazuh Alert Processor - Phase 2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # All alerts from last 24 hours, level 5+
  sudo python modules/alert_processor.py --hours 24 --min-level 5

  # High severity only, markdown report
  sudo python modules/alert_processor.py --min-level 8 --format markdown

  # Alerts from a specific agent
  sudo python modules/alert_processor.py --agent server --hours 12

  # Search for authentication failures
  sudo python modules/alert_processor.py --search "authentication" --hours 24

  # JSON output for AI analysis
  sudo python modules/alert_processor.py --hours 6 --min-level 5 --format json

  # Exclude noisy SCA alerts
  sudo python modules/alert_processor.py --hours 24 --exclude-groups sca
        """
    )
    parser.add_argument('--hours', type=float, help='Only alerts from last N hours')
    parser.add_argument('--min-level', type=int, default=DEFAULT_MIN_LEVEL,
                        help=f'Minimum alert level (default: {DEFAULT_MIN_LEVEL})')
    parser.add_argument('--max-level', type=int, help='Maximum alert level')
    parser.add_argument('--agent', type=str, help='Filter by agent name')
    parser.add_argument('--agent-id', type=str, help='Filter by agent ID')
    parser.add_argument('--rule-id', type=str, help='Filter by rule ID')
    parser.add_argument('--groups', type=str, nargs='+', help='Require one of these groups')
    parser.add_argument('--exclude-groups', type=str, nargs='+',
                        help='Exclude alerts with these groups')
    parser.add_argument('--search', type=str, help='Text search in description/log')
    parser.add_argument('--format', choices=['summary', 'markdown', 'json', 'lines'],
                        default='summary', help='Output format (default: summary)')
    parser.add_argument('--max-alerts', type=int, default=5000,
                        help='Max alert lines to read from file (default: 5000)')
    parser.add_argument('--output', type=str, help='Write output to file')
    parser.add_argument('--stats-only', action='store_true',
                        help='Only show statistics, no alert details')

    args = parser.parse_args()

    try:
        processor = AlertProcessor()
        print("📂 Loading alerts...", file=sys.stderr)
        alerts = processor.load_alerts(max_lines=args.max_alerts)
        print(f"   Loaded {len(alerts)} alerts from {processor.alert_file}",
              file=sys.stderr)

        # Apply filters
        filtered = processor.filter_alerts(
            alerts,
            min_level=args.min_level,
            max_level=args.max_level,
            hours=args.hours,
            agent_name=args.agent,
            agent_id=args.agent_id,
            rule_id=args.rule_id,
            groups=args.groups,
            exclude_groups=args.exclude_groups,
            search=args.search,
        )
        print(f"   After filtering: {len(filtered)} alerts", file=sys.stderr)

        if not filtered:
            print("\n⚠️  No alerts matched the given filters.", file=sys.stderr)
            sys.exit(0)

        # Generate output
        output = ""

        if args.stats_only:
            stats = processor.compute_stats(filtered)
            output = json.dumps(stats, indent=2, default=str)

        elif args.format == 'summary':
            stats = processor.compute_stats(filtered)
            output_lines = []
            output_lines.append(f"\n📊 Alert Summary ({stats['total']} alerts)")
            output_lines.append("=" * 60)

            if stats.get('time_range'):
                tr = stats['time_range']
                output_lines.append(
                    f"Time Range: {tr.get('earliest', '?')} → {tr.get('latest', '?')} ({tr.get('span_hours', '?')}h)"
                )

            output_lines.append("\n🎯 Severity Levels:")
            for level in sorted(stats.get('levels', {}).keys(), reverse=True):
                count = stats['levels'][level]
                tier, emoji = processor.classify_severity(level)
                output_lines.append(f"  {emoji} Level {level:2d} ({tier:10s}): {count}")

            output_lines.append("\n📋 Top Rules:")
            for rule_info in stats.get('top_rules', [])[:10]:
                if isinstance(rule_info, dict):
                    output_lines.append(f"  [{rule_info['count']:4d}] Rule {rule_info['rule_id']}: {rule_info['description']}")

            output_lines.append("\n📡 By Agent:")
            for agent, count in stats.get('by_agent', {}).items():
                output_lines.append(f"  {agent}: {count}")

            if stats.get('mitre_tactics'):
                output_lines.append("\n🎯 MITRE ATT&CK Tactics:")
                for tactic, count in stats['mitre_tactics'].items():
                    output_lines.append(f"  {tactic}: {count}")

            # Show high-severity alerts
            high = [a for a in filtered if a.get('rule', {}).get('level', 0) >= 7]
            if high:
                output_lines.append(f"\n🚨 Notable Alerts (Level 7+): {len(high)}")
                for a in high[:20]:
                    output_lines.append(f"  {processor.format_alert_summary(a)}")

            output_lines.append("")
            output = '\n'.join(output_lines)

        elif args.format == 'markdown':
            output = processor.format_markdown_report(
                filtered,
                title="Wazuh Alert Analysis Report",
                include_details=not args.stats_only
            )

        elif args.format == 'json':
            output = processor.format_json_for_ai(filtered)

        elif args.format == 'lines':
            lines = []
            for a in filtered:
                lines.append(processor.format_alert_summary(a, include_full_log=True))
            output = '\n'.join(lines)

        # Output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"\n✅ Output written to {args.output}", file=sys.stderr)
        else:
            print(output)

    except PermissionError:
        print("\n❌ Permission denied. Run with: sudo python modules/alert_processor.py",
              file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
