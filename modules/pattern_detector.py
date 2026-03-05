#!/usr/bin/env python3
"""
Pattern Detector - Phase 2: Security Pattern Recognition
Detects common attack patterns in Wazuh alert data including brute force,
port scanning, lateral movement, privilege escalation, and anomalies.

Author: AI-SOC Integration Project
Created: February 15, 2026
"""

import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict

logger = logging.getLogger('ai_soc.pattern_detector')


class PatternDetector:
    """
    Detects security-relevant patterns in Wazuh alert data.
    All operations are read-only analysis — no system modifications.
    """

    # ──────────────────────────────────────────────────────
    # BRUTE FORCE DETECTION
    # ──────────────────────────────────────────────────────

    AUTH_FAILURE_RULES = {
        '5503', '5710', '5716', '5720', '5758',  # SSH failures
        '2501', '2502',                            # syslog auth
        '3332',                                    # Postfix SASL
        '60122', '60204',                          # Windows logon failures
        '18100', '18101', '18102',                 # Windows security
    }

    AUTH_FAILURE_GROUPS = {
        'authentication_failed', 'sshd', 'authentication_failures',
        'win_authentication_failed',
    }

    def detect_brute_force(self, alerts: List[Dict],
                           threshold: int = 5,
                           window_minutes: int = 10) -> List[Dict]:
        """
        Detect brute force attempts: repeated authentication failures
        from the same source within a time window.

        Args:
            alerts: List of alert dictionaries
            threshold: Minimum failures to trigger detection
            window_minutes: Time window in minutes

        Returns:
            List of detected brute force patterns
        """
        # Collect auth failure events
        auth_failures = []
        for alert in alerts:
            rule = alert.get('rule', {})
            rule_id = rule.get('id', '')
            groups = set(rule.get('groups', []))

            is_auth_fail = (
                rule_id in self.AUTH_FAILURE_RULES
                or groups & self.AUTH_FAILURE_GROUPS
                or 'authentication_failed' in rule.get('description', '').lower()
            )

            if is_auth_fail:
                auth_failures.append(alert)

        if not auth_failures:
            return []

        # Group by source (src_ip or src_user)
        by_source = defaultdict(list)
        for alert in auth_failures:
            data = alert.get('data', {})
            src = (
                data.get('srcip')
                or data.get('src_ip')
                or data.get('srcuser')
                or alert.get('agent', {}).get('name', 'unknown')
            )
            by_source[src].append(alert)

        # Check for bursts within window
        findings = []
        window = timedelta(minutes=window_minutes)

        for source, events in by_source.items():
            if len(events) < threshold:
                continue

            # Sort by timestamp
            events.sort(key=lambda a: a.get('timestamp', ''))

            # Sliding window check
            burst_start = 0
            for i in range(len(events)):
                try:
                    ts_i = datetime.strptime(events[i]['timestamp'][:19], '%Y-%m-%dT%H:%M:%S')
                    ts_start = datetime.strptime(events[burst_start]['timestamp'][:19], '%Y-%m-%dT%H:%M:%S')

                    # Advance start if outside window
                    while ts_i - ts_start > window and burst_start < i:
                        burst_start += 1
                        ts_start = datetime.strptime(events[burst_start]['timestamp'][:19], '%Y-%m-%dT%H:%M:%S')

                    burst_count = i - burst_start + 1
                    if burst_count >= threshold:
                        # Collect targeted agents
                        burst_events = events[burst_start:i + 1]
                        target_agents = set()
                        target_users = set()
                        rule_ids = set()
                        for e in burst_events:
                            target_agents.add(e.get('agent', {}).get('name', '?'))
                            target_users.add(e.get('data', {}).get('dstuser', ''))
                            rule_ids.add(e.get('rule', {}).get('id', ''))

                        findings.append({
                            'pattern': 'BRUTE_FORCE',
                            'severity': 'HIGH' if burst_count > threshold * 2 else 'MODERATE',
                            'confidence': min(0.95, 0.6 + burst_count * 0.03),
                            'source': source,
                            'count': burst_count,
                            'window_minutes': window_minutes,
                            'time_start': events[burst_start].get('timestamp', ''),
                            'time_end': events[i].get('timestamp', ''),
                            'target_agents': list(target_agents - {''}),
                            'target_users': list(target_users - {''}),
                            'rule_ids': list(rule_ids),
                            'sample_alerts': [
                                events[burst_start].get('rule', {}).get('description', ''),
                                events[i].get('rule', {}).get('description', ''),
                            ],
                        })
                        break  # One finding per source

                except (ValueError, KeyError):
                    continue

        return findings

    # ──────────────────────────────────────────────────────
    # PORT SCAN DETECTION
    # ──────────────────────────────────────────────────────

    PORT_CHANGE_RULES = {'533', '534', '535'}

    def detect_port_scan(self, alerts: List[Dict],
                         threshold: int = 10,
                         window_minutes: int = 5) -> List[Dict]:
        """
        Detect port scanning patterns: rapid port change events
        or connection attempts to multiple ports.

        Args:
            alerts: List of alert dictionaries
            threshold: Minimum events to trigger
            window_minutes: Time window

        Returns:
            Detected port scan patterns
        """
        port_events = []
        for alert in alerts:
            rule = alert.get('rule', {})
            rule_id = rule.get('id', '')
            desc = rule.get('description', '').lower()

            if (rule_id in self.PORT_CHANGE_RULES
                    or 'port' in desc and ('scan' in desc or 'connection' in desc or 'opened' in desc)):
                port_events.append(alert)

        if len(port_events) < threshold:
            return []

        # Group by agent and look for bursts
        by_agent = defaultdict(list)
        for alert in port_events:
            agent = alert.get('agent', {}).get('name', 'unknown')
            by_agent[agent].append(alert)

        findings = []
        for agent, events in by_agent.items():
            if len(events) >= threshold:
                events.sort(key=lambda a: a.get('timestamp', ''))
                findings.append({
                    'pattern': 'PORT_ACTIVITY',
                    'severity': 'MODERATE',
                    'confidence': min(0.85, 0.5 + len(events) * 0.02),
                    'agent': agent,
                    'count': len(events),
                    'time_start': events[0].get('timestamp', ''),
                    'time_end': events[-1].get('timestamp', ''),
                    'description': f'{len(events)} port-related events on {agent}',
                })

        return findings

    # ──────────────────────────────────────────────────────
    # PRIVILEGE ESCALATION DETECTION
    # ──────────────────────────────────────────────────────

    PRIV_ESC_RULES = {'5402', '5403', '5404', '5405', '5407'}
    PRIV_ESC_MITRE = {'T1548', 'T1548.003', 'T1068', 'T1134'}

    def detect_privilege_escalation(self, alerts: List[Dict],
                                     threshold: int = 3,
                                     window_minutes: int = 30) -> List[Dict]:
        """
        Detect privilege escalation patterns: sudo/su activity
        combined with MITRE T1548 indicators.

        Args:
            alerts: Alert list
            threshold: Minimum events
            window_minutes: Time window

        Returns:
            Privilege escalation findings
        """
        priv_events = []
        for alert in alerts:
            rule = alert.get('rule', {})
            rule_id = rule.get('id', '')
            groups = rule.get('groups', [])
            desc = rule.get('description', '').lower()

            # MITRE check
            mitre = rule.get('mitre', {})
            mitre_ids = set()
            if isinstance(mitre, dict):
                mitre_ids = set(mitre.get('id', []))
            elif isinstance(mitre, list):
                for m in mitre:
                    if isinstance(m, dict):
                        mitre_ids.update(m.get('id', []))

            is_priv_esc = (
                rule_id in self.PRIV_ESC_RULES
                or 'sudo' in groups
                or mitre_ids & self.PRIV_ESC_MITRE
                or 'privilege' in desc or 'escalat' in desc
            )

            if is_priv_esc:
                priv_events.append(alert)

        if not priv_events:
            return []

        # Group by user
        by_user = defaultdict(list)
        for alert in priv_events:
            user = (
                alert.get('data', {}).get('srcuser')
                or alert.get('data', {}).get('dstuser')
                or 'unknown'
            )
            by_user[user].append(alert)

        findings = []
        for user, events in by_user.items():
            # Check diversity of commands (sign of exploration)
            commands = set()
            agents = set()
            for e in events:
                cmd = e.get('data', {}).get('command', '')
                if cmd:
                    commands.add(cmd)
                agents.add(e.get('agent', {}).get('name', '?'))

            # Higher confidence if diverse commands or cross-agent
            diversity_score = min(len(commands), 5) / 5
            cross_agent = len(agents) > 1

            if len(events) >= threshold:
                severity = 'HIGH'
                if cross_agent:
                    severity = 'CRITICAL'
                elif len(events) < threshold * 2:
                    severity = 'MODERATE'

                findings.append({
                    'pattern': 'PRIVILEGE_ESCALATION',
                    'severity': severity,
                    'confidence': min(0.90, 0.5 + diversity_score * 0.2 + (0.15 if cross_agent else 0)),
                    'user': user,
                    'count': len(events),
                    'unique_commands': len(commands),
                    'agents': list(agents),
                    'cross_agent': cross_agent,
                    'sample_commands': list(commands)[:5],
                    'time_start': events[-1].get('timestamp', ''),
                    'time_end': events[0].get('timestamp', ''),
                })

        return findings

    # ──────────────────────────────────────────────────────
    # LATERAL MOVEMENT DETECTION
    # ──────────────────────────────────────────────────────

    def detect_lateral_movement(self, alerts: List[Dict],
                                 min_agents: int = 2,
                                 window_minutes: int = 30) -> List[Dict]:
        """
        Detect lateral movement: same source IP or user appearing
        across multiple agents within a time window.

        Args:
            alerts: Alert list
            min_agents: Minimum number of agents from same source
            window_minutes: Time window

        Returns:
            Lateral movement findings
        """
        # Build source → agent → events map
        source_agents = defaultdict(lambda: defaultdict(list))

        for alert in alerts:
            data = alert.get('data', {})
            src = data.get('srcip') or data.get('srcuser') or data.get('src_ip')
            if not src:
                continue

            agent = alert.get('agent', {}).get('name', 'unknown')
            source_agents[src][agent].append(alert)

        findings = []
        for source, agents in source_agents.items():
            if len(agents) >= min_agents:
                all_events = []
                for agent_events in agents.values():
                    all_events.extend(agent_events)

                findings.append({
                    'pattern': 'LATERAL_MOVEMENT',
                    'severity': 'HIGH',
                    'confidence': min(0.85, 0.5 + len(agents) * 0.1),
                    'source': source,
                    'affected_agents': list(agents.keys()),
                    'agent_count': len(agents),
                    'total_events': len(all_events),
                    'description': f'Source {source} appeared on {len(agents)} agents',
                })

        return findings

    # ──────────────────────────────────────────────────────
    # ALERT BURST DETECTION
    # ──────────────────────────────────────────────────────

    def detect_alert_bursts(self, alerts: List[Dict],
                            threshold: int = 20,
                            window_minutes: int = 5) -> List[Dict]:
        """
        Detect sudden bursts of alert activity that may indicate
        an ongoing attack or misconfiguration.

        Args:
            alerts: Alert list
            threshold: Min alerts in window to be a burst
            window_minutes: Time window

        Returns:
            Alert burst findings
        """
        if len(alerts) < threshold:
            return []

        # Bucket alerts by minute
        buckets = defaultdict(list)
        for alert in alerts:
            try:
                ts = alert.get('timestamp', '')[:16]  # YYYY-MM-DDTHH:MM
                buckets[ts].append(alert)
            except (KeyError, IndexError):
                continue

        findings = []
        sorted_minutes = sorted(buckets.keys())

        for i, minute in enumerate(sorted_minutes):
            # Look at window_minutes consecutive minutes
            window_alerts = []
            for j in range(min(window_minutes, len(sorted_minutes) - i)):
                if i + j < len(sorted_minutes):
                    window_alerts.extend(buckets[sorted_minutes[i + j]])

            if len(window_alerts) >= threshold:
                # Analyze what's in the burst
                rule_counts = Counter()
                agent_counts = Counter()
                for a in window_alerts:
                    rule = a.get('rule', {})
                    rule_counts[f"{rule.get('id', '?')}: {rule.get('description', '?')[:40]}"] += 1
                    agent_counts[a.get('agent', {}).get('name', '?')] += 1

                findings.append({
                    'pattern': 'ALERT_BURST',
                    'severity': 'MODERATE',
                    'confidence': min(0.80, 0.4 + len(window_alerts) * 0.01),
                    'count': len(window_alerts),
                    'window_start': minute,
                    'top_rules': dict(rule_counts.most_common(5)),
                    'affected_agents': dict(agent_counts.most_common()),
                    'description': f'{len(window_alerts)} alerts in {window_minutes}-min window starting {minute}',
                })
                break  # Return the first major burst

        return findings

    # ──────────────────────────────────────────────────────
    # SCA COMPLIANCE ANOMALIES
    # ──────────────────────────────────────────────────────

    def detect_compliance_failures(self, alerts: List[Dict]) -> List[Dict]:
        """
        Summarize SCA/compliance check failures visible in alerts.

        Returns:
            Compliance failure summaries per agent.
        """
        sca_alerts = [a for a in alerts if 'sca' in a.get('rule', {}).get('groups', [])]

        if not sca_alerts:
            return []

        # Group by agent
        by_agent = defaultdict(list)
        for alert in sca_alerts:
            agent = alert.get('agent', {}).get('name', 'unknown')
            by_agent[agent].append(alert)

        findings = []
        for agent, events in by_agent.items():
            # Count passed vs failed
            failed = [e for e in events
                      if e.get('data', {}).get('sca', {}).get('check', {}).get('result') == 'failed']
            passed = [e for e in events
                      if e.get('data', {}).get('sca', {}).get('check', {}).get('result') == 'passed']

            if failed:
                policies = set()
                for e in failed:
                    pol = e.get('data', {}).get('sca', {}).get('policy', '')
                    if pol:
                        policies.add(pol)

                findings.append({
                    'pattern': 'COMPLIANCE_FAILURES',
                    'severity': 'MODERATE' if len(failed) < 10 else 'HIGH',
                    'confidence': 0.95,
                    'agent': agent,
                    'total_checks': len(events),
                    'passed': len(passed),
                    'failed': len(failed),
                    'policies': list(policies),
                    'description': f'{agent}: {len(failed)} failed SCA checks out of {len(events)}',
                })

        return findings

    # ──────────────────────────────────────────────────────
    # RUN ALL DETECTORS
    # ──────────────────────────────────────────────────────

    def run_all(self, alerts: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Run all pattern detectors and return combined results.

        Args:
            alerts: List of alert dictionaries

        Returns:
            Dictionary mapping pattern name to list of findings
        """
        results = {}

        detectors = [
            ('brute_force', self.detect_brute_force),
            ('port_activity', self.detect_port_scan),
            ('privilege_escalation', self.detect_privilege_escalation),
            ('lateral_movement', self.detect_lateral_movement),
            ('alert_bursts', self.detect_alert_bursts),
            ('compliance_failures', self.detect_compliance_failures),
        ]

        for name, detector in detectors:
            try:
                findings = detector(alerts)
                if findings:
                    results[name] = findings
            except Exception as e:
                logger.error(f"Pattern detector '{name}' failed: {e}")
                results[name] = [{'error': str(e)}]

        return results

    def format_findings_markdown(self, all_findings: Dict[str, List[Dict]]) -> str:
        """Format all pattern detection findings as Markdown."""
        if not all_findings:
            return "## Pattern Detection Results\n\nNo security patterns detected. ✅\n"

        lines = ["# 🔍 Pattern Detection Results", ""]
        lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
        lines.append(f"**Patterns Detected:** {sum(len(v) for v in all_findings.values())}")
        lines.append("")

        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MODERATE': 2, 'LOW': 3}

        # Flatten and sort by severity
        all_flat = []
        for pattern_type, findings in all_findings.items():
            for f in findings:
                if 'error' not in f:
                    f['_type'] = pattern_type
                    all_flat.append(f)

        all_flat.sort(key=lambda x: severity_order.get(x.get('severity', 'LOW'), 99))

        # Summary table
        lines.append("## Summary")
        lines.append("")
        lines.append("| # | Pattern | Severity | Confidence | Key Detail |")
        lines.append("|---|---------|----------|------------|------------|")

        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MODERATE': '🟡',
            'LOW': '⚪'
        }

        for i, f in enumerate(all_flat, 1):
            sev = f.get('severity', '?')
            emoji = severity_emoji.get(sev, '⚪')
            conf = f.get('confidence', 0)
            detail = f.get('description', f.get('source', f.get('user', f.get('agent', '?'))))
            if isinstance(detail, str) and len(detail) > 50:
                detail = detail[:50] + '...'
            lines.append(f"| {i} | {f.get('pattern', '?')} | {emoji} {sev} | {conf:.0%} | {detail} |")

        lines.append("")

        # Detailed findings
        for i, f in enumerate(all_flat, 1):
            sev = f.get('severity', '?')
            emoji = severity_emoji.get(sev, '⚪')
            lines.append(f"### {emoji} Finding #{i}: {f.get('pattern', '?')}")
            lines.append("")

            for key, value in f.items():
                if key.startswith('_') or key in ('pattern',):
                    continue
                if isinstance(value, list):
                    value = ', '.join(str(v) for v in value[:10])
                elif isinstance(value, dict):
                    value = json.dumps(value, default=str)
                elif isinstance(value, float):
                    value = f"{value:.2%}" if key == 'confidence' else f"{value:.2f}"
                lines.append(f"- **{key}:** {value}")

            lines.append("")

        return '\n'.join(lines)

    def format_findings_json(self, all_findings: Dict[str, List[Dict]]) -> str:
        """Format findings as JSON for AI processing."""
        output = {
            'pattern_analysis': {
                'generated_utc': datetime.now(timezone.utc).isoformat(),
                'patterns_detected': sum(len(v) for v in all_findings.values()),
                'findings': all_findings,
            }
        }
        return json.dumps(output, indent=2, default=str)


def main():
    """CLI for pattern detection."""
    import argparse
    sys_path = __import__('os').path.dirname(__import__('os').path.dirname(__import__('os').path.abspath(__file__)))
    if sys_path not in __import__('sys').path:
        __import__('sys').path.insert(0, sys_path)

    from modules.alert_processor import AlertProcessor

    parser = argparse.ArgumentParser(description='Security Pattern Detector')
    parser.add_argument('--hours', type=float, help='Only alerts from last N hours')
    parser.add_argument('--min-level', type=int, default=3, help='Minimum alert level')
    parser.add_argument('--format', choices=['markdown', 'json', 'summary'],
                        default='summary', help='Output format')
    parser.add_argument('--max-alerts', type=int, default=5000,
                        help='Max lines to read from alert file')
    parser.add_argument('--output', type=str, help='Write to file')

    args = parser.parse_args()

    import sys

    try:
        processor = AlertProcessor()
        print("📂 Loading alerts...", file=sys.stderr)
        alerts = processor.load_alerts(max_lines=args.max_alerts)

        filtered = processor.filter_alerts(alerts, min_level=args.min_level, hours=args.hours)
        print(f"   Analyzing {len(filtered)} alerts for patterns...", file=sys.stderr)

        detector = PatternDetector()
        findings = detector.run_all(filtered)

        total = sum(len(v) for v in findings.values())
        print(f"   Found {total} pattern(s)", file=sys.stderr)

        if args.format == 'markdown':
            output = detector.format_findings_markdown(findings)
        elif args.format == 'json':
            output = detector.format_findings_json(findings)
        else:
            # Summary
            if not findings:
                output = "\n✅ No security patterns detected.\n"
            else:
                lines = [f"\n🔍 Pattern Detection: {total} finding(s)", "=" * 50]
                severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MODERATE': '🟡', 'LOW': '⚪'}
                for pattern_type, pattern_findings in findings.items():
                    for f in pattern_findings:
                        if 'error' in f:
                            continue
                        sev = f.get('severity', '?')
                        emoji = severity_emoji.get(sev, '⚪')
                        desc = f.get('description',
                                     f.get('source', f.get('user', f.get('agent', '?'))))
                        lines.append(f"  {emoji} [{sev}] {f['pattern']}: {desc}")
                lines.append("")
                output = '\n'.join(lines)

        if args.output:
            with open(args.output, 'w') as fp:
                fp.write(output)
            print(f"✅ Output written to {args.output}", file=sys.stderr)
        else:
            print(output)

    except PermissionError:
        print("❌ Permission denied. Run with sudo.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
