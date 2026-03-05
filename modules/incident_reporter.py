#!/usr/bin/env python3
"""
Incident Reporter — Phase 5: Professional Security Report Generation
Generates structured Markdown incident reports from alert data,
pattern detection findings, and AI analysis recommendations.

Author: AI-SOC Integration Project
"""

import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional
from collections import Counter

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class IncidentReporter:
    """Generate professional security incident reports."""

    SEVERITY_EMOJI = {
        'CRITICAL': '🔴', 'EMERGENCY': '🔴',
        'HIGH': '🟠', 'MODERATE': '🟡', 'LOW': '⚪',
    }

    def __init__(self, org_name: str = "AI-SOC Integration",
                 wazuh_version: str = "4.14.3 RC3"):
        self.org_name = org_name
        self.wazuh_version = wazuh_version
        self.report_dir = os.path.join(PROJECT_ROOT, 'reports')
        os.makedirs(self.report_dir, exist_ok=True)

    def generate(self, title: str = "Security Incident Report",
                 alerts: Optional[List[Dict]] = None,
                 findings: Optional[Dict] = None,
                 recommendations: Optional[List[str]] = None,
                 executive_summary: str = "",
                 analyst_notes: str = "") -> str:
        """
        Generate a full incident report in Markdown.

        Args:
            title: Report title
            alerts: Alert data (from alert_processor)
            findings: Pattern detection findings (from pattern_detector)
            recommendations: List of recommended actions
            executive_summary: AI-generated executive summary
            analyst_notes: Free-text analyst notes

        Returns:
            Complete Markdown report string
        """
        alerts = alerts or []
        findings = findings or {}
        recommendations = recommendations or []

        now = datetime.now(timezone.utc)
        report_id = now.strftime('INC-%Y%m%d-%H%M%S')

        sections = [
            self._header(title, report_id, now),
            self._executive_summary(executive_summary, alerts, findings),
            self._environment_info(),
            self._timeline(alerts),
            self._pattern_analysis(findings),
            self._affected_systems(alerts),
            self._mitre_mapping(alerts),
            self._recommendations(recommendations, findings),
            self._alert_details(alerts),
            self._analyst_notes(analyst_notes),
            self._appendix(alerts, findings),
            self._footer(report_id, now),
        ]

        return '\n'.join(sections)

    def generate_daily(self, alerts: List[Dict],
                       findings: Dict) -> str:
        """Generate a daily security summary report."""
        return self.generate(
            title="Daily Security Summary",
            alerts=alerts,
            findings=findings,
            executive_summary=self._auto_executive_summary(alerts, findings),
        )

    def save(self, report: str, filename: Optional[str] = None) -> str:
        """Save report to reports/ directory."""
        if not filename:
            filename = f"incident_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md"
        path = os.path.join(self.report_dir, filename)
        with open(path, 'w') as f:
            f.write(report)
        return path

    # ──────────────────────────────────────────────
    # REPORT SECTIONS
    # ──────────────────────────────────────────────

    def _header(self, title: str, report_id: str, now: datetime) -> str:
        return f"""# {title}

| Field | Value |
|-------|-------|
| **Report ID** | {report_id} |
| **Generated** | {now.strftime('%Y-%m-%d %H:%M:%S')} UTC |
| **System** | Wazuh {self.wazuh_version} |
| **Organization** | {self.org_name} |
| **Classification** | INTERNAL — SOC USE ONLY |

---
"""

    def _executive_summary(self, summary: str,
                            alerts: List[Dict],
                            findings: Dict) -> str:
        if summary:
            return f"## Executive Summary\n\n{summary}\n\n---\n"

        # Auto-generate if not provided
        auto = self._auto_executive_summary(alerts, findings)
        return f"## Executive Summary\n\n{auto}\n\n---\n"

    def _auto_executive_summary(self, alerts: List[Dict],
                                 findings: Dict) -> str:
        """Auto-generate executive summary from data."""
        total = len(alerts)
        total_findings = sum(len(v) for v in findings.values())

        if not alerts and not findings:
            return "No security events to report for this period."

        # Count severities
        high_count = sum(1 for a in alerts
                         if a.get('rule', {}).get('level', 0) >= 8)
        critical_findings = sum(
            1 for fl in findings.values()
            for f in fl if f.get('severity') in ('CRITICAL', 'EMERGENCY')
        )

        # Time range
        timestamps = [a.get('timestamp', '')[:19] for a in alerts if a.get('timestamp')]
        time_range = ""
        if timestamps:
            time_range = f" from {min(timestamps)} to {max(timestamps)}"

        lines = []
        lines.append(
            f"Analysis of **{total} alerts**{time_range} identified "
            f"**{total_findings} security pattern(s)**."
        )

        if critical_findings:
            lines.append(
                f"**{critical_findings} CRITICAL finding(s)** require immediate attention."
            )
        elif high_count:
            lines.append(
                f"{high_count} high-severity alert(s) detected, warranting investigation."
            )
        else:
            lines.append("No critical or high-severity events detected in this period.")

        # Summarize top finding types
        for ptype, pfindings in findings.items():
            if pfindings:
                top = pfindings[0]
                sev = top.get('severity', '?')
                desc = top.get('description', top.get('source', top.get('agent', '?')))
                lines.append(f"- **{ptype.replace('_', ' ').title()}:** {desc} ({sev})")

        return '\n'.join(lines)

    def _environment_info(self) -> str:
        return """## Environment

| Component | Details |
|-----------|---------|
| SIEM | Wazuh (All-in-One) |
| OS | Ubuntu 24.04 LTS |
| Monitored Agents | Multiple endpoints (Linux, Windows, macOS) |
| Network | See deployment configuration |
| Analysis Tool | AllysecLabs AI-SOC (Python 3.12) |

---
"""

    def _timeline(self, alerts: List[Dict]) -> str:
        if not alerts:
            return "## Timeline\n\nNo alert data available.\n\n---\n"

        lines = ["## Timeline\n"]

        # Get time boundaries
        timestamps = []
        for a in alerts:
            try:
                ts = datetime.strptime(a['timestamp'][:19], '%Y-%m-%dT%H:%M:%S')
                timestamps.append((ts, a))
            except (KeyError, ValueError):
                continue

        if not timestamps:
            return "## Timeline\n\nNo timestamp data available.\n\n---\n"

        timestamps.sort(key=lambda x: x[0])

        # Show key events (first, last, highest severity, notable)
        lines.append(f"**Period:** {timestamps[0][0].isoformat()} → {timestamps[-1][0].isoformat()}")
        span = (timestamps[-1][0] - timestamps[0][0]).total_seconds() / 3600
        lines.append(f"**Duration:** {span:.1f} hours")
        lines.append(f"**Total Events:** {len(timestamps)}")
        lines.append("")

        # Notable events (level 7+)
        notable = [(ts, a) for ts, a in timestamps
                    if a.get('rule', {}).get('level', 0) >= 7]

        if notable:
            lines.append("### Key Events\n")
            lines.append("| Time | Level | Agent | Description |")
            lines.append("|------|-------|-------|-------------|")

            # Show up to 30 notable events
            for ts, a in notable[:30]:
                rule = a.get('rule', {})
                agent = a.get('agent', {}).get('name', '?')
                desc = rule.get('description', '?')[:60]
                level = rule.get('level', '?')
                lines.append(f"| {ts.strftime('%H:%M:%S')} | {level} | {agent} | {desc} |")

            if len(notable) > 30:
                lines.append(f"| ... | ... | ... | +{len(notable) - 30} more events |")

        lines.append("\n---\n")
        return '\n'.join(lines)

    def _pattern_analysis(self, findings: Dict) -> str:
        if not findings:
            return "## Pattern Analysis\n\nNo security patterns detected. ✅\n\n---\n"

        lines = ["## Pattern Analysis\n"]
        total = sum(len(v) for v in findings.values())
        lines.append(f"**{total} pattern(s) detected:**\n")

        lines.append("| # | Pattern | Severity | Confidence | Detail |")
        lines.append("|---|---------|----------|------------|--------|")

        i = 0
        for ptype, pfindings in findings.items():
            for f in pfindings:
                if 'error' in f:
                    continue
                i += 1
                sev = f.get('severity', '?')
                emoji = self.SEVERITY_EMOJI.get(sev, '⚪')
                conf = f.get('confidence', 0)
                desc = f.get('description', f.get('source', f.get('user', f.get('agent', '?'))))
                if isinstance(desc, str) and len(desc) > 45:
                    desc = desc[:45] + '…'
                lines.append(f"| {i} | {f.get('pattern', ptype)} | {emoji} {sev} | {conf:.0%} | {desc} |")

        lines.append("\n---\n")
        return '\n'.join(lines)

    def _affected_systems(self, alerts: List[Dict]) -> str:
        if not alerts:
            return ""

        agent_counts = Counter()
        agent_levels = {}

        for a in alerts:
            name = a.get('agent', {}).get('name', '?')
            level = a.get('rule', {}).get('level', 0)
            agent_counts[name] += 1
            agent_levels[name] = max(agent_levels.get(name, 0), level)

        lines = ["## Affected Systems\n"]
        lines.append("| Agent | Alert Count | Max Severity | Status |")
        lines.append("|-------|-------------|--------------|--------|")

        for agent, count in agent_counts.most_common():
            max_level = agent_levels[agent]
            if max_level >= 11:
                status = "🔴 Critical"
            elif max_level >= 8:
                status = "🟠 High"
            elif max_level >= 5:
                status = "🟡 Moderate"
            else:
                status = "⚪ Low"
            lines.append(f"| {agent} | {count} | Level {max_level} | {status} |")

        lines.append("\n---\n")
        return '\n'.join(lines)

    def _mitre_mapping(self, alerts: List[Dict]) -> str:
        tactic_counts = Counter()
        technique_ids = set()

        for a in alerts:
            mitre = a.get('rule', {}).get('mitre', {})
            if isinstance(mitre, dict):
                for t in mitre.get('tactic', []):
                    tactic_counts[t] += 1
                for tid in mitre.get('id', []):
                    technique_ids.add(tid)
            elif isinstance(mitre, list):
                for m in mitre:
                    if isinstance(m, dict):
                        for t in m.get('tactic', []):
                            tactic_counts[t] += 1
                        for tid in m.get('id', []):
                            technique_ids.add(tid)

        if not tactic_counts:
            return ""

        lines = ["## MITRE ATT&CK Mapping\n"]
        lines.append("| Tactic | Count |")
        lines.append("|--------|-------|")
        for tactic, count in tactic_counts.most_common():
            lines.append(f"| {tactic} | {count} |")

        if technique_ids:
            lines.append(f"\n**Techniques observed:** {', '.join(sorted(technique_ids))}")

        lines.append("\n---\n")
        return '\n'.join(lines)

    def _recommendations(self, recommendations: List[str],
                          findings: Dict) -> str:
        lines = ["## Recommendations\n"]

        if recommendations:
            lines.append("### Analyst Recommendations\n")
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        # Auto-generate recommendations from findings
        auto_recs = self._auto_recommendations(findings)
        if auto_recs:
            lines.append("### Automated Recommendations\n")
            lines.append("| Priority | Action | Rationale |")
            lines.append("|----------|--------|-----------|")
            for priority, action, rationale in auto_recs:
                lines.append(f"| {priority} | {action} | {rationale} |")

        lines.append("\n---\n")
        return '\n'.join(lines)

    def _auto_recommendations(self, findings: Dict) -> List[tuple]:
        """Generate recommendations based on findings."""
        recs = []

        for ptype, pfindings in findings.items():
            for f in pfindings:
                if 'error' in f:
                    continue

                sev = f.get('severity', 'LOW')
                pattern = f.get('pattern', ptype)

                if pattern == 'BRUTE_FORCE':
                    src = f.get('source', '?')
                    recs.append((
                        '🟠 Immediate',
                        f'Investigate source {src} and consider temporary block',
                        f'{f.get("count", "?")} auth failures detected'
                    ))
                elif pattern == 'LATERAL_MOVEMENT':
                    recs.append((
                        '🔴 Immediate',
                        f'Isolate affected agents and investigate',
                        f'Same source across {f.get("agent_count", "?")} agents'
                    ))
                elif pattern == 'PRIVILEGE_ESCALATION' and sev in ('HIGH', 'CRITICAL'):
                    recs.append((
                        '🟠 Short-term',
                        f'Audit user {f.get("user", "?")} activities',
                        f'{f.get("unique_commands", "?")} distinct privileged commands'
                    ))
                elif pattern == 'COMPLIANCE_FAILURES':
                    recs.append((
                        '🟡 Long-term',
                        f'Remediate SCA failures on {f.get("agent", "?")}',
                        f'{f.get("failed", "?")} of {f.get("total_checks", "?")} checks failed'
                    ))
                elif pattern == 'PORT_ACTIVITY':
                    recs.append((
                        '🟡 Short-term',
                        f'Review port changes on {f.get("agent", "?")}',
                        f'{f.get("count", "?")} port events detected'
                    ))

        # Sort by priority
        priority_order = {'🔴 Immediate': 0, '🟠 Immediate': 1,
                          '🟠 Short-term': 2, '🟡 Short-term': 3,
                          '🟡 Long-term': 4}
        recs.sort(key=lambda x: priority_order.get(x[0], 99))

        return recs

    def _alert_details(self, alerts: List[Dict]) -> str:
        if not alerts:
            return ""

        # Show top 20 highest-severity alerts
        sorted_alerts = sorted(alerts,
                                key=lambda a: a.get('rule', {}).get('level', 0),
                                reverse=True)

        lines = ["## Alert Details (Top 20 by Severity)\n"]
        lines.append("| Time | Level | Rule ID | Agent | Description |")
        lines.append("|------|-------|---------|-------|-------------|")

        for a in sorted_alerts[:20]:
            rule = a.get('rule', {})
            ts = a.get('timestamp', '?')[:19]
            level = rule.get('level', '?')
            rid = rule.get('id', '?')
            agent = a.get('agent', {}).get('name', '?')
            desc = rule.get('description', '?')[:50]
            lines.append(f"| {ts} | {level} | {rid} | {agent} | {desc} |")

        if len(alerts) > 20:
            lines.append(f"\n*+ {len(alerts) - 20} additional alerts not shown*")

        lines.append("\n---\n")
        return '\n'.join(lines)

    def _analyst_notes(self, notes: str) -> str:
        if not notes:
            return ""
        return f"## Analyst Notes\n\n{notes}\n\n---\n"

    def _appendix(self, alerts: List[Dict], findings: Dict) -> str:
        lines = ["## Appendix\n"]

        # Alert statistics
        if alerts:
            level_counts = Counter(a.get('rule', {}).get('level', 0) for a in alerts)
            lines.append("### Alert Level Distribution\n")
            lines.append("| Level | Count |")
            lines.append("|-------|-------|")
            for level in sorted(level_counts.keys(), reverse=True):
                lines.append(f"| {level} | {level_counts[level]} |")
            lines.append("")

            group_counts = Counter()
            for a in alerts:
                for g in a.get('rule', {}).get('groups', []):
                    group_counts[g] += 1
            if group_counts:
                lines.append("### Top Alert Groups\n")
                lines.append("| Group | Count |")
                lines.append("|-------|-------|")
                for group, count in group_counts.most_common(15):
                    lines.append(f"| {group} | {count} |")

        lines.append("\n---\n")
        return '\n'.join(lines)

    def _footer(self, report_id: str, now: datetime) -> str:
        return f"""---

*Report {report_id} — Generated by AI-SOC Integration*
*{now.strftime('%Y-%m-%d %H:%M:%S')} UTC*
*Classification: INTERNAL — SOC USE ONLY*
"""


# ──────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────

def main():
    """CLI for generating reports."""
    import argparse

    parser = argparse.ArgumentParser(description='AI-SOC Incident Reporter')
    parser.add_argument('--hours', type=float, help='Alert hours to analyze')
    parser.add_argument('--min-level', type=int, default=3,
                        help='Minimum alert level')
    parser.add_argument('--title', default='Security Incident Report',
                        help='Report title')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--daily', action='store_true',
                        help='Generate daily summary report')
    parser.add_argument('--max-alerts', type=int, default=5000)

    args = parser.parse_args()

    try:
        from modules.alert_processor import AlertProcessor
        from modules.pattern_detector import PatternDetector

        processor = AlertProcessor()
        print("📂 Loading alerts...", file=sys.stderr)
        alerts = processor.load_alerts(max_lines=args.max_alerts)
        filtered = processor.filter_alerts(
            alerts, min_level=args.min_level, hours=args.hours)
        print(f"   {len(filtered)} alerts after filtering", file=sys.stderr)

        detector = PatternDetector()
        findings = detector.run_all(filtered)
        total_findings = sum(len(v) for v in findings.values())
        print(f"   {total_findings} pattern(s) detected", file=sys.stderr)

        reporter = IncidentReporter()

        if args.daily:
            report = reporter.generate_daily(filtered, findings)
        else:
            report = reporter.generate(
                title=args.title,
                alerts=filtered,
                findings=findings,
            )

        if args.output:
            path = reporter.save(report, os.path.basename(args.output))
        else:
            path = reporter.save(report)

        print(f"✅ Report saved to {path}", file=sys.stderr)
        print(report)

    except PermissionError:
        print("❌ Permission denied. Run with sudo.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
