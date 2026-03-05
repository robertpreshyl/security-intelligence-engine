#!/usr/bin/env python3
"""
analyze.py — Phase 3: AI-SOC Analysis CLI
Main entry point that ties together alert processing, pattern detection,
and formats output for AI (Copilot) consumption.

Usage:
    # Quick summary of last 24h, level 5+
    sudo python analyze.py --hours 24 --min-level 5

    # Full AI-formatted analysis
    sudo python analyze.py --hours 12 --format ai

    # Pattern detection only
    sudo python analyze.py --patterns-only

    # Save report to file
    sudo python analyze.py --hours 24 --format markdown --output reports/daily.md

Author: AI-SOC Integration Project
"""

import sys
import os
import json
import argparse
from datetime import datetime, timezone

# Ensure project root on path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from modules.alert_processor import AlertProcessor
from modules.pattern_detector import PatternDetector


def load_system_prompt() -> str:
    """Load the SOC analyst system prompt."""
    prompt_path = os.path.join(PROJECT_ROOT, 'prompts', 'soc_analyst_system.md')
    try:
        with open(prompt_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "(System prompt not found at prompts/soc_analyst_system.md)"


def build_ai_package(alerts: list, stats: dict, findings: dict,
                     processor: AlertProcessor) -> str:
    """
    Build a complete AI-ready analysis package combining:
    - Alert data in structured JSON
    - Pattern detection findings
    - System prompt reference
    - Actionable question for the AI

    Returns a formatted string for pasting into Copilot Chat.
    """
    lines = []

    lines.append("=" * 70)
    lines.append("  AI-SOC ANALYSIS PACKAGE")
    lines.append(f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append("=" * 70)
    lines.append("")

    # ── Section 1: Context ──
    lines.append("## CONTEXT")
    lines.append(f"- Wazuh 4.14.3 RC3 | All-in-One | Ubuntu 24.04.4 LTS")
    lines.append(f"- Total alerts analyzed: {stats.get('total', '?')}")
    tr = stats.get('time_range', {})
    lines.append(f"- Time range: {tr.get('earliest', '?')} → {tr.get('latest', '?')}")
    lines.append(f"- Duration: {tr.get('span_hours', '?')}h")
    lines.append("")

    # ── Section 2: Severity overview ──
    lines.append("## SEVERITY DISTRIBUTION")
    for level, count in sorted(stats.get('levels', {}).items(),
                                key=lambda x: int(x[0]), reverse=True):
        tier, emoji = processor.classify_severity(int(level))
        lines.append(f"  {emoji} Level {level:>2} ({tier:8s}): {count}")
    lines.append("")

    # ── Section 3: Pattern detection ──
    total_findings = sum(len(v) for v in findings.values())
    lines.append(f"## PATTERN DETECTION ({total_findings} finding(s))")
    if not findings:
        lines.append("  No security patterns detected. ✅")
    else:
        severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MODERATE': '🟡', 'LOW': '⚪'}
        for ptype, pfindings in findings.items():
            for f in pfindings:
                if 'error' in f:
                    lines.append(f"  ⚠️  {ptype}: ERROR - {f['error']}")
                    continue
                sev = f.get('severity', '?')
                emoji = severity_emoji.get(sev, '⚪')
                desc = f.get('description',
                             f.get('source', f.get('user', f.get('agent', '?'))))
                conf = f.get('confidence', 0)
                lines.append(f"  {emoji} [{sev}] {f['pattern']}: {desc} (confidence: {conf:.0%})")
    lines.append("")

    # ── Section 4: Top alerts for investigation ──
    high_alerts = [a for a in alerts if a.get('rule', {}).get('level', 0) >= 7]
    high_alerts.sort(key=lambda a: a.get('rule', {}).get('level', 0), reverse=True)

    lines.append(f"## HIGH-PRIORITY ALERTS ({len(high_alerts)} at level 7+)")
    for alert in high_alerts[:25]:
        rule = alert.get('rule', {})
        agent = alert.get('agent', {}).get('name', '?')
        ts = alert.get('timestamp', '?')[:19]
        lines.append(f"  [{ts}] L{rule.get('level', '?')} | {agent} | "
                      f"R{rule.get('id', '?')}: {rule.get('description', '?')[:60]}")
    if len(high_alerts) > 25:
        lines.append(f"  ... and {len(high_alerts) - 25} more")
    lines.append("")

    # ── Section 5: Structured data for deeper analysis ──
    lines.append("## STRUCTURED DATA (JSON)")
    lines.append("```json")
    ai_json = processor.format_json_for_ai(alerts)
    # Merge pattern findings into the JSON
    ai_data = json.loads(ai_json)
    ai_data['pattern_analysis'] = findings
    lines.append(json.dumps(ai_data, indent=2, default=str)[:8000])  # Cap at 8KB
    lines.append("```")
    lines.append("")

    # ── Section 6: Request ──
    lines.append("## ANALYSIS REQUEST")
    lines.append("")
    lines.append("Please analyze the above security data as a Tier 2 SOC Analyst.")
    lines.append("Provide:")
    lines.append("1. Executive summary (2-3 sentences)")
    lines.append("2. Threat classification table with MITRE mappings")
    lines.append("3. Detailed analysis of each significant finding")
    lines.append("4. Prioritized recommendations (immediate / short-term / long-term)")
    lines.append("5. False positive assessment and tuning suggestions")
    lines.append("6. Any data gaps or questions you need answered")
    lines.append("")
    lines.append("=" * 70)

    return '\n'.join(lines)


def build_markdown_report(alerts: list, stats: dict, findings: dict,
                          processor: AlertProcessor,
                          detector: PatternDetector) -> str:
    """Build a comprehensive Markdown report."""
    parts = []

    # Header
    parts.append(f"# SOC Alert Analysis Report")
    parts.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    parts.append(f"**System:** Wazuh 4.14.3 RC3 | Ubuntu 24.04.4 LTS")
    parts.append("")

    # Alert summary from processor
    parts.append(processor.format_markdown_report(alerts))
    parts.append("")

    # Pattern detection from detector
    parts.append(detector.format_findings_markdown(findings))

    return '\n'.join(parts)


def main():
    parser = argparse.ArgumentParser(
        description='AI-SOC Analysis Tool — analyze Wazuh alerts for AI consumption',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python analyze.py --hours 24 --min-level 5          # Summary
  sudo python analyze.py --hours 12 --format ai            # AI-ready package
  sudo python analyze.py --patterns-only                   # Pattern detection only
  sudo python analyze.py --format markdown --output r.md   # Save markdown report
  sudo python analyze.py --agent server --min-level 7      # Filter by agent
        """
    )

    parser.add_argument('--hours', type=float,
                        help='Only alerts from last N hours')
    parser.add_argument('--min-level', type=int, default=3,
                        help='Minimum alert level (default: 3)')
    parser.add_argument('--agent', type=str,
                        help='Filter to specific agent name')
    parser.add_argument('--search', type=str,
                        help='Search term in alert descriptions')
    parser.add_argument('--exclude-groups', type=str,
                        help='Comma-separated groups to exclude (e.g. sca,syslog)')
    parser.add_argument('--max-alerts', type=int, default=5000,
                        help='Max alert lines to read (default: 5000)')
    parser.add_argument('--format', choices=['summary', 'ai', 'markdown', 'json', 'patterns'],
                        default='summary',
                        help='Output format (default: summary)')
    parser.add_argument('--patterns-only', action='store_true',
                        help='Run pattern detection only')
    parser.add_argument('--output', type=str,
                        help='Write output to file')
    parser.add_argument('--prompt', action='store_true',
                        help='Print the SOC analyst system prompt')

    args = parser.parse_args()

    # ── Print system prompt if requested ──
    if args.prompt:
        print(load_system_prompt())
        return

    # ── Load and filter alerts ──
    try:
        processor = AlertProcessor()
        print("📂 Loading alerts...", file=sys.stderr)
        alerts = processor.load_alerts(max_lines=args.max_alerts)

        exclude_groups = None
        if args.exclude_groups:
            exclude_groups = [g.strip() for g in args.exclude_groups.split(',')]

        filtered = processor.filter_alerts(
            alerts,
            min_level=args.min_level,
            hours=args.hours,
            agent_name=args.agent,
            search=args.search,
            exclude_groups=exclude_groups,
        )

        print(f"   {len(filtered)} alerts after filtering", file=sys.stderr)

        # ── Run pattern detection ──
        detector = PatternDetector()
        findings = detector.run_all(filtered)
        total_patterns = sum(len(v) for v in findings.values())
        print(f"   {total_patterns} pattern(s) detected", file=sys.stderr)

        # ── Compute stats ──
        stats = processor.compute_stats(filtered)

        # ── Format output ──
        if args.patterns_only or args.format == 'patterns':
            output = detector.format_findings_markdown(findings)

        elif args.format == 'ai':
            output = build_ai_package(filtered, stats, findings, processor)

        elif args.format == 'markdown':
            output = build_markdown_report(filtered, stats, findings,
                                           processor, detector)

        elif args.format == 'json':
            ai_json = processor.format_json_for_ai(filtered)
            data = json.loads(ai_json)
            data['pattern_analysis'] = findings
            output = json.dumps(data, indent=2, default=str)

        else:  # summary
            slines = []
            slines.append(f"\n📊 Alert Summary ({stats.get('total', len(filtered))} alerts)")
            slines.append("=" * 60)
            tr = stats.get('time_range', {})
            if tr:
                slines.append(f"Time Range: {tr.get('earliest', '?')} → {tr.get('latest', '?')} ({tr.get('span_hours', '?')}h)")

            slines.append("\n🎯 Severity Levels:")
            for level in sorted(stats.get('levels', {}).keys(),
                                key=lambda x: int(x), reverse=True):
                count = stats['by_level'][level]
                tier, emoji = processor.classify_severity(int(level))
                slines.append(f"  {emoji} Level {int(level):2d} ({tier:10s}): {count}")

            slines.append("\n📋 Top Rules:")
            for rule_info in stats.get('top_rules', [])[:10]:
                if isinstance(rule_info, dict):
                    slines.append(f"  [{rule_info['count']:4d}] Rule {rule_info['rule_id']}: {rule_info['description']}")

            slines.append("\n📡 By Agent:")
            for agent, count in stats.get('by_agent', {}).items():
                slines.append(f"  {agent}: {count}")

            if stats.get('mitre_tactics'):
                slines.append("\n🎯 MITRE ATT&CK Tactics:")
                for tactic, count in stats['mitre_tactics'].items():
                    slines.append(f"  {tactic}: {count}")

            high = [a for a in filtered if a.get('rule', {}).get('level', 0) >= 7]
            if high:
                slines.append(f"\n🚨 Notable Alerts (Level 7+): {len(high)}")
                for a in high[:15]:
                    slines.append(f"  {processor.format_alert_summary(a)}")

            slines.append("")

            if findings:
                severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MODERATE': '🟡', 'LOW': '⚪'}
                slines.append(f"🔍 Pattern Detection: {total_patterns} finding(s)")
                slines.append("=" * 50)
                for ptype, pfindings in findings.items():
                    for f in pfindings:
                        if 'error' in f:
                            continue
                        sev = f.get('severity', '?')
                        emoji = severity_emoji.get(sev, '⚪')
                        desc = f.get('description',
                                     f.get('source', f.get('user', f.get('agent', '?'))))
                        slines.append(f"  {emoji} [{sev}] {f['pattern']}: {desc}")
                slines.append("")

            output = '\n'.join(slines)

        # ── Output ──
        if args.output:
            os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
            with open(args.output, 'w') as fp:
                fp.write(output)
            print(f"✅ Report saved to {args.output}", file=sys.stderr)
        else:
            print(output)

        # ── Exit code based on severity ──
        if any(f.get('severity') in ('CRITICAL', 'EMERGENCY')
               for fl in findings.values() for f in fl):
            sys.exit(2)  # Critical findings
        elif any(f.get('severity') == 'HIGH'
                 for fl in findings.values() for f in fl):
            sys.exit(1)  # High findings
        else:
            sys.exit(0)  # Normal

    except PermissionError:
        print("❌ Permission denied reading alerts. Run with sudo.", file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(4)


if __name__ == '__main__':
    main()
