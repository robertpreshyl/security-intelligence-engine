#!/usr/bin/env python3
"""
Action Broker — Phase 4: Controlled Action Execution with Safety Gates
Implements the approval workflow, dry-run simulation, audit logging,
and safety controls required for any system-modifying actions.

ALL actions are dry-run by default. Nothing executes without explicit approval.

Author: AI-SOC Integration Project
"""

import json
import os
import sys
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from enum import Enum

# Project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ──────────────────────────────────────────────────────
# ENUMS & CONSTANTS
# ──────────────────────────────────────────────────────

class ActionType(Enum):
    """Categories of actions with risk levels."""
    # Safe actions (approval required once)
    GENERATE_REPORT = "generate_report"
    CREATE_CDB_ENTRY = "create_cdb_entry"            # Add to CDB list (block/allow)
    TUNE_RULE = "tune_rule"                           # Adjust rule severity
    SEND_NOTIFICATION = "send_notification"

    # Elevated actions (require explicit approval + justification)
    CREATE_CUSTOM_RULE = "create_custom_rule"         # Write custom Wazuh rule
    MODIFY_AGENT_GROUP = "modify_agent_group"

    # Dangerous actions (require APPROVE + reason, never auto-execute)
    FIREWALL_BLOCK = "firewall_block"
    SERVICE_RESTART = "service_restart"
    DISABLE_USER = "disable_user"
    ACTIVE_RESPONSE = "active_response"


RISK_LEVELS = {
    ActionType.GENERATE_REPORT: 'LOW',
    ActionType.CREATE_CDB_ENTRY: 'LOW',
    ActionType.TUNE_RULE: 'LOW',
    ActionType.SEND_NOTIFICATION: 'LOW',
    ActionType.CREATE_CUSTOM_RULE: 'MODERATE',
    ActionType.MODIFY_AGENT_GROUP: 'MODERATE',
    ActionType.FIREWALL_BLOCK: 'HIGH',
    ActionType.SERVICE_RESTART: 'HIGH',
    ActionType.DISABLE_USER: 'HIGH',
    ActionType.ACTIVE_RESPONSE: 'HIGH',
}

SAFE_ACTIONS = {ActionType.GENERATE_REPORT, ActionType.CREATE_CDB_ENTRY,
                ActionType.TUNE_RULE, ActionType.SEND_NOTIFICATION}

DANGEROUS_ACTIONS = {ActionType.FIREWALL_BLOCK, ActionType.SERVICE_RESTART,
                     ActionType.DISABLE_USER, ActionType.ACTIVE_RESPONSE}


# ──────────────────────────────────────────────────────
# AUDIT LOGGER
# ──────────────────────────────────────────────────────

class AuditLogger:
    """Immutable audit trail for all action requests and outcomes."""

    def __init__(self, log_dir: Optional[str] = None):
        self.log_dir = log_dir or os.path.join(PROJECT_ROOT, 'logs')
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = os.path.join(self.log_dir, 'action_audit.jsonl')

        # Also set up Python logger
        self.logger = logging.getLogger('ai_soc.audit')
        if not self.logger.handlers:
            handler = logging.FileHandler(
                os.path.join(self.log_dir, 'audit.log'))
            handler.setFormatter(logging.Formatter(
                '%(asctime)s | %(levelname)s | %(message)s'))
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def record(self, action: Dict, outcome: str, details: str = ""):
        """Record an action to the audit log."""
        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action_type': action.get('type', '?'),
            'risk_level': action.get('risk_level', '?'),
            'outcome': outcome,  # APPROVED, DENIED, DRY_RUN, EXECUTED, FAILED
            'details': details,
            'parameters': action.get('parameters', {}),
            'user': os.environ.get('USER', 'unknown'),
            'dry_run': action.get('dry_run', True),
        }

        # Append to JSONL
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(entry, default=str) + '\n')

        # Also log to standard logger
        self.logger.info(
            f"[{outcome}] {entry['action_type']} | "
            f"risk={entry['risk_level']} | dry_run={entry['dry_run']} | "
            f"{details[:100]}"
        )

    def get_recent(self, count: int = 20) -> List[Dict]:
        """Get the most recent audit entries."""
        entries = []
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except FileNotFoundError:
            return []
        return entries[-count:]


# ──────────────────────────────────────────────────────
# ACTION BROKER
# ──────────────────────────────────────────────────────

class ActionBroker:
    """
    Safety-gated action execution system.

    All actions are dry-run by default. The broker:
    1. Validates the action request
    2. Assesses risk level
    3. Runs dry-run simulation
    4. Requires explicit approval
    5. Executes (if approved and not dry-run only)
    6. Logs everything to audit trail
    """

    def __init__(self, dry_run: bool = True, require_approval: bool = True):
        """
        Args:
            dry_run: If True (default), only simulate actions
            require_approval: If True (default), require interactive approval
        """
        self.dry_run = dry_run
        self.require_approval = require_approval
        self.audit = AuditLogger()
        self.max_actions_per_hour = 10  # Rate limit
        self._action_count = 0

    def propose(self, action_type: ActionType,
                parameters: Dict,
                justification: str = "",
                context: str = "") -> Dict:
        """
        Build a structured action proposal.

        Args:
            action_type: Type of action
            parameters: Action-specific parameters
            justification: Why this action is needed
            context: Alert/pattern context that triggered this

        Returns:
            Action proposal dict
        """
        risk = RISK_LEVELS.get(action_type, 'UNKNOWN')
        return {
            'type': action_type.value,
            'action_type_enum': action_type,
            'risk_level': risk,
            'parameters': parameters,
            'justification': justification,
            'context': context,
            'dry_run': self.dry_run,
            'proposed_at': datetime.now(timezone.utc).isoformat(),
        }

    def validate(self, action: Dict) -> Tuple[bool, str]:
        """
        Validate an action proposal.

        Returns (is_valid, reason)
        """
        # Check required fields
        if not action.get('type'):
            return False, "Missing action type"
        if not action.get('parameters'):
            return False, "Missing action parameters"

        # Rate limit
        if self._action_count >= self.max_actions_per_hour:
            return False, f"Rate limit exceeded ({self.max_actions_per_hour}/hour)"

        # Validate action type
        try:
            action_type = action.get('action_type_enum')
            if not action_type:
                action_type = ActionType(action['type'])
        except ValueError:
            return False, f"Unknown action type: {action['type']}"

        # Block dangerous actions in dry-run mode
        if action_type in DANGEROUS_ACTIONS and not self.dry_run:
            if not action.get('justification'):
                return False, "Dangerous actions require justification"

        return True, "Valid"

    def simulate(self, action: Dict) -> Dict:
        """
        Dry-run simulation of an action.

        Returns simulated outcome without executing anything.
        """
        action_type = action.get('type', '')
        params = action.get('parameters', {})
        risk = action.get('risk_level', 'UNKNOWN')

        simulation = {
            'status': 'DRY_RUN',
            'action': action_type,
            'risk_level': risk,
            'would_execute': self._describe_action(action_type, params),
            'reversible': self._is_reversible(action_type),
            'estimated_impact': self._estimate_impact(action_type, params),
        }

        self.audit.record(action, 'DRY_RUN',
                          simulation['would_execute'][:200])
        return simulation

    def request_approval(self, action: Dict) -> bool:
        """
        Interactive approval prompt.

        Returns True if approved.
        """
        risk = action.get('risk_level', 'UNKNOWN')
        action_type = action.get('type', '?')

        print("\n" + "=" * 60)
        print("  ⚠️  ACTION APPROVAL REQUIRED")
        print("=" * 60)
        print(f"  Action:        {action_type}")
        print(f"  Risk Level:    {risk}")
        print(f"  Dry Run:       {action.get('dry_run', True)}")
        print(f"  Justification: {action.get('justification', 'None provided')}")
        print(f"  Parameters:    {json.dumps(action.get('parameters', {}), indent=2)}")

        desc = self._describe_action(action_type, action.get('parameters', {}))
        print(f"\n  This will: {desc}")

        if action.get('dry_run'):
            print("\n  Mode: DRY RUN (no changes will be made)")
        else:
            print("\n  ⚠️  Mode: LIVE EXECUTION (changes WILL be applied)")

        print("=" * 60)

        if risk == 'HIGH':
            prompt = "  Type 'APPROVE' to proceed (or anything else to deny): "
        else:
            prompt = "  Approve? [y/N]: "

        try:
            response = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  ❌ Denied (no input)")
            self.audit.record(action, 'DENIED', 'No input received')
            return False

        if risk == 'HIGH':
            approved = response == 'APPROVE'
        else:
            approved = response.lower() in ('y', 'yes')

        if approved:
            self.audit.record(action, 'APPROVED', f'User approved: {response}')
            print("  ✅ Approved")
        else:
            self.audit.record(action, 'DENIED', f'User denied: {response}')
            print("  ❌ Denied")

        return approved

    def execute(self, action: Dict) -> Dict:
        """
        Execute the full action workflow:
        1. Validate
        2. Simulate (dry-run)
        3. Request approval (if required)
        4. Execute (if not dry-run and approved)

        Returns result dict.
        """
        # Step 1: Validate
        is_valid, reason = self.validate(action)
        if not is_valid:
            self.audit.record(action, 'REJECTED', reason)
            return {'status': 'REJECTED', 'reason': reason}

        # Step 2: Simulate
        simulation = self.simulate(action)

        # If dry-run only, return simulation
        if self.dry_run:
            return simulation

        # Step 3: Approval
        if self.require_approval:
            approved = self.request_approval(action)
            if not approved:
                return {'status': 'DENIED', 'reason': 'User rejected'}

        # Step 4: Execute
        self._action_count += 1
        try:
            result = self._perform_action(action)
            self.audit.record(action, 'EXECUTED', json.dumps(result, default=str)[:200])
            return result
        except Exception as e:
            self.audit.record(action, 'FAILED', str(e))
            return {'status': 'FAILED', 'error': str(e)}

    # ──────────────────────────────────────────────────
    # ACTION IMPLEMENTATIONS
    # ──────────────────────────────────────────────────

    def _perform_action(self, action: Dict) -> Dict:
        """Route to the appropriate action handler."""
        action_type = action.get('type', '')
        params = action.get('parameters', {})

        handlers = {
            ActionType.GENERATE_REPORT.value: self._action_generate_report,
            ActionType.CREATE_CDB_ENTRY.value: self._action_cdb_entry,
            ActionType.TUNE_RULE.value: self._action_tune_rule,
            ActionType.SEND_NOTIFICATION.value: self._action_send_notification,
        }

        handler = handlers.get(action_type)
        if handler:
            return handler(params)
        else:
            return {
                'status': 'NOT_IMPLEMENTED',
                'message': f"Action '{action_type}' is not yet implemented. "
                           f"This is intentional for safety — dangerous actions "
                           f"require manual execution.",
            }

    def _action_generate_report(self, params: Dict) -> Dict:
        """Generate an incident report to file."""
        from modules.incident_reporter import IncidentReporter

        reporter = IncidentReporter()
        output_path = params.get('output',
                                 os.path.join(PROJECT_ROOT, 'reports',
                                              f"incident_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md"))
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        report = reporter.generate(
            title=params.get('title', 'Incident Report'),
            alerts=params.get('alerts', []),
            findings=params.get('findings', {}),
            recommendations=params.get('recommendations', []),
        )

        with open(output_path, 'w') as f:
            f.write(report)

        return {'status': 'EXECUTED', 'output': output_path}

    def _action_cdb_entry(self, params: Dict) -> Dict:
        """Add entry to Wazuh CDB list."""
        list_name = params.get('list_name', '')
        entry = params.get('entry', '')
        if not list_name or not entry:
            return {'status': 'FAILED', 'error': 'list_name and entry required'}

        cdb_path = f"/var/ossec/etc/lists/{list_name}"
        if not os.path.exists(cdb_path):
            return {'status': 'FAILED', 'error': f'CDB list not found: {cdb_path}'}

        with open(cdb_path, 'a') as f:
            f.write(f"{entry}\n")

        return {'status': 'EXECUTED', 'message': f'Added "{entry}" to {list_name}'}

    def _action_tune_rule(self, params: Dict) -> Dict:
        """Create a rule override to adjust severity."""
        rule_id = params.get('rule_id', '')
        new_level = params.get('new_level', '')
        if not rule_id or not new_level:
            return {'status': 'FAILED', 'error': 'rule_id and new_level required'}

        override_dir = os.path.join(PROJECT_ROOT, 'rules')
        os.makedirs(override_dir, exist_ok=True)
        override_file = os.path.join(override_dir, 'ai_soc_overrides.xml')

        rule_xml = (
            f'<group name="ai_soc_tuning">\n'
            f'  <rule id="{rule_id}" level="{new_level}" overwrite="yes">\n'
            f'    <!-- Tuned by AI-SOC on {datetime.now(timezone.utc).isoformat()} -->\n'
            f'    <description>AI-SOC severity adjustment for rule {rule_id}</description>\n'
            f'  </rule>\n'
            f'</group>\n'
        )

        with open(override_file, 'a') as f:
            f.write(rule_xml + '\n')

        return {
            'status': 'EXECUTED',
            'message': f'Rule {rule_id} override written to {override_file}. '
                       f'Requires manager restart to take effect.',
            'note': 'This override file is NOT auto-loaded by Wazuh. '
                    'Manual review and inclusion in ossec.conf is required.',
        }

    def _action_send_notification(self, params: Dict) -> Dict:
        """Placeholder for notification sending."""
        return {
            'status': 'NOT_IMPLEMENTED',
            'message': 'Notification sending not yet configured. '
                       'Configure email/webhook in .env to enable.',
        }

    # ──────────────────────────────────────────────────
    # HELPER METHODS
    # ──────────────────────────────────────────────────

    def _describe_action(self, action_type: str, params: Dict) -> str:
        """Human-readable description of what an action would do."""
        descriptions = {
            'generate_report': f"Generate incident report → {params.get('output', 'reports/')}",
            'create_cdb_entry': f"Add '{params.get('entry', '?')}' to CDB list '{params.get('list_name', '?')}'",
            'tune_rule': f"Override rule {params.get('rule_id', '?')} to level {params.get('new_level', '?')}",
            'send_notification': f"Send notification to {params.get('channel', '?')}",
            'create_custom_rule': f"Create custom detection rule in Wazuh",
            'modify_agent_group': f"Change agent group assignment",
            'firewall_block': f"Block IP {params.get('ip', '?')} via UFW/iptables",
            'service_restart': f"Restart service {params.get('service', '?')}",
            'disable_user': f"Disable user account {params.get('username', '?')}",
            'active_response': f"Trigger Wazuh active response: {params.get('command', '?')}",
        }
        return descriptions.get(action_type, f"Unknown action: {action_type}")

    def _is_reversible(self, action_type: str) -> bool:
        """Whether an action can be undone."""
        reversible = {
            'generate_report', 'create_cdb_entry', 'tune_rule',
            'firewall_block', 'modify_agent_group',
        }
        return action_type in reversible

    def _estimate_impact(self, action_type: str, params: Dict) -> str:
        """Estimate the impact of an action."""
        if action_type in ('generate_report', 'send_notification'):
            return "No system changes. Output only."
        elif action_type == 'create_cdb_entry':
            return "Modifies CDB list file. Takes effect on next rule evaluation."
        elif action_type == 'tune_rule':
            return "Creates rule override file. Requires manual manager restart."
        elif action_type == 'firewall_block':
            return f"BLOCKS network access for IP {params.get('ip', '?')}. Immediate effect."
        elif action_type == 'service_restart':
            return f"RESTARTS {params.get('service', '?')}. Brief service disruption."
        elif action_type == 'disable_user':
            return f"DISABLES user {params.get('username', '?')}. User locked out immediately."
        else:
            return "Impact unknown — review carefully."


# ──────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────

def main():
    """CLI for testing the action broker."""
    import argparse

    parser = argparse.ArgumentParser(description='AI-SOC Action Broker')
    sub = parser.add_subparsers(dest='command', help='Commands')

    # Dry-run test
    p_test = sub.add_parser('test', help='Test dry-run of various actions')

    # Audit log viewer
    p_audit = sub.add_parser('audit', help='View audit log')
    p_audit.add_argument('--count', type=int, default=20,
                         help='Number of entries to show')

    # Generate report
    p_report = sub.add_parser('report', help='Generate incident report')
    p_report.add_argument('--title', default='Test Report')
    p_report.add_argument('--output', help='Output file path')

    args = parser.parse_args()

    if args.command == 'test':
        print("\n🧪 Action Broker — Dry-Run Test")
        print("=" * 50)

        broker = ActionBroker(dry_run=True, require_approval=False)

        # Test a few action types
        actions = [
            broker.propose(
                ActionType.GENERATE_REPORT,
                {'title': 'Daily Security Report'},
                justification='Scheduled daily report'
            ),
            broker.propose(
                ActionType.CREATE_CDB_ENTRY,
                {'list_name': 'blocklist', 'entry': '1.2.3.4:blocked_by_ai_soc'},
                justification='Repeated brute force source'
            ),
            broker.propose(
                ActionType.FIREWALL_BLOCK,
                {'ip': '1.2.3.4'},
                justification='Active brute force attack'
            ),
        ]

        for action in actions:
            print(f"\n{'─' * 40}")
            result = broker.execute(action)
            print(f"  Action: {action['type']}")
            print(f"  Risk:   {action['risk_level']}")
            print(f"  Status: {result['status']}")
            print(f"  Would:  {result.get('would_execute', '?')}")
            print(f"  Undo:   {'Yes' if result.get('reversible') else 'No'}")
            print(f"  Impact: {result.get('estimated_impact', '?')}")

        print(f"\n✅ All dry-run tests complete. See logs/action_audit.jsonl\n")

    elif args.command == 'audit':
        audit = AuditLogger()
        entries = audit.get_recent(args.count)
        if not entries:
            print("No audit entries found.")
            return

        print(f"\n📋 Last {len(entries)} Audit Entries")
        print("=" * 70)
        for entry in entries:
            ts = entry.get('timestamp', '?')[:19]
            outcome = entry.get('outcome', '?')
            action = entry.get('action_type', '?')
            risk = entry.get('risk_level', '?')
            details = entry.get('details', '')[:50]
            emoji = {'APPROVED': '✅', 'DENIED': '❌', 'DRY_RUN': '🔄',
                     'EXECUTED': '⚡', 'FAILED': '💥', 'REJECTED': '🚫'}.get(outcome, '❓')
            print(f"  {emoji} [{ts}] {outcome:10s} | {risk:8s} | {action:20s} | {details}")
        print()

    elif args.command == 'report':
        broker = ActionBroker(dry_run=False, require_approval=True)
        action = broker.propose(
            ActionType.GENERATE_REPORT,
            {
                'title': args.title,
                'output': args.output,
                'alerts': [],
                'findings': {},
            },
            justification='User-requested report generation'
        )
        result = broker.execute(action)
        print(f"Result: {json.dumps(result, indent=2)}")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
