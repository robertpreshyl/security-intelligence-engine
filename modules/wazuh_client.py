#!/usr/bin/env python3
"""
Wazuh API Client - Read-Only Operations
Phase 1: Foundation - Safe data access layer

This module provides a Python interface to the Wazuh REST API.
All operations are read-only to ensure safety.

Author: AI-SOC Integration Project
Created: February 15, 2026
"""

import os
import sys
import json
import time
import urllib3
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

import requests
from dotenv import load_dotenv
from tabulate import tabulate

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables
load_dotenv()


class WazuhAPIError(Exception):
    """Custom exception for Wazuh API errors"""
    pass


class WazuhClient:
    """
    Read-only Wazuh API client with authentication and retry logic.
    
    All methods are read-only to prevent accidental system modifications.
    """
    
    def __init__(self, api_url: str = None, username: str = None, 
                 password: str = None, verify_ssl: bool = None, 
                 read_only: bool = True):
        """
        Initialize Wazuh API client.
        
        Args:
            api_url: Wazuh API URL (default: from .env)
            username: API username (default: from .env)
            password: API password (default: from .env)
            verify_ssl: Verify SSL certificates (default: from .env)
            read_only: Enforce read-only mode (default: True)
        """
        self.api_url = api_url or os.getenv('WAZUH_API_URL', 'https://localhost:55000')
        self.username = username or os.getenv('WAZUH_API_USER', 'wazuh')
        self.password = password or os.getenv('WAZUH_API_PASSWORD')
        self.verify_ssl = verify_ssl if verify_ssl is not None else \
                         os.getenv('WAZUH_VERIFY_SSL', 'False').lower() == 'true'
        self.read_only = read_only
        
        self.token = None
        self.token_expires = None
        self.max_retries = 3
        self.retry_delay = 2  # seconds
        
        if not self.password:
            raise WazuhAPIError("API password not provided. Check .env file.")
    
    def authenticate(self) -> str:
        """
        Authenticate with Wazuh API and obtain JWT token.
        
        Returns:
            JWT authentication token
            
        Raises:
            WazuhAPIError: If authentication fails
        """
        auth_url = f"{self.api_url}/security/user/authenticate"
        
        try:
            response = requests.post(
                auth_url,
                auth=(self.username, self.password),
                params={'raw': 'true'},
                verify=self.verify_ssl,
                timeout=10
            )
            
            if response.status_code == 200:
                self.token = response.text.strip()
                # JWT tokens typically expire after 15 minutes
                self.token_expires = datetime.now() + timedelta(minutes=14)
                return self.token
            else:
                raise WazuhAPIError(
                    f"Authentication failed: {response.status_code} - {response.text}"
                )
                
        except requests.exceptions.RequestException as e:
            raise WazuhAPIError(f"Connection error during authentication: {str(e)}")
    
    def _ensure_authenticated(self):
        """Ensure we have a valid authentication token."""
        if not self.token or (self.token_expires and datetime.now() >= self.token_expires):
            self.authenticate()
    
    def _make_request(self, endpoint: str, method: str = 'GET', 
                     params: Dict = None, retries: int = None) -> Dict:
        """
        Make authenticated request to Wazuh API with retry logic.
        
        Args:
            endpoint: API endpoint (without base URL)
            method: HTTP method (default: GET)
            params: Query parameters
            retries: Number of retry attempts (default: self.max_retries)
            
        Returns:
            JSON response as dictionary
            
        Raises:
            WazuhAPIError: If request fails after all retries
        """
        if self.read_only and method.upper() not in ['GET', 'HEAD']:
            raise WazuhAPIError(
                f"Client is in read-only mode. {method} requests are not allowed."
            )
        
        retries = retries if retries is not None else self.max_retries
        self._ensure_authenticated()
        
        url = f"{self.api_url}{endpoint}"
        headers = {'Authorization': f'Bearer {self.token}'}
        
        for attempt in range(retries):
            try:
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    verify=self.verify_ssl,
                    timeout=30
                )
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 401:
                    # Token expired, re-authenticate
                    self.authenticate()
                    headers = {'Authorization': f'Bearer {self.token}'}
                    continue
                else:
                    error_msg = f"API request failed: {response.status_code}"
                    try:
                        error_data = response.json()
                        error_msg += f" - {error_data.get('detail', response.text)}"
                    except:
                        error_msg += f" - {response.text}"
                    
                    if attempt < retries - 1:
                        time.sleep(self.retry_delay)
                        continue
                    else:
                        raise WazuhAPIError(error_msg)
                        
            except requests.exceptions.RequestException as e:
                if attempt < retries - 1:
                    time.sleep(self.retry_delay)
                    continue
                else:
                    raise WazuhAPIError(f"Connection error: {str(e)}")
        
        raise WazuhAPIError("Max retries exceeded")
    
    # ===========================================
    # READ-ONLY API METHODS
    # ===========================================
    
    def get_api_info(self) -> Dict:
        """Get Wazuh API version and basic information."""
        return self._make_request('/')
    
    def get_agents(self, status: str = None, limit: int = 500, 
                   offset: int = 0) -> Dict:
        """
        Get list of Wazuh agents.
        
        Args:
            status: Filter by status (active, disconnected, never_connected, pending)
            limit: Maximum number of results
            offset: Skip first N results
            
        Returns:
            Dictionary with agent information
        """
        params = {'limit': limit, 'offset': offset}
        if status:
            params['status'] = status
        
        return self._make_request('/agents', params=params)
    
    def get_agent_by_id(self, agent_id: str) -> Dict:
        """
        Get detailed information about a specific agent.
        
        Args:
            agent_id: Agent ID (e.g., '000', '001')
            
        Returns:
            Dictionary with agent details
        """
        return self._make_request(f'/agents/{agent_id}')
    
    def get_rules(self, rule_ids: List[str] = None, search: str = None,
                  level: int = None, limit: int = 100) -> Dict:
        """
        Get Wazuh rules information.
        
        Args:
            rule_ids: List of specific rule IDs
            search: Search string
            level: Filter by rule level
            limit: Maximum number of results
            
        Returns:
            Dictionary with rule information
        """
        params = {'limit': limit}
        if rule_ids:
            params['rule_ids'] = ','.join(rule_ids)
        if search:
            params['search'] = search
        if level is not None:
            params['level'] = level
        
        return self._make_request('/rules', params=params)
    
    def get_rule_by_id(self, rule_id: str) -> Dict:
        """
        Get detailed information about a specific rule.
        
        Args:
            rule_id: Rule ID (e.g., '5402', '5502')
            
        Returns:
            Dictionary with rule details
        """
        params = {'rule_ids': rule_id}
        result = self._make_request('/rules', params=params)
        
        if result.get('data', {}).get('affected_items'):
            return result['data']['affected_items'][0]
        return None
    
    def get_decoders(self, decoder_names: List[str] = None, limit: int = 100) -> Dict:
        """
        Get Wazuh decoders information.
        
        Args:
            decoder_names: List of specific decoder names
            limit: Maximum number of results
            
        Returns:
            Dictionary with decoder information
        """
        params = {'limit': limit}
        if decoder_names:
            params['decoder_names'] = ','.join(decoder_names)
        
        return self._make_request('/decoders', params=params)
    
    def get_manager_info(self) -> Dict:
        """Get Wazuh manager information."""
        return self._make_request('/manager/info')
    
    def get_manager_status(self) -> Dict:
        """Get Wazuh manager process status."""
        return self._make_request('/manager/status')
    
    def get_manager_logs(self, limit: int = 100, level: str = None) -> Dict:
        """
        Get Wazuh manager logs.
        
        Args:
            limit: Maximum number of log entries
            level: Filter by log level (all, error, warning, info, debug)
            
        Returns:
            Dictionary with log entries
        """
        params = {'limit': limit}
        if level:
            params['level'] = level
        
        return self._make_request('/manager/logs', params=params)
    
    def get_cluster_status(self) -> Dict:
        """Get cluster status (if clustering is enabled)."""
        return self._make_request('/cluster/status')
    
    def search_alerts(self, query: str = None, limit: int = 100, 
                     offset: int = 0, sort: str = None) -> Dict:
        """
        Search alerts in the Wazuh indexer.
        
        Note: This requires the indexer to be accessible.
        For file-based alerts, use external alert processor.
        
        Args:
            query: Search query
            limit: Maximum number of results
            offset: Skip first N results
            sort: Sort field
            
        Returns:
            Dictionary with alert data
        """
        params = {
            'limit': limit,
            'offset': offset
        }
        if query:
            params['q'] = query
        if sort:
            params['sort'] = sort
        
        return self._make_request('/alerts', params=params)


def print_agent_summary(agents_data: Dict, verbose: bool = False):
    """
    Print a formatted summary of agents.
    
    Args:
        agents_data: Response from get_agents()
        verbose: Show detailed information
    """
    if not agents_data.get('data', {}).get('affected_items'):
        print("No agents found.")
        return
    
    agents = agents_data['data']['affected_items']
    
    if verbose:
        table_data = []
        for agent in agents:
            table_data.append([
                agent.get('id', 'N/A'),
                agent.get('name', 'N/A'),
                agent.get('ip', 'N/A'),
                agent.get('status', 'N/A'),
                agent.get('os', {}).get('name', 'N/A'),
                agent.get('version', 'N/A'),
            ])
        
        headers = ['ID', 'Name', 'IP', 'Status', 'OS', 'Version']
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
    else:
        # Summary view
        total = agents_data['data']['total_affected_items']
        status_counts = {}
        
        for agent in agents:
            status = agent.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        print(f"\n📊 Agent Summary (Total: {total})")
        print("=" * 40)
        for status, count in sorted(status_counts.items()):
            emoji = "✅" if status == "active" else "⚠️"
            print(f"  {emoji} {status.capitalize()}: {count}")
    
    print()


def print_rule_info(rule_data: Dict):
    """
    Print formatted rule information.
    
    Args:
        rule_data: Rule dictionary from API
    """
    if not rule_data:
        print("Rule not found.")
        return
    
    print(f"\n🔍 Rule ID: {rule_data.get('id')}")
    print(f"Description: {rule_data.get('description')}")
    print(f"Level: {rule_data.get('level')}")
    print(f"Groups: {', '.join(rule_data.get('groups', []))}")
    
    if rule_data.get('mitre'):
        mitre = rule_data['mitre']
        print(f"\n🎯 MITRE ATT&CK:")
        if isinstance(mitre, dict):
            if mitre.get('id'):
                print(f"  IDs: {', '.join(mitre['id'])}")
            if mitre.get('tactic'):
                print(f"  Tactics: {', '.join(mitre['tactic'])}")
            if mitre.get('technique'):
                print(f"  Techniques: {', '.join(mitre['technique'])}")
        elif isinstance(mitre, list):
            # Handle case where mitre is a list of dictionaries
            for item in mitre:
                if isinstance(item, dict):
                    if item.get('id'):
                        print(f"  IDs: {', '.join(item['id'])}")
                    if item.get('tactic'):
                        print(f"  Tactics: {', '.join(item['tactic'])}")
                    if item.get('technique'):
                        print(f"  Techniques: {', '.join(item['technique'])}")
    
    if rule_data.get('pci_dss'):
        print(f"\n📋 Compliance:")
        print(f"  PCI DSS: {', '.join(rule_data['pci_dss'])}")
    
    print()


def test_connection(client: WazuhClient, verbose: bool = True) -> bool:
    """
    Test connection to Wazuh API.
    
    Args:
        client: WazuhClient instance
        verbose: Print detailed results
        
    Returns:
        True if connection successful, False otherwise
    """
    try:
        if verbose:
            print("\n🔗 Testing Wazuh API connection...")
            print(f"   Endpoint: {client.api_url}")
            print(f"   Username: {client.username}")
            print(f"   Read-only mode: {client.read_only}")
        
        # Test authentication
        client.authenticate()
        if verbose:
            print("   ✅ Authentication successful")
        
        # Test API info
        info = client.get_api_info()
        if verbose:
            api_version = info.get('data', {}).get('api_version', 'Unknown')
            print(f"   ✅ API Version: {api_version}")
        
        # Test agents endpoint
        agents = client.get_agents(limit=1)
        total_agents = agents.get('data', {}).get('total_affected_items', 0)
        if verbose:
            print(f"   ✅ Agents accessible: {total_agents} total")
        
        # Test manager info
        manager = client.get_manager_info()
        if verbose:
            manager_version = manager.get('data', {}).get('affected_items', [{}])[0].get('version', 'Unknown')
            print(f"   ✅ Manager Version: {manager_version}")
        
        if verbose:
            print("\n✅ All connectivity tests passed!\n")
        
        return True
        
    except Exception as e:
        if verbose:
            print(f"\n❌ Connection test failed: {str(e)}\n")
        return False


def main():
    """
    Main function for testing the Wazuh API client.
    
    Usage:
        python wazuh_client.py --test              # Test connection
        python wazuh_client.py --agents            # List all agents
        python wazuh_client.py --agents --verbose  # Detailed agent info
        python wazuh_client.py --rule 5402         # Get rule info
        python wazuh_client.py --manager           # Manager status
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Wazuh API Client - Read-Only Operations')
    parser.add_argument('--test', action='store_true', help='Test API connectivity')
    parser.add_argument('--agents', action='store_true', help='List agents')
    parser.add_argument('--rule', type=str, help='Get rule information by ID')
    parser.add_argument('--manager', action='store_true', help='Get manager information')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--limit', type=int, default=100, help='Limit results (default: 100)')
    
    args = parser.parse_args()
    
    try:
        # Initialize client
        client = WazuhClient(read_only=True)
        
        if args.test:
            # Test connectivity
            success = test_connection(client, verbose=True)
            sys.exit(0 if success else 1)
        
        elif args.agents:
            # List agents
            print("\n📡 Retrieving agent information...")
            agents = client.get_agents(limit=args.limit)
            print_agent_summary(agents, verbose=args.verbose)
        
        elif args.rule:
            # Get rule info
            print(f"\n📋 Retrieving rule {args.rule}...")
            rule = client.get_rule_by_id(args.rule)
            print_rule_info(rule)
        
        elif args.manager:
            # Manager info
            print("\n🖥️  Wazuh Manager Information")
            print("=" * 50)
            
            info = client.get_manager_info()
            manager_data = info.get('data', {}).get('affected_items', [{}])[0]
            
            print(f"Version: {manager_data.get('version')}")
            print(f"Compilation Date: {manager_data.get('compilation_date')}")
            print(f"Installation Type: {manager_data.get('type')}")
            
            # Status
            status = client.get_manager_status()
            status_data = status.get('data', {}).get('affected_items', [{}])[0]
            
            print(f"\nDaemons Status:")
            for daemon, daemon_status in status_data.items():
                if isinstance(daemon_status, dict):
                    emoji = "✅" if daemon_status.get('status') == 'running' else "❌"
                    print(f"  {emoji} {daemon}: {daemon_status.get('status', 'unknown')}")
            print()
        
        else:
            # No arguments, show help
            parser.print_help()
            
    except WazuhAPIError as e:
        print(f"\n❌ Wazuh API Error: {str(e)}\n", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
