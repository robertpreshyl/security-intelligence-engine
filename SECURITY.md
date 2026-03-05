# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |

## Reporting a Vulnerability

**Please do NOT open public GitHub issues for security vulnerabilities.**

If you discover a security vulnerability in this project, please report it responsibly:

1. **Email:** security@allyshipglobal.com
2. **Subject:** `[SECURITY] AllysecLabs AI-SOC — <brief description>`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 5 business days
- **Fix Target:** Critical issues within 14 days; others within 30 days

### Scope

This policy covers:
- The AI-SOC codebase and its modules
- API endpoints exposed by the platform
- LLM prompt injection or manipulation vectors
- Authentication and authorization flaws
- Data exfiltration or information disclosure

### Out of Scope

- Vulnerabilities in upstream dependencies (report to the respective project)
- Wazuh core vulnerabilities (report to [Wazuh](https://wazuh.com/security/))
- Social engineering attacks

## Security Best Practices for Deployers

1. **Never commit `.env` files** — they contain API keys and passwords
2. **Use HTTPS** for all API and dashboard access
3. **Restrict network access** — bind services to localhost or use a reverse proxy
4. **Keep dependencies updated** — run `pip audit` regularly
5. **Review LLM outputs** — AI-generated analysis should be verified by human analysts
6. **Enable audit logging** — the `action_audit.jsonl` tracks all automated actions

## Acknowledgments

We appreciate responsible disclosure and will acknowledge reporters (with permission) in our changelog.
