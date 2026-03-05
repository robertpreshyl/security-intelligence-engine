# Contributing to AllysecLabs AI-SOC

Thank you for your interest in contributing! This project bridges AI and cybersecurity operations, and we welcome contributions from both domains.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/YOUR_USERNAME/ai-soc.git`
3. **Set up** the development environment:
   ```bash
   cd ai-soc
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env   # Fill in your values
   ```
4. **Create a branch** for your work: `git checkout -b feature/your-feature-name`

## Development Guidelines

### Code Style
- Python 3.10+ with type hints where practical
- Follow PEP 8 conventions
- Keep functions focused and under 50 lines where possible

### Security First
This is a **security tool**. Every contribution is reviewed with security in mind:
- Never hardcode credentials, IPs, or secrets
- Use environment variables for all configuration
- Sanitize any data before logging or display
- Be cautious with LLM prompt construction (injection risks)

### Commit Messages
Use clear, descriptive commit messages:
```
feat: add MITRE ATT&CK mapping to alert analysis
fix: prevent XSS in dashboard alert display
docs: update API endpoint documentation
```

## What to Contribute

### High-Value Contributions
- New LLM provider integrations
- Additional Wazuh rule parsers
- Dashboard visualizations
- Detection pattern improvements
- Documentation and examples

### Reporting Bugs
- Open an issue with steps to reproduce
- Include relevant log output (redact any sensitive data)
- Specify your environment (OS, Python version, Wazuh version)

### Security Vulnerabilities
**Do NOT open public issues for security bugs.** See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Pull Request Process

1. Ensure your code passes any existing tests
2. Update documentation if you change behavior
3. Keep PRs focused — one feature or fix per PR
4. Describe what your PR does and why

## License

By contributing, you agree that your contributions will be licensed under the project's [AGPL-3.0 License](LICENSE).
