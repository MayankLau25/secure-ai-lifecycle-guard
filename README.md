# Secure AI Lifecycle Guard

Comprehensive auditing and policy enforcement for the AI development lifecycle.

## Features
- **Code Scanner**: Automated detection of OWASP LLM Top 10 vulnerabilities (Injection, Insecure Output Handling, etc.).
- **Policy Engine**: YAML-based policy enforcer aligned with NIST RMF standards.
- **NIST RMF Integration**: Pre-configured security controls for AI model deployments.
- **Audit-ready**: Detailed reports on security findings and policy violations.

## Installation
```bash
pip install -r requirements.txt
```

## Core Components
- `src/audit/code_scanner.py`: Regex-based vulnerability scanner for AI-generated code.
- `src/audit/policy_enforcer.py`: Logic for validating audit findings against organizational policy.
- `config/nist_rmf_v1.yaml`: NIST Risk Management Framework policy definition.

## Testing
```bash
pytest tests/
```

## Usage Example
```python
from src.audit.code_scanner import CodeScanner
from src.audit.policy_enforcer import PolicyEnforcer

scanner = CodeScanner()
findings = scanner.scan_code(ai_generated_code)

enforcer = PolicyEnforcer("config/nist_rmf_v1.yaml")
audit_report = enforcer.enforce(findings)

print(f"Compliance Status: {audit_report['compliant']}")
```
