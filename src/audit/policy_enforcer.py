import yaml
from typing import Dict, List

class PolicyEnforcer:
    def __init__(self, policy_path: str):
        with open(policy_path, 'r') as f:
            self.policy = yaml.safe_load(f)

    def enforce(self, findings: List[Dict]) -> Dict:
        """Enforces NIST-based policies against scanner findings."""
        allowed_severities = self.policy.get('allowed_severities', ['Low'])
        violations = []
        
        for finding in findings:
            if finding['severity'] not in allowed_severities:
                violations.append({
                    "finding": finding,
                    "policy_violation": f"Severity {finding['severity']} not allowed by policy."
                })
        
        return {
            "compliant": len(violations) == 0,
            "violations": violations,
            "policy_version": self.policy.get('version', 'unknown')
        }
