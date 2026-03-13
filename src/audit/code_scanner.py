import re
from typing import List, Dict

class CodeScanner:
    def __init__(self):
        # OWASP LLM Top 10 inspired vulnerability patterns
        self.vulnerabilities = {
            "prompt_injection": re.compile(r"(?:ignore|disregard)\s+(?:all|previous|system)\s+instructions", re.I),
            "insecure_output_handling": re.compile(r"eval\(|exec\(|os\.system\(|subprocess\.Popen\(", re.I),
            "sensitive_data_exposure": re.compile(r"api_key|secret|password|token", re.I),
            "excessive_agency": re.compile(r"rm\s+-rf|chmod\s+777|sudo", re.I)
        }

    def scan_code(self, code: str) -> List[Dict]:
        """Scans code for common AI-generated security vulnerabilities."""
        findings = []
        for vuln_type, pattern in self.vulnerabilities.items():
            matches = pattern.finditer(code)
            for match in matches:
                findings.append({
                    "vulnerability": vuln_type,
                    "line": code.count('\n', 0, match.start()) + 1,
                    "matched_text": match.group(),
                    "severity": "High" if vuln_type in ["excessive_agency", "prompt_injection"] else "Medium"
                })
        return findings
