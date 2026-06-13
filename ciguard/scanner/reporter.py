from ciguard.scanner.taint import Finding

class Reporter:
    def __init__(self, findings: list[Finding]):
        self.findings = findings
    
    def to_text(self):
        if not self.findings:
            return "No vulnerabilities found."
        
        lines = []
        for find in self.findings:
            lines.append(f"[{find.severity}] {find.threat_vector} - {find.file_path} line {find.line}")
            lines.append(f"Message: {find.message}")
            lines.append(f"Fix: {find.fix}")
            lines.append("")
        
        return "\n".join(lines)


    def to_markdown(self) -> str:
        if not self.findings:
            return "## CIGuard\n\nNo vulnerabilities found."
        
        lines = [
            "## CIGuard Security Report",
            "",
            f"Found **{len(self.findings)} issue(s)**",
            "",
            "| Severity | Threat Vector | File | Line | Message |",
            "|----------|--------------|------|------|---------|",
        ]

        for find in self.findings:
            lines.append(f"| {find.severity} | {find.threat_vector} | `{find.file_path}` | {find.line} | {find.message} |")
        
        return "\n".join(lines)