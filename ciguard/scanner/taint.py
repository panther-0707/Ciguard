from ciguard.scanner.parser import Workflow
from ciguard.scanner.trigger import classify_triggers
from ciguard.scanner.ai_detector import is_ai_step
from dataclasses import dataclass

ATTACKER_SOURCES = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
]


@dataclass
class Finding:
    threat_vector: str
    severity: str
    file_path: str
    line: int
    message: str
    fix: str

def analyse_workflow(workflow: Workflow) -> list[Finding]:
    findings = []
    
    if classify_triggers(workflow) == "safe":
        return findings
    
    for job_name, job in workflow.jobs.items():
        for i, step in enumerate(job.steps):
            if step.run:
                for source in ATTACKER_SOURCES:
                    if source in step.run:
                        findings.append(Finding(
                            threat_vector="TV4",
                            severity="CRITICAL",
                            file_path=str(workflow.path),
                            line=i,
                            message=f"Attacker controlled '{source}' which was found directly in run: command",
                            fix="Pass untrusted values via env: variables instead of ${{ }} in run: blocks",
                        ))

    return findings