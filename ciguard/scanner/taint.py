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
        ai_received_tainted_input = False

        for i, step in enumerate(job.steps):

            #TV 4
            if step.run:
                for source in ATTACKER_SOURCES:
                    if source in step.run:
                        findings.append(Finding(
                            threat_vector = "TV4",
                            severity = "CRITICAL",
                            file_path = str(workflow.path),
                            line = i,
                            message = f"Attacker controlled '{source}' which was found directly in run: command",
                            fix="Pass untrusted values via env: variables instead of ${{ }} in run: blocks",
                        ))
                    
            if is_ai_step(step):
                step_text = str(step.with_inputs) + str(step.env) + str(step.run)
                for source in ATTACKER_SOURCES:
                    if source in step_text:
                        ai_received_tainted_input = True

            # TV 5
            if ai_received_tainted_input and step.run and "steps." in step.run and ".outputs." in step.run:
                    findings.append(Finding(
                        threat_vector = "TV5",
                        severity = "CRITICAL",
                        file_path = str(workflow.path),
                        line = i,
                        message = "AI step received attacker input, and its output flows into a shell command",
                        fix="Never pass AI output directly into shell commands, validate AI output first.",
                    ))
            
            # TV 6
            if step.uses and "actions/checkout" in step.uses:
                ref = str(step.with_inputs.get("ref", ""))
                if "pull_request.head" in ref and "pull_request_target" in str(workflow.triggers):
                    findings.append(Finding(
                        threat_vector = "TV6",
                        severity = "CRITICAL",
                        file_path = str(workflow.path),
                        line = i,
                        message = "Workflow uses pull_request_target and checks out PR head - attacker controls the workspace files fed to AI",
                        fix = "Do not check out PR head code in pull_request_target workflows. Use pull_request trigger instead.",
                    ))
            
            #TV 7
            if is_ai_step(step):
                # check if there's no actor guard
                has_guard = False
                if step.if_condition and "github.actor" in step.if_condition:
                    has_guard = True
                if not has_guard:
                    findings.append(Finding(
                        threat_vector="TV7",
                        severity="MEDIUM",
                        file_path = str(workflow.path),
                        line = i,
                        message="AI step is reachable by any external user with no actor guard - attacker can repeatedly trigger this workflow to exhaust your AI API quota",
                        fix="Add an if condition to restrict who can trigger AI steps. Example: if: github.actor == 'trusted-bot' or check author_association",
                    ))


    return findings