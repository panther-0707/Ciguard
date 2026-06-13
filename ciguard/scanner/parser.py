import yaml
from pathlib import Path
from dataclasses import dataclass

@dataclass
class WorkflowStep:
    name: str
    run: str | None
    uses: str | None
    env: dict
    with_inputs: dict

@dataclass
class WorkflowJob:
    name: str
    steps: list[WorkflowStep]
    permissions: dict
    if_condition: str | None

@dataclass
class Workflow:
    path: Path
    name: str
    triggers: dict
    permissions: dict
    jobs: dict[str, WorkflowJob]


def parse_workflow(path: Path) -> Workflow | None:
    try:

        # Extract the object of the yaml

        with open(path) as file:
            content = yaml.safe_load(file)
        
        name = content.get("name")
        triggers = content.get(True) or content.get("on")
        permissions = content.get("permissions") or {}
        jobs = content.get("jobs")


        # Extract jobs and steps

        jobs = {}

        for job_name, job_info in content.get("jobs").items():
            steps = []
            for step in job_info.get("steps"):
                steps.append(WorkflowStep(
                    name = step.get("name", ""),
                    run = step.get("run"),
                    uses = step.get("uses"),
                    env = step.get("env") or {},
                    with_inputs = step.get("with") or {}
                ))
            
            jobs[job_name] = WorkflowJob(
                name = job_name,
                steps = steps,
                permissions = job_info.get("permissions") or {},
                if_condition = job_info.get("if"),
            )


        return Workflow(
            path = path,
            name = name,
            triggers = triggers,
            permissions = permissions,
            jobs = jobs,
        )
    

    except:
        return None
    
