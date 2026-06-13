import yaml
from pathlib import Path
from dataclasses import dataclass

@dataclass
class WorkflowStep:
    name: str
    run: str | None
    uses: str | None
    env: dict
    own_env: dict
    with_inputs: dict
    if_condition: str | None

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
        raw_on = content.get(True) or content.get("on") or {}
        if isinstance(raw_on, str):
            triggers = {raw_on: None}
        elif isinstance(raw_on, list):
            triggers = {t: None for t in raw_on}
        else:
            triggers = raw_on
        permissions = content.get("permissions") or {}
        workflow_env = content.get("env") or {}


        # Extract jobs and steps

        jobs = {}

        for job_name, job_info in content.get("jobs").items():
            job_env = job_info.get("env") or {}
            steps = []
            for step in job_info.get("steps") or []:
                steps.append(WorkflowStep(
                    name = step.get("name", ""),
                    run = step.get("run"),
                    uses = step.get("uses"),
                    env = {**workflow_env, **job_env, **(step.get("env") or {})},
                    own_env = step.get("env") or {},
                    with_inputs = step.get("with") or {},
                    if_condition=step.get("if"),
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
    

    except Exception as e:
        print(f"[warn] could not parse {path}: {e}")
        return None
    
