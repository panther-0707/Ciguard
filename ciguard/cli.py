import click
import sys
from ciguard.scanner.loader import find_workflows
from ciguard.scanner.parser import parse_workflow
from ciguard.scanner.taint import analyse_workflow
from ciguard.scanner.reporter import Reporter


@click.group()
def main():
    """gh-prompt-scan — detect prompt injection in GitHub Actions workflows."""
    pass

@main.command()
@click.option("--path", default=".", help="Path to repo")
def scan(path):
    workflow_files = find_workflows(path)

    if not workflow_files:
        click.echo("No workflow files found.")
        return
    
    click.echo(f"Scanning {len(workflow_files)} workflow file(s) ...")

    all_findings = []

    for wf_path in workflow_files:
        workflow = parse_workflow(wf_path)
        if workflow:
            findings = analyse_workflow(workflow)
            all_findings.extend(findings)

    reporter = Reporter(all_findings)
    click.echo(reporter.to_text())

    if all_findings:
        sys.exit(1)


@main.command()
def version():
    click.echo("gh-prompt-scan version 0.1.0")