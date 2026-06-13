# CIGuard

**A static analyzer that finds prompt-injection and related vulnerabilities in AI-integrated GitHub Actions workflows.**

CIGuard scans the workflow YAML in a repository's `.github/workflows/` directory and flags patterns where untrusted, attacker-controlled input can reach a shell command, an AI agent, or the runner — the class of bugs behind "pwn request" and prompt-injection attacks in CI pipelines.

It is designed to run as a CI gate: it exits non-zero when it finds issues, so a build can fail on a vulnerable workflow.

> CIGuard is a linter for common dangerous patterns, **not** a proof of safety. A clean report does not guarantee a workflow is secure. See [Limitations](#limitations).

---

## Why this exists

Workflows triggered by events like `pull_request_target`, `issue_comment`, or `issues` run with the *base* repository's permissions and secrets, but their input (issue titles, PR bodies, comments, branch names) is controlled by anyone on the internet. When that untrusted input is interpolated into a shell command or fed to an AI agent that can run tools, an attacker can inject commands or instructions. CIGuard looks for these data-flow patterns automatically.

The threat-vector taxonomy (TV4–TV7) is based on the Heimdallr research paper (arXiv:2605.05969).

---

## What it detects

| Vector | Severity | What it flags |
|--------|----------|---------------|
| **TV4** | CRITICAL | An attacker-controlled context expression (e.g. `github.event.issue.title`) used **directly inside a `run:` block**, where GitHub interpolates it before the shell runs — classic command injection. |
| **TV5** | CRITICAL | An AI step receives attacker-controlled input **and** a step output later flows into a shell command, so model output can drive shell execution. |
| **TV6** | CRITICAL | A `pull_request_target` workflow that **checks out the PR head** (`github.head_ref` / `pull_request.head.*`), giving attacker-controlled code access to the privileged runner context. |
| **TV7** | MEDIUM | An AI step reachable by **any external user with no actor guard**, allowing repeated triggering to exhaust your AI API quota. |

Severity reflects impact: CRITICAL findings can lead to code execution or secret exposure; MEDIUM findings are abuse/cost risks.

---

## Installation

Requires **Python 3.10+**.

```bash
git clone https://github.com/panther-0707/Ciguard.git
cd Ciguard
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -e .
```

This installs the `ciguard` command (via `[project.scripts]` in `pyproject.toml`). Dependencies: `pyyaml`, `click`.

---

## Usage

Scan the current repository:

```bash
ciguard scan --path .
```

Scan a different repository:

```bash
ciguard scan --path /path/to/repo
```

Show the version:

```bash
ciguard version
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings (scan clean, or no workflow files found) |
| `1` | One or more findings reported |

The non-zero exit on findings is what lets CIGuard fail a CI build.

### Example output

```
Scanning 2 workflow file(s) ...
[CRITICAL] TV4 - .github/workflows/triage.yml step 1
Message: Attacker controlled 'github.event.issue.title' which was found directly in run: command
Fix: Pass untrusted values via env: variables instead of ${{ }} in run: blocks
```

---

## Running CIGuard in CI

Add a workflow that runs CIGuard on every push and pull request. Because the scan only reads your workflow files, run it on the safe `pull_request` trigger:

```yaml
name: CIGuard
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e .
      - run: ciguard scan --path .
```

The job fails automatically if CIGuard reports any findings.

---

## How it works

CIGuard runs a small pipeline over each workflow file:

1. **Loader** finds `*.yml` / `*.yaml` files under `.github/workflows/`.
2. **Parser** loads the YAML into typed objects, normalizing the `on:` field (which YAML parses as the boolean `True`, and which may be a string, list, or mapping).
3. **Trigger classifier** decides whether the workflow is reachable by untrusted users. Workflows with only "safe" triggers (`push`, `schedule`, `workflow_dispatch`) are skipped.
4. **AI detector** identifies steps that invoke a known AI action or set an AI provider API key.
5. **Taint analysis** walks the steps of each externally-triggerable job and emits findings for TV4–TV7.

---

## Limitations

CIGuard catches common patterns; it is not exhaustive and can produce both false positives and false negatives. Known gaps in the current version:

- **Only step-level `env` is inspected.** API keys defined at the job or workflow level are not detected, so an AI step configured that way may be missed.
- **TV5 is a heuristic.** It flags when an AI step received tainted input and *any* later step references a `steps.*.outputs.*` value in a shell command, without confirming the referenced output belongs to the AI step. It may over- or under-report.
- **AI-action matching is exact.** `is_ai_step` matches known action names without the `@version` suffix and is case-sensitive; renamed env keys, action subpaths (`.../setup@v1`), or differently-cased names may be missed.
- **`step` numbers are positions, not file line numbers.** A finding's `step` index is the step's position within its job.
- **Detection uses substring matching** on expression strings, so unusual syntax (such as index form `['title']`) may not match.
- **`ATTACKER_SOURCES` is a curated list,** not a complete enumeration of every untrusted GitHub context.

Treat CIGuard's output as a prompt to review a workflow by hand, not as a security guarantee.

---

## Development

Run the test suite:

```bash
pytest -v
```

Contributions that add test cases for new threat vectors or edge cases are especially welcome.

---

## License

Released under the MIT License. See [`LICENSE`](LICENSE) for details.

---

## Acknowledgements

The threat-vector taxonomy is based on the Heimdallr research paper (arXiv:2605.05969).
