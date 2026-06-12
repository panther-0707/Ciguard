from ciguard.scanner.parser import WorkflowStep

KNOWN_AI_ACTIONS = {
    "anthropics/claude-code-action",
    "anthropics/claude-code-base-action",
    "google-github-actions/run-gemini-cli",
    "actions/ai-inference",
    "openai/codex-action",
    "qodo-ai/pr-agent",
}

AI_KEY_PATTERNS = [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
]



def is_ai_step(step: WorkflowStep) -> bool:
    # Way 1: check step.uses
    if step.uses:  # make sure it exists first
        action = step.uses.split("@")[0]  # strip @v1
        if action in KNOWN_AI_ACTIONS:
            return True
    # Way 2: check step.env
    for key in step.env: 
        if key in AI_KEY_PATTERNS:
            return True

    return False