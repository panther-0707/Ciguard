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


def normalize_action(uses: str) -> str:
    ref = uses.split("@")[0].lower()
    parts = ref.split("/")
    return f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else ref



def is_ai_step(step: WorkflowStep) -> bool:
    # check step.uses
    if step.uses:
        action = normalize_action(step.uses)
        if action in KNOWN_AI_ACTIONS:
            return True
        
    # check step.env
    for key in step.own_env: 
        if key in AI_KEY_PATTERNS:
            return True

    return False