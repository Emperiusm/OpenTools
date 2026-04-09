---
description: Run a saved security workflow recipe
---

# Recipe Runner

Execute a predefined security workflow from `recipes.json`. Recipes are reusable, shareable workflow definitions that chain multiple tools together.

## Workflow

### 1. Load recipes

Read `recipes.json` from the project root. If the user specifies a recipe name, find it. Otherwise, list available recipes.

### 2. List mode (no recipe specified)

Display available recipes:

```markdown
## Available Recipes

| # | Name | Description | Tools Required |
|---|------|-------------|----------------|
| 1 | quick-web-audit | Nuclei + Nikto + Semgrep parallel scan | nuclei-mcp, nikto-mcp, semgrep |
| 2 | apk-analysis | Full Android APK static analysis | JADX, codebadger, gitleaks |
| ... | ... | ... | ... |

Use: `/recipe <name> --target <target>`
```

### 3. Run mode (recipe specified)

**3a. Parse recipe definition:**
- Read the recipe from `recipes.json`
- Validate all required tools are available (run quick checks from `/setup`)
- If tools are missing, report which ones and ask user to proceed or abort

**3b. Substitute variables:**
- Replace `{{target}}` with the user-provided target
- Replace `{{output_dir}}` with `./engagements/<recipe-name>-<timestamp>/`
- Replace any other `{{variable}}` placeholders with user-provided values

**3c. Execute steps:**
- For `parallel: true` recipes, run all steps concurrently using the Agent tool
- For sequential recipes, run steps in order
- Log each step's output to the engagement directory
- If a step fails, report the error and ask whether to continue with remaining steps

**3d. Consolidate output:**
- Merge findings from all steps using the recipe's `output` format
- Deduplicate findings that appear from multiple tools
- Rank by severity
- Generate summary report

### 4. Recipe format reference

Recipes in `recipes.json` follow this schema:

```json
{
  "id": "recipe-id",
  "name": "Human-Readable Name",
  "description": "What this recipe does",
  "requires": ["tool1", "tool2"],
  "variables": {
    "target": { "description": "Target URL or path", "required": true },
    "severity": { "description": "Min severity to report", "default": "medium" }
  },
  "steps": [
    {
      "name": "Step description",
      "tool": "tool-name",
      "command": "command with {{target}} substitution",
      "timeout": 300
    }
  ],
  "parallel": true,
  "output": "consolidated-findings-table"
}
```

### 5. User-defined recipes

Users can add their own recipes to `recipes.json`. If a user describes a workflow they want to save, offer to create a recipe entry for it.
