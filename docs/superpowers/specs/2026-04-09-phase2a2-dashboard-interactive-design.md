# Phase 2A-2: Dashboard Interactive — Design Specification

**Date:** 2026-04-09
**Status:** Approved
**Author:** slabl + Claude
**Depends on:** Phase 2A-1 dashboard core (merged)

## 1. Overview

Add full CRUD interactivity to the TUI dashboard: engagement creation/deletion, finding addition, IOC addition, recipe execution with live per-step progress, report generation, context-sensitive export, engagement import, and bulk finding actions with checkbox multi-select.

Builds on the existing dashboard (sidebar, summary strip, 4 tabs, detail modal). All new features are modals or screens that overlay the existing layout.

## 2. Decisions

| Decision | Choice |
|----------|--------|
| Validation strictness | Match CLI behavior exactly (no stricter) |
| Recipe runner progress | Hybrid: step-level progress list + collapsible stdout panel |
| Export settings memory | Per-session (reset on dashboard quit) |
| Bulk finding selection | Checkbox column with Space toggle, Ctrl+A select all |
| Recipe launch flow | One modal (recipe picker + variable fields) → runner screen |
| Recipe progress mechanism | `run_with_progress()` generator yielding per-step events |
| Multi-line fields | TextArea for description/evidence, Input for everything else |
| Delete behavior | Hard delete with confirmation dialog, single transaction |

## 3. File Structure

```
packages/cli/src/opentools/dashboard/
├── widgets/
│   ├── __init__.py
│   ├── form_field.py          # FormField: label + Input/Select/TextArea + validation
│   └── checkbox_table.py      # CheckboxTable: DataTable with checkbox column + multi-select
├── dialogs/
│   ├── __init__.py
│   ├── engagement_create.py   # EngagementCreateDialog(ModalScreen)
│   ├── engagement_delete.py   # EngagementDeleteDialog(ModalScreen)
│   ├── finding_add.py         # FindingAddDialog(ModalScreen)
│   ├── ioc_add.py             # IOCAddDialog(ModalScreen)
│   ├── export_dialog.py       # ExportDialog(ModalScreen) — context-sensitive
│   ├── report_dialog.py       # ReportDialog(ModalScreen)
│   ├── import_dialog.py       # ImportDialog(ModalScreen)
│   └── recipe_launch.py       # RecipeLaunchDialog(ModalScreen) — picker + variables
├── screens/
│   ├── __init__.py
│   └── recipe_runner.py       # RecipeRunnerScreen(Screen) — full screen with progress
├── (existing files — modified)
│   ├── app.py                 # New keybindings
│   ├── state.py               # New CRUD methods
│   ├── sidebar.py             # New delete/export bindings
│   ├── tabs/findings.py       # CheckboxTable, add/export bindings, bulk actions
│   └── tabs/iocs.py           # Add/export bindings
```

## 4. Reusable Widgets

### 4.1 FormField (`widgets/form_field.py`)

Wraps a label, an input widget (Input, Select, or TextArea), and a validation error display.

```python
class FormField(Widget):
    def __init__(self, label: str, input_widget: Input | Select | TextArea,
                 required: bool = False):
        ...

    def validate(self) -> bool:
        """Check required field. Returns True if valid."""
        # If required and empty → show error, return False
        # Otherwise → clear error, return True

    def get_value(self) -> str:
        """Return current input value."""

    def show_error(self, message: str):
        """Show red error text below the field."""

    def clear_error(self):
        """Hide error text."""
```

Layout per field:
```
┌ Name * ─────────────────────┐
│ my-pentest                  │
└─────────────────────────────┘
  Name is required              ← red, hidden until validation fails
```

The asterisk in the label indicates required fields.

Used by all 7 modal dialogs for consistent form UX.

### 4.2 CheckboxTable (`widgets/checkbox_table.py`)

DataTable subclass with a checkbox first column and external checked-state tracking.

```python
class CheckboxTable(DataTable):
    _checked: set[str]  # set of row keys

    def add_checked_row(self, *cells, key: str) -> None:
        """Add a row with a checkbox cell prepended."""
        checkbox = "[x]" if key in self._checked else "[ ]"
        self.add_row(checkbox, *cells, key=key)

    def toggle_check(self, row_key: str) -> None:
        """Toggle checkbox for a row, update the cell display."""
        if row_key in self._checked:
            self._checked.discard(row_key)
        else:
            self._checked.add(row_key)
        self._update_checkbox_cell(row_key)

    def select_all(self) -> None:
        """Check all currently visible rows."""

    def deselect_all(self) -> None:
        """Uncheck all rows."""

    def get_checked_keys(self) -> list[str]:
        """Return keys of all checked rows."""
```

Bindings: Space=toggle current row, Ctrl+A=select all, Ctrl+D=deselect all.

Replaces the plain DataTable in the findings tab.

## 5. Modal Dialogs

All modals receive `state: DashboardState` in their constructor for data access and mutations. They share this pattern:

```python
class SomeDialog(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    SomeDialog { align: center middle; }
    #dialog-container {
        width: 60%; max-width: 80; height: auto; max-height: 80%;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    """

    def compose(self):
        with Vertical(id="dialog-container"):
            yield Static("[bold]Title[/bold]")
            yield FormField(...)
            with Horizontal():
                yield Button("Submit", variant="primary", id="submit")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event):
        if event.button.id == "submit":
            if self._validate_all():
                self._do_action()
                self.dismiss(True)
        elif event.button.id == "cancel":
            self.dismiss(False)
```

### 5.1 EngagementCreateDialog

Fields:
- Name (Input, required)
- Target (Input, required)
- Type (Select from EngagementType enum values)
- Scope (Input, optional)

On submit: generates UUID, creates Engagement via `state.create_engagement()`, refreshes sidebar.

### 5.2 EngagementDeleteDialog

No form fields — confirmation only:

```
Delete engagement "my-pentest"?

This will permanently delete:
- 15 findings
- 8 IOCs
- 23 timeline events
- 3 artifacts

This cannot be undone.

[Delete]  [Cancel]
```

Counts fetched from `state.summary`. Delete button uses `variant="error"` (red).

On confirm: `state.delete_engagement(engagement_id)`, refreshes sidebar, clears main area.

### 5.3 FindingAddDialog

Fields:
- Tool (Input, required)
- Title (Input, required)
- Severity (Select from Severity enum, required)
- CWE (Input, optional, placeholder="CWE-89")
- File Path (Input, optional)
- Line Start (Input, optional, numeric)
- Description (TextArea, optional)
- Evidence (TextArea, optional)

On submit: generates UUID and timestamp, creates Finding via `state.add_finding()`, refreshes findings tab.

### 5.4 IOCAddDialog

Fields:
- Type (Select from IOCType enum, required)
- Value (Input, required)
- Context (Input, optional)

On submit: generates UUID, creates IOC via `state.add_ioc()`, refreshes IOCs tab.

### 5.5 ExportDialog

Context-sensitive — receives an `export_context` parameter indicating what to export.

| Context | Format Options | Default Filename |
|---------|---------------|-----------------|
| `"findings"` | SARIF, CSV, JSON | `{engagement}-findings.{ext}` |
| `"iocs"` | CSV, JSON, STIX | `{engagement}-iocs.{ext}` |
| `"engagement"` | JSON, ZIP (bundle) | `{engagement}-export.{ext}` |

Fields:
- Format (Select, options depend on context)
- Output Path (Input, pre-filled with default filename)
- TLP (Select: white/green/amber/red — only shown for STIX format)

Per-session memory: class-level dict `_last_settings: dict[str, dict]` keyed by export_context. Pre-fills format and path prefix from last use.

On submit: calls the appropriate export function, writes to file, shows toast with path.

### 5.6 ReportDialog

Fields:
- Template (Select, populated from `ReportGenerator.list_templates()`)
- Format (Select: markdown, html)
- Output Path (Input, pre-filled)
- Client (Input, optional)
- Assessor (Input, optional)
- Classification (Input, optional, default "INTERNAL")

On submit: calls `ReportGenerator.generate()` with `extra_context={"client": ..., "assessor": ..., "classification": ...}`, writes to file, shows toast.

### 5.7 ImportDialog

Fields:
- File Path (Input, required, placeholder="Path to .json or .zip export file")

On submit: calls `import_engagement()`, refreshes sidebar, shows toast with new engagement name.

### 5.8 RecipeLaunchDialog

Two-part modal — recipe picker at top, variable fields below (dynamically rendered based on selected recipe):

```
┌─── Run Recipe ─────────────────────────┐
│ Recipe: [▼ quick-web-audit          ]  │
│                                        │
│ Description: Nuclei + Nikto + ffuf     │
│ parallel scan on a URL                 │
│                                        │
│ Variables:                             │
│ ┌ target * ────────────────────────┐   │
│ │ https://example.com              │   │
│ └──────────────────────────────────┘   │
│                                        │
│ [ ] Dry run                            │
│                                        │
│ [Run]  [Cancel]                        │
└────────────────────────────────────────┘
```

When recipe selection changes, variable fields rebuild dynamically. Variables with defaults show the default as placeholder text.

On submit: dismisses with `(recipe_id, variables, dry_run)` tuple. The app then pushes `RecipeRunnerScreen`.

## 6. Recipe Runner Screen

Full screen that replaces the dashboard view during recipe execution.

### 6.1 Layout

```
┌─────────────────────────────────────────────────────────┐
│  Recipe: Quick Web Audit                    [Esc Cancel] │
│  Target: https://example.com                             │
│  Status: RUNNING (2/3 steps complete)                    │
├──────────────────────────────────────────────────────────┤
│  Steps:                                                  │
│  [x] Nuclei scan ...................... 45s  DONE        │
│  [>] Nikto scan ....................... 12s  RUNNING     │
│  [ ] Directory fuzzing                      PENDING      │
├──────────────────────────────────────────────────────────┤
│  Output [o to toggle]:                                   │
│  ┌──────────────────────────────────────────────────┐    │
│  │ [nikto] + OSVDB-3092: /admin/: Dir found         │    │
│  │ [nikto] + OSVDB-3268: /icons/: Indexing found    │    │
│  └──────────────────────────────────────────────────┘    │
├──────────────────────────────────────────────────────────┤
│  o Output │ Esc Cancel │ Enter Back (when complete)      │
└──────────────────────────────────────────────────────────┘
```

### 6.2 RecipeRunner API Addition

Add a generator method to `packages/cli/src/opentools/recipes.py`:

```python
async def run_with_progress(
    self,
    recipe_id: str,
    variables: dict[str, str],
) -> AsyncGenerator[tuple[str, str, StepResult | None], None]:
    """Execute recipe, yielding (event, step_name, result) per step.
    
    Events: "started", "completed"
    """
    recipe = self.get_recipe(recipe_id)
    # ... validate, substitute variables ...
    
    for step, cmd in resolved_steps:
        yield ("started", step.name, None)
        result = await self._run_step(step, cmd, quiet=True)
        yield ("completed", step.name, result)
```

For parallel recipes, yield started/completed events as steps finish (unordered).

### 6.3 Screen Execution

The screen runs the recipe in a `@work` thread:

```python
@work(thread=True)
async def _execute_recipe(self):
    async for event, step_name, result in self.runner.run_with_progress(...):
        self.call_from_thread(self._update_step, event, step_name, result)
```

Step display widget updates on each event:
- `"started"` → set step to RUNNING state (spinner indicator)
- `"completed"` → set step to DONE/FAILED, show duration

### 6.4 Stdout Panel

`RichLog` widget at the bottom. Hidden by default. `o` key toggles visibility.

When a step completes, its stdout is appended to the RichLog. For the currently running step, stdout streams line-by-line (if `run_with_progress` yields partial output — future enhancement).

For now: stdout displayed after step completion, not during.

### 6.5 Step Type Display

| Step Type | Visual |
|-----------|--------|
| Shell | `[x] step-name ... 45s DONE` or `[!] step-name ... 12s FAILED (exit 1)` |
| MCP Tool | `[?] step-name — Execute in Claude: {command}` (no auto-run) |
| Manual | `[?] step-name — {instruction}` + `[Mark Done]` button |

MCP and manual steps require user action. The screen pauses on these until the user presses Enter (MCP: acknowledges they'll run it in Claude) or clicks Mark Done (manual).

## 7. Bulk Finding Actions

### 7.1 CheckboxTable Integration

Replace the `DataTable` in `tabs/findings.py` with `CheckboxTable`. The existing `update_from_state()` method changes from `table.add_row(...)` to `table.add_checked_row(..., key=finding.id)`.

### 7.2 Bulk Action Flow

When `f` (flag FP) or `s` (cycle status) is pressed:
1. Check if any rows are checked (`table.get_checked_keys()`)
2. If checked rows exist → apply action to ALL checked findings
3. If no checked rows → apply action to the single cursor row (existing behavior)
4. Show toast: "Flagged 5 findings as false positive" or "Updated status for 3 findings"

```python
def action_flag_fp(self) -> None:
    table = self.query_one(CheckboxTable)
    checked = table.get_checked_keys()
    if checked:
        for fid in checked:
            self.state.flag_false_positive(fid)
        self.app.notify(f"Flagged {len(checked)} finding(s) as false positive")
        table.deselect_all()
    else:
        # single row action (existing behavior)
        fid = self._get_cursor_finding_id()
        if fid:
            self.state.flag_false_positive(fid)
            self.app.notify("Flagged as false positive")
    self.update_from_state()
```

### 7.3 Filter + Bulk Interaction

`Ctrl+A` selects all **visible** (filtered) rows. This enables the workflow: filter by tool → select all → bulk flag as FP.

## 8. Keybinding Map

### Global (app.py)

| Key | Action | Binding Name |
|-----|--------|-------------|
| `n` | New engagement dialog | `new_engagement` |
| `R` (Shift) | Recipe launch dialog | `run_recipe` |
| `G` (Shift) | Report generation dialog | `generate_report` |
| `I` (Shift) | Import engagement dialog | `import_engagement` |
| (existing) `q`, `Tab`, `r`, `1-4` | Quit, sidebar, refresh, tabs | unchanged |

### Sidebar

| Key | Action |
|-----|--------|
| `d` | Delete selected engagement |
| `e` | Export selected engagement |

### Findings Tab

| Key | Action |
|-----|--------|
| `a` | Add finding dialog |
| `e` | Export findings dialog |
| `Space` | Toggle checkbox on current row |
| `ctrl+a` | Select all visible findings |
| `ctrl+d` | Deselect all |
| (existing) `f`, `s`, `Enter`, `/` | Flag FP, cycle status, detail, filter |

### IOCs Tab

| Key | Action |
|-----|--------|
| `i` | Add IOC dialog |
| `e` | Export IOCs dialog |
| (existing) `/` | Filter |

## 9. State Layer Additions (`state.py`)

New methods on `DashboardState`:

```python
def create_engagement(self, name: str, target: str, eng_type: str,
                      scope: str | None = None) -> str:
    """Create engagement. Returns new ID."""

def delete_engagement(self, engagement_id: str) -> None:
    """Delete engagement and all associated data."""

def add_finding(self, engagement_id: str, tool: str, title: str,
                severity: str, cwe: str | None = None,
                file_path: str | None = None, line_start: int | None = None,
                description: str | None = None, evidence: str | None = None) -> str:
    """Add finding. Returns new ID."""

def add_ioc(self, engagement_id: str, ioc_type: str, value: str,
            context: str | None = None) -> str:
    """Add IOC. Returns new ID."""
```

## 10. Store Layer Addition (`engagement/store.py`)

New method:

```python
def delete_engagement(self, engagement_id: str) -> None:
    """Delete engagement and all associated data in a single transaction."""
    self._conn.execute("BEGIN IMMEDIATE")
    try:
        self._conn.execute("DELETE FROM audit_log WHERE engagement_id = ?", (engagement_id,))
        self._conn.execute("DELETE FROM artifacts WHERE engagement_id = ?", (engagement_id,))
        self._conn.execute("DELETE FROM iocs WHERE engagement_id = ?", (engagement_id,))
        self._conn.execute("DELETE FROM timeline_events WHERE engagement_id = ?", (engagement_id,))
        self._conn.execute("DELETE FROM findings WHERE engagement_id = ?", (engagement_id,))
        self._conn.execute("DELETE FROM engagements WHERE id = ?", (engagement_id,))
        self._conn.commit()
    except Exception:
        self._conn.rollback()
        raise
```

FK-safe deletion order: children first (audit_log, artifacts, iocs, timeline_events, findings), then parent (engagements). FTS sync triggers handle findings_fts cleanup automatically.

## 11. Recipe Runner API Addition (`recipes.py`)

New async generator method on `RecipeRunner`:

```python
async def run_with_progress(
    self,
    recipe_id: str,
    variables: dict[str, str],
    dry_run: bool = False,
) -> AsyncGenerator[tuple[str, str, StepResult | None], None]:
    """Execute recipe yielding per-step progress events.
    
    Yields: (event_type, step_name, step_result)
    - ("started", step_name, None)
    - ("completed", step_name, StepResult)
    """
```

For sequential recipes: yields events in step order.
For parallel recipes: yields events as steps complete (non-deterministic order).

## 12. Files Changed Summary

| File | Action | Description |
|------|--------|-------------|
| `dashboard/widgets/__init__.py` | Create | Package init |
| `dashboard/widgets/form_field.py` | Create | FormField reusable widget |
| `dashboard/widgets/checkbox_table.py` | Create | CheckboxTable with multi-select |
| `dashboard/dialogs/__init__.py` | Create | Package init |
| `dashboard/dialogs/engagement_create.py` | Create | Engagement creation modal |
| `dashboard/dialogs/engagement_delete.py` | Create | Deletion confirmation modal |
| `dashboard/dialogs/finding_add.py` | Create | Finding addition modal |
| `dashboard/dialogs/ioc_add.py` | Create | IOC addition modal |
| `dashboard/dialogs/export_dialog.py` | Create | Context-sensitive export modal |
| `dashboard/dialogs/report_dialog.py` | Create | Report generation modal |
| `dashboard/dialogs/import_dialog.py` | Create | Engagement import modal |
| `dashboard/dialogs/recipe_launch.py` | Create | Recipe picker + variables modal |
| `dashboard/screens/__init__.py` | Create | Package init |
| `dashboard/screens/recipe_runner.py` | Create | Full-screen recipe execution |
| `dashboard/app.py` | Modify | New keybindings (n, R, G, I) + action methods |
| `dashboard/state.py` | Modify | Add create/delete/add methods |
| `dashboard/sidebar.py` | Modify | Add d/e bindings |
| `dashboard/tabs/findings.py` | Modify | CheckboxTable, a/e bindings, bulk actions |
| `dashboard/tabs/iocs.py` | Modify | Add i/e bindings |
| `engagement/store.py` | Modify | Add delete_engagement() |
| `recipes.py` | Modify | Add run_with_progress() generator |
| `tests/test_dashboard.py` | Modify | Tests for new state methods + delete |
| `tests/test_recipes.py` | Modify | Tests for run_with_progress() |

## 13. Testing Strategy

| Area | Tests |
|------|-------|
| FormField | Required validation fails on empty, passes on filled; get_value returns input; show_error/clear_error toggle visibility |
| CheckboxTable | toggle_check flips state; select_all/deselect_all; get_checked_keys returns correct set |
| State CRUD | create_engagement returns ID, get confirms creation; delete_engagement removes all data; add_finding/add_ioc return IDs |
| Store delete | delete_engagement removes from all 6 tables; transaction rollback on failure; FTS entries cleaned up |
| Bulk actions | Flag FP on 3 checked findings → all 3 flagged; cycle status on checked findings → all updated |
| Recipe progress | run_with_progress yields started/completed for each step; sequential order; parallel unordered |
| Export dialog | Per-session memory: export once, re-open, format pre-filled |
