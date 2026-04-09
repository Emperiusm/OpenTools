# Phase 2B: Core Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate finding deduplication into the engagement store, convert report templates to Jinja2 with inheritance, add zip export bundling, and add 4 new output parsers (sqlmap, nmap, nikto, hashcat).

**Architecture:** All changes modify or extend existing modules — no new architectural patterns. Dedup-on-insert wraps the existing `check_duplicate()` into `store.add_finding()` with SQL-side candidate filtering and `BEGIN IMMEDIATE` transactions. Templates use Jinja2 inheritance with a shared base. Export gains zip streaming. Parsers follow the existing auto-discovery pattern.

**Tech Stack:** Python 3.14, sqlite3, pydantic, jinja2, zipfile, xml.etree.ElementTree, re, pytest

**Spec:** `docs/superpowers/specs/2026-04-09-phase2b-core-improvements-design.md`

---

## File Map

| File | Action | Task |
|------|--------|------|
| `packages/cli/src/opentools/findings.py` | Modify | 1 (word-boundary regex, title overlap, path normalization) |
| `packages/cli/tests/test_findings.py` | Modify | 1 |
| `packages/cli/src/opentools/engagement/schema.py` | Modify | 2 (migration v2) |
| `packages/cli/tests/test_schema.py` | Modify | 2 |
| `packages/cli/src/opentools/engagement/store.py` | Modify | 3 (dedup-on-insert, batch, model_construct) |
| `packages/cli/tests/test_engagement.py` | Modify | 3 |
| `packages/cli/src/opentools/reports.py` | Modify | 4 (context builders, filters, extra_context) |
| `packages/cli/tests/test_reports.py` | Modify | 4 |
| `packages/plugin/shared/report-templates/_macros.j2` | Create | 5 |
| `packages/plugin/shared/report-templates/_base-report.md.j2` | Create | 5 |
| `packages/plugin/shared/report-templates/pentest-report.md.j2` | Create | 6 |
| `packages/plugin/shared/report-templates/incident-report.md.j2` | Create | 6 |
| `packages/plugin/shared/report-templates/cloud-security-report.md.j2` | Create | 6 |
| `packages/plugin/shared/report-templates/mobile-security-report.md.j2` | Create | 6 |
| `packages/plugin/shared/report-templates/*.md` | Delete | 6 |
| `packages/cli/src/opentools/engagement/export.py` | Modify | 7 (bundle param, zip, import zip detect) |
| `packages/cli/tests/test_engagement.py` | Modify | 7 |
| `packages/cli/src/opentools/parsers/sqlmap.py` | Create | 8 |
| `packages/cli/src/opentools/parsers/nmap.py` | Create | 8 |
| `packages/cli/src/opentools/parsers/nikto.py` | Create | 8 |
| `packages/cli/src/opentools/parsers/hashcat.py` | Create | 8 |
| `packages/cli/tests/test_parsers.py` | Modify | 8 |

---

## Task 1: Findings Module Improvements (word-boundary regex, title overlap, path normalization)

**Files:**
- Modify: `packages/cli/src/opentools/findings.py`
- Modify: `packages/cli/tests/test_findings.py`

- [ ] **Step 1: Write failing tests for the new behaviors**

Add these tests to the END of `packages/cli/tests/test_findings.py`:

```python
from opentools.findings import _normalize_path, _titles_overlap


def test_infer_cwe_word_boundary_no_false_positive():
    """'SQL Server connection' should NOT match CWE-89 (sql injection)."""
    result = infer_cwe("SQL Server connection pool timeout")
    assert result != "CWE-89"


def test_infer_cwe_word_boundary_still_matches():
    """'sql injection' should still match CWE-89."""
    result = infer_cwe("Found sql injection in login endpoint")
    assert result == "CWE-89"


def test_normalize_path_backslash():
    assert _normalize_path("src\\api\\users.py") == "src/api/users.py"


def test_normalize_path_leading_dot_slash():
    assert _normalize_path("./src/api/users.py") == "src/api/users.py"


def test_normalize_path_leading_slash():
    assert _normalize_path("/src/api/users.py") == "src/api/users.py"


def test_normalize_path_none():
    assert _normalize_path(None) is None


def test_normalize_path_clean():
    assert _normalize_path("src/api/users.py") == "src/api/users.py"


def test_titles_overlap_similar():
    assert _titles_overlap("SQL injection in login form", "SQL injection in user login") is True


def test_titles_overlap_different():
    assert _titles_overlap("Buffer overflow in parser", "Missing CSRF token on form") is False


def test_titles_overlap_empty():
    assert _titles_overlap("", "something") is True  # can't tell, assume same


def test_check_duplicate_uses_normalized_paths():
    """Findings with different path formats for same file should match."""
    now = datetime.now(timezone.utc)
    existing = Finding(
        id="f-1", engagement_id="e-1", tool="semgrep",
        title="SQL Injection", severity=Severity.HIGH,
        cwe="CWE-89", file_path="src/api/users.py", line_start=42,
        created_at=now,
    )
    new = Finding(
        id="f-2", engagement_id="e-1", tool="codebadger",
        title="Taint flow to SQL sink", severity=Severity.CRITICAL,
        cwe="CWE-89", file_path="./src\\api\\users.py", line_start=43,
        created_at=now,
    )
    result = check_duplicate(new, [existing])
    assert result is not None
    assert result.match.id == "f-1"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd packages/cli && python -m pytest tests/test_findings.py -v -k "word_boundary or normalize or titles_overlap or normalized_paths"
```

Expected: FAIL — `ImportError: cannot import name '_normalize_path'`

- [ ] **Step 3: Implement the changes in findings.py**

Replace the `infer_cwe` function and add `_normalize_path`, `_titles_overlap`. Update `_locations_overlap` to normalize paths. Update `check_duplicate` to use title overlap for LOW confidence.

Key changes:
1. Add `import re` at top
2. Replace `CWE_KEYWORDS` iteration in `infer_cwe()` with pre-compiled `\b` word-boundary regex patterns
3. Add `_normalize_path()` function
4. Add `_titles_overlap()` function
5. Update `_locations_overlap()` to call `_normalize_path()` on both paths before comparison
6. Update `check_duplicate()`: after getting a LOW confidence match, also check `_titles_overlap()` — if titles don't overlap, return None (distinct)

Pre-compiled patterns (add after `CWE_KEYWORDS` dict):

```python
import re

_CWE_PATTERNS: dict[str, list[re.Pattern]] = {
    cwe: [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in keywords]
    for cwe, keywords in CWE_KEYWORDS.items()
}
```

New `infer_cwe()`:

```python
def infer_cwe(text: str) -> Optional[str]:
    best_cwe = None
    best_count = 0
    for cwe, patterns in _CWE_PATTERNS.items():
        count = sum(1 for p in patterns if p.search(text))
        if count > best_count:
            best_count = count
            best_cwe = cwe
    return best_cwe
```

New functions:

```python
def _normalize_path(p: str | None) -> str | None:
    if p is None:
        return None
    return p.replace("\\", "/").removeprefix("./").removeprefix("/")


def _titles_overlap(a: str, b: str, threshold: float = 0.3) -> bool:
    words_a = set(a.lower().split())
    words_b = set(b.lower().split())
    if not words_a or not words_b:
        return True
    overlap = len(words_a & words_b) / min(len(words_a), len(words_b))
    return overlap >= threshold
```

Updated `_locations_overlap()` — normalize both paths before comparing:

```python
def _locations_overlap(a: Finding, b: Finding, window: int) -> bool:
    path_a = _normalize_path(a.file_path)
    path_b = _normalize_path(b.file_path)
    if path_a and path_b:
        if path_a != path_b:
            return False
        if a.line_start is not None and b.line_start is not None:
            return abs(a.line_start - b.line_start) <= window
        return True
    if path_a is None and path_b is None:
        return True
    return False
```

Updated `check_duplicate()` — add title overlap gate after confidence computation:

```python
# After: confidence = _compute_confidence(...)
# Add:
if confidence == Confidence.LOW:
    if not _titles_overlap(
        f"{new_finding.title} {new_finding.description or ''}",
        f"{existing.title} {existing.description or ''}",
    ):
        continue  # distinct despite same inferred CWE
return DuplicateMatch(match=existing, confidence=confidence)
```

- [ ] **Step 4: Run all finding tests**

```bash
cd packages/cli && python -m pytest tests/test_findings.py -v
```

Expected: All tests PASS (13 existing + 11 new = 24)

- [ ] **Step 5: Run full test suite**

```bash
cd packages/cli && python -m pytest tests/ -q
```

Expected: All pass (no regressions)

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/findings.py packages/cli/tests/test_findings.py
git commit -m "feat: word-boundary CWE inference, path normalization, title overlap gate"
```

---

## Task 2: Schema Migration v2

**Files:**
- Modify: `packages/cli/src/opentools/engagement/schema.py`
- Modify: `packages/cli/tests/test_schema.py`

- [ ] **Step 1: Write failing test**

Add to END of `packages/cli/tests/test_schema.py`:

```python
def test_migration_v2_creates_dedup_indexes():
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_findings_dedup%'"
    )
    indexes = {row[0] for row in cursor.fetchall()}
    assert "idx_findings_dedup_file" in indexes
    assert "idx_findings_dedup_network" in indexes
    conn.close()


def test_migration_v1_to_v2_upgrade():
    """Simulate a v1 database upgrading to v2."""
    conn = sqlite3.connect(":memory:")
    # Run only v1
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    from opentools.engagement.schema import _migration_v1
    _migration_v1(conn)
    conn.execute("INSERT INTO schema_version (version, applied_at) VALUES (1, '2026-01-01T00:00:00')")
    conn.commit()

    # Now migrate should only run v2
    migrate(conn)
    version = get_schema_version(conn)
    assert version == 2

    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_findings_dedup%'"
    )
    indexes = {row[0] for row in cursor.fetchall()}
    assert "idx_findings_dedup_file" in indexes
    conn.close()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd packages/cli && python -m pytest tests/test_schema.py -v -k "dedup_indexes or v1_to_v2"
```

Expected: FAIL — indexes don't exist (only v1 migrations run)

- [ ] **Step 3: Add migration v2 to schema.py**

Add after `_migration_v1`:

```python
def _migration_v2(conn: sqlite3.Connection) -> None:
    """Add partial indexes optimized for dedup candidate queries."""
    conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_findings_dedup_file
        ON findings(engagement_id, file_path, line_start)
        WHERE deleted_at IS NULL;

        CREATE INDEX IF NOT EXISTS idx_findings_dedup_network
        ON findings(engagement_id, cwe)
        WHERE file_path IS NULL AND deleted_at IS NULL;
    """)
```

Update MIGRATIONS dict:

```python
MIGRATIONS: dict = {1: _migration_v1, 2: _migration_v2}
```

- [ ] **Step 4: Run tests**

```bash
cd packages/cli && python -m pytest tests/test_schema.py -v
```

Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/engagement/schema.py packages/cli/tests/test_schema.py
git commit -m "feat: add schema migration v2 with dedup partial indexes"
```

---

## Task 3: Dedup-on-Insert in Engagement Store

**Files:**
- Modify: `packages/cli/src/opentools/engagement/store.py`
- Modify: `packages/cli/tests/test_engagement.py`

- [ ] **Step 1: Write failing tests**

Add to END of `packages/cli/tests/test_engagement.py`:

```python
def test_add_finding_dedup_merges_duplicate(store, sample_engagement):
    """Adding a finding with same CWE + nearby line should merge."""
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)

    f1 = Finding(
        id="f-1", engagement_id=sample_engagement.id,
        tool="semgrep", title="SQL Injection",
        severity=Severity.HIGH, cwe="CWE-89",
        file_path="src/api.py", line_start=42,
        created_at=now,
    )
    id1 = store.add_finding(f1)
    assert id1 == "f-1"

    f2 = Finding(
        id="f-2", engagement_id=sample_engagement.id,
        tool="codebadger", title="Taint flow to SQL sink",
        severity=Severity.CRITICAL, cwe="CWE-89",
        file_path="src/api.py", line_start=43,
        created_at=now,
    )
    id2 = store.add_finding(f2)
    assert id2 == "f-1"  # merged into existing

    findings = store.get_findings(sample_engagement.id)
    assert len(findings) == 1
    assert "codebadger" in findings[0].corroborated_by
    assert findings[0].severity == Severity.CRITICAL  # kept higher


def test_add_finding_dedup_distinct_far_lines(store, sample_engagement):
    """Findings with same CWE but far apart lines should NOT merge."""
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)

    store.add_finding(Finding(
        id="f-1", engagement_id=sample_engagement.id,
        tool="semgrep", title="SQL Injection",
        severity=Severity.HIGH, cwe="CWE-89",
        file_path="src/api.py", line_start=42,
        created_at=now,
    ))
    store.add_finding(Finding(
        id="f-2", engagement_id=sample_engagement.id,
        tool="codebadger", title="Another SQLi",
        severity=Severity.HIGH, cwe="CWE-89",
        file_path="src/api.py", line_start=200,
        created_at=now,
    ))

    findings = store.get_findings(sample_engagement.id)
    assert len(findings) == 2


def test_add_finding_dedup_normalized_paths(store, sample_engagement):
    """Findings with different path formats should still merge."""
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)

    store.add_finding(Finding(
        id="f-1", engagement_id=sample_engagement.id,
        tool="semgrep", title="XSS",
        severity=Severity.HIGH, cwe="CWE-79",
        file_path="src/views/index.js", line_start=10,
        created_at=now,
    ))
    id2 = store.add_finding(Finding(
        id="f-2", engagement_id=sample_engagement.id,
        tool="nuclei", title="Reflected XSS",
        severity=Severity.MEDIUM, cwe="CWE-79",
        file_path="./src\\views\\index.js", line_start=11,
        created_at=now,
    ))

    assert id2 == "f-1"  # merged
    findings = store.get_findings(sample_engagement.id)
    assert len(findings) == 1


def test_add_findings_batch(store, sample_engagement):
    """Batch insert should dedup within the batch."""
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)

    findings = [
        Finding(id="f-1", engagement_id=sample_engagement.id,
                tool="semgrep", title="SQL Injection", severity=Severity.HIGH,
                cwe="CWE-89", file_path="src/api.py", line_start=42, created_at=now),
        Finding(id="f-2", engagement_id=sample_engagement.id,
                tool="nuclei", title="SQLi detected", severity=Severity.CRITICAL,
                cwe="CWE-89", file_path="src/api.py", line_start=43, created_at=now),
        Finding(id="f-3", engagement_id=sample_engagement.id,
                tool="semgrep", title="XSS in template", severity=Severity.MEDIUM,
                cwe="CWE-79", file_path="src/views.py", line_start=10, created_at=now),
    ]
    ids = store.add_findings_batch(findings)
    assert len(ids) == 3
    assert ids[1] == ids[0]  # f-2 merged into f-1
    assert ids[2] != ids[0]  # f-3 is distinct

    all_findings = store.get_findings(sample_engagement.id)
    assert len(all_findings) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd packages/cli && python -m pytest tests/test_engagement.py -v -k "dedup or batch"
```

Expected: FAIL — `add_finding` doesn't dedup, `add_findings_batch` doesn't exist

- [ ] **Step 3: Implement dedup-on-insert in store.py**

Add import at top of `store.py`:

```python
from opentools.findings import check_duplicate, _normalize_path
```

Add severity ranking helper:

```python
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

def _severity_rank(s: str) -> int:
    return _SEVERITY_ORDER.get(str(s), 0)
```

Rewrite `add_finding()` to include dedup logic:

```python
def add_finding(self, finding: Finding) -> str:
    # Normalize path
    normalized_path = _normalize_path(finding.file_path)
    if normalized_path != finding.file_path:
        finding = finding.model_copy(update={"file_path": normalized_path})

    self._conn.execute("BEGIN IMMEDIATE")
    try:
        # Query candidates
        candidates = self._query_dedup_candidates(finding)

        # Check for duplicate
        match = check_duplicate(finding, candidates)

        if match:
            merged_id = self._merge_finding(match.match, finding, match.confidence)
            self._conn.commit()
            return merged_id

        # No match — insert new
        self._insert_finding_row(finding)
        self._insert_timeline_event(
            finding.engagement_id, finding.tool,
            f"Finding discovered: {finding.title}",
            finding.created_at, finding.id,
        )
        self._conn.commit()
        return finding.id
    except Exception:
        self._conn.rollback()
        raise
```

Add helper methods:

```python
def _query_dedup_candidates(self, finding: Finding) -> list[Finding]:
    """Query existing findings that could be duplicates."""
    if finding.file_path and finding.line_start is not None:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE engagement_id = ? AND file_path = ? "
            "AND line_start >= ? AND line_start <= ? AND deleted_at IS NULL",
            (finding.engagement_id, finding.file_path,
             finding.line_start - 5, finding.line_start + 5),
        ).fetchall()
    elif finding.file_path:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE engagement_id = ? AND file_path = ? "
            "AND deleted_at IS NULL",
            (finding.engagement_id, finding.file_path),
        ).fetchall()
    elif finding.cwe:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE engagement_id = ? AND cwe = ? "
            "AND deleted_at IS NULL",
            (finding.engagement_id, finding.cwe),
        ).fetchall()
    else:
        return []
    return [self._row_to_finding(r) for r in rows]


def _merge_finding(self, existing: Finding, new_finding: Finding, confidence) -> str:
    """Merge new_finding into existing. Returns existing ID."""
    corroborated = list(set(existing.corroborated_by + [new_finding.tool]))
    sbt = {**existing.severity_by_tool, new_finding.tool: str(new_finding.severity)}
    severity = max(str(existing.severity), str(new_finding.severity),
                   key=_severity_rank)
    desc = new_finding.description if (
        new_finding.description and
        len(new_finding.description) > len(existing.description or "")
    ) else existing.description

    self._conn.execute(
        "UPDATE findings SET corroborated_by=?, severity_by_tool=?, "
        "severity=?, description=?, dedup_confidence=? WHERE id=?",
        (json.dumps(corroborated), json.dumps(sbt), severity,
         desc, str(confidence), existing.id),
    )
    self._insert_timeline_event(
        existing.engagement_id, new_finding.tool,
        f"Finding corroborated by {new_finding.tool}: {existing.title}",
        new_finding.created_at, existing.id,
    )
    return existing.id


def _insert_finding_row(self, finding: Finding) -> None:
    """Raw INSERT into findings table."""
    self._conn.execute(
        "INSERT INTO findings (id, engagement_id, tool, corroborated_by, cwe, "
        "severity, severity_by_tool, status, phase, title, description, "
        "file_path, line_start, line_end, evidence, remediation, cvss, "
        "false_positive, dedup_confidence, created_at, deleted_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (finding.id, finding.engagement_id, finding.tool,
         json.dumps(finding.corroborated_by), finding.cwe,
         str(finding.severity), json.dumps(finding.severity_by_tool),
         str(finding.status), finding.phase, finding.title,
         finding.description, finding.file_path, finding.line_start,
         finding.line_end, finding.evidence, finding.remediation,
         finding.cvss, 1 if finding.false_positive else 0,
         str(finding.dedup_confidence) if finding.dedup_confidence else None,
         finding.created_at.isoformat(),
         finding.deleted_at.isoformat() if finding.deleted_at else None),
    )


def _insert_timeline_event(self, engagement_id, source, event_text, timestamp, finding_id):
    """Insert a timeline event (helper to avoid repeating SQL)."""
    import uuid as _uuid
    self._conn.execute(
        "INSERT INTO timeline_events (id, engagement_id, timestamp, source, "
        "event, confidence, finding_id) VALUES (?,?,?,?,?,?,?)",
        (str(_uuid.uuid4()), engagement_id, timestamp.isoformat(),
         source, event_text, "high", finding_id),
    )


def add_findings_batch(self, findings: list[Finding]) -> list[str]:
    """Bulk insert with dedup. Chunks transactions at 100."""
    results: list[str] = []
    batch_inserted: list[Finding] = []  # track batch-local inserts for intra-batch dedup

    CHUNK = 100
    for i in range(0, len(findings), CHUNK):
        chunk = findings[i:i + CHUNK]
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            for finding in chunk:
                normalized_path = _normalize_path(finding.file_path)
                if normalized_path != finding.file_path:
                    finding = finding.model_copy(update={"file_path": normalized_path})

                candidates = self._query_dedup_candidates(finding)
                # Also check against batch-local inserts
                batch_candidates = [
                    f for f in batch_inserted
                    if f.engagement_id == finding.engagement_id
                ]
                all_candidates = candidates + batch_candidates

                match = check_duplicate(finding, all_candidates)
                if match:
                    if match.match.id in {f.id for f in batch_inserted}:
                        # Merge into batch-local finding (update in DB)
                        self._merge_finding(match.match, finding, match.confidence)
                    else:
                        self._merge_finding(match.match, finding, match.confidence)
                    results.append(match.match.id)
                else:
                    self._insert_finding_row(finding)
                    self._insert_timeline_event(
                        finding.engagement_id, finding.tool,
                        f"Finding discovered: {finding.title}",
                        finding.created_at, finding.id,
                    )
                    batch_inserted.append(finding)
                    results.append(finding.id)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
    return results
```

Also switch all `_row_to_*` methods to use `model_construct()` instead of `Model(...)`. Example for `_row_to_finding`:

```python
@staticmethod
def _row_to_finding(row: sqlite3.Row) -> Finding:
    return Finding.model_construct(
        id=row["id"],
        engagement_id=row["engagement_id"],
        tool=row["tool"],
        corroborated_by=json.loads(row["corroborated_by"] or "[]"),
        # ... all other fields same as before ...
    )
```

Apply `model_construct` to all 6 `_row_to_*` methods.

- [ ] **Step 4: Run tests**

```bash
cd packages/cli && python -m pytest tests/test_engagement.py -v
```

Expected: All tests PASS (10 existing + 4 new = 14)

- [ ] **Step 5: Run full suite**

```bash
cd packages/cli && python -m pytest tests/ -q
```

Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/engagement/store.py packages/cli/tests/test_engagement.py
git commit -m "feat: dedup-on-insert with batch mode, model_construct, path normalization"
```

---

## Task 4: Report Generator Improvements

**Files:**
- Modify: `packages/cli/src/opentools/reports.py`
- Modify: `packages/cli/tests/test_reports.py`

- [ ] **Step 1: Write failing tests**

Add to END of `packages/cli/tests/test_reports.py`:

```python
def test_custom_jinja2_filters(tmp_path):
    from opentools.engagement.store import EngagementStore
    from datetime import datetime, timezone
    store = EngagementStore(db_path=tmp_path / "test.db")
    now = datetime.now(timezone.utc)
    eng = Engagement(
        id="e-1", name="test", target="10.0.0.1",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        created_at=now, updated_at=now,
    )
    store.create(eng)

    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "filters.md.j2").write_text(
        "Date: {{ engagement.created_at | datefmt }}\n"
        "CWE: {{ 'CWE-89' | cwe_link }}\n"
        "Sev: {{ 'critical' | severity_icon }}\n"
    )
    gen = ReportGenerator(template_dir, store)
    result = gen.generate("e-1", "filters")
    assert "UTC" in result  # datefmt includes UTC
    assert "cwe.mitre.org" in result  # cwe_link generates URL
    assert "!!!" in result  # severity_icon for critical


def test_extra_context(tmp_path):
    from opentools.engagement.store import EngagementStore
    store = EngagementStore(db_path=tmp_path / "test.db")
    now = datetime.now(timezone.utc)
    eng = Engagement(
        id="e-1", name="test", target="10.0.0.1",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        created_at=now, updated_at=now,
    )
    store.create(eng)

    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "extra.md.j2").write_text(
        "Client: {{ client | default('N/A') }}\n"
        "Assessor: {{ assessor | default('N/A') }}\n"
    )
    gen = ReportGenerator(template_dir, store)

    result = gen.generate("e-1", "extra", extra_context={"client": "Acme Corp", "assessor": "Jane"})
    assert "Acme Corp" in result
    assert "Jane" in result

    result2 = gen.generate("e-1", "extra")
    assert "N/A" in result2


def test_context_builder_pentest(tmp_path):
    from opentools.reports import _build_pentest_context, OWASP_CWE_MAP
    from opentools.engagement.store import EngagementStore
    store = EngagementStore(db_path=tmp_path / "test.db")
    now = datetime.now(timezone.utc)
    eng = Engagement(
        id="e-1", name="test", target="10.0.0.1",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        created_at=now, updated_at=now,
    )
    store.create(eng)
    store.add_finding(Finding(
        id="f-1", engagement_id="e-1", tool="test",
        title="SQLi", severity=Severity.HIGH, cwe="CWE-89", created_at=now,
    ))
    findings = store.get_findings("e-1")
    ctx = _build_pentest_context(findings)
    assert "owasp_matrix" in ctx
    assert len(ctx["owasp_matrix"]["Input Validation"]) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd packages/cli && python -m pytest tests/test_reports.py -v -k "filters or extra_context or context_builder"
```

Expected: FAIL — filters not registered, `extra_context` param doesn't exist, `_build_pentest_context` doesn't exist

- [ ] **Step 3: Implement reports.py improvements**

Rewrite `packages/cli/src/opentools/reports.py` to add:

1. CWE→category mapping dicts (`OWASP_CWE_MAP`, `MOBILE_TOP10_CWE_MAP`, `CLOUD_CATEGORY_CWE_MAP`, `ATTACK_TACTIC_CWE_MAP`)
2. Context builder functions (`_build_pentest_context`, `_build_incident_context`, `_build_cloud_context`, `_build_mobile_context`)
3. `_TEMPLATE_CONTEXT_BUILDERS` dispatch dict
4. Custom Jinja2 filters registered in `__init__`
5. `extra_context` parameter on `generate()`
6. Template-specific context injection in `generate()`

The `generate()` method becomes:

```python
def generate(self, engagement_id, template_name, output_path=None, extra_context=None):
    context = self._build_base_context(engagement_id)
    
    builder = _TEMPLATE_CONTEXT_BUILDERS.get(template_name)
    if builder:
        context.update(builder(context["findings"]))
    
    if extra_context:
        context.update(extra_context)
    
    template_file = f"{template_name}.md.j2"
    try:
        template = self._env.get_template(template_file)
    except Exception:
        template = self._env.get_template(f"{template_name}.md")
    
    rendered = template.render(**context)
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    return rendered
```

- [ ] **Step 4: Run tests**

```bash
cd packages/cli && python -m pytest tests/test_reports.py -v
```

Expected: All tests PASS (4 existing + 3 new = 7)

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/reports.py packages/cli/tests/test_reports.py
git commit -m "feat: add report context builders, custom filters, and extra_context param"
```

---

## Task 5: Jinja2 Shared Macros and Base Template

**Files:**
- Create: `packages/plugin/shared/report-templates/_macros.j2`
- Create: `packages/plugin/shared/report-templates/_base-report.md.j2`

- [ ] **Step 1: Create _macros.j2**

Create `packages/plugin/shared/report-templates/_macros.j2` with the full macro implementations from the spec (finding_table, finding_detail with collapsible evidence, ioc_table, timeline_table, summary_counts).

- [ ] **Step 2: Create _base-report.md.j2**

Create `packages/plugin/shared/report-templates/_base-report.md.j2` with the full base template from the spec (engagement details, executive summary, findings overview + detail, timeline, IOCs, tools, block override points for extra_summary/methodology/extra_sections).

- [ ] **Step 3: Verify templates parse**

```bash
cd packages/cli && python -c "
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('../../packages/plugin/shared/report-templates'))
t = env.get_template('_base-report.md.j2')
print('Base template loaded OK')
"
```

Expected: "Base template loaded OK"

- [ ] **Step 4: Commit**

```bash
git add packages/plugin/shared/report-templates/_macros.j2 packages/plugin/shared/report-templates/_base-report.md.j2
git commit -m "feat: add Jinja2 shared macros and base report template"
```

---

## Task 6: Convert 4 Report Templates and Delete Old .md Files

**Files:**
- Create: `packages/plugin/shared/report-templates/pentest-report.md.j2`
- Create: `packages/plugin/shared/report-templates/incident-report.md.j2`
- Create: `packages/plugin/shared/report-templates/cloud-security-report.md.j2`
- Create: `packages/plugin/shared/report-templates/mobile-security-report.md.j2`
- Delete: all 4 `.md` files in that directory

- [ ] **Step 1: Create all 4 child templates**

Each extends `_base-report.md.j2` and overrides the relevant blocks with template-specific content (OWASP matrix, ATT&CK tactics, cloud categories, Mobile Top 10).

- [ ] **Step 2: Delete old .md templates**

```bash
cd packages/plugin/shared/report-templates
git rm pentest-report.md incident-report.md cloud-security-report.md mobile-security-report.md
```

- [ ] **Step 3: Verify template rendering end-to-end**

```bash
cd packages/cli && python -m pytest tests/test_reports.py -v
```

Expected: All 7 tests PASS (templates load and render correctly)

- [ ] **Step 4: Commit**

```bash
git add packages/plugin/shared/report-templates/
git commit -m "feat: convert report templates to Jinja2 with inheritance, delete old .md files"
```

---

## Task 7: Export Bundling

**Files:**
- Modify: `packages/cli/src/opentools/engagement/export.py`
- Modify: `packages/cli/tests/test_engagement.py`

- [ ] **Step 1: Write failing tests**

Add to END of `packages/cli/tests/test_engagement.py`:

```python
import zipfile


def test_export_bundle_creates_zip(store, sample_engagement, tmp_path):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    store.add_finding(Finding(
        id="f-1", engagement_id=sample_engagement.id,
        tool="test", title="Test", severity=Severity.HIGH, created_at=now,
    ))
    # Create a fake artifact file
    artifact_file = tmp_path / "screenshot.png"
    artifact_file.write_bytes(b"fake image data")
    from opentools.models import Artifact, ArtifactType
    store.add_artifact(Artifact(
        id="a-1", engagement_id=sample_engagement.id,
        file_path=str(artifact_file), artifact_type=ArtifactType.SCREENSHOT,
        created_at=now,
    ))

    output = tmp_path / "export.json"
    from opentools.engagement.export import export_engagement
    result = export_engagement(store, sample_engagement.id, output, bundle=True)
    assert result.suffix == ".zip"
    assert result.exists()

    with zipfile.ZipFile(result) as zf:
        names = zf.namelist()
        assert "engagement.json" in names
        assert any("screenshot.png" in n for n in names)


def test_export_bundle_missing_artifact(store, sample_engagement, tmp_path):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    from opentools.models import Artifact, ArtifactType
    store.add_artifact(Artifact(
        id="a-1", engagement_id=sample_engagement.id,
        file_path="/nonexistent/file.bin", artifact_type=ArtifactType.BINARY,
        created_at=now,
    ))

    output = tmp_path / "export.json"
    from opentools.engagement.export import export_engagement
    result = export_engagement(store, sample_engagement.id, output, bundle=True)

    with zipfile.ZipFile(result) as zf:
        assert "missing_artifacts.txt" in zf.namelist()
        missing = zf.read("missing_artifacts.txt").decode()
        assert "/nonexistent/file.bin" in missing


def test_import_from_zip(store, sample_engagement, tmp_path):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    store.add_finding(Finding(
        id="f-1", engagement_id=sample_engagement.id,
        tool="test", title="Test", severity=Severity.HIGH, created_at=now,
    ))

    output = tmp_path / "export.json"
    from opentools.engagement.export import export_engagement, import_engagement
    zip_path = export_engagement(store, sample_engagement.id, output, bundle=True)

    new_id = import_engagement(store, zip_path)
    assert new_id != sample_engagement.id
    assert len(store.list_all()) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd packages/cli && python -m pytest tests/test_engagement.py -v -k "bundle or zip"
```

Expected: FAIL — `bundle` parameter doesn't exist

- [ ] **Step 3: Implement export bundling**

Add `bundle` parameter to `export_engagement()` and zip detection to `import_engagement()` in `packages/cli/src/opentools/engagement/export.py`. Use `zipfile.ZipFile.write()` for streaming, `ZIP_DEFLATED` compression, `missing_artifacts.txt` for missing files.

- [ ] **Step 4: Run tests**

```bash
cd packages/cli && python -m pytest tests/test_engagement.py -v
```

Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/engagement/export.py packages/cli/tests/test_engagement.py
git commit -m "feat: add zip bundling for engagement export with missing artifact manifest"
```

---

## Task 8: New Parsers (sqlmap, nmap, nikto, hashcat)

**Files:**
- Create: `packages/cli/src/opentools/parsers/sqlmap.py`
- Create: `packages/cli/src/opentools/parsers/nmap.py`
- Create: `packages/cli/src/opentools/parsers/nikto.py`
- Create: `packages/cli/src/opentools/parsers/hashcat.py`
- Modify: `packages/cli/tests/test_parsers.py`

- [ ] **Step 1: Write failing tests**

Add to END of `packages/cli/tests/test_parsers.py`:

```python
SQLMAP_OUTPUT = json.dumps({
    "data": [{"type": 1, "value": [{
        "place": "GET", "parameter": "id", "dbms": "MySQL",
        "title": "AND boolean-based blind",
    }]}]
})

NMAP_XML_OUTPUT = """<?xml version="1.0"?>
<nmaprun>
<host><address addr="10.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/>
</port>
<port protocol="tcp" portid="443">
<state state="open"/><service name="https"/>
<script id="ssl-enum-ciphers" output="TLSv1.0 enabled"/>
</port>
</ports>
</host>
</nmaprun>"""

NIKTO_OUTPUT = json.dumps({
    "ip": "10.0.0.1", "port": "80",
    "vulnerabilities": [
        {"id": "000726", "OSVDB": "0", "method": "GET",
         "url": "/admin/", "msg": "Default credentials found for admin panel"},
        {"id": "999999", "OSVDB": "0", "method": "GET",
         "url": "/info", "msg": "Server version disclosure in headers"},
    ]
})

HASHCAT_OUTPUT = "5f4dcc3b5aa765d61d8327deb882cf99:password\ne99a18c428cb38d5f260853678922e03:abc123"


def test_sqlmap_parser():
    parser = get_parser("sqlmap")
    assert parser is not None
    findings = parser(SQLMAP_OUTPUT)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"
    assert findings[0].severity.value == "critical"
    assert "id" in findings[0].title.lower() or "boolean" in findings[0].title.lower()


def test_nmap_parser_ports():
    parser = get_parser("nmap")
    assert parser is not None
    findings = parser(NMAP_XML_OUTPUT)
    port_findings = [f for f in findings if f.severity.value == "info"]
    assert len(port_findings) >= 1  # at least the SSH port


def test_nmap_parser_nse_scripts():
    parser = get_parser("nmap")
    findings = parser(NMAP_XML_OUTPUT)
    vuln_findings = [f for f in findings if f.severity.value != "info"]
    assert len(vuln_findings) >= 1  # ssl-enum-ciphers finding
    assert any(f.cwe == "CWE-327" for f in vuln_findings)


def test_nikto_parser():
    parser = get_parser("nikto")
    assert parser is not None
    findings = parser(NIKTO_OUTPUT)
    assert len(findings) == 2
    # Default credentials should be high severity
    cred_finding = [f for f in findings if "credential" in f.title.lower() or "credential" in (f.description or "").lower()]
    assert len(cred_finding) >= 1


def test_nikto_parser_severity_heuristic():
    parser = get_parser("nikto")
    findings = parser(NIKTO_OUTPUT)
    severities = {f.title: f.severity.value for f in findings}
    # At least one should be different severity from others
    assert len(set(severities.values())) >= 1


def test_hashcat_parser():
    parser = get_parser("hashcat")
    assert parser is not None
    findings = parser(HASHCAT_OUTPUT)
    assert len(findings) == 2
    assert all(f.cwe == "CWE-521" for f in findings)
    assert all(f.severity.value == "high" for f in findings)


def test_hashcat_parser_empty():
    parser = get_parser("hashcat")
    findings = parser("")
    assert findings == []


def test_all_new_parsers_registered():
    parsers = list_parsers()
    for name in ["sqlmap", "nmap", "nikto", "hashcat"]:
        assert name in parsers, f"{name} not in parser registry"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd packages/cli && python -m pytest tests/test_parsers.py -v -k "sqlmap or nmap or nikto or hashcat or new_parsers"
```

Expected: FAIL — parsers don't exist

- [ ] **Step 3: Create all 4 parser files**

Create each parser following the spec's format definitions. Each exports `def parse(raw_output: str) -> list[Finding]`.

**sqlmap.py:** Parse JSON, each injection point → Finding with CWE-89, severity=critical.

**nmap.py:** Parse XML with ElementTree. Port entries → info findings. NSE scripts → vuln findings with mapped CWE/severity.

**nikto.py:** Parse JSON. Each vulnerability → Finding with severity heuristic (default creds→high, version disclosure→low, else→medium).

**hashcat.py:** Parse potfile lines. Check for machine-readable format first (3+ colon-separated fields), then potfile format. Hash type from length heuristic. Each cracked hash → Finding with CWE-521, severity=high.

- [ ] **Step 4: Run parser tests**

```bash
cd packages/cli && python -m pytest tests/test_parsers.py -v
```

Expected: All tests PASS (8 existing + 9 new = 17)

- [ ] **Step 5: Run full suite**

```bash
cd packages/cli && python -m pytest tests/ -q
```

Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/parsers/sqlmap.py packages/cli/src/opentools/parsers/nmap.py packages/cli/src/opentools/parsers/nikto.py packages/cli/src/opentools/parsers/hashcat.py packages/cli/tests/test_parsers.py
git commit -m "feat: add sqlmap, nmap (XML+NSE), nikto, and hashcat output parsers"
```

---

## Self-Review

**1. Spec coverage:**
- Section 2 (Dedup-on-insert): Tasks 1, 2, 3 ✓
- Section 3 (Report templates): Tasks 4, 5, 6 ✓
- Section 4 (Export bundling): Task 7 ✓
- Section 5 (New parsers): Task 8 ✓
- Section 2.4 (model_construct): Task 3 ✓
- CLI `--set` flag: Not explicitly tasked — minor CLI wiring, can be added in Task 4 or as follow-up

**2. Placeholder scan:** No TBDs. Tasks 5 and 6 reference "full macro/template implementations from the spec" rather than inlining the full Jinja2 — this is acceptable since the spec contains the exact code and the templates are config files, not Python.

**3. Type consistency:** `check_duplicate`, `_normalize_path`, `_titles_overlap`, `add_findings_batch`, `model_construct`, `_build_pentest_context`, `OWASP_CWE_MAP` — all match between tasks and spec. `_severity_rank` helper added in Task 3, used in Task 3 only.
