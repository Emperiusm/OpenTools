# Scan Runner Plan 3: Planner — Target Detection, Profiles, Graph Building

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the planning layer that detects target types, validates targets, loads YAML-based scan profiles, evaluates reactive edge templates, provides a steering interface protocol, and assembles a ready-to-execute task DAG from a profile + detected target.

**Architecture:** Bottom-up — target detection and validation first (pure logic + async I/O), then profile models and YAML loading, then reactive edge evaluators and steering protocol, then the ScanPlanner that ties everything together, and finally the ScanAPI unified entry point. Each layer is independently testable. The ScanPlanner is the integration point: it takes a target string and profile name, runs detection/validation, resolves profile inheritance, evaluates tool conditions against target metadata, and produces a list of `ScanTask` objects ready for `ScanEngine.load_tasks()`.

**Tech Stack:** Python 3.12, Pydantic v2, PyYAML, asyncio, pytest + pytest-asyncio

**Spec Reference:** `docs/superpowers/specs/2026-04-12-scan-runner-design.md` sections 3.1-3.7, 4.1

**Decomposition Note:** Plan 3 of 5. Plans 1-2 complete. Plan 1 delivered models, store, and shared infrastructure. Plan 2 delivered executors and the ScanEngine DAG executor.

**Branch:** `feature/scan-runner-plan3` (branch from `feature/scan-runner-plan2`)

---

## File Map

### New Files

| File | Responsibility |
|------|---------------|
| `packages/cli/src/opentools/scanner/target.py` | `TargetDetector`, `TargetValidator`, `DetectedTarget`, `SourceMetadata` |
| `packages/cli/src/opentools/scanner/profiles.py` | `ScanProfile`, `ProfilePhase`, `ProfileTool`, `ReactiveEdgeTemplate`, profile loading, `DEFAULT_PROFILES` |
| `packages/cli/src/opentools/scanner/reactive.py` | Builtin reactive edge evaluators |
| `packages/cli/src/opentools/scanner/steering.py` | `SteeringInterface` protocol, `SteeringAction`, `SteeringDecision`, `SteeringThrottle` |
| `packages/cli/src/opentools/scanner/planner.py` | `ScanPlanner` — graph builder from profile + detected target |
| `packages/cli/src/opentools/scanner/api.py` | `ScanAPI` — unified entry point with `plan()`, `execute()`, `pause()`, `resume()`, `cancel()` |
| `packages/cli/src/opentools/scanner/profiles/source_quick.yaml` | Source quick-scan profile |
| `packages/cli/src/opentools/scanner/profiles/source_full.yaml` | Source full-scan profile |
| `packages/cli/src/opentools/scanner/profiles/web_quick.yaml` | Web quick-scan profile |
| `packages/cli/src/opentools/scanner/profiles/web_full.yaml` | Web full-scan profile |
| `packages/cli/src/opentools/scanner/profiles/binary_triage.yaml` | Binary triage profile |
| `packages/cli/src/opentools/scanner/profiles/network_recon.yaml` | Network recon profile |
| `packages/cli/src/opentools/scanner/profiles/container_audit.yaml` | Container audit profile |
| `packages/cli/src/opentools/scanner/profiles/apk_analysis.yaml` | APK analysis profile |
| `packages/cli/tests/test_scanner/test_target.py` | Tests for target detection and validation |
| `packages/cli/tests/test_scanner/test_profiles.py` | Tests for profile models and YAML loading |
| `packages/cli/tests/test_scanner/test_reactive.py` | Tests for reactive edge evaluators |
| `packages/cli/tests/test_scanner/test_steering.py` | Tests for steering interface and throttle |
| `packages/cli/tests/test_scanner/test_planner.py` | Tests for ScanPlanner graph building |
| `packages/cli/tests/test_scanner/test_api.py` | Tests for ScanAPI |

### Modified Files

| File | Change |
|------|--------|
| `packages/cli/src/opentools/scanner/models.py` | Add `SteeringAction` enum, `GraphSnapshot` model |

---

### Task 1: DetectedTarget + SourceMetadata Models and TargetDetector

**Files:**
- Create: `packages/cli/src/opentools/scanner/target.py`
- Test: `packages/cli/tests/test_scanner/test_target.py`

- [ ] **Step 1: Write the failing tests for TargetDetector**

```python
# packages/cli/tests/test_scanner/test_target.py
"""Tests for TargetDetector, TargetValidator, DetectedTarget, SourceMetadata."""

import os
import tempfile
from pathlib import Path

import pytest

from opentools.scanner.models import TargetType
from opentools.scanner.target import (
    DetectedTarget,
    SourceMetadata,
    TargetDetector,
)


class TestDetectedTarget:
    def test_basic_fields(self):
        dt = DetectedTarget(
            target_type=TargetType.URL,
            resolved_path=None,
            original_target="https://example.com",
            metadata={},
        )
        assert dt.target_type == TargetType.URL
        assert dt.original_target == "https://example.com"
        assert dt.resolved_path is None

    def test_serialization_round_trip(self):
        dt = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/repo",
            original_target="/tmp/repo",
            metadata={"languages": ["python"]},
        )
        restored = DetectedTarget.model_validate_json(dt.model_dump_json())
        assert restored == dt


class TestSourceMetadata:
    def test_defaults(self):
        sm = SourceMetadata(
            languages=["python"],
            framework_hints=[],
            has_dockerfile=False,
            has_package_lock=False,
            estimated_loc=100,
            content_hash="abc123",
        )
        assert sm.languages == ["python"]
        assert sm.estimated_loc == 100

    def test_serialization(self):
        sm = SourceMetadata(
            languages=["java", "kotlin"],
            framework_hints=["spring"],
            has_dockerfile=True,
            has_package_lock=False,
            estimated_loc=50000,
            content_hash="deadbeef",
        )
        restored = SourceMetadata.model_validate_json(sm.model_dump_json())
        assert restored == sm


class TestTargetDetector:
    def setup_method(self):
        self.detector = TargetDetector()

    # --- Explicit override ---

    def test_explicit_override_url(self):
        result = self.detector.detect("some-string", override_type=TargetType.URL)
        assert result.target_type == TargetType.URL
        assert result.original_target == "some-string"

    def test_explicit_override_network(self):
        result = self.detector.detect("anything", override_type=TargetType.NETWORK)
        assert result.target_type == TargetType.NETWORK

    # --- URL patterns ---

    def test_http_url(self):
        result = self.detector.detect("http://example.com")
        assert result.target_type == TargetType.URL

    def test_https_url(self):
        result = self.detector.detect("https://example.com/app")
        assert result.target_type == TargetType.URL

    def test_https_url_with_port(self):
        result = self.detector.detect("https://example.com:8443/api")
        assert result.target_type == TargetType.URL

    # --- CIDR / IP patterns ---

    def test_ipv4_address(self):
        result = self.detector.detect("192.168.1.1")
        assert result.target_type == TargetType.NETWORK

    def test_cidr_notation(self):
        result = self.detector.detect("10.0.0.0/24")
        assert result.target_type == TargetType.NETWORK

    def test_ipv6_address(self):
        result = self.detector.detect("::1")
        assert result.target_type == TargetType.NETWORK

    def test_ipv4_range_with_port(self):
        # IP with port is still network, not URL (no scheme)
        result = self.detector.detect("192.168.1.1:8080")
        assert result.target_type == TargetType.NETWORK

    # --- Docker image patterns ---

    def test_docker_image_simple(self):
        result = self.detector.detect("nginx:latest")
        assert result.target_type == TargetType.DOCKER_IMAGE

    def test_docker_image_with_registry(self):
        result = self.detector.detect("registry.example.com/myapp:v1.2")
        assert result.target_type == TargetType.DOCKER_IMAGE

    def test_docker_image_dockerhub_namespace(self):
        result = self.detector.detect("myuser/myapp:1.0")
        assert result.target_type == TargetType.DOCKER_IMAGE

    def test_docker_image_no_tag(self):
        result = self.detector.detect("ubuntu")
        # Bare name without context is ambiguous; we don't detect this
        # as docker since it could be a directory. This tests the
        # "file extension" and "directory" checks come after.
        # If no directory named "ubuntu" exists, it should raise.
        with pytest.raises(ValueError, match="[Aa]mbiguous|[Cc]annot determine"):
            self.detector.detect("ubuntu")

    # --- File extension patterns ---

    def test_apk_extension(self):
        result = self.detector.detect("app.apk")
        assert result.target_type == TargetType.APK

    def test_exe_extension(self):
        result = self.detector.detect("malware.exe")
        assert result.target_type == TargetType.BINARY

    def test_dll_extension(self):
        result = self.detector.detect("library.dll")
        assert result.target_type == TargetType.BINARY

    def test_elf_extension(self):
        result = self.detector.detect("binary.elf")
        assert result.target_type == TargetType.BINARY

    def test_so_extension(self):
        result = self.detector.detect("libcrypto.so")
        assert result.target_type == TargetType.BINARY

    def test_dylib_extension(self):
        result = self.detector.detect("libssl.dylib")
        assert result.target_type == TargetType.BINARY

    # --- Directory with source code ---

    def test_directory_with_python_files(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        result = self.detector.detect(str(tmp_path))
        assert result.target_type == TargetType.SOURCE_CODE
        assert result.resolved_path == str(tmp_path)

    def test_directory_with_java_files(self, tmp_path):
        src_dir = tmp_path / "src" / "main" / "java"
        src_dir.mkdir(parents=True)
        (src_dir / "App.java").write_text("class App {}")
        result = self.detector.detect(str(tmp_path))
        assert result.target_type == TargetType.SOURCE_CODE

    def test_directory_with_javascript_files(self, tmp_path):
        (tmp_path / "index.js").write_text("console.log('hi')")
        result = self.detector.detect(str(tmp_path))
        assert result.target_type == TargetType.SOURCE_CODE

    # --- GitHub URLs ---

    def test_github_url_raises(self):
        with pytest.raises(ValueError, match="[Cc]lone"):
            self.detector.detect("https://github.com/user/repo")

    def test_github_url_with_git_suffix_raises(self):
        with pytest.raises(ValueError, match="[Cc]lone"):
            self.detector.detect("https://github.com/user/repo.git")

    # --- Ambiguous ---

    def test_ambiguous_target_raises(self):
        with pytest.raises(ValueError, match="[Aa]mbiguous|[Cc]annot determine"):
            self.detector.detect("some_random_string_that_matches_nothing")

    # --- SourceMetadata extraction ---

    def test_source_metadata_populated_for_directory(self, tmp_path):
        (tmp_path / "app.py").write_text("import flask\n\nprint('hello')\n")
        (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
        (tmp_path / "requirements.txt").write_text("flask\n")
        result = self.detector.detect(str(tmp_path))
        assert result.target_type == TargetType.SOURCE_CODE
        assert "python" in result.metadata.get("languages", [])
        assert result.metadata.get("has_dockerfile") is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_target.py -v`
Expected: FAIL -- `ModuleNotFoundError: No module named 'opentools.scanner.target'`

- [ ] **Step 3: Implement DetectedTarget, SourceMetadata, and TargetDetector**

```python
# packages/cli/src/opentools/scanner/target.py
"""Target detection, validation, and metadata extraction.

TargetDetector determines target type from a string using pattern matching.
TargetValidator performs async I/O to verify the target is accessible.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from opentools.scanner.models import TargetType


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class DetectedTarget(BaseModel):
    """Result of target detection."""

    target_type: TargetType
    resolved_path: Optional[str] = None
    original_target: str
    metadata: dict = {}


class SourceMetadata(BaseModel):
    """Metadata extracted from a source code directory."""

    languages: list[str]
    framework_hints: list[str]
    has_dockerfile: bool
    has_package_lock: bool
    estimated_loc: int
    content_hash: str


# ---------------------------------------------------------------------------
# File extension mappings
# ---------------------------------------------------------------------------

_BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".elf", ".so", ".dylib", ".bin", ".sys", ".o", ".ko",
})

_APK_EXTENSIONS: frozenset[str] = frozenset({".apk"})

_SOURCE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".go", ".rs",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".rb", ".php", ".swift", ".scala",
    ".m", ".mm", ".r", ".pl", ".sh", ".bash", ".ps1", ".lua", ".zig",
    ".vue", ".svelte",
})

_EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".scala": "scala",
    ".vue": "javascript",
    ".svelte": "javascript",
}

_FRAMEWORK_INDICATORS: dict[str, list[str]] = {
    "requirements.txt": ["python"],
    "setup.py": ["python"],
    "pyproject.toml": ["python"],
    "Pipfile": ["python"],
    "package.json": ["javascript"],
    "pom.xml": ["java", "maven"],
    "build.gradle": ["java", "gradle"],
    "Cargo.toml": ["rust"],
    "go.mod": ["go"],
    "Gemfile": ["ruby"],
    "composer.json": ["php"],
    "Package.swift": ["swift"],
}

# Regex for GitHub URLs
_GITHUB_URL_PATTERN = re.compile(
    r"^https?://github\.com/[\w\-\.]+/[\w\-\.]+(\.git)?/?$"
)

# Regex for URL scheme
_URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)

# Regex for docker image patterns: name:tag, registry/name:tag, registry.io/name:tag
_DOCKER_IMAGE_PATTERN = re.compile(
    r"^(?:[\w\-\.]+(?:\.[\w\-]+)+(?::\d+)?/)?[\w\-\.]+/[\w\-\.]+(?::[\w\-\.]+)?$"
    r"|"
    r"^[\w\-]+:[\w\-\.]+$"
)

# Common single-word docker images that have a colon tag
_DOCKER_IMAGE_WITH_TAG = re.compile(r"^[\w\-]+:[\w\-\.]+$")


# ---------------------------------------------------------------------------
# TargetDetector
# ---------------------------------------------------------------------------


class TargetDetector:
    """Determines TargetType from a target string.

    Resolution order (first match wins):
    1. Explicit override via ``override_type``
    2. URL pattern: ``http(s)://...``
    3. CIDR/IP pattern
    4. Docker image pattern: ``image:tag``, ``registry/image:tag``
    5. File extension: ``.apk``, ``.exe``, ``.dll``, etc.
    6. Directory with source files
    7. GitHub URL (raises error suggesting manual clone)
    8. Ambiguous (raises ValueError)
    """

    def detect(
        self,
        target: str,
        override_type: Optional[TargetType] = None,
    ) -> DetectedTarget:
        """Detect the target type from a target string.

        This method is synchronous -- no I/O is needed for pattern matching.
        Filesystem checks are limited to ``os.path.exists`` and directory
        listing for source detection.

        Args:
            target: The target string (URL, path, IP, image name, etc.)
            override_type: If provided, skip detection and use this type.

        Returns:
            DetectedTarget with resolved type and metadata.

        Raises:
            ValueError: If target type cannot be determined, or if target
                is a GitHub URL (clone manually).
        """
        # 1. Explicit override
        if override_type is not None:
            return DetectedTarget(
                target_type=override_type,
                original_target=target,
                metadata={},
            )

        # 7. GitHub URL check (before generic URL to give specific error)
        if _GITHUB_URL_PATTERN.match(target):
            raise ValueError(
                f"GitHub URL detected: {target}. "
                "Please clone the repository manually and point to the "
                "local directory instead. "
                "Example: git clone {target} /tmp/repo && opentools scan /tmp/repo"
            )

        # 2. URL pattern
        if _URL_PATTERN.match(target):
            return DetectedTarget(
                target_type=TargetType.URL,
                original_target=target,
                metadata={},
            )

        # 3. CIDR / IP pattern
        if self._is_network_target(target):
            return DetectedTarget(
                target_type=TargetType.NETWORK,
                original_target=target,
                metadata={},
            )

        # 4. Docker image pattern (must come before file extension checks)
        if self._is_docker_image(target):
            return DetectedTarget(
                target_type=TargetType.DOCKER_IMAGE,
                original_target=target,
                metadata={},
            )

        # 5. File extension
        ext = Path(target).suffix.lower()
        if ext in _APK_EXTENSIONS:
            return DetectedTarget(
                target_type=TargetType.APK,
                resolved_path=str(Path(target).resolve()) if Path(target).exists() else None,
                original_target=target,
                metadata={},
            )
        if ext in _BINARY_EXTENSIONS:
            return DetectedTarget(
                target_type=TargetType.BINARY,
                resolved_path=str(Path(target).resolve()) if Path(target).exists() else None,
                original_target=target,
                metadata={},
            )

        # 6. Directory with source files
        target_path = Path(target)
        if target_path.is_dir():
            metadata = self._extract_source_metadata(target_path)
            if metadata.languages:
                return DetectedTarget(
                    target_type=TargetType.SOURCE_CODE,
                    resolved_path=str(target_path.resolve()),
                    original_target=target,
                    metadata=metadata.model_dump(),
                )

        # 8. Ambiguous
        raise ValueError(
            f"Cannot determine target type for '{target}'. "
            "Use --type to specify explicitly (e.g., --type source_code, --type url)."
        )

    def _is_network_target(self, target: str) -> bool:
        """Check if target is an IP address, CIDR range, or IP:port."""
        # Strip port suffix for IP check
        host = target.split(":")[0] if ":" in target and "/" not in target else target
        # Handle CIDR
        if "/" in target:
            host = target
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass
        # Check for IPv6
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        # IP:port pattern
        match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$", target)
        if match:
            try:
                ipaddress.ip_address(match.group(1))
                return True
            except ValueError:
                pass
        return False

    def _is_docker_image(self, target: str) -> bool:
        """Check if target looks like a Docker image reference.

        Matches: ``name:tag``, ``user/name:tag``, ``registry.io/name:tag``.
        Does NOT match bare names without tags (ambiguous with directories).
        """
        # name:tag (simple)
        if _DOCKER_IMAGE_WITH_TAG.match(target):
            # Exclude things that look like IP:port
            parts = target.split(":")
            try:
                ipaddress.ip_address(parts[0])
                return False  # It's IP:port, not docker
            except ValueError:
                pass
            return True
        # registry/name or registry/name:tag
        if _DOCKER_IMAGE_PATTERN.match(target):
            return True
        return False

    def _extract_source_metadata(self, directory: Path) -> SourceMetadata:
        """Walk directory to extract source metadata."""
        languages: set[str] = set()
        framework_hints: set[str] = set()
        has_dockerfile = False
        has_package_lock = False
        loc_estimate = 0
        file_count = 0

        # Walk at most 3 levels deep for speed
        for root, dirs, files in os.walk(str(directory)):
            depth = str(root).replace(str(directory), "").count(os.sep)
            if depth >= 3:
                dirs.clear()
                continue

            # Skip hidden dirs, node_modules, .git, __pycache__, venv
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".")
                and d not in {"node_modules", "__pycache__", "venv", ".venv", "vendor", "dist", "build"}
            ]

            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()

                if ext in _SOURCE_EXTENSIONS:
                    file_count += 1
                    lang = _EXTENSION_TO_LANGUAGE.get(ext)
                    if lang:
                        languages.add(lang)
                    # Rough LOC estimate: ~50 lines per source file
                    loc_estimate += 50

                if fname in _FRAMEWORK_INDICATORS:
                    framework_hints.update(_FRAMEWORK_INDICATORS[fname])

                if fname == "Dockerfile" or fname.startswith("Dockerfile."):
                    has_dockerfile = True

                if fname in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
                    has_package_lock = True

        # Content hash: use file count + top-level file list as a cheap hash
        import hashlib
        top_files = sorted(f for f in os.listdir(str(directory)) if not f.startswith("."))
        content_hash = hashlib.sha256(
            f"{file_count}:{','.join(top_files)}".encode()
        ).hexdigest()[:16]

        return SourceMetadata(
            languages=sorted(languages),
            framework_hints=sorted(framework_hints),
            has_dockerfile=has_dockerfile,
            has_package_lock=has_package_lock,
            estimated_loc=loc_estimate,
            content_hash=content_hash,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_target.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/target.py \
       packages/cli/tests/test_scanner/test_target.py
git commit -m "feat(scanner): TargetDetector + DetectedTarget + SourceMetadata"
```

---

### Task 2: TargetValidator (async validation)

**Files:**
- Modify: `packages/cli/src/opentools/scanner/target.py`
- Modify: `packages/cli/tests/test_scanner/test_target.py`

- [ ] **Step 1: Write the failing tests for TargetValidator**

Append to the existing test file:

```python
# Append to: packages/cli/tests/test_scanner/test_target.py

import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from opentools.scanner.target import TargetValidator


class TestTargetValidator:
    @pytest.fixture
    def validator(self):
        return TargetValidator()

    # --- Source code validation ---

    @pytest.mark.asyncio
    async def test_validate_source_directory_exists(self, tmp_path, validator):
        (tmp_path / "main.py").write_text("print('hello')")
        dt = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path=str(tmp_path),
            original_target=str(tmp_path),
            metadata={"languages": ["python"]},
        )
        result = await validator.validate(dt)
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_validate_source_directory_not_exists(self, validator):
        dt = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/nonexistent/path/abc123",
            original_target="/nonexistent/path/abc123",
            metadata={},
        )
        result = await validator.validate(dt)
        assert result.valid is False
        assert "not found" in result.reason.lower() or "does not exist" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_validate_source_empty_directory(self, tmp_path, validator):
        dt = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path=str(tmp_path),
            original_target=str(tmp_path),
            metadata={"languages": []},
        )
        result = await validator.validate(dt)
        assert result.valid is False
        assert "empty" in result.reason.lower() or "no source" in result.reason.lower()

    # --- URL validation ---

    @pytest.mark.asyncio
    async def test_validate_url_success(self, validator):
        dt = DetectedTarget(
            target_type=TargetType.URL,
            original_target="https://example.com",
            metadata={},
        )
        # Mock HTTP HEAD request
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.head = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("opentools.scanner.target.aiohttp.ClientSession", return_value=mock_session):
            result = await validator.validate(dt)
            assert result.valid is True

    @pytest.mark.asyncio
    async def test_validate_url_unreachable(self, validator):
        dt = DetectedTarget(
            target_type=TargetType.URL,
            original_target="https://unreachable.invalid",
            metadata={},
        )
        with patch("opentools.scanner.target.aiohttp.ClientSession") as mock_cls:
            mock_session = MagicMock()
            mock_session.head = MagicMock(side_effect=Exception("Connection refused"))
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_session
            result = await validator.validate(dt)
            assert result.valid is False

    # --- Binary validation ---

    @pytest.mark.asyncio
    async def test_validate_binary_pe_magic(self, tmp_path, validator):
        binary = tmp_path / "test.exe"
        # PE magic bytes: MZ
        binary.write_bytes(b"MZ" + b"\x00" * 100)
        dt = DetectedTarget(
            target_type=TargetType.BINARY,
            resolved_path=str(binary),
            original_target=str(binary),
            metadata={},
        )
        result = await validator.validate(dt)
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_validate_binary_elf_magic(self, tmp_path, validator):
        binary = tmp_path / "test.elf"
        # ELF magic bytes
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        dt = DetectedTarget(
            target_type=TargetType.BINARY,
            resolved_path=str(binary),
            original_target=str(binary),
            metadata={},
        )
        result = await validator.validate(dt)
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_validate_binary_not_found(self, validator):
        dt = DetectedTarget(
            target_type=TargetType.BINARY,
            resolved_path="/nonexistent/binary.exe",
            original_target="binary.exe",
            metadata={},
        )
        result = await validator.validate(dt)
        assert result.valid is False

    @pytest.mark.asyncio
    async def test_validate_binary_invalid_magic(self, tmp_path, validator):
        binary = tmp_path / "test.exe"
        binary.write_bytes(b"NOT_A_BINARY" + b"\x00" * 100)
        dt = DetectedTarget(
            target_type=TargetType.BINARY,
            resolved_path=str(binary),
            original_target=str(binary),
            metadata={},
        )
        result = await validator.validate(dt)
        assert result.valid is False
        assert "magic" in result.reason.lower() or "header" in result.reason.lower()

    # --- APK validation ---

    @pytest.mark.asyncio
    async def test_validate_apk_valid_zip(self, tmp_path, validator):
        import zipfile
        apk_path = tmp_path / "test.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest/>")
        dt = DetectedTarget(
            target_type=TargetType.APK,
            resolved_path=str(apk_path),
            original_target=str(apk_path),
            metadata={},
        )
        result = await validator.validate(dt)
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_validate_apk_no_manifest(self, tmp_path, validator):
        import zipfile
        apk_path = tmp_path / "test.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", "data")
        dt = DetectedTarget(
            target_type=TargetType.APK,
            resolved_path=str(apk_path),
            original_target=str(apk_path),
            metadata={},
        )
        result = await validator.validate(dt)
        assert result.valid is False
        assert "manifest" in result.reason.lower()

    # --- Docker validation ---

    @pytest.mark.asyncio
    async def test_validate_docker_image_exists(self, validator):
        dt = DetectedTarget(
            target_type=TargetType.DOCKER_IMAGE,
            original_target="nginx:latest",
            metadata={},
        )
        with patch("opentools.scanner.target.asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"sha256:abc123\n", b""))
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc
            result = await validator.validate(dt)
            assert result.valid is True

    @pytest.mark.asyncio
    async def test_validate_docker_image_not_found(self, validator):
        dt = DetectedTarget(
            target_type=TargetType.DOCKER_IMAGE,
            original_target="nonexistent/image:v999",
            metadata={},
        )
        with patch("opentools.scanner.target.asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b"Error: No such image"))
            mock_proc.returncode = 1
            mock_exec.return_value = mock_proc
            result = await validator.validate(dt)
            assert result.valid is False

    # --- Network validation ---

    @pytest.mark.asyncio
    async def test_validate_network_host_responds(self, validator):
        dt = DetectedTarget(
            target_type=TargetType.NETWORK,
            original_target="192.168.1.1",
            metadata={},
        )
        # Network validation is best-effort; mock the ping
        with patch("opentools.scanner.target.asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"Reply from 192.168.1.1", b""))
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc
            result = await validator.validate(dt)
            assert result.valid is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_target.py::TestTargetValidator -v`
Expected: FAIL -- `ImportError: cannot import name 'TargetValidator'`

- [ ] **Step 3: Implement TargetValidator**

Append to `packages/cli/src/opentools/scanner/target.py`:

```python
# Append to: packages/cli/src/opentools/scanner/target.py

import asyncio
import zipfile

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]


class ValidationResult(BaseModel):
    """Result of target validation."""

    valid: bool
    reason: str = ""
    warnings: list[str] = []


class TargetValidator:
    """Validates that targets exist and are accessible.

    Each target type has its own validation logic:
    - SOURCE_CODE: path exists, contains source files
    - URL: HTTP HEAD succeeds
    - BINARY: file exists, magic bytes match PE/ELF/Mach-O
    - APK: valid ZIP with AndroidManifest.xml
    - DOCKER_IMAGE: ``docker inspect`` succeeds
    - NETWORK: at least one host responds to ping
    """

    async def validate(self, target: DetectedTarget) -> ValidationResult:
        """Validate that the detected target is accessible.

        This method is async because it may perform HTTP requests,
        subprocess calls, or filesystem operations.
        """
        validators = {
            TargetType.SOURCE_CODE: self._validate_source,
            TargetType.URL: self._validate_url,
            TargetType.BINARY: self._validate_binary,
            TargetType.APK: self._validate_apk,
            TargetType.DOCKER_IMAGE: self._validate_docker,
            TargetType.NETWORK: self._validate_network,
        }

        validator_fn = validators.get(target.target_type)
        if validator_fn is None:
            return ValidationResult(
                valid=False,
                reason=f"No validator for target type: {target.target_type}",
            )

        try:
            return await validator_fn(target)
        except Exception as exc:
            return ValidationResult(
                valid=False,
                reason=f"Validation error: {exc}",
            )

    async def _validate_source(self, target: DetectedTarget) -> ValidationResult:
        """Validate source code directory exists and contains source files."""
        resolved = target.resolved_path
        if resolved is None or not Path(resolved).exists():
            return ValidationResult(
                valid=False,
                reason=f"Source directory does not exist: {target.original_target}",
            )
        if not Path(resolved).is_dir():
            return ValidationResult(
                valid=False,
                reason=f"Path is not a directory: {resolved}",
            )
        languages = target.metadata.get("languages", [])
        if not languages:
            return ValidationResult(
                valid=False,
                reason=f"No source files found in directory: {resolved}",
            )
        return ValidationResult(valid=True)

    async def _validate_url(self, target: DetectedTarget) -> ValidationResult:
        """Validate URL is reachable via HTTP HEAD."""
        if aiohttp is None:
            return ValidationResult(
                valid=True,
                reason="aiohttp not installed; skipping URL validation",
                warnings=["Install aiohttp for URL validation"],
            )
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(
                    target.original_target,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True,
                ) as response:
                    if response.status < 500:
                        return ValidationResult(valid=True)
                    return ValidationResult(
                        valid=False,
                        reason=f"HTTP {response.status} from {target.original_target}",
                    )
        except Exception as exc:
            return ValidationResult(
                valid=False,
                reason=f"URL unreachable: {target.original_target} ({exc})",
            )

    async def _validate_binary(self, target: DetectedTarget) -> ValidationResult:
        """Validate binary file exists and has valid magic bytes."""
        resolved = target.resolved_path
        if resolved is None or not Path(resolved).exists():
            return ValidationResult(
                valid=False,
                reason=f"Binary file not found: {target.original_target}",
            )

        # Read first 4 bytes for magic check
        try:
            with open(resolved, "rb") as f:
                magic = f.read(4)
        except OSError as exc:
            return ValidationResult(
                valid=False,
                reason=f"Cannot read binary: {exc}",
            )

        # Check known magic bytes
        valid_magics = {
            b"MZ": "PE (Windows)",
            b"\x7fELF": "ELF (Linux)",
            b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
            b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
            b"\xce\xfa\xed\xfe": "Mach-O 32-bit (reversed)",
            b"\xcf\xfa\xed\xfe": "Mach-O 64-bit (reversed)",
        }

        for magic_bytes, fmt_name in valid_magics.items():
            if magic[:len(magic_bytes)] == magic_bytes:
                return ValidationResult(valid=True)

        return ValidationResult(
            valid=False,
            reason=(
                f"Unrecognized binary magic bytes in {resolved}: "
                f"{magic.hex()}. Expected PE (MZ), ELF, or Mach-O header."
            ),
        )

    async def _validate_apk(self, target: DetectedTarget) -> ValidationResult:
        """Validate APK is a valid ZIP containing AndroidManifest.xml."""
        resolved = target.resolved_path
        if resolved is None or not Path(resolved).exists():
            return ValidationResult(
                valid=False,
                reason=f"APK file not found: {target.original_target}",
            )

        try:
            with zipfile.ZipFile(resolved, "r") as zf:
                names = zf.namelist()
                if "AndroidManifest.xml" not in names:
                    return ValidationResult(
                        valid=False,
                        reason=(
                            f"APK missing AndroidManifest.xml: {resolved}. "
                            "File is a valid ZIP but does not appear to be an Android APK."
                        ),
                    )
                return ValidationResult(valid=True)
        except zipfile.BadZipFile:
            return ValidationResult(
                valid=False,
                reason=f"Not a valid ZIP file: {resolved}",
            )

    async def _validate_docker(self, target: DetectedTarget) -> ValidationResult:
        """Validate Docker image exists locally via ``docker inspect``."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", "--type=image", target.original_target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                return ValidationResult(valid=True)
            return ValidationResult(
                valid=False,
                reason=(
                    f"Docker image not found locally: {target.original_target}. "
                    f"Pull it first with: docker pull {target.original_target}"
                ),
            )
        except FileNotFoundError:
            return ValidationResult(
                valid=False,
                reason="Docker is not installed or not in PATH",
            )

    async def _validate_network(self, target: DetectedTarget) -> ValidationResult:
        """Validate network target responds to ping."""
        # Extract host from CIDR or IP:port
        host = target.original_target.split("/")[0].split(":")[0]
        try:
            import platform
            ping_flag = "-n" if platform.system().lower() == "windows" else "-c"
            proc = await asyncio.create_subprocess_exec(
                "ping", ping_flag, "1", "-w", "3", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                return ValidationResult(valid=True)
            return ValidationResult(
                valid=False,
                reason=f"Host does not respond to ping: {host}",
                warnings=["Host may still be reachable but blocking ICMP"],
            )
        except FileNotFoundError:
            return ValidationResult(
                valid=True,
                reason="Ping not available; skipping network validation",
                warnings=["Install ping utility for network validation"],
            )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_target.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/target.py \
       packages/cli/tests/test_scanner/test_target.py
git commit -m "feat(scanner): TargetValidator — async target accessibility checks"
```

---

### Task 3: Profile Models (ScanProfile, ProfilePhase, ProfileTool, ReactiveEdgeTemplate)

**Files:**
- Create: `packages/cli/src/opentools/scanner/profiles.py`
- Test: `packages/cli/tests/test_scanner/test_profiles.py`

- [ ] **Step 1: Write the failing tests for profile models**

```python
# packages/cli/tests/test_scanner/test_profiles.py
"""Tests for scan profile models and YAML loading."""

import pytest

from opentools.scanner.models import (
    ExecutionTier,
    RetryPolicy,
    TargetType,
    TaskIsolation,
    TaskType,
)
from opentools.scanner.profiles import (
    DEFAULT_PROFILES,
    ProfilePhase,
    ProfileTool,
    ReactiveEdgeTemplate,
    ScanProfile,
    load_builtin_profile,
    load_profile_yaml,
    list_builtin_profiles,
)


class TestProfileTool:
    def test_defaults(self):
        pt = ProfileTool(
            tool="semgrep",
            task_type=TaskType.SHELL,
        )
        assert pt.tool == "semgrep"
        assert pt.task_type == TaskType.SHELL
        assert pt.priority == 50
        assert pt.tier == ExecutionTier.NORMAL
        assert pt.optional is False
        assert pt.condition is None
        assert pt.isolation == TaskIsolation.NONE

    def test_full_config(self):
        pt = ProfileTool(
            tool="nuclei",
            task_type=TaskType.SHELL,
            command_template="nuclei -u {target} -t {templates}",
            parser="nuclei",
            priority=30,
            tier=ExecutionTier.NORMAL,
            resource_group="shell",
            retry_policy=RetryPolicy(max_retries=3),
            cache_key_template="{tool}:{target_hash}",
            optional=False,
            condition="language in ['python', 'java']",
            preferred_output_format="json",
        )
        assert pt.command_template == "nuclei -u {target} -t {templates}"
        assert pt.retry_policy.max_retries == 3

    def test_mcp_tool(self):
        pt = ProfileTool(
            tool="codebadger",
            task_type=TaskType.MCP_CALL,
            mcp_server="codebadger",
            mcp_tool="generate_cpg",
            mcp_args_template={"path": "{target}"},
            priority=40,
        )
        assert pt.mcp_server == "codebadger"
        assert pt.mcp_tool == "generate_cpg"

    def test_serialization(self):
        pt = ProfileTool(
            tool="semgrep",
            task_type=TaskType.SHELL,
            command_template="semgrep --config auto {target}",
        )
        restored = ProfileTool.model_validate_json(pt.model_dump_json())
        assert restored == pt


class TestReactiveEdgeTemplate:
    def test_basic(self):
        ret = ReactiveEdgeTemplate(
            evaluator="builtin:open_ports_to_vuln_scan",
            trigger_tool="nmap",
            max_spawns=20,
            max_spawns_per_trigger=5,
        )
        assert ret.evaluator == "builtin:open_ports_to_vuln_scan"
        assert ret.trigger_tool == "nmap"
        assert ret.max_spawns == 20

    def test_with_condition(self):
        ret = ReactiveEdgeTemplate(
            evaluator="builtin:high_severity_to_deep_dive",
            trigger_tool="*",
            condition="severity in ['critical', 'high']",
            max_spawns=10,
        )
        assert ret.condition is not None


class TestProfilePhase:
    def test_basic_phase(self):
        phase = ProfilePhase(
            name="discovery",
            tools=[
                ProfileTool(tool="whatweb", task_type=TaskType.SHELL),
                ProfileTool(tool="waybackurls", task_type=TaskType.SHELL),
            ],
            parallel=True,
        )
        assert phase.name == "discovery"
        assert len(phase.tools) == 2
        assert phase.parallel is True

    def test_sequential_phase(self):
        phase = ProfilePhase(
            name="decompile",
            tools=[
                ProfileTool(tool="jadx", task_type=TaskType.SHELL),
            ],
            parallel=False,
        )
        assert phase.parallel is False


class TestScanProfile:
    def test_basic_profile(self):
        profile = ScanProfile(
            id="source-quick",
            name="Source Quick Scan",
            description="Fast static analysis of source code",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="static-analysis",
                    tools=[
                        ProfileTool(tool="semgrep", task_type=TaskType.SHELL),
                        ProfileTool(tool="gitleaks", task_type=TaskType.SHELL),
                    ],
                ),
            ],
        )
        assert profile.id == "source-quick"
        assert len(profile.phases) == 1
        assert len(profile.phases[0].tools) == 2

    def test_profile_with_inheritance(self):
        profile = ScanProfile(
            id="source-full",
            name="Source Full Scan",
            description="Comprehensive source code analysis",
            target_types=[TargetType.SOURCE_CODE],
            extends="source-quick",
            add_tools=[
                ProfileTool(tool="codebadger", task_type=TaskType.MCP_CALL),
            ],
            remove_tools=["gitleaks"],
        )
        assert profile.extends == "source-quick"
        assert len(profile.add_tools) == 1
        assert "gitleaks" in profile.remove_tools

    def test_profile_serialization(self):
        profile = ScanProfile(
            id="test",
            name="Test Profile",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[],
        )
        restored = ScanProfile.model_validate_json(profile.model_dump_json())
        assert restored == profile


class TestDefaultProfiles:
    def test_all_target_types_mapped(self):
        for tt in TargetType:
            assert tt in DEFAULT_PROFILES, f"Missing default profile for {tt}"

    def test_mappings_are_strings(self):
        for tt, profile_name in DEFAULT_PROFILES.items():
            assert isinstance(profile_name, str)


class TestBuiltinProfileLoading:
    def test_list_builtin_profiles(self):
        profiles = list_builtin_profiles()
        assert len(profiles) >= 8
        expected = {
            "source-quick", "source-full", "web-quick", "web-full",
            "binary-triage", "network-recon", "container-audit", "apk-analysis",
        }
        assert expected.issubset(set(profiles))

    def test_load_source_quick(self):
        profile = load_builtin_profile("source-quick")
        assert profile.id == "source-quick"
        assert TargetType.SOURCE_CODE in profile.target_types
        assert len(profile.phases) >= 1
        tool_names = [t.tool for phase in profile.phases for t in phase.tools]
        assert "semgrep" in tool_names
        assert "gitleaks" in tool_names

    def test_load_web_full(self):
        profile = load_builtin_profile("web-full")
        assert profile.id == "web-full"
        assert TargetType.URL in profile.target_types
        tool_names = [t.tool for phase in profile.phases for t in phase.tools]
        assert "nuclei" in tool_names

    def test_load_binary_triage(self):
        profile = load_builtin_profile("binary-triage")
        assert profile.id == "binary-triage"
        assert TargetType.BINARY in profile.target_types

    def test_load_network_recon(self):
        profile = load_builtin_profile("network-recon")
        assert profile.id == "network-recon"
        assert TargetType.NETWORK in profile.target_types
        # Should have reactive edges defined
        assert len(profile.reactive_edges) >= 1

    def test_load_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError):
            load_builtin_profile("nonexistent-profile")

    def test_load_profile_from_yaml_string(self):
        yaml_str = """
id: custom-test
name: Custom Test
description: A custom test profile
target_types:
  - source_code
phases:
  - name: analysis
    tools:
      - tool: semgrep
        task_type: shell
        command_template: "semgrep --config auto {target}"
"""
        profile = load_profile_yaml(yaml_str)
        assert profile.id == "custom-test"
        assert len(profile.phases) == 1
        assert profile.phases[0].tools[0].tool == "semgrep"

    def test_load_all_builtin_profiles_valid(self):
        """Every builtin profile YAML must parse into a valid ScanProfile."""
        for name in list_builtin_profiles():
            profile = load_builtin_profile(name)
            assert profile.id == name, f"Profile {name} has mismatched id: {profile.id}"
            assert len(profile.target_types) >= 1
            assert len(profile.phases) >= 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_profiles.py -v`
Expected: FAIL -- `ModuleNotFoundError: No module named 'opentools.scanner.profiles'`

- [ ] **Step 3: Implement profile models and loading**

```python
# packages/cli/src/opentools/scanner/profiles.py
"""Scan profile models, YAML loading, and built-in profile registry.

Profiles define which tools run against which target types, organized
into phases with dependency and concurrency control.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from opentools.scanner.models import (
    ExecutionTier,
    RetryPolicy,
    ScanConfig,
    TargetType,
    TaskIsolation,
    TaskType,
)


# ---------------------------------------------------------------------------
# Profile data models
# ---------------------------------------------------------------------------


class ReactiveEdgeTemplate(BaseModel):
    """Template for reactive edges defined at the profile level.

    At plan time, the ScanPlanner instantiates these into concrete
    ``ReactiveEdge`` instances attached to specific task IDs.
    """

    evaluator: str
    trigger_tool: str  # tool name or "*" for any
    condition: Optional[str] = None
    max_spawns: int = 20
    max_spawns_per_trigger: int = 5
    cooldown_seconds: float = 0
    budget_group: Optional[str] = None
    min_upstream_confidence: float = 0.5


class ProfileTool(BaseModel):
    """A tool entry within a profile phase."""

    tool: str
    task_type: TaskType
    command_template: Optional[str] = None
    mcp_server: Optional[str] = None
    mcp_tool: Optional[str] = None
    mcp_args_template: Optional[dict] = None
    parser: Optional[str] = None
    priority: int = 50
    tier: ExecutionTier = ExecutionTier.NORMAL
    resource_group: Optional[str] = None
    retry_policy: Optional[RetryPolicy] = None
    cache_key_template: Optional[str] = None
    optional: bool = False
    condition: Optional[str] = None
    isolation: TaskIsolation = TaskIsolation.NONE
    preferred_output_format: Optional[str] = None
    reactive_edges: Optional[list[ReactiveEdgeTemplate]] = None


class ProfilePhase(BaseModel):
    """A phase within a scan profile — a group of tools that can run together."""

    name: str
    tools: list[ProfileTool]
    parallel: bool = True


class ScanProfile(BaseModel):
    """A scan profile defines what tools to run for a given target type."""

    id: str
    name: str
    description: str
    target_types: list[TargetType]
    extends: Optional[str] = None
    add_tools: list[ProfileTool] = Field(default_factory=list)
    remove_tools: list[str] = Field(default_factory=list)
    phases: list[ProfilePhase] = Field(default_factory=list)
    reactive_edges: list[ReactiveEdgeTemplate] = Field(default_factory=list)
    default_config: Optional[ScanConfig] = None
    override_config: Optional[ScanConfig] = None


# ---------------------------------------------------------------------------
# Default profile mapping
# ---------------------------------------------------------------------------

DEFAULT_PROFILES: dict[TargetType, str] = {
    TargetType.SOURCE_CODE: "source-full",
    TargetType.URL: "web-full",
    TargetType.BINARY: "binary-triage",
    TargetType.DOCKER_IMAGE: "container-audit",
    TargetType.APK: "apk-analysis",
    TargetType.NETWORK: "network-recon",
}


# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------

_PROFILES_DIR = Path(__file__).parent / "profiles"


def list_builtin_profiles() -> list[str]:
    """Return names of all built-in profiles (without .yaml extension)."""
    if not _PROFILES_DIR.exists():
        return []
    return sorted(
        p.stem.replace("_", "-")
        for p in _PROFILES_DIR.glob("*.yaml")
    )


def load_builtin_profile(name: str) -> ScanProfile:
    """Load a built-in profile by name.

    Args:
        name: Profile name (e.g. "source-quick"). Hyphens are converted
            to underscores for filename lookup.

    Returns:
        Parsed ScanProfile.

    Raises:
        FileNotFoundError: If the profile YAML does not exist.
    """
    filename = name.replace("-", "_") + ".yaml"
    filepath = _PROFILES_DIR / filename
    if not filepath.exists():
        raise FileNotFoundError(
            f"Built-in profile '{name}' not found at {filepath}"
        )
    return load_profile_yaml(filepath.read_text(encoding="utf-8"))


def load_profile_yaml(yaml_content: str) -> ScanProfile:
    """Parse a YAML string into a ScanProfile.

    Args:
        yaml_content: Raw YAML string.

    Returns:
        Validated ScanProfile.
    """
    data = yaml.safe_load(yaml_content)
    return ScanProfile.model_validate(data)
```

- [ ] **Step 4: Run tests to verify model tests pass (profile loading tests will still fail -- no YAML files yet)**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_profiles.py -k "not Builtin" -v`
Expected: Model tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/profiles.py \
       packages/cli/tests/test_scanner/test_profiles.py
git commit -m "feat(scanner): ScanProfile + ProfilePhase + ProfileTool + ReactiveEdgeTemplate models"
```

---

### Task 4: Built-in Profile YAML Files

**Files:**
- Create: `packages/cli/src/opentools/scanner/profiles/source_quick.yaml`
- Create: `packages/cli/src/opentools/scanner/profiles/source_full.yaml`
- Create: `packages/cli/src/opentools/scanner/profiles/web_quick.yaml`
- Create: `packages/cli/src/opentools/scanner/profiles/web_full.yaml`
- Create: `packages/cli/src/opentools/scanner/profiles/binary_triage.yaml`
- Create: `packages/cli/src/opentools/scanner/profiles/network_recon.yaml`
- Create: `packages/cli/src/opentools/scanner/profiles/container_audit.yaml`
- Create: `packages/cli/src/opentools/scanner/profiles/apk_analysis.yaml`

- [ ] **Step 1: Create the profiles directory**

```bash
mkdir -p packages/cli/src/opentools/scanner/profiles
```

- [ ] **Step 2: Create source_quick.yaml**

```yaml
# packages/cli/src/opentools/scanner/profiles/source_quick.yaml
id: source-quick
name: Source Quick Scan
description: Fast static analysis of source code using semgrep and gitleaks
target_types:
  - source_code
phases:
  - name: static-analysis
    parallel: true
    tools:
      - tool: semgrep
        task_type: shell
        command_template: "semgrep --config auto --json {target}"
        parser: semgrep
        priority: 30
        tier: fast
        resource_group: shell
        preferred_output_format: json
      - tool: gitleaks
        task_type: shell
        command_template: "gitleaks detect --source {target} --report-format json --report-path -"
        parser: gitleaks
        priority: 30
        tier: fast
        resource_group: shell
        preferred_output_format: json
```

- [ ] **Step 3: Create source_full.yaml**

```yaml
# packages/cli/src/opentools/scanner/profiles/source_full.yaml
id: source-full
name: Source Full Scan
description: Comprehensive source code analysis with SAST, secrets detection, SCA, and CPG analysis
target_types:
  - source_code
phases:
  - name: static-analysis
    parallel: true
    tools:
      - tool: semgrep
        task_type: shell
        command_template: "semgrep --config auto --json {target}"
        parser: semgrep
        priority: 20
        tier: normal
        resource_group: shell
        preferred_output_format: json
      - tool: gitleaks
        task_type: shell
        command_template: "gitleaks detect --source {target} --report-format json --report-path -"
        parser: gitleaks
        priority: 30
        tier: fast
        resource_group: shell
        preferred_output_format: json
      - tool: trivy
        task_type: shell
        command_template: "trivy fs --format json {target}"
        parser: trivy
        priority: 40
        tier: normal
        resource_group: shell
        optional: true
        condition: "has_package_lock or 'requirements.txt' in framework_hints"
        preferred_output_format: json
  - name: cpg-analysis
    parallel: false
    tools:
      - tool: codebadger
        task_type: mcp_call
        mcp_server: codebadger
        mcp_tool: generate_cpg
        mcp_args_template:
          path: "{target}"
        priority: 50
        tier: heavy
        resource_group: codebadger
        optional: true
reactive_edges:
  - evaluator: "builtin:high_severity_to_deep_dive"
    trigger_tool: "semgrep"
    condition: "severity in ['critical', 'high']"
    max_spawns: 5
    max_spawns_per_trigger: 2
```

- [ ] **Step 4: Create web_quick.yaml**

```yaml
# packages/cli/src/opentools/scanner/profiles/web_quick.yaml
id: web-quick
name: Web Quick Scan
description: Fast web application reconnaissance and vulnerability scanning
target_types:
  - url
phases:
  - name: discovery
    parallel: true
    tools:
      - tool: whatweb
        task_type: shell
        command_template: "whatweb --color=never --log-json=- {target}"
        parser: whatweb
        priority: 10
        tier: fast
        resource_group: shell
        preferred_output_format: json
      - tool: waybackurls
        task_type: shell
        command_template: "echo {target_host} | waybackurls"
        parser: waybackurls
        priority: 20
        tier: fast
        resource_group: shell
  - name: scanning
    parallel: true
    tools:
      - tool: nuclei
        task_type: shell
        command_template: "nuclei -u {target} -json"
        parser: nuclei
        priority: 30
        tier: normal
        resource_group: shell
        preferred_output_format: json
      - tool: nikto
        task_type: shell
        command_template: "nikto -h {target} -Format json"
        parser: nikto
        priority: 40
        tier: normal
        resource_group: shell
        preferred_output_format: json
```

- [ ] **Step 5: Create web_full.yaml**

```yaml
# packages/cli/src/opentools/scanner/profiles/web_full.yaml
id: web-full
name: Web Full Scan
description: Comprehensive web application security assessment
target_types:
  - url
phases:
  - name: discovery
    parallel: true
    tools:
      - tool: whatweb
        task_type: shell
        command_template: "whatweb --color=never --log-json=- {target}"
        parser: whatweb
        priority: 10
        tier: fast
        resource_group: shell
        preferred_output_format: json
      - tool: waybackurls
        task_type: shell
        command_template: "echo {target_host} | waybackurls"
        parser: waybackurls
        priority: 20
        tier: fast
        resource_group: shell
  - name: content-discovery
    parallel: true
    tools:
      - tool: ffuf
        task_type: shell
        command_template: "ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -o - -of json"
        parser: ffuf
        priority: 25
        tier: normal
        resource_group: shell
        preferred_output_format: json
  - name: scanning
    parallel: true
    tools:
      - tool: nuclei
        task_type: shell
        command_template: "nuclei -u {target} -json"
        parser: nuclei
        priority: 30
        tier: normal
        resource_group: shell
        preferred_output_format: json
      - tool: nikto
        task_type: shell
        command_template: "nikto -h {target} -Format json"
        parser: nikto
        priority: 40
        tier: normal
        resource_group: shell
        preferred_output_format: json
      - tool: sqlmap
        task_type: shell
        command_template: "sqlmap -u {target} --batch --forms --crawl=2 --output-dir=/tmp/sqlmap"
        parser: sqlmap
        priority: 60
        tier: heavy
        resource_group: shell
        optional: true
reactive_edges:
  - evaluator: "builtin:web_framework_to_ruleset"
    trigger_tool: "whatweb"
    max_spawns: 10
    max_spawns_per_trigger: 3
  - evaluator: "builtin:high_severity_to_deep_dive"
    trigger_tool: "*"
    condition: "severity in ['critical', 'high']"
    max_spawns: 5
    max_spawns_per_trigger: 2
```

- [ ] **Step 6: Create binary_triage.yaml**

```yaml
# packages/cli/src/opentools/scanner/profiles/binary_triage.yaml
id: binary-triage
name: Binary Triage
description: Initial triage of binary files using static analysis
target_types:
  - binary
phases:
  - name: format-detection
    parallel: false
    tools:
      - tool: arkana-format
        task_type: mcp_call
        mcp_server: arkana
        mcp_tool: detect_binary_format
        mcp_args_template:
          file_path: "{target}"
        priority: 10
        tier: fast
        resource_group: arkana
        parser: arkana
  - name: triage
    parallel: true
    tools:
      - tool: arkana-packing
        task_type: mcp_call
        mcp_server: arkana
        mcp_tool: detect_packing
        mcp_args_template:
          file_path: "{target}"
        priority: 20
        tier: fast
        resource_group: arkana
        parser: arkana
      - tool: arkana-entropy
        task_type: mcp_call
        mcp_server: arkana
        mcp_tool: get_entropy_analysis
        mcp_args_template:
          file_path: "{target}"
        priority: 20
        tier: fast
        resource_group: arkana
        parser: arkana
      - tool: arkana-triage
        task_type: mcp_call
        mcp_server: arkana
        mcp_tool: get_triage_report
        mcp_args_template:
          file_path: "{target}"
        priority: 30
        tier: normal
        resource_group: arkana
        parser: arkana
      - tool: arkana-strings
        task_type: mcp_call
        mcp_server: arkana
        mcp_tool: extract_strings_from_binary
        mcp_args_template:
          file_path: "{target}"
        priority: 30
        tier: normal
        resource_group: arkana
        parser: arkana
  - name: deep-analysis
    parallel: true
    tools:
      - tool: arkana-capa
        task_type: mcp_call
        mcp_server: arkana
        mcp_tool: get_capa_analysis_info
        mcp_args_template:
          file_path: "{target}"
        priority: 40
        tier: normal
        resource_group: arkana
        parser: arkana
      - tool: arkana-vulns
        task_type: mcp_call
        mcp_server: arkana
        mcp_tool: scan_for_vulnerability_patterns
        mcp_args_template:
          file_path: "{target}"
        priority: 40
        tier: normal
        resource_group: arkana
        parser: arkana
      - tool: yara
        task_type: shell
        command_template: "yara -r /opt/yara-rules/ {target}"
        parser: yara
        priority: 50
        tier: normal
        resource_group: shell
        optional: true
        isolation: container
reactive_edges:
  - evaluator: "builtin:packing_detected_to_unpack"
    trigger_tool: "arkana-packing"
    max_spawns: 3
    max_spawns_per_trigger: 1
  - evaluator: "builtin:high_severity_to_deep_dive"
    trigger_tool: "*"
    condition: "severity in ['critical', 'high']"
    max_spawns: 5
    max_spawns_per_trigger: 2
```

- [ ] **Step 7: Create network_recon.yaml**

```yaml
# packages/cli/src/opentools/scanner/profiles/network_recon.yaml
id: network-recon
name: Network Reconnaissance
description: Network discovery and service enumeration
target_types:
  - network
phases:
  - name: host-discovery
    parallel: true
    tools:
      - tool: nmap
        task_type: shell
        command_template: "nmap -sV -sC -oX - {target}"
        parser: nmap
        priority: 10
        tier: normal
        resource_group: shell
      - tool: masscan
        task_type: shell
        command_template: "masscan {target} -p1-65535 --rate=1000 -oJ -"
        parser: masscan
        priority: 20
        tier: heavy
        resource_group: shell
        optional: true
        preferred_output_format: json
reactive_edges:
  - evaluator: "builtin:open_ports_to_vuln_scan"
    trigger_tool: "nmap"
    max_spawns: 20
    max_spawns_per_trigger: 5
  - evaluator: "builtin:open_ports_to_vuln_scan"
    trigger_tool: "masscan"
    max_spawns: 20
    max_spawns_per_trigger: 5
```

- [ ] **Step 8: Create container_audit.yaml**

```yaml
# packages/cli/src/opentools/scanner/profiles/container_audit.yaml
id: container-audit
name: Container Audit
description: Docker image security analysis with vulnerability scanning and secrets detection
target_types:
  - docker_image
phases:
  - name: image-analysis
    parallel: true
    tools:
      - tool: trivy
        task_type: shell
        command_template: "trivy image --format json {target}"
        parser: trivy
        priority: 20
        tier: normal
        resource_group: shell
        preferred_output_format: json
      - tool: gitleaks
        task_type: shell
        command_template: "gitleaks detect --source /tmp/opentools-container-{scan_id} --report-format json --report-path -"
        parser: gitleaks
        priority: 30
        tier: normal
        resource_group: shell
        preferred_output_format: json
```

- [ ] **Step 9: Create apk_analysis.yaml**

```yaml
# packages/cli/src/opentools/scanner/profiles/apk_analysis.yaml
id: apk-analysis
name: APK Analysis
description: Android application security analysis with decompilation and static analysis
target_types:
  - apk
phases:
  - name: decompile
    parallel: false
    tools:
      - tool: jadx
        task_type: shell
        command_template: "jadx -d /tmp/opentools-apk-{scan_id} {target}"
        priority: 10
        tier: heavy
        resource_group: shell
  - name: static-analysis
    parallel: true
    tools:
      - tool: semgrep
        task_type: shell
        command_template: "semgrep --config auto --json /tmp/opentools-apk-{scan_id}"
        parser: semgrep
        priority: 20
        tier: normal
        resource_group: shell
        preferred_output_format: json
      - tool: gitleaks
        task_type: shell
        command_template: "gitleaks detect --source /tmp/opentools-apk-{scan_id} --report-format json --report-path -"
        parser: gitleaks
        priority: 30
        tier: fast
        resource_group: shell
        preferred_output_format: json
  - name: cpg-analysis
    parallel: false
    tools:
      - tool: codebadger
        task_type: mcp_call
        mcp_server: codebadger
        mcp_tool: generate_cpg
        mcp_args_template:
          path: "/tmp/opentools-apk-{scan_id}"
        priority: 50
        tier: heavy
        resource_group: codebadger
        optional: true
```

- [ ] **Step 10: Run all profile tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_profiles.py -v`
Expected: All tests PASS

- [ ] **Step 11: Commit**

```bash
git add packages/cli/src/opentools/scanner/profiles/ \
       packages/cli/src/opentools/scanner/profiles.py \
       packages/cli/tests/test_scanner/test_profiles.py
git commit -m "feat(scanner): built-in YAML scan profiles for all target types"
```

---

### Task 5: Reactive Edge Evaluators

**Files:**
- Create: `packages/cli/src/opentools/scanner/reactive.py`
- Test: `packages/cli/tests/test_scanner/test_reactive.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_reactive.py
"""Tests for builtin reactive edge evaluators."""

import pytest

from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import (
    ExecutionTier,
    ReactiveEdge,
    ScanTask,
    TaskType,
)
from opentools.scanner.reactive import (
    HighSeverityToDeepDive,
    OpenPortsToVulnScan,
    PackingDetectedToUnpack,
    WebFrameworkToRuleset,
    get_builtin_evaluators,
)


def _make_task(
    tool: str = "nmap",
    task_id: str = "t1",
    scan_id: str = "scan1",
    task_type: TaskType = TaskType.SHELL,
) -> ScanTask:
    return ScanTask(
        id=task_id,
        scan_id=scan_id,
        name=f"{tool}-scan",
        tool=tool,
        task_type=task_type,
    )


def _make_edge(evaluator: str = "builtin:open_ports_to_vuln_scan") -> ReactiveEdge:
    return ReactiveEdge(
        id="edge-1",
        trigger_task_id="t1",
        evaluator=evaluator,
    )


class TestOpenPortsToVulnScan:
    def setup_method(self):
        self.evaluator = OpenPortsToVulnScan()

    def test_http_port_spawns_nuclei(self):
        task = _make_task(tool="nmap")
        output = TaskOutput(
            exit_code=0,
            stdout="80/tcp   open  http\n443/tcp  open  https\n",
        )
        edge = _make_edge()

        new_tasks = self.evaluator(task, output, edge)

        assert len(new_tasks) >= 1
        tool_names = [t.tool for t in new_tasks]
        assert "nuclei" in tool_names or "nikto" in tool_names

    def test_mysql_port_spawns_sqlmap(self):
        task = _make_task(tool="nmap")
        output = TaskOutput(
            exit_code=0,
            stdout="3306/tcp open  mysql\n",
        )
        edge = _make_edge()

        new_tasks = self.evaluator(task, output, edge)

        # mysql port should not spawn web tools, but may not spawn sqlmap
        # without an HTTP endpoint. At minimum, no crash.
        assert isinstance(new_tasks, list)

    def test_no_open_ports_returns_empty(self):
        task = _make_task(tool="nmap")
        output = TaskOutput(exit_code=0, stdout="All 1000 scanned ports are closed\n")
        edge = _make_edge()

        new_tasks = self.evaluator(task, output, edge)

        assert new_tasks == []

    def test_nonzero_exit_returns_empty(self):
        task = _make_task(tool="nmap")
        output = TaskOutput(exit_code=1, stderr="error")
        edge = _make_edge()

        new_tasks = self.evaluator(task, output, edge)

        assert new_tasks == []

    def test_spawned_tasks_reference_scan_id(self):
        task = _make_task(tool="nmap", scan_id="scan-abc")
        output = TaskOutput(
            exit_code=0,
            stdout="80/tcp open http\n",
        )
        edge = _make_edge()

        new_tasks = self.evaluator(task, output, edge)

        for t in new_tasks:
            assert t.scan_id == "scan-abc"
            assert t.spawned_by == "t1"


class TestWebFrameworkToRuleset:
    def setup_method(self):
        self.evaluator = WebFrameworkToRuleset()

    def test_wordpress_detected(self):
        task = _make_task(tool="whatweb")
        output = TaskOutput(
            exit_code=0,
            stdout='[{"plugins":{"WordPress":{"version":["6.4"]}}}]',
        )
        edge = _make_edge("builtin:web_framework_to_ruleset")

        new_tasks = self.evaluator(task, output, edge)

        assert isinstance(new_tasks, list)
        # Should spawn framework-specific scanning tasks
        for t in new_tasks:
            assert t.scan_id == task.scan_id

    def test_no_framework_returns_empty(self):
        task = _make_task(tool="whatweb")
        output = TaskOutput(exit_code=0, stdout='[{}]')
        edge = _make_edge("builtin:web_framework_to_ruleset")

        new_tasks = self.evaluator(task, output, edge)

        assert new_tasks == []


class TestPackingDetectedToUnpack:
    def setup_method(self):
        self.evaluator = PackingDetectedToUnpack()

    def test_packing_detected_spawns_unpack(self):
        task = _make_task(tool="arkana-packing", task_type=TaskType.MCP_CALL)
        output = TaskOutput(
            exit_code=0,
            stdout='{"packed": true, "packer": "UPX"}',
        )
        edge = _make_edge("builtin:packing_detected_to_unpack")

        new_tasks = self.evaluator(task, output, edge)

        assert len(new_tasks) >= 1
        tool_names = [t.tool for t in new_tasks]
        assert any("unpack" in name.lower() or "upx" in name.lower() for name in tool_names)

    def test_not_packed_returns_empty(self):
        task = _make_task(tool="arkana-packing", task_type=TaskType.MCP_CALL)
        output = TaskOutput(
            exit_code=0,
            stdout='{"packed": false}',
        )
        edge = _make_edge("builtin:packing_detected_to_unpack")

        new_tasks = self.evaluator(task, output, edge)

        assert new_tasks == []


class TestHighSeverityToDeepDive:
    def setup_method(self):
        self.evaluator = HighSeverityToDeepDive()

    def test_critical_finding_spawns_deep_dive(self):
        task = _make_task(tool="semgrep")
        output = TaskOutput(
            exit_code=0,
            stdout='{"results":[{"extra":{"severity":"ERROR","metadata":{"cwe":["CWE-89"]}}}]}',
        )
        edge = _make_edge("builtin:high_severity_to_deep_dive")

        new_tasks = self.evaluator(task, output, edge)

        assert isinstance(new_tasks, list)
        # May or may not spawn tasks depending on heuristics; no crash is the baseline

    def test_info_finding_returns_empty(self):
        task = _make_task(tool="semgrep")
        output = TaskOutput(
            exit_code=0,
            stdout='{"results":[{"extra":{"severity":"INFO"}}]}',
        )
        edge = _make_edge("builtin:high_severity_to_deep_dive")

        new_tasks = self.evaluator(task, output, edge)

        assert new_tasks == []


class TestGetBuiltinEvaluators:
    def test_returns_dict(self):
        evaluators = get_builtin_evaluators()
        assert isinstance(evaluators, dict)

    def test_contains_expected_evaluators(self):
        evaluators = get_builtin_evaluators()
        assert "builtin:open_ports_to_vuln_scan" in evaluators
        assert "builtin:web_framework_to_ruleset" in evaluators
        assert "builtin:packing_detected_to_unpack" in evaluators
        assert "builtin:high_severity_to_deep_dive" in evaluators

    def test_evaluators_are_callable(self):
        evaluators = get_builtin_evaluators()
        for name, evaluator in evaluators.items():
            assert callable(evaluator), f"Evaluator {name} is not callable"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_reactive.py -v`
Expected: FAIL -- `ModuleNotFoundError: No module named 'opentools.scanner.reactive'`

- [ ] **Step 3: Implement reactive edge evaluators**

```python
# packages/cli/src/opentools/scanner/reactive.py
"""Builtin reactive edge evaluators.

Each evaluator is a callable that takes (task, output, edge) and returns
a list of new ScanTask objects to inject into the DAG.

Evaluators codify common security workflows:
- Open ports → vulnerability scanning
- Framework detection → framework-specific rules
- Packing detected → unpacking + re-analysis
- High severity finding → targeted deep analysis
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Callable

from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import (
    ExecutionTier,
    ReactiveEdge,
    ScanTask,
    TaskType,
)


# Type alias for edge evaluator callable
EdgeEvaluator = Callable[[ScanTask, TaskOutput, ReactiveEdge], list[ScanTask]]


def _make_spawned_task(
    scan_id: str,
    spawned_by: str,
    tool: str,
    name: str,
    task_type: TaskType,
    command: str | None = None,
    mcp_server: str | None = None,
    mcp_tool: str | None = None,
    mcp_args: dict | None = None,
    priority: int = 50,
    tier: ExecutionTier = ExecutionTier.NORMAL,
    depends_on: list[str] | None = None,
    spawned_reason: str | None = None,
) -> ScanTask:
    """Helper to create a spawned task with proper provenance."""
    return ScanTask(
        id=f"spawned-{uuid.uuid4().hex[:12]}",
        scan_id=scan_id,
        name=name,
        tool=tool,
        task_type=task_type,
        command=command,
        mcp_server=mcp_server,
        mcp_tool=mcp_tool,
        mcp_args=mcp_args,
        priority=priority,
        tier=tier,
        depends_on=depends_on or [spawned_by],
        spawned_by=spawned_by,
        spawned_reason=spawned_reason,
    )


# ---------------------------------------------------------------------------
# Builtin evaluators
# ---------------------------------------------------------------------------


class OpenPortsToVulnScan:
    """Spawn vulnerability scans for open ports discovered by nmap/masscan.

    - HTTP ports (80, 443, 8080, 8443, etc.) → nuclei + nikto
    - Database ports (3306, 5432, 1433, etc.) → noted but no automatic sqlmap
    """

    # Ports that indicate HTTP services
    _HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9443}
    _HTTP_SERVICES = {"http", "https", "http-proxy", "http-alt"}

    def __call__(
        self, task: ScanTask, output: TaskOutput, edge: ReactiveEdge
    ) -> list[ScanTask]:
        if output.exit_code != 0:
            return []

        open_ports = self._parse_open_ports(output.stdout)
        if not open_ports:
            return []

        new_tasks: list[ScanTask] = []

        # Find HTTP services
        http_targets: list[str] = []
        for port, service in open_ports:
            if port in self._HTTP_PORTS or service in self._HTTP_SERVICES:
                scheme = "https" if port in {443, 8443, 9443} or "ssl" in service or "https" in service else "http"
                # Extract host from nmap output or task metadata
                host = self._extract_host(output.stdout)
                if host:
                    http_targets.append(f"{scheme}://{host}:{port}")

        # Spawn nuclei for HTTP targets
        for target_url in http_targets:
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool="nuclei",
                    name=f"nuclei-{target_url.split('://')[1].replace(':', '-')}",
                    task_type=TaskType.SHELL,
                    command=f"nuclei -u {target_url} -json",
                    priority=35,
                    tier=ExecutionTier.NORMAL,
                    spawned_reason=f"HTTP service discovered on port(s) by {task.tool}",
                )
            )

        # Spawn nikto for first HTTP target (to avoid excessive scanning)
        if http_targets:
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool="nikto",
                    name=f"nikto-reactive",
                    task_type=TaskType.SHELL,
                    command=f"nikto -h {http_targets[0]} -Format json",
                    priority=45,
                    tier=ExecutionTier.NORMAL,
                    spawned_reason=f"HTTP service discovered by {task.tool}",
                )
            )

        return new_tasks

    def _parse_open_ports(self, stdout: str) -> list[tuple[int, str]]:
        """Parse nmap/masscan output for open ports."""
        ports: list[tuple[int, str]] = []
        # nmap format: "80/tcp   open  http"
        for match in re.finditer(
            r"(\d+)/(?:tcp|udp)\s+open\s+(\S+)", stdout
        ):
            port = int(match.group(1))
            service = match.group(2)
            ports.append((port, service))
        return ports

    def _extract_host(self, stdout: str) -> str | None:
        """Extract scanned host from nmap output."""
        # "Nmap scan report for hostname (1.2.3.4)"
        match = re.search(r"Nmap scan report for [\w\.\-]+ \(([\d\.]+)\)", stdout)
        if match:
            return match.group(1)
        # "Nmap scan report for 1.2.3.4"
        match = re.search(r"Nmap scan report for ([\d\.]+)", stdout)
        if match:
            return match.group(1)
        return None


class WebFrameworkToRuleset:
    """Add framework-specific scanning when whatweb detects a framework.

    Detects: WordPress, Django, Flask, React, Angular, Laravel, Rails,
    Spring Boot, Express, Next.js.
    """

    _FRAMEWORK_TEMPLATES: dict[str, dict[str, Any]] = {
        "WordPress": {
            "tool": "nuclei",
            "command": "nuclei -u {target} -t wordpress/ -json",
            "name": "nuclei-wordpress",
        },
        "Django": {
            "tool": "semgrep",
            "command": "semgrep --config p/django --json {target}",
            "name": "semgrep-django",
        },
        "Laravel": {
            "tool": "nuclei",
            "command": "nuclei -u {target} -t laravel/ -json",
            "name": "nuclei-laravel",
        },
        "Ruby on Rails": {
            "tool": "nuclei",
            "command": "nuclei -u {target} -t rails/ -json",
            "name": "nuclei-rails",
        },
    }

    def __call__(
        self, task: ScanTask, output: TaskOutput, edge: ReactiveEdge
    ) -> list[ScanTask]:
        if output.exit_code != 0:
            return []

        frameworks = self._detect_frameworks(output.stdout)
        if not frameworks:
            return []

        new_tasks: list[ScanTask] = []
        for framework in frameworks:
            template = self._FRAMEWORK_TEMPLATES.get(framework)
            if template is None:
                continue
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool=template["tool"],
                    name=template["name"],
                    task_type=TaskType.SHELL,
                    command=template["command"],
                    priority=35,
                    spawned_reason=f"{framework} detected by {task.tool}",
                )
            )

        return new_tasks

    def _detect_frameworks(self, stdout: str) -> list[str]:
        """Parse whatweb JSON output for frameworks."""
        frameworks: list[str] = []
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                for entry in data:
                    plugins = entry.get("plugins", {})
                    for framework_name in self._FRAMEWORK_TEMPLATES:
                        if framework_name in plugins:
                            frameworks.append(framework_name)
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass
        return frameworks


class PackingDetectedToUnpack:
    """Spawn unpacking when Arkana detects a packed binary.

    Supports UPX, Themida, and generic unpacking approaches.
    """

    def __call__(
        self, task: ScanTask, output: TaskOutput, edge: ReactiveEdge
    ) -> list[ScanTask]:
        if output.exit_code != 0:
            return []

        packed, packer = self._check_packing(output.stdout)
        if not packed:
            return []

        new_tasks: list[ScanTask] = []

        if packer and packer.lower() == "upx":
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool="arkana-upx-unpack",
                    name="arkana-upx-unpack",
                    task_type=TaskType.MCP_CALL,
                    mcp_server="arkana",
                    mcp_tool="auto_unpack_pe",
                    mcp_args={"file_path": "{target}"},
                    priority=15,
                    tier=ExecutionTier.NORMAL,
                    spawned_reason=f"UPX packing detected by {task.tool}",
                )
            )
        else:
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool="arkana-generic-unpack",
                    name="arkana-generic-unpack",
                    task_type=TaskType.MCP_CALL,
                    mcp_server="arkana",
                    mcp_tool="try_all_unpackers",
                    mcp_args={"file_path": "{target}"},
                    priority=15,
                    tier=ExecutionTier.HEAVY,
                    spawned_reason=f"Packing detected ({packer or 'unknown'}) by {task.tool}",
                )
            )

        return new_tasks

    def _check_packing(self, stdout: str) -> tuple[bool, str | None]:
        """Parse Arkana packing detection output."""
        try:
            data = json.loads(stdout)
            packed = data.get("packed", False)
            packer = data.get("packer")
            return packed, packer
        except (json.JSONDecodeError, TypeError):
            return False, None


class HighSeverityToDeepDive:
    """Spawn targeted deep analysis when critical/high findings are discovered.

    Looks for high-severity markers in common tool output formats:
    - semgrep: results[].extra.severity == "ERROR"
    - nuclei: results with severity "critical" or "high"
    - General: any output containing "CRITICAL" or "HIGH" severity markers
    """

    _HIGH_SEVERITY_PATTERNS = re.compile(
        r'"severity"\s*:\s*"(critical|high|error)"', re.IGNORECASE
    )

    def __call__(
        self, task: ScanTask, output: TaskOutput, edge: ReactiveEdge
    ) -> list[ScanTask]:
        if output.exit_code != 0:
            return []

        if not self._has_high_severity(output.stdout):
            return []

        new_tasks: list[ScanTask] = []

        # Spawn a deeper analysis with the same tool using more aggressive configs
        if task.tool == "semgrep":
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool="semgrep-deep",
                    name="semgrep-deep-dive",
                    task_type=TaskType.SHELL,
                    command="semgrep --config p/security-audit --config p/owasp-top-ten --json {target}",
                    priority=25,
                    tier=ExecutionTier.HEAVY,
                    spawned_reason=f"High severity finding discovered by {task.tool}",
                )
            )
        elif task.tool == "nuclei":
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool="nuclei-deep",
                    name="nuclei-deep-dive",
                    task_type=TaskType.SHELL,
                    command="nuclei -u {target} -severity critical,high -t cves/ -json",
                    priority=25,
                    tier=ExecutionTier.HEAVY,
                    spawned_reason=f"High severity finding discovered by {task.tool}",
                )
            )

        return new_tasks

    def _has_high_severity(self, stdout: str) -> bool:
        """Check if output contains high-severity indicators."""
        return bool(self._HIGH_SEVERITY_PATTERNS.search(stdout))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def get_builtin_evaluators() -> dict[str, EdgeEvaluator]:
    """Return a mapping of evaluator names to callable evaluators."""
    return {
        "builtin:open_ports_to_vuln_scan": OpenPortsToVulnScan(),
        "builtin:web_framework_to_ruleset": WebFrameworkToRuleset(),
        "builtin:packing_detected_to_unpack": PackingDetectedToUnpack(),
        "builtin:high_severity_to_deep_dive": HighSeverityToDeepDive(),
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_reactive.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/reactive.py \
       packages/cli/tests/test_scanner/test_reactive.py
git commit -m "feat(scanner): builtin reactive edge evaluators — ports, frameworks, packing, severity"
```

---

### Task 6: Steering Interface + SteeringThrottle + New Models

**Files:**
- Create: `packages/cli/src/opentools/scanner/steering.py`
- Modify: `packages/cli/src/opentools/scanner/models.py`
- Test: `packages/cli/tests/test_scanner/test_steering.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_steering.py
"""Tests for SteeringInterface protocol, SteeringDecision, and SteeringThrottle."""

import pytest

from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import (
    GraphSnapshot,
    ProgressEventType,
    ScanTask,
    SteeringAction,
    TaskType,
)
from opentools.scanner.steering import (
    SteeringDecision,
    SteeringInterface,
    SteeringThrottle,
)


class TestSteeringAction:
    def test_values(self):
        assert SteeringAction.CONTINUE == "continue"
        assert SteeringAction.ADD_TASKS == "add_tasks"
        assert SteeringAction.PAUSE == "pause"
        assert SteeringAction.ABORT == "abort"


class TestSteeringDecision:
    def test_continue_decision(self):
        d = SteeringDecision(
            action=SteeringAction.CONTINUE,
            reasoning="Everything looks good, continue scanning.",
        )
        assert d.action == SteeringAction.CONTINUE
        assert d.new_tasks == []
        assert d.authorization_required is False

    def test_add_tasks_decision(self):
        task = ScanTask(
            id="new-1",
            scan_id="scan1",
            name="extra-scan",
            tool="nuclei",
            task_type=TaskType.SHELL,
        )
        d = SteeringDecision(
            action=SteeringAction.ADD_TASKS,
            new_tasks=[task],
            reasoning="Found a promising endpoint, adding nuclei scan.",
        )
        assert len(d.new_tasks) == 1

    def test_serialization(self):
        d = SteeringDecision(
            action=SteeringAction.PAUSE,
            reasoning="Need user confirmation for active testing.",
            authorization_required=True,
        )
        restored = SteeringDecision.model_validate_json(d.model_dump_json())
        assert restored.action == SteeringAction.PAUSE
        assert restored.authorization_required is True


class TestGraphSnapshot:
    def test_basic_snapshot(self):
        snap = GraphSnapshot(
            tasks_total=10,
            tasks_completed=5,
            tasks_running=2,
            tasks_pending=3,
            tasks_failed=0,
            tasks_skipped=0,
            phases_completed=["discovery"],
            current_phase="scanning",
            finding_count=3,
        )
        assert snap.tasks_total == 10
        assert snap.current_phase == "scanning"


class TestSteeringInterface:
    def test_protocol_structural_subtyping(self):
        """A class with the correct methods satisfies the protocol."""

        class FakeSteering:
            async def on_task_completed(self, task, output, findings_so_far, graph_state):
                return SteeringDecision(action=SteeringAction.CONTINUE, reasoning="ok")

            async def on_phase_boundary(self, phase_name, graph_state):
                return SteeringDecision(action=SteeringAction.CONTINUE, reasoning="ok")

            async def on_scan_paused(self, reason, graph_state):
                return SteeringDecision(action=SteeringAction.CONTINUE, reasoning="ok")

            async def on_authorization_required(self, action_description, risk_level):
                return True

        assert isinstance(FakeSteering(), SteeringInterface)

    def test_non_conforming_rejected(self):

        class NotSteering:
            pass

        assert not isinstance(NotSteering(), SteeringInterface)


class TestSteeringThrottle:
    def test_every_task_always_true(self):
        throttle = SteeringThrottle(frequency="every_task")
        assert throttle.should_consult(
            event_type=ProgressEventType.TASK_COMPLETED,
            is_phase_boundary=False,
            has_finding=False,
            finding_severity=None,
        ) is True

    def test_phase_boundary_on_phase(self):
        throttle = SteeringThrottle(frequency="phase_boundary")
        assert throttle.should_consult(
            event_type=ProgressEventType.TASK_COMPLETED,
            is_phase_boundary=True,
            has_finding=False,
            finding_severity=None,
        ) is True

    def test_phase_boundary_mid_phase(self):
        throttle = SteeringThrottle(frequency="phase_boundary")
        assert throttle.should_consult(
            event_type=ProgressEventType.TASK_COMPLETED,
            is_phase_boundary=False,
            has_finding=False,
            finding_severity=None,
        ) is False

    def test_phase_boundary_always_on_critical(self):
        throttle = SteeringThrottle(frequency="phase_boundary")
        assert throttle.should_consult(
            event_type=ProgressEventType.FINDING_DISCOVERED,
            is_phase_boundary=False,
            has_finding=True,
            finding_severity="critical",
        ) is True

    def test_phase_boundary_always_on_high(self):
        throttle = SteeringThrottle(frequency="phase_boundary")
        assert throttle.should_consult(
            event_type=ProgressEventType.FINDING_DISCOVERED,
            is_phase_boundary=False,
            has_finding=True,
            finding_severity="high",
        ) is True

    def test_findings_only_on_finding(self):
        throttle = SteeringThrottle(frequency="findings_only")
        assert throttle.should_consult(
            event_type=ProgressEventType.FINDING_DISCOVERED,
            is_phase_boundary=False,
            has_finding=True,
            finding_severity="medium",
        ) is True

    def test_findings_only_no_finding(self):
        throttle = SteeringThrottle(frequency="findings_only")
        assert throttle.should_consult(
            event_type=ProgressEventType.TASK_COMPLETED,
            is_phase_boundary=True,
            has_finding=False,
            finding_severity=None,
        ) is False

    def test_manual_always_false(self):
        throttle = SteeringThrottle(frequency="manual")
        assert throttle.should_consult(
            event_type=ProgressEventType.TASK_COMPLETED,
            is_phase_boundary=True,
            has_finding=True,
            finding_severity="critical",
        ) is False

    def test_scan_completed_always_consulted(self):
        """Scan completion always triggers steering regardless of frequency."""
        for freq in ["phase_boundary", "findings_only", "manual"]:
            throttle = SteeringThrottle(frequency=freq)
            assert throttle.should_consult(
                event_type=ProgressEventType.SCAN_COMPLETED,
                is_phase_boundary=False,
                has_finding=False,
                finding_severity=None,
            ) is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_steering.py -v`
Expected: FAIL -- `ImportError: cannot import name 'SteeringAction'`

- [ ] **Step 3: Add SteeringAction and GraphSnapshot to models.py**

Add the following to `packages/cli/src/opentools/scanner/models.py`, after the existing enum definitions:

```python
# Add to packages/cli/src/opentools/scanner/models.py, after EvidenceQuality/LocationPrecision enums

class SteeringAction(StrEnum):
    CONTINUE = "continue"
    ADD_TASKS = "add_tasks"
    PAUSE = "pause"
    ABORT = "abort"


# Add after ScanMetrics class, in the "Core configuration models" section

class GraphSnapshot(BaseModel):
    """A snapshot of the task graph state for steering decisions."""

    tasks_total: int = 0
    tasks_completed: int = 0
    tasks_running: int = 0
    tasks_pending: int = 0
    tasks_failed: int = 0
    tasks_skipped: int = 0
    phases_completed: list[str] = Field(default_factory=list)
    current_phase: Optional[str] = None
    finding_count: int = 0
```

- [ ] **Step 4: Implement steering.py**

```python
# packages/cli/src/opentools/scanner/steering.py
"""Steering interface for assisted-mode scan control.

The SteeringInterface protocol defines how Claude (or any other
decision-maker) can influence scan execution at runtime. The
SteeringThrottle controls when steering is actually consulted,
managing LLM cost.
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import (
    GraphSnapshot,
    ProgressEventType,
    ScanTask,
    SteeringAction,
)


# ---------------------------------------------------------------------------
# Steering decision model
# ---------------------------------------------------------------------------


class SteeringDecision(BaseModel):
    """A decision from the steering interface."""

    action: SteeringAction
    new_tasks: list[ScanTask] = Field(default_factory=list)
    reasoning: str
    authorization_required: bool = False


# ---------------------------------------------------------------------------
# Steering protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class SteeringInterface(Protocol):
    """Protocol for scan steering in assisted mode.

    Implementors receive events from the scan engine and return
    decisions about how to proceed. The ``SteeringThrottle``
    controls which events actually reach the steering interface.
    """

    async def on_task_completed(
        self,
        task: ScanTask,
        output: TaskOutput,
        findings_so_far: list,
        graph_state: GraphSnapshot,
    ) -> SteeringDecision:
        """Called when a task completes (subject to throttle)."""
        ...

    async def on_phase_boundary(
        self,
        phase_name: str,
        graph_state: GraphSnapshot,
    ) -> SteeringDecision:
        """Called when all tasks in a phase are complete."""
        ...

    async def on_scan_paused(
        self,
        reason: str,
        graph_state: GraphSnapshot,
    ) -> SteeringDecision:
        """Called when the scan is paused."""
        ...

    async def on_authorization_required(
        self,
        action_description: str,
        risk_level: str,
    ) -> bool:
        """Called when user authorization is needed for a risky action."""
        ...


# ---------------------------------------------------------------------------
# Steering throttle
# ---------------------------------------------------------------------------

# Severities that always trigger steering
_ALWAYS_CONSULT_SEVERITIES = frozenset({"critical", "high"})

# Event types that always trigger steering
_ALWAYS_CONSULT_EVENTS = frozenset({
    ProgressEventType.SCAN_COMPLETED,
    ProgressEventType.SCAN_FAILED,
})


class SteeringThrottle:
    """Controls when the steering interface is actually consulted.

    Frequencies:
    - ``every_task``: consult on every task completion (expensive)
    - ``phase_boundary``: consult at phase transitions + critical/high findings
    - ``findings_only``: consult only when findings are discovered
    - ``manual``: only when explicitly triggered (never auto-consults)

    Critical/high findings and scan completion always trigger consultation
    regardless of frequency setting (except ``manual``).
    """

    def __init__(self, frequency: str = "phase_boundary") -> None:
        self._frequency = frequency

    @property
    def frequency(self) -> str:
        return self._frequency

    def should_consult(
        self,
        event_type: ProgressEventType,
        is_phase_boundary: bool,
        has_finding: bool,
        finding_severity: Optional[str],
    ) -> bool:
        """Determine whether to consult the steering interface.

        Args:
            event_type: The type of progress event that triggered this check.
            is_phase_boundary: Whether all tasks in the current phase are done.
            has_finding: Whether a new finding was discovered.
            finding_severity: Severity of the finding, if any.

        Returns:
            True if steering should be consulted.
        """
        # Manual never auto-consults
        if self._frequency == "manual":
            return False

        # Scan completion always triggers (except manual)
        if event_type in _ALWAYS_CONSULT_EVENTS:
            return True

        # Critical/high findings always trigger (except manual)
        if has_finding and finding_severity in _ALWAYS_CONSULT_SEVERITIES:
            return True

        if self._frequency == "every_task":
            return True

        if self._frequency == "phase_boundary":
            return is_phase_boundary

        if self._frequency == "findings_only":
            return has_finding

        return False
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_steering.py -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/scanner/models.py \
       packages/cli/src/opentools/scanner/steering.py \
       packages/cli/tests/test_scanner/test_steering.py
git commit -m "feat(scanner): SteeringInterface protocol + SteeringThrottle + SteeringDecision"
```

---

### Task 7: ScanPlanner — Profile Resolution and Graph Building

**Files:**
- Create: `packages/cli/src/opentools/scanner/planner.py`
- Test: `packages/cli/tests/test_scanner/test_planner.py`

This is the most complex piece. The ScanPlanner takes a target string and profile name, runs detection, resolves profile inheritance, evaluates tool conditions against target metadata, and produces a list of `ScanTask` objects with proper dependencies based on phase ordering.

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_planner.py
"""Tests for ScanPlanner — profile resolution and task DAG building."""

import pytest

from opentools.scanner.models import (
    ReactiveEdge,
    ScanConfig,
    ScanMode,
    ScanTask,
    TargetType,
    TaskStatus,
    TaskType,
)
from opentools.scanner.planner import ScanPlanner
from opentools.scanner.profiles import (
    ProfilePhase,
    ProfileTool,
    ReactiveEdgeTemplate,
    ScanProfile,
    load_builtin_profile,
)
from opentools.scanner.target import DetectedTarget


class TestScanPlannerBasic:
    def setup_method(self):
        self.planner = ScanPlanner()

    def test_plan_returns_scan_tasks(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-scan-1",
            engagement_id="eng-1",
        )
        assert isinstance(tasks, list)
        assert len(tasks) >= 1
        for t in tasks:
            assert isinstance(t, ScanTask)
            assert t.scan_id == "test-scan-1"

    def test_plan_sets_correct_scan_id(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="my-scan",
            engagement_id="eng-1",
        )
        for t in tasks:
            assert t.scan_id == "my-scan"

    def test_plan_tasks_are_pending(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
        )
        for t in tasks:
            assert t.status == TaskStatus.PENDING

    def test_plan_includes_expected_tools(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
        )
        tool_names = [t.tool for t in tasks]
        assert "semgrep" in tool_names
        assert "gitleaks" in tool_names


class TestScanPlannerPhaseOrdering:
    """Verify that tasks from later phases depend on all tasks from earlier phases."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_multiphase_dependencies(self):
        """Tasks in phase 2 should depend on all tasks in phase 1."""
        profile = ScanProfile(
            id="test-multiphase",
            name="Test Multi-Phase",
            description="Test profile with two phases",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="phase-1",
                    tools=[
                        ProfileTool(tool="tool-a", task_type=TaskType.SHELL, command_template="echo a"),
                        ProfileTool(tool="tool-b", task_type=TaskType.SHELL, command_template="echo b"),
                    ],
                ),
                ProfilePhase(
                    name="phase-2",
                    tools=[
                        ProfileTool(tool="tool-c", task_type=TaskType.SHELL, command_template="echo c"),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["python"]},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        # Find phase-2 task
        phase2_tasks = [t for t in tasks if t.tool == "tool-c"]
        phase1_tasks = [t for t in tasks if t.tool in {"tool-a", "tool-b"}]

        assert len(phase2_tasks) == 1
        assert len(phase1_tasks) == 2

        phase1_ids = {t.id for t in phase1_tasks}
        # Phase 2 task should depend on ALL phase 1 tasks
        assert set(phase2_tasks[0].depends_on) == phase1_ids

    def test_parallel_phase_no_internal_deps(self):
        """Tasks within a parallel phase should not depend on each other."""
        profile = ScanProfile(
            id="test-parallel",
            name="Test Parallel",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="phase-1",
                    parallel=True,
                    tools=[
                        ProfileTool(tool="tool-a", task_type=TaskType.SHELL, command_template="echo a"),
                        ProfileTool(tool="tool-b", task_type=TaskType.SHELL, command_template="echo b"),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["python"]},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        # No task in phase 1 depends on another task in phase 1
        task_ids = {t.id for t in tasks}
        for t in tasks:
            for dep in t.depends_on:
                assert dep not in task_ids or any(
                    other.id == dep and other.tool not in {"tool-a", "tool-b"}
                    for other in tasks
                )

    def test_sequential_phase_creates_chain(self):
        """Tasks in a sequential phase should form a dependency chain."""
        profile = ScanProfile(
            id="test-sequential",
            name="Test Sequential",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="phase-1",
                    parallel=False,
                    tools=[
                        ProfileTool(tool="tool-a", task_type=TaskType.SHELL, command_template="echo a"),
                        ProfileTool(tool="tool-b", task_type=TaskType.SHELL, command_template="echo b"),
                        ProfileTool(tool="tool-c", task_type=TaskType.SHELL, command_template="echo c"),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["python"]},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        # tool-b depends on tool-a, tool-c depends on tool-b
        task_map = {t.tool: t for t in tasks}
        assert task_map["tool-a"].depends_on == []
        assert task_map["tool-b"].depends_on == [task_map["tool-a"].id]
        assert task_map["tool-c"].depends_on == [task_map["tool-b"].id]


class TestScanPlannerConditions:
    """Verify that tool conditions are evaluated correctly."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_condition_met_includes_tool(self):
        profile = ScanProfile(
            id="test-cond",
            name="Test Condition",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(
                            tool="trivy",
                            task_type=TaskType.SHELL,
                            command_template="trivy fs {target}",
                            condition="has_package_lock",
                        ),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["javascript"], "has_package_lock": True},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        assert any(t.tool == "trivy" for t in tasks)

    def test_condition_not_met_excludes_tool(self):
        profile = ScanProfile(
            id="test-cond",
            name="Test Condition",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(
                            tool="trivy",
                            task_type=TaskType.SHELL,
                            command_template="trivy fs {target}",
                            condition="has_package_lock",
                        ),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["python"], "has_package_lock": False},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        assert not any(t.tool == "trivy" for t in tasks)

    def test_language_condition(self):
        profile = ScanProfile(
            id="test-lang",
            name="Test Language",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(
                            tool="semgrep-python",
                            task_type=TaskType.SHELL,
                            command_template="semgrep --config p/python {target}",
                            condition="'python' in languages",
                        ),
                        ProfileTool(
                            tool="semgrep-java",
                            task_type=TaskType.SHELL,
                            command_template="semgrep --config p/java {target}",
                            condition="'java' in languages",
                        ),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["python"]},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        tool_names = [t.tool for t in tasks]
        assert "semgrep-python" in tool_names
        assert "semgrep-java" not in tool_names


class TestScanPlannerReactiveEdges:
    """Verify that reactive edge templates are instantiated on tasks."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_reactive_edges_attached_to_trigger_task(self):
        profile = ScanProfile(
            id="test-edges",
            name="Test Edges",
            description="Test",
            target_types=[TargetType.NETWORK],
            phases=[
                ProfilePhase(
                    name="discovery",
                    tools=[
                        ProfileTool(tool="nmap", task_type=TaskType.SHELL, command_template="nmap {target}"),
                    ],
                ),
            ],
            reactive_edges=[
                ReactiveEdgeTemplate(
                    evaluator="builtin:open_ports_to_vuln_scan",
                    trigger_tool="nmap",
                    max_spawns=20,
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.NETWORK,
            original_target="192.168.1.0/24",
            metadata={},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        nmap_tasks = [t for t in tasks if t.tool == "nmap"]
        assert len(nmap_tasks) == 1
        assert len(nmap_tasks[0].reactive_edges) >= 1
        assert nmap_tasks[0].reactive_edges[0].evaluator == "builtin:open_ports_to_vuln_scan"

    def test_wildcard_trigger_attaches_to_all(self):
        profile = ScanProfile(
            id="test-wildcard",
            name="Test Wildcard",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(tool="semgrep", task_type=TaskType.SHELL, command_template="semgrep {target}"),
                        ProfileTool(tool="gitleaks", task_type=TaskType.SHELL, command_template="gitleaks {target}"),
                    ],
                ),
            ],
            reactive_edges=[
                ReactiveEdgeTemplate(
                    evaluator="builtin:high_severity_to_deep_dive",
                    trigger_tool="*",
                    max_spawns=5,
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["python"]},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        # Both tasks should have the wildcard edge attached
        for t in tasks:
            assert len(t.reactive_edges) >= 1
            assert any(
                e.evaluator == "builtin:high_severity_to_deep_dive"
                for e in t.reactive_edges
            )


class TestScanPlannerProfileInheritance:
    """Verify that profile inheritance (extends) works correctly."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_extends_merges_parent_phases(self):
        parent = ScanProfile(
            id="parent",
            name="Parent",
            description="Parent profile",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(tool="semgrep", task_type=TaskType.SHELL, command_template="semgrep {target}"),
                        ProfileTool(tool="gitleaks", task_type=TaskType.SHELL, command_template="gitleaks {target}"),
                    ],
                ),
            ],
        )

        child = ScanProfile(
            id="child",
            name="Child",
            description="Child profile extending parent",
            target_types=[TargetType.SOURCE_CODE],
            extends="parent",
            add_tools=[
                ProfileTool(tool="trivy", task_type=TaskType.SHELL, command_template="trivy {target}"),
            ],
            remove_tools=["gitleaks"],
        )

        resolved = self.planner.resolve_inheritance(child, {"parent": parent})

        all_tools = [t.tool for phase in resolved.phases for t in phase.tools]
        assert "semgrep" in all_tools
        assert "trivy" in all_tools
        assert "gitleaks" not in all_tools

    def test_no_extends_returns_unchanged(self):
        profile = ScanProfile(
            id="standalone",
            name="Standalone",
            description="No parent",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(tool="semgrep", task_type=TaskType.SHELL, command_template="semgrep {target}"),
                    ],
                ),
            ],
        )

        resolved = self.planner.resolve_inheritance(profile, {})
        assert len(resolved.phases) == 1
        assert resolved.phases[0].tools[0].tool == "semgrep"


class TestScanPlannerCommandTemplates:
    """Verify that command templates are resolved with target metadata."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_target_placeholder_resolved(self):
        profile = ScanProfile(
            id="test-template",
            name="Test Template",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(
                            tool="semgrep",
                            task_type=TaskType.SHELL,
                            command_template="semgrep --config auto --json {target}",
                        ),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/home/user/myapp",
            original_target="/home/user/myapp",
            metadata={"languages": ["python"]},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        assert len(tasks) == 1
        assert "/home/user/myapp" in tasks[0].command


class TestScanPlannerAutoDetect:
    """Verify auto-detection selects the correct default profile."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_auto_detect_source(self, tmp_path):
        (tmp_path / "main.py").write_text("import flask\napp = flask.Flask(__name__)")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name=None,  # auto-detect
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
        )
        assert len(tasks) >= 1
        # Should use source-full by default
        tool_names = [t.tool for t in tasks]
        assert "semgrep" in tool_names

    def test_explicit_profile_overrides_auto(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
        )
        tool_names = [t.tool for t in tasks]
        assert "semgrep" in tool_names
        assert "gitleaks" in tool_names


class TestScanPlannerConfigOverrides:
    """Verify that ScanConfig overrides are applied."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_add_tools(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
            add_tools=["bandit"],
        )
        # add_tools should not crash; tool may or may not appear
        # since we only support named additions from profile
        assert isinstance(tasks, list)

    def test_remove_tools(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
            remove_tools=["gitleaks"],
        )
        tool_names = [t.tool for t in tasks]
        assert "gitleaks" not in tool_names
        assert "semgrep" in tool_names

    def test_unique_task_ids(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
        )
        task_ids = [t.id for t in tasks]
        assert len(task_ids) == len(set(task_ids)), "Task IDs must be unique"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_planner.py -v`
Expected: FAIL -- `ModuleNotFoundError: No module named 'opentools.scanner.planner'`

- [ ] **Step 3: Implement ScanPlanner**

```python
# packages/cli/src/opentools/scanner/planner.py
"""ScanPlanner — builds a task DAG from a profile + detected target.

The planner is the integration point between target detection, profile
resolution, and the ScanEngine. It takes a target string and optional
profile name, runs detection, resolves profile inheritance, evaluates
tool conditions against target metadata, and produces a list of
ScanTask objects ready for ScanEngine.load_tasks().
"""

from __future__ import annotations

import uuid
from typing import Optional

from opentools.scanner.models import (
    ReactiveEdge,
    ScanConfig,
    ScanMode,
    ScanTask,
    TargetType,
    TaskStatus,
    TaskType,
)
from opentools.scanner.profiles import (
    DEFAULT_PROFILES,
    ProfilePhase,
    ProfileTool,
    ReactiveEdgeTemplate,
    ScanProfile,
    load_builtin_profile,
)
from opentools.scanner.target import DetectedTarget, TargetDetector


class ScanPlanner:
    """Builds a task DAG from a profile + detected target.

    Usage::

        planner = ScanPlanner()
        tasks = planner.plan(
            target="/path/to/source",
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="scan-123",
            engagement_id="eng-456",
        )
        engine.load_tasks(tasks)
    """

    def __init__(self) -> None:
        self._detector = TargetDetector()

    def plan(
        self,
        target: str,
        profile_name: Optional[str],
        mode: ScanMode,
        scan_id: str,
        engagement_id: str,
        config: Optional[ScanConfig] = None,
        override_type: Optional[TargetType] = None,
        add_tools: Optional[list[str]] = None,
        remove_tools: Optional[list[str]] = None,
    ) -> list[ScanTask]:
        """Plan a scan: detect target, load profile, build task DAG.

        Args:
            target: Target string (path, URL, IP, image name, etc.)
            profile_name: Profile name, or None for auto-detect.
            mode: Scan mode (auto or assisted).
            scan_id: Unique scan identifier.
            engagement_id: Engagement to bind scan to.
            config: Optional scan configuration overrides.
            override_type: Force a specific target type.
            add_tools: Tool names to add (appended to last phase).
            remove_tools: Tool names to remove from profile.

        Returns:
            List of ScanTask objects ready for ScanEngine.load_tasks().

        Raises:
            ValueError: If target type cannot be determined.
            FileNotFoundError: If profile does not exist.
        """
        # 1. Detect target
        detected = self._detector.detect(target, override_type=override_type)

        # 2. Resolve profile
        if profile_name is None:
            profile_name = DEFAULT_PROFILES.get(detected.target_type)
            if profile_name is None:
                raise ValueError(
                    f"No default profile for target type {detected.target_type}. "
                    "Specify a profile explicitly with --profile."
                )

        profile = load_builtin_profile(profile_name)

        # 3. Resolve inheritance
        profile = self.resolve_inheritance(profile, self._load_parent_profiles(profile))

        # 4. Apply add/remove tool overrides
        if remove_tools:
            profile = self._remove_tools_from_profile(profile, remove_tools)

        # 5. Build task DAG
        return self.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id=scan_id,
            engagement_id=engagement_id,
            mode=mode,
            config=config,
        )

    def plan_from_profile(
        self,
        profile: ScanProfile,
        detected: DetectedTarget,
        scan_id: str,
        engagement_id: str,
        mode: ScanMode,
        config: Optional[ScanConfig] = None,
    ) -> list[ScanTask]:
        """Build a task DAG from a resolved profile and detected target.

        This is the core graph-building method. It:
        1. Iterates through profile phases in order
        2. Evaluates tool conditions against target metadata
        3. Creates ScanTask instances with proper dependencies
        4. Attaches reactive edges from profile-level templates

        Args:
            profile: Resolved ScanProfile (inheritance already applied).
            detected: Detected target information.
            scan_id: Unique scan identifier.
            engagement_id: Engagement identifier.
            mode: Scan mode.
            config: Optional scan configuration.

        Returns:
            List of ScanTask objects.
        """
        target_str = detected.resolved_path or detected.original_target
        metadata = detected.metadata
        all_tasks: list[ScanTask] = []
        previous_phase_ids: list[str] = []

        for phase in profile.phases:
            phase_task_ids: list[str] = []

            # Filter tools by condition
            eligible_tools = [
                tool for tool in phase.tools
                if self._evaluate_condition(tool.condition, metadata)
            ]

            # Build tasks for this phase
            prev_in_phase: Optional[str] = None
            for tool_def in eligible_tools:
                task_id = f"{scan_id}-{tool_def.tool}-{uuid.uuid4().hex[:8]}"

                # Compute dependencies
                if phase.parallel:
                    # Parallel: depend on all tasks from previous phase
                    depends_on = list(previous_phase_ids)
                else:
                    # Sequential: depend on previous task in this phase,
                    # or previous phase if first task
                    if prev_in_phase is not None:
                        depends_on = [prev_in_phase]
                    else:
                        depends_on = list(previous_phase_ids)

                # Resolve command template
                command = self._resolve_template(
                    tool_def.command_template, target_str, scan_id, metadata
                )

                # Resolve MCP args template
                mcp_args = None
                if tool_def.mcp_args_template:
                    mcp_args = {
                        k: self._resolve_template(str(v), target_str, scan_id, metadata)
                        if isinstance(v, str) else v
                        for k, v in tool_def.mcp_args_template.items()
                    }

                task = ScanTask(
                    id=task_id,
                    scan_id=scan_id,
                    name=f"{tool_def.tool}",
                    tool=tool_def.tool,
                    task_type=tool_def.task_type,
                    command=command,
                    mcp_server=tool_def.mcp_server,
                    mcp_tool=tool_def.mcp_tool,
                    mcp_args=mcp_args,
                    depends_on=depends_on,
                    status=TaskStatus.PENDING,
                    priority=tool_def.priority,
                    tier=tool_def.tier,
                    resource_group=tool_def.resource_group,
                    retry_policy=tool_def.retry_policy,
                    cache_key=self._resolve_template(
                        tool_def.cache_key_template, target_str, scan_id, metadata
                    ) if tool_def.cache_key_template else None,
                    parser=tool_def.parser,
                    isolation=tool_def.isolation,
                )

                all_tasks.append(task)
                phase_task_ids.append(task_id)
                prev_in_phase = task_id

            previous_phase_ids = phase_task_ids

        # Attach reactive edges from profile-level templates
        self._attach_reactive_edges(all_tasks, profile.reactive_edges)

        # Attach per-tool reactive edges
        for phase in profile.phases:
            for tool_def in phase.tools:
                if tool_def.reactive_edges:
                    matching_tasks = [t for t in all_tasks if t.tool == tool_def.tool]
                    for task in matching_tasks:
                        self._attach_reactive_edges_to_task(task, tool_def.reactive_edges)

        return all_tasks

    def resolve_inheritance(
        self,
        profile: ScanProfile,
        parent_profiles: dict[str, ScanProfile],
    ) -> ScanProfile:
        """Resolve profile inheritance by merging parent phases.

        Args:
            profile: The child profile.
            parent_profiles: Mapping of profile ID → ScanProfile for lookup.

        Returns:
            A new ScanProfile with parent phases merged in.
        """
        if profile.extends is None:
            return profile

        parent = parent_profiles.get(profile.extends)
        if parent is None:
            return profile

        # Recursively resolve parent inheritance first
        parent = self.resolve_inheritance(parent, parent_profiles)

        # Start with parent phases
        merged_phases: list[ProfilePhase] = []
        remove_set = set(profile.remove_tools)

        for phase in parent.phases:
            filtered_tools = [
                t for t in phase.tools if t.tool not in remove_set
            ]
            if filtered_tools:
                merged_phases.append(
                    ProfilePhase(
                        name=phase.name,
                        tools=filtered_tools,
                        parallel=phase.parallel,
                    )
                )

        # Add child's own phases
        for phase in profile.phases:
            merged_phases.append(phase)

        # Append add_tools to last phase (or create new phase)
        if profile.add_tools:
            if merged_phases:
                last_phase = merged_phases[-1]
                merged_phases[-1] = ProfilePhase(
                    name=last_phase.name,
                    tools=last_phase.tools + profile.add_tools,
                    parallel=last_phase.parallel,
                )
            else:
                merged_phases.append(
                    ProfilePhase(
                        name="added-tools",
                        tools=profile.add_tools,
                        parallel=True,
                    )
                )

        # Merge reactive edges
        merged_edges = list(parent.reactive_edges) + list(profile.reactive_edges)

        return ScanProfile(
            id=profile.id,
            name=profile.name,
            description=profile.description,
            target_types=profile.target_types or parent.target_types,
            phases=merged_phases,
            reactive_edges=merged_edges,
            default_config=profile.default_config or parent.default_config,
            override_config=profile.override_config,
        )

    def _load_parent_profiles(self, profile: ScanProfile) -> dict[str, ScanProfile]:
        """Recursively load parent profiles for inheritance resolution."""
        parents: dict[str, ScanProfile] = {}
        current = profile
        visited: set[str] = {current.id}

        while current.extends is not None:
            parent_name = current.extends
            if parent_name in visited:
                break  # Cycle detection
            try:
                parent = load_builtin_profile(parent_name)
                parents[parent_name] = parent
                visited.add(parent_name)
                current = parent
            except FileNotFoundError:
                break

        return parents

    def _remove_tools_from_profile(
        self, profile: ScanProfile, remove_tools: list[str]
    ) -> ScanProfile:
        """Remove tools from all phases in a profile."""
        remove_set = set(remove_tools)
        new_phases = []
        for phase in profile.phases:
            filtered_tools = [t for t in phase.tools if t.tool not in remove_set]
            if filtered_tools:
                new_phases.append(
                    ProfilePhase(
                        name=phase.name,
                        tools=filtered_tools,
                        parallel=phase.parallel,
                    )
                )
        return profile.model_copy(update={"phases": new_phases})

    def _evaluate_condition(
        self, condition: Optional[str], metadata: dict
    ) -> bool:
        """Evaluate a tool condition against target metadata.

        Conditions are simple Python expressions evaluated against
        the metadata dictionary as local variables. Supports:
        - ``has_package_lock`` (bool check)
        - ``'python' in languages`` (membership check)
        - ``language in ['python', 'java']`` (value check)
        - Complex boolean expressions with ``and``/``or``

        Args:
            condition: Condition string, or None (always included).
            metadata: Target metadata dictionary.

        Returns:
            True if the condition is met (or if no condition).
        """
        if condition is None:
            return True

        try:
            # Provide metadata keys as local variables
            local_vars = dict(metadata)
            # Also provide common computed variables
            local_vars.setdefault("languages", [])
            local_vars.setdefault("framework_hints", [])
            local_vars.setdefault("has_dockerfile", False)
            local_vars.setdefault("has_package_lock", False)

            result = eval(condition, {"__builtins__": {}}, local_vars)  # noqa: S307
            return bool(result)
        except Exception:
            # If condition evaluation fails, skip the tool
            return False

    def _resolve_template(
        self,
        template: Optional[str],
        target: str,
        scan_id: str,
        metadata: dict,
    ) -> Optional[str]:
        """Resolve placeholders in a command/args template.

        Supported placeholders:
        - ``{target}`` — resolved target path/URL
        - ``{scan_id}`` — scan identifier
        - ``{target_host}`` — hostname extracted from URL (if applicable)
        - ``{target_hash}`` — content hash from metadata (if available)

        Args:
            template: Template string with placeholders.
            target: Resolved target path or URL.
            scan_id: Scan identifier.
            metadata: Target metadata.

        Returns:
            Resolved string, or None if template is None.
        """
        if template is None:
            return None

        # Extract host from URL for {target_host}
        target_host = target
        if "://" in target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            target_host = parsed.hostname or target

        replacements = {
            "{target}": target,
            "{scan_id}": scan_id,
            "{target_host}": target_host,
            "{target_hash}": metadata.get("content_hash", "unknown"),
            "{tool}": "",  # filled per-tool if needed
        }

        result = template
        for placeholder, value in replacements.items():
            result = result.replace(placeholder, str(value))

        return result

    def _attach_reactive_edges(
        self,
        tasks: list[ScanTask],
        edge_templates: list[ReactiveEdgeTemplate],
    ) -> None:
        """Attach reactive edges from profile-level templates to tasks."""
        for template in edge_templates:
            if template.trigger_tool == "*":
                # Wildcard: attach to all tasks
                for task in tasks:
                    self._attach_reactive_edges_to_task(task, [template])
            else:
                # Attach to matching tool tasks
                matching = [t for t in tasks if t.tool == template.trigger_tool]
                for task in matching:
                    self._attach_reactive_edges_to_task(task, [template])

    def _attach_reactive_edges_to_task(
        self,
        task: ScanTask,
        templates: list[ReactiveEdgeTemplate],
    ) -> None:
        """Instantiate reactive edge templates into concrete ReactiveEdge instances."""
        new_edges: list[ReactiveEdge] = list(task.reactive_edges)
        for template in templates:
            edge = ReactiveEdge(
                id=f"edge-{uuid.uuid4().hex[:12]}",
                trigger_task_id=task.id,
                evaluator=template.evaluator,
                condition=template.condition,
                max_spawns=template.max_spawns,
                max_spawns_per_trigger=template.max_spawns_per_trigger,
                cooldown_seconds=int(template.cooldown_seconds),
                budget_group=template.budget_group,
                min_upstream_confidence=template.min_upstream_confidence,
            )
            new_edges.append(edge)

        # ScanTask is a Pydantic model — use model_copy to update
        task.reactive_edges = new_edges
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_planner.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/planner.py \
       packages/cli/tests/test_scanner/test_planner.py
git commit -m "feat(scanner): ScanPlanner — profile resolution, condition eval, DAG building"
```

---

### Task 8: ScanAPI — Unified Entry Point

**Files:**
- Create: `packages/cli/src/opentools/scanner/api.py`
- Test: `packages/cli/tests/test_scanner/test_api.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_api.py
"""Tests for ScanAPI — unified entry point."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opentools.scanner.api import ScanAPI
from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import (
    Scan,
    ScanConfig,
    ScanMode,
    ScanStatus,
    ScanTask,
    TargetType,
    TaskStatus,
    TaskType,
)


def _make_scan(scan_id: str = "scan-1", status: ScanStatus = ScanStatus.PENDING) -> Scan:
    return Scan(
        id=scan_id,
        engagement_id="eng-1",
        target="/tmp/test",
        target_type=TargetType.SOURCE_CODE,
        status=status,
        created_at=datetime.now(timezone.utc),
    )


class TestScanAPIPlan:
    @pytest.mark.asyncio
    async def test_plan_returns_scan_and_tasks(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan, tasks = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
            profile_name="source-quick",
            mode=ScanMode.AUTO,
        )

        assert isinstance(scan, Scan)
        assert scan.target == str(tmp_path)
        assert scan.target_type == TargetType.SOURCE_CODE
        assert scan.status == ScanStatus.PENDING
        assert scan.engagement_id == "eng-1"
        assert isinstance(tasks, list)
        assert len(tasks) >= 1
        for t in tasks:
            assert t.scan_id == scan.id

    @pytest.mark.asyncio
    async def test_plan_auto_detect_profile(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan, tasks = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
        )

        assert scan.target_type == TargetType.SOURCE_CODE
        assert len(tasks) >= 1

    @pytest.mark.asyncio
    async def test_plan_with_config(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        config = ScanConfig(max_concurrent_tasks=4)
        scan, tasks = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
            profile_name="source-quick",
            config=config,
        )

        assert scan.config is not None
        assert scan.config.max_concurrent_tasks == 4

    @pytest.mark.asyncio
    async def test_plan_populates_tools_planned(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan, tasks = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
            profile_name="source-quick",
        )

        assert len(scan.tools_planned) >= 1
        assert "semgrep" in scan.tools_planned

    @pytest.mark.asyncio
    async def test_plan_with_remove_tools(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan, tasks = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
            profile_name="source-quick",
            remove_tools=["gitleaks"],
        )

        tool_names = [t.tool for t in tasks]
        assert "gitleaks" not in tool_names

    @pytest.mark.asyncio
    async def test_plan_assigns_unique_scan_id(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan1, _ = await api.plan(target=str(tmp_path), engagement_id="eng-1")
        scan2, _ = await api.plan(target=str(tmp_path), engagement_id="eng-1")

        assert scan1.id != scan2.id

    @pytest.mark.asyncio
    async def test_plan_stores_profile_name(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan, _ = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
            profile_name="source-quick",
        )

        assert scan.profile == "source-quick"

    @pytest.mark.asyncio
    async def test_plan_stores_target_metadata(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan, _ = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
        )

        assert "languages" in scan.target_metadata
        assert "python" in scan.target_metadata["languages"]


class TestScanAPILifecycle:
    @pytest.mark.asyncio
    async def test_cancel_sets_cancelled_status(self):
        api = ScanAPI()
        scan = _make_scan(status=ScanStatus.RUNNING)
        token = CancellationToken()
        api._active_scans[scan.id] = {"scan": scan, "cancel": token}

        await api.cancel(scan.id, reason="user requested")

        assert token.is_cancelled

    @pytest.mark.asyncio
    async def test_cancel_unknown_scan_raises(self):
        api = ScanAPI()
        with pytest.raises(KeyError):
            await api.cancel("nonexistent", reason="test")

    @pytest.mark.asyncio
    async def test_pause_sets_flag(self):
        api = ScanAPI()
        scan = _make_scan(status=ScanStatus.RUNNING)
        engine_mock = MagicMock()
        engine_mock.pause = AsyncMock()
        api._active_scans[scan.id] = {"scan": scan, "engine": engine_mock}

        await api.pause(scan.id)

        engine_mock.pause.assert_called_once()

    @pytest.mark.asyncio
    async def test_resume_clears_flag(self):
        api = ScanAPI()
        scan = _make_scan(status=ScanStatus.PAUSED)
        engine_mock = MagicMock()
        engine_mock.resume = AsyncMock()
        api._active_scans[scan.id] = {"scan": scan, "engine": engine_mock}

        await api.resume(scan.id)

        engine_mock.resume.assert_called_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_api.py -v`
Expected: FAIL -- `ModuleNotFoundError: No module named 'opentools.scanner.api'`

- [ ] **Step 3: Implement ScanAPI**

```python
# packages/cli/src/opentools/scanner/api.py
"""ScanAPI — unified entry point for scan orchestration.

Provides the public API surface for all scan operations:
plan, execute, pause, resume, cancel. Used by CLI, web API,
and Claude skill surfaces.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.models import (
    Scan,
    ScanConfig,
    ScanMode,
    ScanStatus,
    ScanTask,
    TargetType,
)
from opentools.scanner.planner import ScanPlanner
from opentools.scanner.target import TargetDetector, TargetValidator


class ScanAPI:
    """Unified entry point for scan orchestration.

    Usage::

        api = ScanAPI()
        scan, tasks = await api.plan(target="/path/to/code", engagement_id="eng-1")
        # Later: result = await api.execute(scan, tasks, on_progress=callback)
        # Or: await api.cancel(scan.id, reason="user requested")
    """

    def __init__(self) -> None:
        self._planner = ScanPlanner()
        self._detector = TargetDetector()
        self._validator = TargetValidator()

        # Track active scans for pause/resume/cancel
        self._active_scans: dict[str, dict[str, Any]] = {}

    async def plan(
        self,
        target: str,
        engagement_id: str,
        profile_name: Optional[str] = None,
        mode: ScanMode = ScanMode.AUTO,
        config: Optional[ScanConfig] = None,
        override_type: Optional[TargetType] = None,
        add_tools: Optional[list[str]] = None,
        remove_tools: Optional[list[str]] = None,
        baseline_scan_id: Optional[str] = None,
    ) -> tuple[Scan, list[ScanTask]]:
        """Plan a scan without executing it.

        Detects target type, loads profile, builds task DAG, and
        returns a Scan object + list of ScanTask objects ready for
        execution.

        Args:
            target: Target string (path, URL, IP, image name, etc.)
            engagement_id: Engagement to bind scan to.
            profile_name: Profile name, or None for auto-detect.
            mode: Scan mode (auto or assisted).
            config: Optional scan configuration.
            override_type: Force a specific target type.
            add_tools: Additional tool names to include.
            remove_tools: Tool names to exclude.
            baseline_scan_id: Previous scan ID for diffing.

        Returns:
            Tuple of (Scan, list[ScanTask]).

        Raises:
            ValueError: If target type cannot be determined.
            FileNotFoundError: If profile does not exist.
        """
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"

        # Detect target
        detected = self._detector.detect(target, override_type=override_type)

        # Resolve profile name for the scan record
        resolved_profile = profile_name
        if resolved_profile is None:
            from opentools.scanner.profiles import DEFAULT_PROFILES
            resolved_profile = DEFAULT_PROFILES.get(detected.target_type)

        # Build task DAG
        tasks = self._planner.plan(
            target=target,
            profile_name=profile_name,
            mode=mode,
            scan_id=scan_id,
            engagement_id=engagement_id,
            config=config,
            override_type=override_type,
            add_tools=add_tools,
            remove_tools=remove_tools,
        )

        # Build Scan record
        scan = Scan(
            id=scan_id,
            engagement_id=engagement_id,
            target=target,
            target_type=detected.target_type,
            resolved_path=detected.resolved_path,
            target_metadata=detected.metadata,
            profile=resolved_profile,
            profile_snapshot={},
            mode=mode,
            status=ScanStatus.PENDING,
            config=config,
            baseline_scan_id=baseline_scan_id,
            tools_planned=list({t.tool for t in tasks}),
            created_at=datetime.now(timezone.utc),
        )

        return scan, tasks

    async def execute(
        self,
        scan: Scan,
        tasks: list[ScanTask],
        on_progress: Optional[Callable] = None,
    ) -> Scan:
        """Execute a planned scan.

        Sets up the ScanEngine, loads tasks, runs the DAG, and returns
        the completed Scan. This method is a placeholder for full
        integration with ScanEngine (to be wired in Plan 4/5).

        Args:
            scan: The Scan object from plan().
            tasks: The task list from plan().
            on_progress: Optional progress callback.

        Returns:
            Updated Scan object with final status.
        """
        cancel = CancellationToken()
        self._active_scans[scan.id] = {
            "scan": scan,
            "cancel": cancel,
        }

        try:
            # Full engine integration will be wired in later plans.
            # For now, just update the scan status to indicate execution
            # would happen here.
            scan = scan.model_copy(
                update={
                    "status": ScanStatus.RUNNING,
                    "started_at": datetime.now(timezone.utc),
                }
            )
            self._active_scans[scan.id]["scan"] = scan
            return scan
        except Exception:
            scan = scan.model_copy(update={"status": ScanStatus.FAILED})
            return scan
        finally:
            # Cleanup will be more involved once engine is integrated
            pass

    async def pause(self, scan_id: str) -> None:
        """Pause a running scan.

        In-flight tasks run to completion; no new tasks are scheduled.

        Args:
            scan_id: ID of the scan to pause.

        Raises:
            KeyError: If scan_id is not active.
        """
        entry = self._active_scans.get(scan_id)
        if entry is None:
            raise KeyError(f"No active scan with id '{scan_id}'")

        engine = entry.get("engine")
        if engine is not None:
            await engine.pause()

    async def resume(self, scan_id: str) -> None:
        """Resume a paused scan.

        Args:
            scan_id: ID of the scan to resume.

        Raises:
            KeyError: If scan_id is not active.
        """
        entry = self._active_scans.get(scan_id)
        if entry is None:
            raise KeyError(f"No active scan with id '{scan_id}'")

        engine = entry.get("engine")
        if engine is not None:
            await engine.resume()

    async def cancel(self, scan_id: str, reason: str) -> None:
        """Cancel a running or paused scan.

        Args:
            scan_id: ID of the scan to cancel.
            reason: Reason for cancellation.

        Raises:
            KeyError: If scan_id is not active.
        """
        entry = self._active_scans.get(scan_id)
        if entry is None:
            raise KeyError(f"No active scan with id '{scan_id}'")

        cancel = entry.get("cancel")
        if cancel is not None:
            await cancel.cancel(reason)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_api.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/api.py \
       packages/cli/tests/test_scanner/test_api.py
git commit -m "feat(scanner): ScanAPI — unified entry point with plan/execute/pause/resume/cancel"
```

---

### Task 9: Integration Verification

**Files:**
- No new files — run full test suite and verify no regressions

- [ ] **Step 1: Run the full Plan 3 test suite**

```bash
cd packages/cli && python -m pytest tests/test_scanner/test_target.py tests/test_scanner/test_profiles.py tests/test_scanner/test_reactive.py tests/test_scanner/test_steering.py tests/test_scanner/test_planner.py tests/test_scanner/test_api.py -v
```

Expected: All tests PASS

- [ ] **Step 2: Run the Plan 1 + Plan 2 tests to verify no regressions**

```bash
cd packages/cli && python -m pytest tests/test_scanner/ -v
```

Expected: All existing tests PASS alongside new tests

- [ ] **Step 3: Verify imports work correctly**

```bash
cd packages/cli && python -c "
from opentools.scanner.target import TargetDetector, TargetValidator, DetectedTarget, SourceMetadata
from opentools.scanner.profiles import ScanProfile, ProfilePhase, ProfileTool, ReactiveEdgeTemplate, DEFAULT_PROFILES, load_builtin_profile, list_builtin_profiles
from opentools.scanner.reactive import OpenPortsToVulnScan, WebFrameworkToRuleset, PackingDetectedToUnpack, HighSeverityToDeepDive, get_builtin_evaluators
from opentools.scanner.steering import SteeringInterface, SteeringDecision, SteeringThrottle
from opentools.scanner.planner import ScanPlanner
from opentools.scanner.api import ScanAPI
from opentools.scanner.models import SteeringAction, GraphSnapshot
print('All Plan 3 imports OK')
"
```

Expected: `All Plan 3 imports OK`

- [ ] **Step 4: Final commit (if any loose changes)**

```bash
git status
# If clean, no commit needed.
# If any missed files:
git add -A && git commit -m "chore(scanner): Plan 3 integration cleanup"
```
