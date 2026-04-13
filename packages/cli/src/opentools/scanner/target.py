"""Target detection, validation, and metadata extraction.

TargetDetector determines target type from a string using pattern matching.
TargetValidator performs async I/O to verify the target is accessible.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import zipfile
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from opentools.scanner.models import TargetType

__all__ = [
    "DetectedTarget",
    "SourceMetadata",
    "TargetDetector",
    "TargetValidator",
    "ValidationResult",
]

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]


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
                f"Example: git clone {target} /tmp/repo && opentools scan /tmp/repo"
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

        # Walk at most 4 levels deep for speed
        for root, dirs, files in os.walk(str(directory)):
            depth = str(root).replace(str(directory), "").count(os.sep)
            if depth >= 4:
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


# ---------------------------------------------------------------------------
# TargetValidator
# ---------------------------------------------------------------------------


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
