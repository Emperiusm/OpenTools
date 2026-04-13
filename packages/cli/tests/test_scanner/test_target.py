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


# ---------------------------------------------------------------------------
# Task 2: TargetValidator tests
# ---------------------------------------------------------------------------

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
