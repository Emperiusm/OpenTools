"""Security-focused regex extractors for stage 2 of the extraction pipeline.

Each extractor implements the SecurityExtractor protocol and emits
ExtractedEntity rows with tracked character offsets. Platform-aware
extractors honor the ``platform`` key in ExtractionContext.engagement_metadata
when set; otherwise they run in auto mode.
"""
from __future__ import annotations

import re

from opentools.chain.extractors.base import ExtractedEntity, ExtractionContext
from opentools.chain.mitre_catalog import is_valid_technique
from opentools.chain.types import MentionField
from opentools.models import Finding


# ─── MITRE technique ─────────────────────────────────────────────────────


class MitreTechniqueExtractor:
    name = "regex_mitre"
    entity_type = "mitre_technique"
    confidence = 0.95

    _pattern = re.compile(r"\b(T\d{4}(?:\.\d{3})?|TA\d{4})\b")

    def applies_to(self, finding: Finding) -> bool:
        return True

    def extract(
        self,
        text: str,
        field: MentionField,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        for m in self._pattern.finditer(text):
            value = m.group(0)
            if not is_valid_technique(value):
                continue
            out.append(
                ExtractedEntity(
                    type=self.entity_type,
                    value=value.upper(),
                    field=field,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    extractor=self.name,
                    confidence=self.confidence,
                )
            )
        return out


# ─── Windows file path ───────────────────────────────────────────────────


class WindowsPathExtractor:
    name = "regex_windows_path"
    entity_type = "file_path"
    confidence = 0.9

    _pattern = re.compile(r"\b[A-Za-z]:\\[^\s\"<>|*?\r\n]+")

    def applies_to(self, finding: Finding) -> bool:
        return True

    def platform_allows(self, engagement_metadata: dict) -> bool:
        platform = engagement_metadata.get("platform", "auto")
        return platform not in {"linux", "macos"}

    def extract(
        self,
        text: str,
        field: MentionField,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        if not self.platform_allows(ctx.engagement_metadata):
            return []
        out: list[ExtractedEntity] = []
        for m in self._pattern.finditer(text):
            out.append(
                ExtractedEntity(
                    type=self.entity_type,
                    value=m.group(0),
                    field=field,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    extractor=self.name,
                    confidence=self.confidence,
                )
            )
        return out


# ─── Registry key ────────────────────────────────────────────────────────


class RegistryKeyExtractor:
    name = "regex_registry"
    entity_type = "registry_key"
    confidence = 0.95

    _pattern = re.compile(r"\bHK(?:LM|CU|U|CR|CC)\\[A-Za-z0-9_\\. \-]+")

    def applies_to(self, finding: Finding) -> bool:
        return True

    def extract(
        self,
        text: str,
        field: MentionField,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        for m in self._pattern.finditer(text):
            value = m.group(0).rstrip(" ")
            out.append(
                ExtractedEntity(
                    type=self.entity_type,
                    value=value,
                    field=field,
                    offset_start=m.start(),
                    offset_end=m.start() + len(value),
                    extractor=self.name,
                    confidence=self.confidence,
                )
            )
        return out


# ─── Process name ────────────────────────────────────────────────────────


class ProcessNameExtractor:
    name = "regex_process"
    entity_type = "process"
    confidence = 0.8

    _pattern_exe = re.compile(r"\b([A-Za-z0-9_\-]+\.exe)\b")
    _pattern_unix = re.compile(r"(?:^|\s)(/usr/(?:s?bin|local/bin)/\S+)")

    def applies_to(self, finding: Finding) -> bool:
        return True

    def extract(
        self,
        text: str,
        field: MentionField,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        for m in self._pattern_exe.finditer(text):
            out.append(
                ExtractedEntity(
                    type=self.entity_type,
                    value=m.group(1),
                    field=field,
                    offset_start=m.start(1),
                    offset_end=m.end(1),
                    extractor=self.name,
                    confidence=self.confidence,
                )
            )
        for m in self._pattern_unix.finditer(text):
            out.append(
                ExtractedEntity(
                    type=self.entity_type,
                    value=m.group(1),
                    field=field,
                    offset_start=m.start(1),
                    offset_end=m.end(1),
                    extractor=self.name,
                    confidence=self.confidence,
                )
            )
        return out


# ─── Port ────────────────────────────────────────────────────────────────


class PortExtractor:
    name = "regex_port"
    entity_type = "port"
    confidence = 0.8

    # Context-aware: requires the word "port" nearby, or ":NNNN" adjacency
    # to a host/IP token. A standalone 4-digit number is not a port.
    _pattern_named = re.compile(r"\bport[\s:]+(\d{1,5})\b", re.IGNORECASE)

    def applies_to(self, finding: Finding) -> bool:
        return True

    def extract(
        self,
        text: str,
        field: MentionField,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        for m in self._pattern_named.finditer(text):
            value = m.group(1)
            if int(value) > 65535:
                continue
            out.append(
                ExtractedEntity(
                    type=self.entity_type,
                    value=value,
                    field=field,
                    offset_start=m.start(1),
                    offset_end=m.end(1),
                    extractor=self.name,
                    confidence=self.confidence,
                )
            )
        return out


# ─── Windows user (DOMAIN\user or user@DOMAIN) ──────────────────────────


class WindowsUserExtractor:
    name = "regex_windows_user"
    entity_type = "user"
    confidence = 0.7

    _pattern = re.compile(r"\b([A-Z][A-Z0-9_]{1,20})\\([A-Za-z][A-Za-z0-9._-]{0,30})\b")

    def applies_to(self, finding: Finding) -> bool:
        return True

    def extract(
        self,
        text: str,
        field: MentionField,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        for m in self._pattern.finditer(text):
            out.append(
                ExtractedEntity(
                    type=self.entity_type,
                    value=f"{m.group(1)}\\{m.group(2)}",
                    field=field,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    extractor=self.name,
                    confidence=self.confidence,
                )
            )
        return out


# ─── Package version ─────────────────────────────────────────────────────


class PackageVersionExtractor:
    name = "regex_package_version"
    entity_type = "package"
    confidence = 0.7

    # Matches pkg@X.Y.Z or pkg@X.Y.Z-rc1 etc
    _pattern = re.compile(r"\b([A-Za-z][A-Za-z0-9_\-]{1,60}@\d+(?:\.\d+){0,3}(?:-[A-Za-z0-9]+)?)\b")

    def applies_to(self, finding: Finding) -> bool:
        return True

    def extract(
        self,
        text: str,
        field: MentionField,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        for m in self._pattern.finditer(text):
            out.append(
                ExtractedEntity(
                    type=self.entity_type,
                    value=m.group(1),
                    field=field,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    extractor=self.name,
                    confidence=self.confidence,
                )
            )
        return out


# Convenience list of all built-in security extractors.
BUILTIN_SECURITY_EXTRACTORS: list = [
    MitreTechniqueExtractor(),
    WindowsPathExtractor(),
    RegistryKeyExtractor(),
    ProcessNameExtractor(),
    PortExtractor(),
    WindowsUserExtractor(),
    PackageVersionExtractor(),
]
