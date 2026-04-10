"""Stage-2 extractor wrapping the ``ioc-finder`` library.

Harvests IPs, domains, URLs, emails, hashes, and CVEs from the provided
text. ``ioc-finder`` does not report positional offsets, so all produced
``ExtractedEntity`` rows have ``offset_start`` / ``offset_end`` set to
None. The library handles common defanging patterns natively.
"""
from __future__ import annotations

from typing import Iterable

import ioc_finder

from opentools.chain.extractors.base import ExtractedEntity, ExtractionContext
from opentools.chain.types import MentionField
from opentools.models import Finding


# Mapping of ioc-finder result keys to chain entity types.
_IOC_KEY_TO_ENTITY_TYPE: dict[str, str] = {
    "ipv4s": "ip",
    "ipv6s": "ip",
    "urls": "url",
    "email_addresses": "email",
    "domains": "domain",
    "md5s": "hash_md5",
    "sha1s": "hash_sha1",
    "sha256s": "hash_sha256",
    "cves": "cve",
}


class IocFinderExtractor:
    """Stage-2 extractor using the ``ioc-finder`` package."""

    name: str = "ioc_finder"
    confidence: float = 0.9

    # Protocol compatibility — this extractor does not bind to a single
    # entity_type because it emits many.
    entity_type: str = "multi"

    def applies_to(self, finding: Finding) -> bool:
        return True

    def extract(
        self,
        text: str,
        field: MentionField,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        if not text:
            return []
        raw = ioc_finder.find_iocs(text)
        results: list[ExtractedEntity] = []
        for key, entity_type in _IOC_KEY_TO_ENTITY_TYPE.items():
            values = raw.get(key) or []
            for value in _iter_strings(values):
                results.append(
                    ExtractedEntity(
                        type=entity_type,
                        value=value,
                        field=field,
                        offset_start=None,
                        offset_end=None,
                        extractor=self.name,
                        confidence=self.confidence,
                    )
                )
        return results


def _iter_strings(values: Iterable) -> Iterable[str]:
    """Yield only non-empty string values, dropping nested structures."""
    for v in values:
        if isinstance(v, str) and v:
            yield v
