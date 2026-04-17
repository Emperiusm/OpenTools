"""ScanPipeline — assembles the parsing pipeline and runs it on task output.

Wires together: ParserRouter -> NormalizationEngine -> DedupEngine ->
CorroborationScorer -> SuppressionEngine -> FindingLifecycle -> Store.

Used by ScanEngine._mark_completed to process task output into findings.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import (
    DeduplicatedFinding,
    RawFinding,
    ScanTask,
)
from opentools.scanner.parsing.confidence import CorroborationScorer
from opentools.scanner.parsing.dedup import DedupEngine
from opentools.scanner.parsing.lifecycle import FindingLifecycle
from opentools.scanner.parsing.normalization import NormalizationEngine
from opentools.scanner.parsing.router import ParserRouter
from opentools.scanner.parsing.suppression import SuppressionEngine

if TYPE_CHECKING:
    from opentools.scanner.store import ScanStoreProtocol

logger = logging.getLogger(__name__)


class ScanPipeline:
    """Assembles and runs the full finding processing pipeline.

    Usage::

        pipeline = ScanPipeline(store=store, engagement_id="eng-1", scan_id="scan-1")
        findings = await pipeline.process_task_output(task, output)
    """

    def __init__(
        self,
        store: ScanStoreProtocol,
        engagement_id: str,
        scan_id: str,
    ) -> None:
        self.store = store
        self.engagement_id = engagement_id
        self.scan_id = scan_id

        # Pipeline stages
        self.router = ParserRouter()
        self._normalization = NormalizationEngine()
        self._dedup = DedupEngine()
        self._corroboration = CorroborationScorer()
        self._suppression = SuppressionEngine()
        self._lifecycle = FindingLifecycle()

        # Register builtin parsers
        self._register_builtin_parsers()

    def _register_builtin_parsers(self) -> None:
        """Register all available builtin parsers."""
        try:
            from opentools.scanner.parsing.parsers.semgrep import SemgrepParser
            self.router.register(SemgrepParser())
        except ImportError:
            pass
        try:
            from opentools.scanner.parsing.parsers.gitleaks import GitleaksParser
            self.router.register(GitleaksParser())
        except ImportError:
            pass
        try:
            from opentools.scanner.parsing.parsers.nmap import NmapParser
            self.router.register(NmapParser())
        except ImportError:
            pass
        try:
            from opentools.scanner.parsing.parsers.trivy import TrivyParser
            self.router.register(TrivyParser())
        except ImportError:
            pass
        try:
            from opentools.scanner.parsing.parsers.generic_json import GenericJsonParser
            self.router.register(GenericJsonParser())
        except ImportError:
            pass
        try:
            from opentools.scanner.parsing.parsers.nuclei import NucleiParser
            self.router.register(NucleiParser())
        except ImportError:
            pass
        try:
            from opentools.scanner.parsing.parsers.nikto import NiktoParser
            self.router.register(NiktoParser())
        except ImportError:
            pass
        try:
            from opentools.scanner.parsing.parsers.whatweb import WhatWebParser
            self.router.register(WhatWebParser())
        except ImportError:
            pass
        try:
            from opentools.scanner.parsing.parsers.waybackurls import WaybackurlsParser
            self.router.register(WaybackurlsParser())
        except ImportError:
            pass

    async def process_task_output(
        self,
        task: ScanTask,
        output: TaskOutput,
    ) -> list[DeduplicatedFinding]:
        """Run the full pipeline on a completed task's output.

        1. Route to parser -> yield RawFinding objects
        2. Normalize each RawFinding
        3. Save raw findings to store
        4. Deduplicate
        5. Score corroboration
        6. Apply suppression rules
        7. Apply lifecycle transitions
        8. Save dedup findings to store
        9. Return dedup findings

        Returns an empty list if no parser matches or output is empty.
        """
        if not output.stdout:
            return []

        # 1. Parse — route to correct parser
        parser_name = task.parser
        if parser_name is None:
            logger.debug("No parser specified for task %s, skipping", task.id)
            return []

        parser = self.router.get(parser_name)
        if parser is None:
            logger.warning("Parser '%s' not found for task %s", parser_name, task.id)
            return []

        # Encode once; orjson.loads() accepts both bytes and str but bytes
        # avoids a redundant internal copy in the C extension.
        raw_bytes = output.stdout.encode("utf-8")

        if not parser.validate(raw_bytes):
            logger.warning(
                "Parser '%s' rejected output from task %s", parser_name, task.id
            )
            return []

        # Parsing is CPU-bound (JSON decode, hashing, Pydantic construction).
        # Offload to a thread to avoid blocking the engine's scheduling loop.
        import asyncio

        def _parse_sync() -> list[RawFinding]:
            results: list[RawFinding] = []
            for finding in parser.parse(raw_bytes, self.scan_id, task.id):
                results.append(finding)
            return results

        try:
            raw_findings = await asyncio.to_thread(_parse_sync)
        except Exception:
            logger.exception("Parser '%s' crashed on task %s", parser_name, task.id)
            return []

        if not raw_findings:
            return []

        # 2. Normalize
        raw_findings = self._normalization.normalize(raw_findings)

        # 3. Save raw findings to store (batched)
        if hasattr(self.store, 'save_raw_findings_batch'):
            await self.store.save_raw_findings_batch(raw_findings)
        else:
            for rf in raw_findings:
                await self.store.save_raw_finding(rf)

        # 4. Deduplicate
        dedup_findings = self._dedup.deduplicate(raw_findings)

        # Set engagement_id and scan_id on each dedup finding
        for df in dedup_findings:
            df.engagement_id = self.engagement_id
            df.first_seen_scan_id = self.scan_id

        # 5. Corroboration scoring
        dedup_findings = self._corroboration.score(dedup_findings)

        # 6. Suppression
        rules = await self.store.get_suppression_rules(
            engagement_id=self.engagement_id
        )
        if rules:
            dedup_findings = self._suppression.apply(rules, dedup_findings)

        # 7. Lifecycle transitions
        dedup_findings = self._lifecycle.apply(dedup_findings)

        # 8. Save dedup findings to store (batched)
        if hasattr(self.store, 'save_dedup_findings_batch'):
            await self.store.save_dedup_findings_batch(dedup_findings)
        else:
            for df in dedup_findings:
                await self.store.save_dedup_finding(df)

        return dedup_findings
