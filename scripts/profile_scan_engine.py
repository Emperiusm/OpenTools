"""Profile the scan engine + pipeline in isolation (no web server).

This targets the densest compute paths directly:
  ScanAPI.plan -> ScanEngine.run -> ScanPipeline.process_task_output

Usage:
    # Python-level flame graph:
    sudo py-spy record -o profiles/engine.svg -- python scripts/profile_scan_engine.py

    # With C-extension frames:
    sudo py-spy record -o profiles/engine_native.svg --native -- python scripts/profile_scan_engine.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Ensure packages are importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "packages" / "cli" / "src"))


async def main() -> None:
    from opentools.scanner.api import ScanAPI
    from opentools.scanner.models import ScanConfig, ScanMode

    api = ScanAPI()

    targets = [
        # Add your real targets here for realistic profiling:
        "https://example.com",
        # "/path/to/local/repo",
        # "192.168.1.1",
    ]

    rounds = 20  # Repeat to accumulate enough samples for py-spy

    for i in range(rounds):
        for target in targets:
            try:
                scan, tasks = await api.plan(
                    target=target,
                    engagement_id=f"profile-eng-{i}",
                    mode=ScanMode.AUTO,
                    config=ScanConfig(max_concurrent_tasks=4),
                )
                print(f"[{i+1}/{rounds}] Planned {len(tasks)} tasks for {target}")

                # Execute (will run shell commands — only use with safe targets)
                # result = await api.execute(scan, tasks)
                # print(f"  -> {result.status.value}")

            except Exception as e:
                print(f"[{i+1}/{rounds}] {target}: {e}")


if __name__ == "__main__":
    asyncio.run(main())
