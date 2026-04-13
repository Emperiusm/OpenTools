"""Comprehensive profiler for OpenTools using cProfile + snakeviz.

Works on any Python version (including 3.14). Generates .prof files
that can be visualized with snakeviz (interactive flame-graph-like browser UI)
or analyzed with pstats.

Usage:
    python scripts/profile_cprofile.py [target]

    Targets:
      engine     — scan planner + target detection (default)
      tui        — TUI dashboard (launches interactively)
      all        — both sequentially

    After profiling, view results:
      pip install snakeviz
      snakeviz profiles/engine.prof
      snakeviz profiles/tui.prof
"""

from __future__ import annotations

import asyncio
import cProfile
import pstats
import sys
from io import StringIO
from pathlib import Path

PROFILE_DIR = Path(__file__).resolve().parent.parent / "profiles"
PROFILE_DIR.mkdir(exist_ok=True)

# Ensure packages are importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "packages" / "cli" / "src"))


# ------------------------------------------------------------------
# Scan Engine profiling
# ------------------------------------------------------------------

def profile_engine() -> None:
    """Profile ScanAPI.plan in a tight loop."""
    print("=" * 50)
    print("  Profiling: Scan Engine")
    print("=" * 50)

    async def _run():
        from opentools.scanner.api import ScanAPI
        from opentools.scanner.models import ScanConfig, ScanMode

        api = ScanAPI()
        targets = [
            "https://example.com",
            "192.168.1.1",
            "/tmp/fakerepo",
        ]

        for i in range(100):
            for target in targets:
                try:
                    scan, tasks = await api.plan(
                        target=target,
                        engagement_id=f"profile-eng-{i}",
                        mode=ScanMode.AUTO,
                        config=ScanConfig(max_concurrent_tasks=4),
                    )
                    if i % 25 == 0:
                        print(f"  [{i+1}/100] Planned {len(tasks)} tasks for {target}")
                except Exception:
                    pass

    prof = cProfile.Profile()
    prof.enable()
    asyncio.run(_run())
    prof.disable()

    # Save binary .prof for snakeviz
    out_path = PROFILE_DIR / "engine.prof"
    prof.dump_stats(str(out_path))
    print(f"\n  Saved: {out_path}")

    # Print top 30 cumulative
    print("\n  Top 30 by cumulative time:")
    print("  " + "-" * 70)
    stream = StringIO()
    stats = pstats.Stats(prof, stream=stream)
    stats.sort_stats("cumulative")
    stats.print_stats(30)
    print(stream.getvalue())


# ------------------------------------------------------------------
# TUI Dashboard profiling
# ------------------------------------------------------------------

def profile_tui() -> None:
    """Profile the Textual dashboard. Interact, then press 'q' to quit."""
    print("=" * 50)
    print("  Profiling: TUI Dashboard")
    print("=" * 50)
    print()
    print("  Interact with the dashboard to generate profile data:")
    print("    - Switch tabs (1/2/3/4)")
    print("    - Filter findings (/)")
    print("    - Select engagements")
    print("    - Let auto-refresh tick")
    print("    - Press 'q' to quit and save profile")
    print()

    prof = cProfile.Profile()
    prof.enable()

    try:
        from opentools.dashboard import launch_dashboard
        db_path = Path("engagements/opentools.db")
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # Try to find plugin dir for richer data
        try:
            from opentools.plugin import discover_plugin_dir
            plugin_dir = discover_plugin_dir()
            db_path = plugin_dir.parent.parent / "engagements" / "opentools.db"
            launch_dashboard(db_path=db_path, plugin_dir=plugin_dir)
        except (FileNotFoundError, Exception):
            launch_dashboard(db_path=db_path)
    except Exception as e:
        print(f"  Dashboard failed to launch: {e}")
        print("  Create an engagement first: opentools engagement create --name test --target 127.0.0.1 --type pentest")
    finally:
        prof.disable()

    out_path = PROFILE_DIR / "tui.prof"
    prof.dump_stats(str(out_path))
    print(f"\n  Saved: {out_path}")

    print("\n  Top 30 by cumulative time:")
    print("  " + "-" * 70)
    stream = StringIO()
    stats = pstats.Stats(prof, stream=stream)
    stats.sort_stats("cumulative")
    stats.print_stats(30)
    print(stream.getvalue())


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "all"

    if target in ("engine", "all"):
        profile_engine()
    if target in ("tui", "all"):
        profile_tui()

    print("=" * 50)
    print("  Profiling complete!")
    print("=" * 50)
    print()
    print("  View flame graphs with snakeviz:")
    print("    pip install snakeviz")
    for f in PROFILE_DIR.glob("*.prof"):
        print(f"    snakeviz {f}")
    print()
    print("  Or analyze in Python:")
    print("    import pstats")
    print("    s = pstats.Stats('profiles/engine.prof')")
    print("    s.sort_stats('cumulative').print_stats(50)")


if __name__ == "__main__":
    main()
