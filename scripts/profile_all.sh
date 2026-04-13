#!/usr/bin/env bash
# ------------------------------------------------------------------
# profile_all.sh — comprehensive py-spy profiling for OpenTools
#
# Profiles ALL subsystems:
#   1. TUI Dashboard  (render loop, layout, text, I/O polling)
#   2. Web Backend     (FastAPI, serialization, SSE, DB queries)
#   3. Scan Engine     (DAG scheduler, pipeline, dedup, normalization)
#
# Usage (run from project root in WSL):
#   chmod +x scripts/profile_all.sh
#   ./scripts/profile_all.sh [duration_seconds]
#
# Prerequisites:
#   pip install py-spy
#   pip install -e packages/cli
#   pip install -e packages/web/backend   # only needed for backend profile
#
# Output:
#   profiles/tui_<timestamp>.svg              — TUI Python frames
#   profiles/tui_<timestamp>_native.svg       — TUI Python + C frames
#   profiles/backend_<timestamp>.svg          — Backend Python frames
#   profiles/backend_<timestamp>_native.svg   — Backend Python + C frames
#   profiles/engine_<timestamp>.svg           — Scan engine Python frames
#   profiles/engine_<timestamp>_native.svg    — Scan engine Python + C frames
# ------------------------------------------------------------------

set -euo pipefail

DURATION="${1:-30}"
PROFILE_DIR="profiles"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
UVICORN_PORT=8000

mkdir -p "$PROFILE_DIR"

echo "============================================"
echo "  OpenTools Comprehensive Profiler"
echo "  Duration per target: ${DURATION}s"
echo "  Output: ${PROFILE_DIR}/"
echo "============================================"
echo ""

# ------------------------------------------------------------------
# Preflight
# ------------------------------------------------------------------
if ! command -v py-spy &>/dev/null; then
    echo "ERROR: py-spy not found. Install with: pip install py-spy"
    exit 1
fi

if ! python -c "import opentools" &>/dev/null; then
    echo "WARN: opentools not importable. Run: pip install -e packages/cli"
fi

# ------------------------------------------------------------------
# 1. TUI Dashboard
# ------------------------------------------------------------------
echo "========================================"
echo "  [1/3] TUI Dashboard"
echo "========================================"
echo ""
echo "This profiles the Textual render loop, layout engine,"
echo "Rich text rendering, and SQLite/Docker I/O polling."
echo ""
echo ">>> INTERACT with the dashboard while it records:"
echo "    - Switch between tabs (1/2/3/4)"
echo "    - Type in filter inputs"
echo "    - Select different engagements"
echo "    - Let auto-refresh tick (select an active engagement)"
echo "    - Open finding detail modals (Enter)"
echo "    - Press 'q' to quit when done (or wait for timeout)"
echo ""

echo "[1a] Python-level frames..."
sudo py-spy record \
    --output "${PROFILE_DIR}/tui_${TIMESTAMP}.svg" \
    --duration "$DURATION" \
    --rate 100 \
    --subprocesses \
    --format flamegraph \
    -- opentools dashboard 2>/dev/null || {
    echo "  WARN: TUI profile exited (may need engagement data)."
    echo "  If 'opentools dashboard' doesn't launch, create an engagement first:"
    echo "    opentools engagement create --name test --target 127.0.0.1 --type pentest"
    echo ""
    echo "  Or run directly with: sudo py-spy record -o profiles/tui.svg -- opentools dashboard"
}

echo "[1b] Native (Python + C extension) frames..."
sudo py-spy record \
    --output "${PROFILE_DIR}/tui_${TIMESTAMP}_native.svg" \
    --duration "$DURATION" \
    --rate 100 \
    --native \
    --subprocesses \
    --format flamegraph \
    -- opentools dashboard 2>/dev/null || true

echo ""
echo "  TUI profiles written:"
echo "    ${PROFILE_DIR}/tui_${TIMESTAMP}.svg"
echo "    ${PROFILE_DIR}/tui_${TIMESTAMP}_native.svg"
echo ""

# ------------------------------------------------------------------
# 2. Scan Engine (isolated, no web server)
# ------------------------------------------------------------------
echo "========================================"
echo "  [2/3] Scan Engine (isolated)"
echo "========================================"
echo ""
echo "Profiles: ScanAPI.plan, ScanPlanner, TargetDetector,"
echo "          profile resolution, task DAG construction."
echo ""

echo "[2a] Python-level frames..."
sudo py-spy record \
    --output "${PROFILE_DIR}/engine_${TIMESTAMP}.svg" \
    --duration "$DURATION" \
    --rate 100 \
    --format flamegraph \
    -- python scripts/profile_scan_engine.py || {
    echo "  WARN: Scan engine profile failed. Check profile_scan_engine.py."
}

echo "[2b] Native frames..."
sudo py-spy record \
    --output "${PROFILE_DIR}/engine_${TIMESTAMP}_native.svg" \
    --duration "$DURATION" \
    --rate 100 \
    --native \
    --format flamegraph \
    -- python scripts/profile_scan_engine.py || true

echo ""
echo "  Engine profiles written:"
echo "    ${PROFILE_DIR}/engine_${TIMESTAMP}.svg"
echo "    ${PROFILE_DIR}/engine_${TIMESTAMP}_native.svg"
echo ""

# ------------------------------------------------------------------
# 3. Web Backend (FastAPI + uvicorn)
# ------------------------------------------------------------------
echo "========================================"
echo "  [3/3] Web Backend (FastAPI)"
echo "========================================"
echo ""
echo "Profiles: request handling, Pydantic serialization,"
echo "          SQLAlchemy/asyncpg queries, SSE streaming,"
echo "          chain graph queries, GZip middleware."
echo ""
echo ">>> IN ANOTHER TERMINAL, run the load test while this records:"
echo "    python scripts/profile_loadtest.py --rounds 20"
echo ""
echo "    Or manually hit endpoints:"
echo "    curl http://localhost:${UVICORN_PORT}/api/v1/scans"
echo "    curl http://localhost:${UVICORN_PORT}/api/chain/entities"
echo ""

echo "[3a] Python-level frames..."
sudo py-spy record \
    --output "${PROFILE_DIR}/backend_${TIMESTAMP}.svg" \
    --duration "$DURATION" \
    --rate 100 \
    --subprocesses \
    --format flamegraph \
    -- python -m uvicorn app.main:app \
        --host 0.0.0.0 \
        --port "$UVICORN_PORT" \
        --app-dir packages/web/backend \
        --no-access-log || {
    echo "  WARN: Backend profile failed. Check DB connection / dependencies."
}

echo "[3b] Native frames..."
sudo py-spy record \
    --output "${PROFILE_DIR}/backend_${TIMESTAMP}_native.svg" \
    --duration "$DURATION" \
    --rate 100 \
    --native \
    --subprocesses \
    --format flamegraph \
    -- python -m uvicorn app.main:app \
        --host 0.0.0.0 \
        --port "$UVICORN_PORT" \
        --app-dir packages/web/backend \
        --no-access-log || true

echo ""
echo "  Backend profiles written:"
echo "    ${PROFILE_DIR}/backend_${TIMESTAMP}.svg"
echo "    ${PROFILE_DIR}/backend_${TIMESTAMP}_native.svg"
echo ""

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
echo "============================================"
echo "  PROFILING COMPLETE"
echo "============================================"
echo ""
echo "Generated flame graphs:"
echo ""
ls -lh "${PROFILE_DIR}"/*_${TIMESTAMP}*.svg 2>/dev/null || echo "  (no SVG files found)"
echo ""
echo "Open in browser to analyze:"
echo "  - Look for WIDE bars (most CPU time)"
echo "  - Click to zoom into call stacks"
echo "  - Compare Python vs native SVGs"
echo ""
echo "Key subsystems to look for in each:"
echo ""
echo "  TUI Dashboard:"
echo "    * Textual compositor / render / layout"
echo "    * Rich Console.render / text measurement"
echo "    * DashboardState.refresh_selected (SQLite queries)"
echo "    * EngagementStore.get_summary (N+1 query pattern)"
echo "    * ContainerManager.status (Docker API polling)"
echo "    * DataTable.clear / add_row (full rebuild)"
echo ""
echo "  Scan Engine:"
echo "    * ScanPlanner.plan (task DAG construction)"
echo "    * TargetDetector.detect"
echo "    * Profile resolution / tool selection"
echo ""
echo "  Web Backend:"
echo "    * Pydantic model_copy / model_dump_json"
echo "    * SQLAlchemy async session overhead"
echo "    * GZipMiddleware compression"
echo "    * SSE event_generator polling loop"
echo "    * DedupEngine.deduplicate (O(n^2) fuzzy pass)"
echo "    * NormalizationEngine.normalize (regex matching)"
