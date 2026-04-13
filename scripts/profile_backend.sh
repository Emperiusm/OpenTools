#!/usr/bin/env bash
# ------------------------------------------------------------------
# profile_backend.sh — py-spy flame graph profiler for OpenTools
#
# Usage (run from WSL):
#   chmod +x scripts/profile_backend.sh
#   ./scripts/profile_backend.sh [duration_seconds]
#
# Prerequisites:
#   pip install py-spy
#   pip install -e packages/cli   # opentools core
#   pip install -e packages/web/backend  # fastapi app
#
# Output:
#   profiles/flamegraph_<timestamp>.svg
#   profiles/flamegraph_<timestamp>_native.svg  (with C-extension frames)
# ------------------------------------------------------------------

set -euo pipefail

DURATION="${1:-30}"
PROFILE_DIR="profiles"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
UVICORN_PORT=8000

mkdir -p "$PROFILE_DIR"

echo "=== OpenTools Backend Profiler ==="
echo "Duration: ${DURATION}s"
echo ""

# Check py-spy is installed
if ! command -v py-spy &>/dev/null; then
    echo "ERROR: py-spy not found. Install with: pip install py-spy"
    exit 1
fi

# --- Option 1: Launch uvicorn under py-spy (recommended) ---
echo "[1/3] Starting uvicorn under py-spy (Python-level)..."
echo "      Output: ${PROFILE_DIR}/flamegraph_${TIMESTAMP}.svg"
echo ""
echo ">>> While this runs, exercise the app! Hit these endpoints:"
echo "    curl http://localhost:${UVICORN_PORT}/api/v1/scans"
echo "    curl http://localhost:${UVICORN_PORT}/api/chain/entities"
echo "    POST to /api/v1/scans to trigger scan execution"
echo "    GET  /api/v1/scans/{id}/stream for SSE profiling"
echo ""

sudo py-spy record \
    --output "${PROFILE_DIR}/flamegraph_${TIMESTAMP}.svg" \
    --duration "$DURATION" \
    --rate 100 \
    --subprocesses \
    --format flamegraph \
    -- python -m uvicorn app.main:app \
        --host 0.0.0.0 \
        --port "$UVICORN_PORT" \
        --app-dir packages/web/backend \
        --no-access-log

echo ""
echo "[2/3] Starting uvicorn under py-spy (native C-extension frames)..."
echo "      Output: ${PROFILE_DIR}/flamegraph_${TIMESTAMP}_native.svg"
echo ""

sudo py-spy record \
    --output "${PROFILE_DIR}/flamegraph_${TIMESTAMP}_native.svg" \
    --duration "$DURATION" \
    --rate 100 \
    --native \
    --subprocesses \
    --format flamegraph \
    -- python -m uvicorn app.main:app \
        --host 0.0.0.0 \
        --port "$UVICORN_PORT" \
        --app-dir packages/web/backend \
        --no-access-log

echo ""
echo "[3/3] Done! Open the SVGs in your browser:"
echo "  ${PROFILE_DIR}/flamegraph_${TIMESTAMP}.svg          (Python frames)"
echo "  ${PROFILE_DIR}/flamegraph_${TIMESTAMP}_native.svg   (Python + C frames)"
echo ""
echo "=== What to look for ==="
echo "  - Wide bars = functions consuming the most CPU"
echo "  - Click to zoom into specific call stacks"
echo "  - Compare Python vs native to see if time is in Python or C extensions"
echo "  - Key subsystems to watch:"
echo "    * ScanEngine._schedule_loop / _execute_task"
echo "    * ScanPipeline.process_task_output"
echo "    * DedupEngine.deduplicate (O(n^2) fuzzy pass)"
echo "    * NormalizationEngine.normalize (regex + CWE lookups)"
echo "    * Pydantic model_copy / model_dump_json (serialization overhead)"
echo "    * SqliteScanStore (I/O in SSE polling loop)"
