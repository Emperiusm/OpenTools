#!/usr/bin/env bash
# scripts/check_test_count.sh
#
# Enforce "passed >= expected_min, failed == 0" at phase boundaries.
# Called in CI after every test run. Additional tests added mid-phase
# don't break the gate because it uses >= not exact match.
set -euo pipefail

EXPECTED_MIN="${1:-}"
if [ -z "$EXPECTED_MIN" ]; then
    echo "usage: $0 <expected-min-passing-count>"
    exit 2
fi

OUTPUT=$(python -m pytest packages/ -q 2>&1 | tail -5)
PASSED=$(echo "$OUTPUT" | grep -oE '[0-9]+ passed' | head -1 | grep -oE '[0-9]+' || echo 0)
FAILED=$(echo "$OUTPUT" | grep -oE '[0-9]+ failed' | head -1 | grep -oE '[0-9]+' || echo 0)

if [ -n "$FAILED" ] && [ "$FAILED" != "0" ]; then
    echo "FAILED: $FAILED test(s) failing"
    echo "$OUTPUT"
    exit 1
fi

if [ "$PASSED" -lt "$EXPECTED_MIN" ]; then
    echo "REGRESSION: expected at least $EXPECTED_MIN passing, got $PASSED"
    echo "$OUTPUT"
    exit 1
fi

echo "OK: $PASSED tests passing (>= $EXPECTED_MIN)"
