"""Load test driver for profiling OpenTools backend.

Run this in a separate terminal while py-spy is recording.
Exercises the heaviest code paths to generate a useful flame graph.

Usage:
    python scripts/profile_loadtest.py [--base-url http://localhost:8000] [--rounds 5]
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
import urllib.error


def _post(url: str, data: dict, token: str | None = None) -> dict | None:
    body = json.dumps(data).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"  POST {url} -> {e.code}: {e.read().decode()[:200]}")
        return None


def _get(url: str, token: str | None = None) -> dict | None:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"  GET {url} -> {e.code}")
        return None


def register_and_login(base: str) -> str | None:
    """Register a test user and get a bearer token."""
    email = f"profiler_{int(time.time())}@test.local"
    password = "Prof1l3r!Pass"

    print(f"[auth] Registering {email}...")
    _post(f"{base}/api/v1/auth/register", {
        "email": email,
        "password": password,
    })

    print("[auth] Logging in...")
    # fastapi-users uses form-encoded login
    login_data = f"username={email}&password={password}".encode()
    req = urllib.request.Request(
        f"{base}/api/v1/auth/login",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            token = body.get("access_token")
            if token:
                print(f"[auth] Got token: {token[:20]}...")
                return token
    except urllib.error.HTTPError as e:
        print(f"[auth] Login failed: {e.code} {e.read().decode()[:200]}")
    return None


def run_load(base: str, token: str | None, rounds: int) -> None:
    """Hit the heaviest endpoints repeatedly."""

    endpoints = [
        # Scan CRUD — exercises SqliteScanStore, Pydantic serialization
        ("GET", f"{base}/api/v1/scans", None),
        ("GET", f"{base}/api/v1/scans/profiles", None),

        # Chain data layer — exercises SQLAlchemy, graph queries
        ("GET", f"{base}/api/chain/entities?limit=100", None),

        # System endpoint — lightweight baseline
        ("GET", f"{base}/api/v1/system/health", None),
    ]

    for r in range(1, rounds + 1):
        print(f"\n--- Round {r}/{rounds} ---")
        for method, url, body in endpoints:
            start = time.perf_counter()
            if method == "GET":
                result = _get(url, token)
            else:
                result = _post(url, body or {}, token)
            elapsed = (time.perf_counter() - start) * 1000
            status = "ok" if result is not None else "err"
            print(f"  {method} {url.replace(base, '')} -> {status} ({elapsed:.0f}ms)")

        # Try to trigger a scan plan (heaviest operation)
        print("  POST /api/v1/scans (scan plan)...")
        scan_result = _post(f"{base}/api/v1/scans", {
            "target": "https://example.com",
            "engagement_id": "profile-test-eng",
            "mode": "auto",
            "concurrency": 4,
        }, token)
        if scan_result and "id" in scan_result:
            scan_id = scan_result["id"]
            print(f"  Scan created: {scan_id}")

            # Hit the per-scan endpoints
            _get(f"{base}/api/v1/scans/{scan_id}", token)
            _get(f"{base}/api/v1/scans/{scan_id}/tasks", token)
            _get(f"{base}/api/v1/scans/{scan_id}/findings", token)

        time.sleep(0.1)  # Brief pause between rounds


def main() -> None:
    parser = argparse.ArgumentParser(description="Load test for profiling")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--rounds", type=int, default=10)
    args = parser.parse_args()

    print(f"=== OpenTools Load Test ===")
    print(f"Target: {args.base_url}")
    print(f"Rounds: {args.rounds}")
    print()

    token = register_and_login(args.base_url)
    if not token:
        print("[warn] Running without auth — expect 401s on protected endpoints")

    run_load(args.base_url, token, args.rounds)

    print("\n=== Load test complete ===")


if __name__ == "__main__":
    main()
