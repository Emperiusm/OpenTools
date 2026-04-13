"""Ephemeral proxy context manager with guaranteed teardown.

Usage::
    async with ephemeral_proxy(provider, ...) as endpoint:
        result = await run_streaming(args, on_output, env=endpoint.env)
    # Node is destroyed here, guaranteed.
"""
from __future__ import annotations
import asyncio, logging, os
from contextlib import asynccontextmanager
from typing import AsyncIterator
from opentools.scanner.infra.provider import CloudNodeProvider, ProvisioningError

logger = logging.getLogger(__name__)
PROXY_TAG = "opentools-ephemeral-proxy"

class ProxyEndpoint:
    """Usable result of a provisioned proxy — env vars for subprocess injection."""
    def __init__(self, host: str, socks_port: int) -> None:
        self.host = host
        self.socks_port = socks_port

    @property
    def env(self) -> dict[str, str]:
        proxy_url = f"socks5://127.0.0.1:{self.socks_port}"
        return {
            **os.environ,
            "HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url,
            "http_proxy": proxy_url, "https_proxy": proxy_url,
            "ALL_PROXY": proxy_url,
        }

@asynccontextmanager
async def ephemeral_proxy(
    provider: CloudNodeProvider,
    region: str = "nyc3",
    ssh_key: str = "",
    ssh_key_path: str = "~/.ssh/id_ed25519",
    local_socks_port: int = 10800,
    scan_id: str = "",
    _skip_tunnel: bool = False,  # for unit testing
) -> AsyncIterator[ProxyEndpoint]:
    """Provision proxy, optionally tunnel, yield endpoint. GUARANTEES teardown."""
    tags = [PROXY_TAG, f"scan:{scan_id}"]
    provider_id: str | None = None
    tunnel_proc: asyncio.subprocess.Process | None = None

    try:
        provider_id = await provider.create_node(region=region, ssh_public_key=ssh_key, tags=tags)
        logger.info("Provisioning node %s in %s", provider_id, region)
        ip_address = await provider.wait_until_ready(provider_id)

        if not _skip_tunnel:
            tunnel_proc = await _establish_tunnel(ip_address, ssh_key_path, local_socks_port)

        endpoint = ProxyEndpoint(host=ip_address, socks_port=local_socks_port)
        logger.info("Proxy ready: 127.0.0.1:%d → %s (node %s)", local_socks_port, ip_address, provider_id)
        yield endpoint
    finally:
        if tunnel_proc is not None and tunnel_proc.returncode is None:
            tunnel_proc.terminate()
            try:
                await asyncio.wait_for(tunnel_proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                tunnel_proc.kill()
                await tunnel_proc.wait()
            logger.info("SSH tunnel terminated")

        if provider_id is not None:
            await _shielded_destroy(provider, provider_id)

async def _shielded_destroy(provider: CloudNodeProvider, provider_id: str) -> None:
    """Destroy node, shielded from asyncio.CancelledError.
    Pattern: create concrete Task, shield it, if cancelled await task directly."""
    destroy_task = asyncio.ensure_future(provider.destroy_node(provider_id))
    try:
        await asyncio.shield(destroy_task)
        logger.info("Node %s destroyed", provider_id)
    except asyncio.CancelledError:
        try:
            await destroy_task
            logger.info("Node %s destroyed (post-cancellation)", provider_id)
        except Exception:
            logger.exception("Failed to destroy node %s during cancellation", provider_id)
        raise
    except Exception:
        logger.exception("Failed to destroy node %s", provider_id)

async def _establish_tunnel(
    ip_address: str, ssh_key_path: str, local_port: int,
    max_retries: int = 5, retry_delay: float = 3.0,
) -> asyncio.subprocess.Process:
    """Start SSH dynamic SOCKS5 tunnel with retry for sshd startup race."""
    expanded_key = os.path.expanduser(ssh_key_path)
    for attempt in range(max_retries):
        proc = await asyncio.create_subprocess_exec(
            "ssh", "-D", str(local_port), "-N",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3", "-o", "ExitOnForwardFailure=yes",
            "-i", expanded_key, f"root@{ip_address}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.sleep(2.0)
        if proc.returncode is None:
            return proc
        stderr = b""
        if proc.stderr:
            stderr = await proc.stderr.read()
        if attempt < max_retries - 1:
            logger.debug("SSH attempt %d failed: %s", attempt + 1, stderr.decode(errors="replace").strip())
            await asyncio.sleep(retry_delay)
            continue
        raise ProvisioningError(f"SSH tunnel failed after {max_retries} attempts: {stderr.decode(errors='replace')}")
    raise ProvisioningError("SSH tunnel failed: exhausted retries")
