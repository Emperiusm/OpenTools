"""Ephemeral infrastructure provisioning for proxied scan execution."""
from opentools.scanner.infra.provider import (
    CloudNodeProvider,
    EphemeralNode,
    ProvisioningError,
    ProvisioningTimeout,
)
from opentools.scanner.infra.digitalocean import DigitalOceanProvider
from opentools.scanner.infra.vultr import VultrProvider
from opentools.scanner.infra.proxy import ProxyEndpoint, ephemeral_proxy, PROXY_TAG

__all__ = [
    "CloudNodeProvider",
    "DigitalOceanProvider",
    "EphemeralNode",
    "PROXY_TAG",
    "ProvisioningError",
    "ProvisioningTimeout",
    "ProxyEndpoint",
    "VultrProvider",
    "ephemeral_proxy",
]
