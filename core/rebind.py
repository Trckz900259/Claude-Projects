"""
rebind.py — DNS-rebinding helper (shared infrastructure).

DNS rebinding defeats SSRF filters that resolve a hostname, decide it's safe,
then resolve it AGAIN when fetching (a TOCTOU): we serve a public IP for the
safety check, then flip to the internal target for the fetch. We wrap public
rebinding services (rbndr.us / whonow / Singularity of Origin) rather than run a
DNS server here.

SAFETY GATE (enforced): the rebinding engine may ONLY ever rebind toward an
AUTHORIZED target. The internal/second IP must be explicitly allowed — either it
passes the program scope check, or it is listed in the program's
`ssrf.allowed_internal_targets`. Otherwise we refuse to build the payload.
"""

from __future__ import annotations

import ipaddress
import logging

from core.exceptions import OutOfScopeError

log = logging.getLogger("rebind")


def ip_to_hex(ip: str) -> str:
    """rbndr.us encodes each IPv4 as 8 hex chars, e.g. 127.0.0.1 -> 7f000001."""
    return f"{int(ipaddress.IPv4Address(ip)):08x}"


def rbndr_hostname(public_ip: str, target_ip: str) -> str:
    """A rbndr.us name that alternates between the two IPs with a tiny TTL."""
    return f"{ip_to_hex(public_ip)}.{ip_to_hex(target_ip)}.rbndr.us"


class DnsRebinder:
    def __init__(self, scope=None, allowed_internal: list[str] | None = None,
                 logger: logging.Logger | None = None) -> None:
        self.scope = scope
        self.allowed_internal = [a.strip() for a in (allowed_internal or [])]
        self.log = logger or log

    def _is_authorized_target(self, target_ip: str) -> bool:
        # Explicit allow-list (e.g. an internal range the program authorizes).
        for entry in self.allowed_internal:
            try:
                if "/" in entry and ipaddress.ip_address(target_ip) in ipaddress.ip_network(entry, strict=False):
                    return True
                if entry == target_ip:
                    return True
            except ValueError:
                continue
        # Or the scope allow-list accepts it.
        if self.scope is not None and self.scope.check(target_ip).allowed:
            return True
        return False

    def make_rebind(self, public_ip: str, target_ip: str, provider: str = "rbndr") -> str:
        """
        Return a rebinding hostname that alternates public_ip <-> target_ip.
        Refuses unless target_ip is authorized (safety gate).
        """
        if not self._is_authorized_target(target_ip):
            raise OutOfScopeError(
                target_ip,
                "DNS rebinding may only target an authorized in-scope/internal target. "
                "Add it to ssrf.allowed_internal_targets if the program permits it.")
        if provider == "rbndr":
            host = rbndr_hostname(public_ip, target_ip)
            self.log.info("rebind hostname (TTL~0, alternates %s<->%s): %s",
                          public_ip, target_ip, host)
            return host
        # whonow / Singularity would be constructed here for other providers.
        raise ValueError(f"unknown rebind provider {provider!r}")
