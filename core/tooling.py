"""
tooling.py — detection of the external CLI tools the platform wraps.

The platform leans on proven tools (subfinder, httpx, gau, katana, dalfox, ...)
rather than reinventing them. But the framework must still RUN if some are
missing: each wrapper checks availability first and degrades gracefully with a
clear message. This module is the single registry of those tools.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ExternalTool:
    name: str            # the command name on PATH
    purpose: str         # what we use it for
    stage: str           # 'recon' | 'xss' | 'callback' | 'verify'
    install: str         # how to install it
    kind: str = "go"     # 'go' | 'pip' | 'python' | 'other'


# The canonical list. Order roughly follows the pipeline.
TOOLS: list[ExternalTool] = [
    ExternalTool("subfinder", "Subdomain enumeration", "recon",
                 "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ExternalTool("httpx", "Probe which hosts are live (HTTP/S)", "recon",
                 "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ExternalTool("gau", "Harvest known URLs from archives", "recon",
                 "go install github.com/lc/gau/v2/cmd/gau@latest"),
    ExternalTool("katana", "Active crawl to discover URLs", "recon",
                 "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    ExternalTool("arjun", "Hidden HTTP parameter discovery", "recon",
                 "pip install arjun", kind="pip"),
    ExternalTool("gf", "Grep harvested URLs for XSS-likely patterns", "xss",
                 "go install github.com/tomnomnom/gf@latest", kind="go"),
    ExternalTool("kxss", "Find reflected, unfiltered special chars", "xss",
                 "go install github.com/Emoe/kxss@latest"),
    ExternalTool("dalfox", "Fire & verify reflected/stored XSS payloads", "xss",
                 "go install github.com/hahwul/dalfox/v2@latest"),
    ExternalTool("interactsh-client", "Out-of-band (blind XSS) callback listener",
                 "callback",
                 "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    # --- Access-control module (Prompt 2). All optional — wrapped when present. ---
    ExternalTool("mitmdump", "Proxy capture of authenticated traffic", "accesscontrol",
                 "pip install mitmproxy", kind="pip"),
    ExternalTool("ffuf", "Variant fuzzing for 403 bypass", "accesscontrol",
                 "go install github.com/ffuf/ffuf/v2@latest"),
    ExternalTool("nomore403", "403/401 bypass permutations", "accesscontrol",
                 "go install github.com/devploit/nomore403@latest"),
    ExternalTool("jwt_tool", "Heavy-lifting JWT attacks (optional)", "accesscontrol",
                 "pipx install jwt_tool  # or git clone ticarpi/jwt_tool", kind="other"),
    ExternalTool("clairvoyance", "GraphQL schema reconstruction (introspection off)",
                 "accesscontrol", "pip install clairvoyance", kind="pip"),
]


def is_available(tool_name: str) -> bool:
    """True if the command is found on PATH."""
    return shutil.which(tool_name) is not None


def tool_version(tool_name: str) -> str:
    """Best-effort version string (or '' if it can't be determined quickly)."""
    if not is_available(tool_name):
        return ""
    for flag in ("-version", "--version", "version", "-V"):
        try:
            out = subprocess.run(
                [tool_name, flag], capture_output=True, text=True, timeout=8
            )
            text = (out.stdout or out.stderr).strip().splitlines()
            if text:
                return text[0][:80]
        except Exception:
            continue
    return "(installed)"


def check_python_module(module: str) -> bool:
    """True if a Python module (e.g. 'playwright') can be imported."""
    import importlib.util

    return importlib.util.find_spec(module) is not None


def status_report() -> list[dict]:
    """
    Build a list of {name, available, purpose, stage, install, version} rows for
    the `bbp doctor` command. Includes Playwright as a special Python check.
    """
    rows: list[dict] = []
    for t in TOOLS:
        available = is_available(t.name)
        rows.append(
            {
                "name": t.name,
                "available": available,
                "purpose": t.purpose,
                "stage": t.stage,
                "install": t.install,
                "version": tool_version(t.name) if available else "",
            }
        )
    # Playwright is a Python package + browser, not a PATH command.
    pw = check_python_module("playwright")
    rows.append(
        {
            "name": "playwright (python)",
            "available": pw,
            "purpose": "Headless-browser verification (proves payload executes)",
            "stage": "verify",
            "install": "pip install playwright && playwright install chromium",
            "version": "",
        }
    )
    return rows
