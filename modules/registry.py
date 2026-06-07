"""
registry.py — maps a module name to its class.

Adding a new vuln module later (sqli, ssrf, ...) is just one line here.
"""

from __future__ import annotations

from modules.base import Module
from modules.xss.module import XssModule

REGISTRY: dict[str, type[Module]] = {
    "xss": XssModule,
}


def get_module_class(name: str) -> type[Module]:
    name = name.lower()
    if name not in REGISTRY:
        raise KeyError(
            f"Unknown module {name!r}. Available: {', '.join(sorted(REGISTRY))}"
        )
    return REGISTRY[name]


def available_modules() -> list[str]:
    return sorted(REGISTRY)
