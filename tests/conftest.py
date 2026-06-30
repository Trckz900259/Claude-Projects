"""
Pytest setup: make sure the repo root is importable so `from core...` works
even without `pip install -e .`. (Installing editable also works; this is a
belt-and-braces convenience.)
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _disarm_egress_guard():
    """
    Building a PlatformContext ARMS the structural egress guard process-wide
    (it monkeypatches socket.connect). That is what we want in production, but in
    the test process it must not leak between tests — otherwise one test's ctx
    could block an unrelated test's legitimate localhost I/O. So we disarm after
    every test. Tests that need it armed (test_egress.py) arm it themselves.
    """
    yield
    try:
        from core import egress

        egress.disarm()
    except Exception:
        pass
