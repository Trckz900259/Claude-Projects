"""
Pytest setup: make sure the repo root is importable so `from core...` works
even without `pip install -e .`. (Installing editable also works; this is a
belt-and-braces convenience.)
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
