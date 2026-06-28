"""Shared pytest fixtures.

Every test gets its own fresh in-memory SQLite database, so tests are fully
isolated from one another and from any on-disk file. In-memory databases are
created and torn down per test, which keeps the suite fast.
"""

import pytest

from goldbot import Database


@pytest.fixture
def db():
    """A fresh, initialized in-memory database with NO accounts seeded.

    Use this when the test wants to control account creation itself.
    """
    database = Database(":memory:")
    database.initialize()
    yield database
    database.close()


@pytest.fixture
def seeded_db(db):
    """A fresh in-memory database with all 10 accounts seeded from config."""
    db.seed_accounts()
    return db
