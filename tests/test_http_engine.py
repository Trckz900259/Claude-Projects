"""
Tests for the HTTP engine.

The critical guarantee we prove here: an out-of-scope request raises
OutOfScopeError *before any network call is attempted*. We prove "no network
call" by swapping in a fake session that explodes if it is ever used.
"""

import pytest

from core.config import HttpConfig
from core.exceptions import OutOfScopeError
from core.http_engine import HttpEngine
from core.ratelimit import RateLimiter
from core.scope import ScopeEnforcer, ScopeRule


class ExplodingSession:
    """A stand-in for requests.Session that fails if .request() is ever called."""

    def __init__(self):
        self.called = False

    def request(self, *args, **kwargs):
        self.called = True
        raise AssertionError("Network call attempted for an out-of-scope target!")


class RecordingSession:
    """Captures the headers of the request that would have been sent."""

    def __init__(self):
        self.last_headers = None

    def request(self, method, url, headers=None, **kwargs):
        self.last_headers = headers
        return _FakeResponse(method, url, headers)


class _FakeResponse:
    def __init__(self, method, url, headers):
        self.status_code = 200
        self.headers = {"Content-Type": "text/html"}
        self.text = "ok"
        self.content = b"ok"
        self.url = url

        class _Req:
            pass

        self.request = _Req()
        self.request.headers = headers or {}
        self.request.body = None


@pytest.fixture
def engine_factory():
    def _make(session):
        scope = ScopeEnforcer(in_scope=[ScopeRule("domain", "example.com")])
        limiter = RateLimiter(requests_per_second=100, per_host_rps=100, max_concurrency=4)
        cfg = HttpConfig(user_agent="UnitTest BugBounty (contact: test@example.com)")
        engine = HttpEngine(scope=scope, rate_limiter=limiter, http_config=cfg)
        engine._session = session  # inject the fake
        return engine

    return _make


def test_out_of_scope_request_raises_and_makes_no_network_call(engine_factory):
    session = ExplodingSession()
    engine = engine_factory(session)

    with pytest.raises(OutOfScopeError):
        engine.get("https://not-in-scope.com/secret")

    assert session.called is False  # proof: we never touched the network


def test_in_scope_request_sets_user_agent(engine_factory):
    session = RecordingSession()
    engine = engine_factory(session)

    engine.get("https://example.com/")

    assert session.last_headers is not None
    assert session.last_headers["User-Agent"] == "UnitTest BugBounty (contact: test@example.com)"


def test_out_of_scope_error_names_the_target(engine_factory):
    engine = engine_factory(ExplodingSession())
    with pytest.raises(OutOfScopeError) as excinfo:
        engine.get("https://evil.example.org/")
    assert "evil.example.org" in str(excinfo.value)
