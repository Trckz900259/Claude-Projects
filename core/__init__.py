"""
core — the shared foundation for the Bug Bounty Platform.

Everything safety-critical lives here:

* config.py         — loads a per-program profile (scope, rules, rate limits...)
* scope.py          — the allow-list enforcer (out-of-scope = hard refusal)
* ratelimit.py      — thread-safe, conservative rate limiting
* http_engine.py    — the ONLY sanctioned way to make outbound requests; every
                      request passes through scope + rate-limit + User-Agent
* datastore.py      — the single SQLite datastore shared by every module
* logging_setup.py  — structured logging for reproducibility
* exceptions.py     — typed errors (e.g. OutOfScopeError)

Design rule: vuln modules and recon NEVER talk to the network directly. They go
through HttpEngine, so the scope allow-list can never be bypassed.
"""

__all__ = []
