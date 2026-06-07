"""
orchestrator — the fault-tolerant, queue-based run engine.

Drives a module across the whole in-scope surface: each candidate is tested
independently (one failure or one hit never halts the run), with concurrency
bounded by the rate limiter, and runs are resumable via the datastore queue.
"""
