"""
modules.accesscontrol — Broken Access Control / IDOR module (Prompt 2).

Several cooperating engines on a shared multi-identity foundation:
  * stateful REST replay + compare (the core), with a confidence-scoring
    decision engine,
  * a GraphQL authorization tester,
  * a JWT forgery tester,
  * a race-condition engine,
  * a 403/access-control bypass sub-module.

Safety is enforced in code: own-accounts-only (>= 2 of YOUR accounts required),
read-only proof, fresh/own state for races, plus the inherited scope allow-list,
rate limiting, User-Agent, and 'automated scanning allowed' gate.
"""
