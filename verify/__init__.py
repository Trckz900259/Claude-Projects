"""
verify — shared verification service.

Loads a candidate in a headless browser (Playwright) and confirms a benign proof
payload ACTUALLY executes, then captures a screenshot/video. Unverified
candidates are kept separate so you never submit something unproven.
"""
