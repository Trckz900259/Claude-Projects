"""
recon — the reconnaissance pipeline.

Runs ONCE and populates the single shared inventory in the datastore:
subfinder (subdomains) -> httpx (live hosts) -> gau + katana (URLs) ->
arjun (parameters). Everything downstream consumes that inventory.
"""
