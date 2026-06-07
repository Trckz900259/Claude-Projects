# Validation lab

A local, **isolated** set of deliberately-vulnerable targets for validating the
platform's modules. Nothing is exposed to the internet (every port binds to
`127.0.0.1`), and the cloud-metadata module is pointed ONLY at a **mock** IMDS
server with fake credentials — never a real `169.254.169.254`.

## Start / stop

```bash
make lab-up        # start the targets (localhost only)
make lab-status    # show container status + reachability
make lab-down      # stop and remove (and volumes)
```

Targets (all on `127.0.0.1`):

| Target | Port | Exercises |
|---|---|---|
| OWASP Juice Shop | 3000 | XSS, IDOR/BOLA, SQLi, auth |
| DVWA | 8081 | XSS, SQLi, cmd-injection, LFI, CSRF (selectable levels) |
| DVGA | 5013 | GraphQL authorization |
| SSRF lab | 8300 | SSRF + internal Spring-Actuator mock (`:9099`) |
| Mock IMDS | 8200 | AWS/GCP/Azure metadata (FAKE creds only) |

## Run the benchmark

```bash
# No Docker? Validate against the bundled fixtures (what we test in CI):
python tests/fixtures/vulnerable_app.py 8000 &
python tests/fixtures/vulnerable_api.py 8100 &
python tests/fixtures/vulnerable_ssrf.py 8300 &
bbp benchmark validation/lab_profile.local.yml

# With the Docker lab up:
make benchmark        # uses validation/lab_profile.docker.yml
```

Then explore the results:

```bash
bbp dashboard --db data/benchmark.db   # -> the "Validation" tab
```

## Preparing the public apps

Juice Shop / DVWA / DVGA need a per-target program config (scope = the localhost
port) and, for IDOR/GraphQL, **two registered test accounts** in a gitignored
identities file. Fill in `validation/lab_profile.docker.yml` and add the configs
under `config/`. The bundled `ssrf-lab` target works out of the box.

## Safety

Local-only, torn down on demand. The cloud-metadata module is exercised ONLY
against `mock-metadata` (fake creds). No real external target is ever touched.
