"""
mock_metadata.py — a SAFE imitation of cloud instance-metadata services.

The SSRF cloud-metadata module is exercised ONLY against this mock, NEVER against
a real 169.254.169.254. It imitates AWS (IMDSv1 + IMDSv2), GCP, and Azure IMDS
responses with OBVIOUSLY-FAKE credentials, so the metadata/internal logic can be
validated with zero risk.

In the Docker lab this runs as a container with the network alias
`169.254.169.254` on the ISOLATED network, so the SSRF app reaches it exactly as
it would a real metadata service — but it's a harmless fake on a private net.

Run standalone:  python lab/mock_metadata.py 8200
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAKE_ROLE = "mock-lab-role"
FAKE_CREDS = {
    "Code": "Success", "Type": "AWS-HMAC", "AccessKeyId": "ASIAFAKE000MOCKLAB00",
    "SecretAccessKey": "FAKEMOCKLABwJalrXUtnFEMIEXAMPLEKEY", "Token": "FAKE-MOCK-SESSION-TOKEN",
    "Expiration": "2030-01-01T00:00:00Z",
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_PUT(self):
        # AWS IMDSv2 token request.
        if self.path.startswith("/latest/api/token"):
            return self._send(200, "FAKE-IMDSV2-TOKEN-MOCKLAB")
        return self._send(404, "not found")

    def do_GET(self):
        p = self.path
        # AWS
        if p.rstrip("/").endswith("/iam/security-credentials"):
            return self._send(200, FAKE_ROLE)
        if FAKE_ROLE in p or "/iam/security-credentials/" in p:
            return self._send(200, json.dumps(FAKE_CREDS), "application/json")
        if "/latest/user-data" in p:
            return self._send(200, "#!/bin/bash\nexport DB_PASSWORD=fake-mock-init-secret\n")
        if "/latest/meta-data" in p:
            return self._send(200, "ami-id\nhostname\niam/\nuser-data\ninstance-id")
        # GCP (requires Metadata-Flavor: Google in real life; we accept it)
        if "computeMetadata" in p:
            if "token" in p:
                return self._send(200, json.dumps({"access_token": "FAKE.GCP.MOCK.TOKEN",
                                                    "token_type": "Bearer", "expires_in": 3599}),
                                  "application/json")
            return self._send(200, json.dumps({"project": {"projectId": "mock-lab-project"}}),
                              "application/json")
        # Azure
        if "metadata/identity/oauth2/token" in p:
            return self._send(200, json.dumps({"access_token": "FAKE.AZURE.MOCK.TOKEN",
                                               "token_type": "Bearer"}), "application/json")
        if "/metadata/instance" in p or "/metadata/v1" in p:
            return self._send(200, json.dumps({"compute": {"name": "mock-lab-vm",
                                              "location": "mocklab"}}), "application/json")
        return self._send(404, "not found")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8200
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"MOCK metadata server (FAKE creds only) on :{port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
