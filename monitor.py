#!/usr/bin/env python3
"""Collect public proxy/VPN configs and measure TCP endpoint reachability.

Important: TCP reachability is NOT proof that a VPN tunnel works, nor does a
GitHub-hosted runner represent Iranian mobile/fixed-line ISP connectivity.
"""
from __future__ import annotations

import base64
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCES_FILE = ROOT / "sources.txt"
CONFIG_DIR = ROOT / "configs"
REPORT_DIR = ROOT / "reports"
MAX_FILES_PER_REPO = 40
MAX_FILE_BYTES = 1_500_000
TIMEOUT_SECONDS = 3
MAX_TESTS = 500
UA = "scan_link-daily-monitor/1.0"
SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "socks://", "ssr://", "hy2://", "hysteria2://", "tuic://")

def fetch(url: str, limit: int = MAX_FILE_BYTES) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=12) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("response exceeded size limit")
    return data

def decode_text(data: bytes) -> str:
    text = data.decode("utf-8", errors="ignore").strip()
    # Many subscription endpoints return base64-encoded text.
    if text and not any(s in text.lower() for s in SCHEMES):
        compact = re.sub(r"\s+", "", text)
        if len(compact) >= 16 and re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
            try:
                decoded = base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4))
                candidate = decoded.decode("utf-8", errors="ignore")
                if any(s in candidate.lower() for s in SCHEMES):
                    return candidate
            except Exception:
                pass
    return text

def source_urls() -> list[str]:
    urls = []
    if SOURCES_FILE.exists():
        for raw in SOURCES_FILE.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and line.startswith(("http://", "https://")):
                urls.append(line)
    secret_url = os.environ.get("SUBSCRIPTION_URL", "").strip()
    if secret_url.startswith(("http://", "https://")):
        urls.append(secret_url)
    return list(dict.fromkeys(urls))

def github_repo_files(url: str) -> list[tuple[str, str]]:
    """Return raw URLs for a bounded set of text-like files in a public repo."""
    parsed = urllib.parse.urlparse(url)
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return []
    owner, repo = parts[0], parts[1].removesuffix(".git")
    api = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
    payload = json.loads(fetch(api, 5_000_000).decode("utf-8"))
    allowed = (".txt", ".yaml", ".yml", ".json", ".conf", ".list", ".ini", ".md", ".log", ".sub")
    selected = []
    for item in payload.get("tree", []):
        path = item.get("path", "")
        if item.get("type") != "blob" or not path.lower().endswith(allowed):
            continue
        if any(part in path.lower() for part in (".github/", "node_modules/", "vendor/", "docs/")):
            continue
        selected.append((path, f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{urllib.parse.quote(path, safe='/')}"))
    selected.sort(key=lambda x: (not any(k in x[0].lower() for k in ("config", "proxy", "vpn", "node", "sub", "all")), len(x[0])))
    return selected[:MAX_FILES_PER_REPO]

def get_source_text(url: str) -> list[tuple[str, str]]:
    if "github.com" in urllib.parse.urlparse(url).netloc.lower():
        files = github_repo_files(url)
        if files:
            results = []
            for path, raw_url in files:
                try:
                    text = decode_text(fetch(raw_url))
                    if any(s in text.lower() for s in SCHEMES):
                        results.append((f"{url}#{path}", text))
                except Exception as exc:
                    print(f"WARN file fetch failed ({path}): {exc}")
            return results
    return [(url, decode_text(fetch(url)))]

def extract_configs(text: str) -> list[str]:
    found = []
    # Configs are URI-based; retain each complete URI until whitespace.
    for line in text.splitlines():
        line = line.strip().strip('"').strip("'")
        if not line or line.startswith(("#", "//")):
            continue
        for match in re.finditer(r"(?i)(?:vless|vmess|trojan|ss|ssr|socks|hy2|hysteria2|tuic)://[^\s\"'<>]+", line):
            item = match.group(0).rstrip("),;")
            if len(item) < 12:
                continue
            found.append(item)
    return found

def endpoint(config: str) -> tuple[str, int] | None:
    scheme = config.split("://", 1)[0].lower()
    body = config.split("://", 1)[1]
    if scheme == "vmess":
        try:
            raw = base64.urlsafe_b64decode(body.split("#", 1)[0] + "=" * (-len(body.split("#", 1)[0]) % 4))
            obj = json.loads(raw.decode("utf-8", errors="ignore"))
            return str(obj.get("add", "")), int(obj.get("port", 0))
        except Exception:
            return None
    if scheme == "ss":
        # SIP002: method:password@host:port may itself be base64 encoded.
        candidate = body.split("#", 1)[0].split("?", 1)[0]
        if "@" not in candidate:
            try:
                candidate = base64.urlsafe_b64decode(candidate + "=" * (-len(candidate) % 4)).decode()
            except Exception:
                return None
        authority = candidate.rsplit("@", 1)[-1]
    elif scheme in ("vless", "trojan", "socks", "ssr", "hy2", "hysteria2", "tuic"):
        authority = body.split("#", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1]
    else:
        return None
    # Handle bracketed IPv6 and normal host:port.
    try:
        parsed = urllib.parse.urlsplit("//" + authority)
        host = parsed.hostname
        port = parsed.port
        if host and port and 1 <= port <= 65535:
            return host, port
    except ValueError:
        pass
    return None

def tcp_probe(host: str, port: int) -> dict:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS):
            ms = round((time.perf_counter() - start) * 1000, 2)
        return {"tcp_reachable": True, "tcp_connect_ms": ms, "error": None}
    except Exception as exc:
        return {"tcp_reachable": False, "tcp_connect_ms": None, "error": type(exc).__name__}

def main() -> None:
    CONFIG_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)
    sources = source_urls()
    source_status, unique = [], {}
    for url in sources:
        try:
            chunks = get_source_text(url)
            count = 0
            for source_label, text in chunks:
                for config in extract_configs(text):
                    unique.setdefault(config, {"source": source_label})
                    count += 1
            source_status.append({"source": url, "ok": True, "configs_found": count})
            print(f"OK {url}: {count} config entries")
        except Exception as exc:
            source_status.append({"source": url, "ok": False, "error": type(exc).__name__})
            print(f"WARN source failed {url}: {type(exc).__name__}")

    tested = []
    for config, meta in list(unique.items())[:MAX_TESTS]:
        ep = endpoint(config)
        if not ep:
            tested.append({"config": config, **meta, "tcp_reachable": False, "tcp_connect_ms": None, "error": "unsupported_or_unparseable_endpoint"})
            continue
        host, port = ep
        result = tcp_probe(host, port)
        tested.append({"config": config, **meta, "host": host, "port": port, **result})

    reachable = sorted(
        (x for x in tested if x.get("tcp_reachable") and x.get("tcp_connect_ms") is not None),
        key=lambda x: x["tcp_connect_ms"]
    )
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report = {
        "generated_at_utc": stamp,
        "test_environment": "GitHub-hosted Ubuntu runner",
        "method": "TCP connect latency to the proxy endpoint; this is not a VPN tunnel or ISP-specific test",
        "sources": source_status,
        "unique_configs_found": len(unique),
        "endpoints_tested": len(tested),
        "tcp_reachable_count": len(reachable),
        "fastest_tcp_endpoints": [
            {k: x.get(k) for k in ("config", "source", "host", "port", "tcp_connect_ms")}
            for x in reachable[:10]
        ],
        "operator_status": {
            "hamrah_aval": {"verified": False, "reason": "No test probe on the Hamrah Aval network is configured."},
            "irancell": {"verified": False, "reason": "No test probe on the Irancell network is configured."},
            "mokhaberat": {"verified": False, "reason": "No test probe on the fixed-line network is configured."}
        }
    }
    (REPORT_DIR / "latest.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (CONFIG_DIR / "fastest-tcp.txt").write_text(
        "# Fastest TCP-reachable endpoints from GitHub Actions; NOT verified working VPN tunnels.\n"
        f"# Generated UTC: {stamp}\n" +
        "".join(x["config"] + "\n" for x in reachable[:10]), encoding="utf-8"
    )
    for filename, label in (("hamrah-aval.txt", "Hamrah Aval"), ("irancell.txt", "Irancell"), ("mokhaberat.txt", "Mokhaberat")):
        (CONFIG_DIR / filename).write_text(
            f"# {label}: no operator-specific results published yet.\n"
            "# A test probe connected through this ISP is required before configs can be listed here.\n",
            encoding="utf-8"
        )
    print(f"Finished: {len(unique)} unique configs, {len(reachable)} TCP-reachable endpoints.")
    if not sources:
        print("WARN: no sources configured.")

if __name__ == "__main__":
    main()
