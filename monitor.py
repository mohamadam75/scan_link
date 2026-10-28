#!/usr/bin/env python3
"""Collect public proxy/VPN configs and measure TCP endpoint reachability.

Important: TCP reachability is NOT proof that a VPN tunnel works, nor does a
GitHub-hosted runner represent Iranian mobile/fixed-line ISP connectivity.
"""
from __future__ import annotations

import base64
import json
import hashlib
import os
import re
import socket
import time
import subprocess
import tempfile
import shutil
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
TIMEOUT_SECONDS = 2
PROBE_ATTEMPTS = 3
MAX_ACCEPTABLE_TCP_MS = 1200
MAX_TCP_JITTER_MS = 500
MAX_TESTS = 500
MAX_TUNNEL_TESTS = 100
TUNNEL_TIMEOUT_SECONDS = 7
TEST_URL = "https://www.gstatic.com/generate_204"
OUTPUT_LIMIT = 15
PER_OPERATOR_LIMIT = 5
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
    repo_meta = json.loads(fetch(f"https://api.github.com/repos/{owner}/{repo}", 500_000).decode("utf-8"))
    branch = repo_meta.get("default_branch", "main")
    api = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{urllib.parse.quote(branch, safe='/')}?recursive=1"
    payload = json.loads(fetch(api, 5_000_000).decode("utf-8"))
    allowed = (".txt", ".yaml", ".yml", ".json", ".conf", ".list", ".ini", ".md", ".log", ".sub")
    selected = []
    for item in payload.get("tree", []):
        path = item.get("path", "")
        if item.get("type") != "blob" or not path.lower().endswith(allowed):
            continue
        if any(part in path.lower() for part in (".github/", "node_modules/", "vendor/", "docs/")):
            continue
        selected.append((path, f"https://raw.githubusercontent.com/{owner}/{repo}/{urllib.parse.quote(branch, safe='/')}/{urllib.parse.quote(path, safe='/')}"))
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
            # Reject obvious truncation artifacts before endpoint parsing.
            if len(item) < 12 or item.endswith(("{", "[", "=", "&", "?", ":")):
                continue
            if not is_valid_config(item):
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

def is_valid_config(config: str) -> bool:
    """Conservative syntax/endpoint validation; this does not prove tunnel functionality."""
    if any(ch in config for ch in ("\n", "\r", "<", ">")):
        return False
    if config.endswith(("{", "[", "=", "&", "?")) or "&extra={" in config:
        return False
    scheme = config.split("://", 1)[0].lower() if "://" in config else ""
    ep = endpoint(config)
    if not ep:
        return False
    host, port = ep
    if not host or not (1 <= port <= 65535):
        return False
    if scheme == "vmess":
        try:
            body = config.split("://", 1)[1].split("#", 1)[0]
            raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
            obj = json.loads(raw.decode("utf-8"))
            return bool(obj.get("add") and int(obj.get("port", 0)) and obj.get("id"))
        except Exception:
            return False
    if scheme in ("vless", "trojan"):
        authority = config.split("://", 1)[1].split("?", 1)[0].split("#", 1)[0]
        userinfo = authority.rsplit("@", 1)[0] if "@" in authority else ""
        return bool(userinfo and not userinfo.endswith(":"))
    if scheme in ("ss", "ssr", "socks", "hy2", "hysteria2", "tuic"):
        return True
    return False


def xray_outbound(config: str) -> dict | None:
    """Convert common share links to Xray outbound JSON. Unsupported schemes are skipped."""
    scheme = config.split("://", 1)[0].lower()
    body = config.split("://", 1)[1].split("#", 1)[0]
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(config).query, keep_blank_values=True)
    def one(key, default=""):
        return q.get(key, [default])[0]
    try:
        if scheme == "vmess":
            raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
            v = json.loads(raw.decode("utf-8"))
            host, port, user_id = str(v["add"]), int(v["port"]), str(v["id"])
            net = str(v.get("net", "tcp")).lower()
            security = str(v.get("tls", "")).lower()
            stream = {"network": net, "security": "tls" if security in ("tls", "true") else "none"}
            if stream["security"] == "tls":
                stream["tlsSettings"] = {"serverName": str(v.get("sni") or v.get("host") or host), "allowInsecure": False}
            if net == "ws":
                stream["wsSettings"] = {"path": str(v.get("path", "/")), "headers": {"Host": str(v.get("host") or host)}}
            elif net == "grpc":
                stream["grpcSettings"] = {"serviceName": str(v.get("path", ""))}
            elif net == "httpupgrade":
                stream["httpupgradeSettings"] = {"path": str(v.get("path", "/")), "host": str(v.get("host") or host)}
            return {"protocol": "vmess", "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": user_id, "alterId": int(v.get("aid", 0) or 0), "security": str(v.get("scy", "auto") or "auto")}]}]}, "streamSettings": stream}
        parsed = urllib.parse.urlsplit(config)
        host, port = parsed.hostname, parsed.port
        if not host or not port:
            return None
        if scheme == "vless":
            uid = urllib.parse.unquote(parsed.username or "")
            if not uid:
                return None
            net = one("type", "tcp").lower()
            security = one("security", "none").lower()
            stream = {"network": net, "security": security}
            if security == "tls":
                stream["tlsSettings"] = {"serverName": one("sni", host), "allowInsecure": False}
                if one("fp"):
                    stream["tlsSettings"]["fingerprint"] = one("fp")
            elif security == "reality":
                stream["realitySettings"] = {"serverName": one("sni", host), "fingerprint": one("fp", "chrome"), "publicKey": one("pbk"), "shortId": one("sid"), "spiderX": one("spx", "/")}
                if not one("pbk"):
                    return None
            if net == "ws":
                stream["wsSettings"] = {"path": one("path", "/"), "headers": {"Host": one("host", host)}}
            elif net == "grpc":
                stream["grpcSettings"] = {"serviceName": one("serviceName", one("service_name", "")), "multiMode": one("mode") == "multi"}
            elif net == "httpupgrade":
                stream["httpupgradeSettings"] = {"path": one("path", "/"), "host": one("host", host)}
            elif net not in ("tcp", "raw", "kcp"):
                return None
            flow = one("flow")
            user = {"id": uid, "encryption": one("encryption", "none")}
            if flow:
                user["flow"] = flow
            return {"protocol": "vless", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}, "streamSettings": stream}
        if scheme == "trojan":
            password = urllib.parse.unquote(parsed.username or "")
            if not password:
                return None
            stream = {"network": one("type", "tcp"), "security": "tls", "tlsSettings": {"serverName": one("sni", one("peer", host)), "allowInsecure": False}}
            if one("fp"):
                stream["tlsSettings"]["fingerprint"] = one("fp")
            if stream["network"] == "ws":
                stream["wsSettings"] = {"path": one("path", "/"), "headers": {"Host": one("host", host)}}
            elif stream["network"] == "grpc":
                stream["grpcSettings"] = {"serviceName": one("serviceName", "")}
            elif stream["network"] not in ("tcp", "raw"):
                return None
            return {"protocol": "trojan", "settings": {"servers": [{"address": host, "port": port, "password": password}]}, "streamSettings": stream}
        if scheme == "ss":
            candidate = body.split("?", 1)[0]
            if "@" not in candidate:
                candidate = base64.urlsafe_b64decode(candidate + "=" * (-len(candidate) % 4)).decode()
            userinfo, authority = candidate.rsplit("@", 1)
            if ":" not in userinfo:
                return None
            method, password = userinfo.split(":", 1)
            parsed_auth = urllib.parse.urlsplit("//" + authority)
            if not parsed_auth.hostname or not parsed_auth.port:
                return None
            return {"protocol": "shadowsocks", "settings": {"servers": [{"address": parsed_auth.hostname, "port": parsed_auth.port, "method": method, "password": urllib.parse.unquote(password)}]}}
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return None


def tunnel_probe(config: str, xray_path: str) -> dict:
    """Run one config with Xray and require a real HTTPS response through its SOCKS tunnel."""
    outbound = xray_outbound(config)
    if not outbound:
        return {"tunnel_ok": False, "tunnel_ms": None, "error": "unsupported_or_unparseable"}
    with tempfile.TemporaryDirectory(prefix="scan-link-") as tmp:
        config_path = Path(tmp) / "xray.json"
        runtime_config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
        }
        config_path.write_text(json.dumps(runtime_config), encoding="utf-8")
        started = time.perf_counter()
        proc = None
        try:
            proc = subprocess.Popen([xray_path, "run", "-c", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    return {"tunnel_ok": False, "tunnel_ms": None, "error": "xray_start_failed"}
                try:
                    with socket.create_connection(("127.0.0.1", 10808), timeout=0.15):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                return {"tunnel_ok": False, "tunnel_ms": None, "error": "local_proxy_not_ready"}
            result = subprocess.run(
                ["curl", "--silent", "--show-error", "--output", os.devnull, "--max-time", str(TUNNEL_TIMEOUT_SECONDS),
                 "--write-out", "%{http_code}", "--socks5-hostname", "127.0.0.1:10808", TEST_URL],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=TUNNEL_TIMEOUT_SECONDS + 2,
            )
            elapsed = round((time.perf_counter() - started) * 1000, 2)
            ok = result.returncode == 0 and result.stdout.strip().isdigit() and 200 <= int(result.stdout.strip()) < 400
            return {"tunnel_ok": ok, "tunnel_ms": elapsed if ok else None, "http_status": result.stdout.strip() if result.returncode == 0 else None, "error": None if ok else "https_through_tunnel_failed"}
        except (OSError, subprocess.TimeoutExpired):
            return {"tunnel_ok": False, "tunnel_ms": None, "error": "probe_timeout_or_runtime_error"}
        finally:
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1)

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

    xray_path = shutil.which("xray") or os.environ.get("XRAY_PATH")
    tested = []
    candidates = sorted(unique.items(), key=lambda item: hashlib.sha256(item[0].encode("utf-8")).digest())[:MAX_TESTS]
    tunnel_candidates = [item for item in candidates if xray_outbound(item[0]) is not None][:MAX_TUNNEL_TESTS]
    if not xray_path:
        print("ERROR: Xray binary not found; refusing to publish unverified configs.")
    else:
        for config, meta in tunnel_candidates:
            result = tunnel_probe(config, xray_path)
            ep = endpoint(config)
            host, port = ep if ep else ("", 0)
            tested.append({"config": config, **meta, "host": host, "port": port, **result})
            if result.get("tunnel_ok"):
                print(f"TUNNEL OK {host}:{port} {result.get('tunnel_ms')}ms")
    working = sorted((x for x in tested if x.get("tunnel_ok")), key=lambda x: x["tunnel_ms"])
    seen, unique_working = set(), []
    for item in working:
        key = (item.get("host"), item.get("port"))
        if key in seen:
            continue
        seen.add(key)
        unique_working.append(item)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report = {
        "generated_at_utc": stamp,
        "test_environment": "GitHub-hosted Ubuntu runner; not an Iranian ISP",
        "method": f"Xray tunnel test: start supported outbound, then HTTPS GET to {TEST_URL} through local SOCKS5; timeout {TUNNEL_TIMEOUT_SECONDS}s. Successful tunnel tests only are published.",
        "sources": source_status,
        "unique_configs_found": len(unique),
        "candidate_configs_tested": len(tested),
        "tunnel_success_count": len(working),
        "unique_working_endpoints": len(unique_working),
        "tested": [{k: x.get(k) for k in ("source", "host", "port", "tunnel_ok", "tunnel_ms", "http_status", "error")} for x in tested],
        "fastest_tunnel_configs": [{k: x.get(k) for k in ("config", "source", "host", "port", "tunnel_ms", "http_status")} for x in unique_working[:OUTPUT_LIMIT]],
        "operator_status": {
            "hamrah_aval": {"verified": False, "reason": "GitHub runner is not connected to Hamrah Aval."},
            "irancell": {"verified": False, "reason": "GitHub runner is not connected to Irancell."},
            "mokhaberat": {"verified": False, "reason": "GitHub runner is not connected to the fixed-line network."}
        }
    }
    (REPORT_DIR / "latest.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    header = (f"# Only configs that passed an Xray tunnel + HTTPS request test; generated UTC: {stamp}\n"
              f"# Environment: GitHub Actions, not an Iranian ISP. Successful tunnel tests: {len(unique_working)}\n")
    (CONFIG_DIR / "fastest-tcp.txt").write_text(header + "".join(x["config"] + "\n" for x in unique_working[:OUTPUT_LIMIT]), encoding="utf-8")
    for filename, label in (("hamrah-aval.txt", "Hamrah Aval"), ("irancell.txt", "Irancell"), ("mokhaberat.txt", "Mokhaberat fixed-line")):
        (CONFIG_DIR / filename).write_text(
            f"# No ISP-specific verification is available for {label}; do not treat this as an operator-tested list.\n"
            f"# Generic Xray tunnel successes from GitHub runner: {len(unique_working)}\n"
            + "".join(x["config"] + "\n" for x in unique_working[:PER_OPERATOR_LIMIT]), encoding="utf-8"
        )
    print(f"Finished: {len(unique)} unique configs, {len(tested)} tunnel tests, {len(unique_working)} verified HTTPS-through-tunnel candidates.")
    if not sources:
        print("WARN: no sources configured.")

if __name__ == "__main__":
    main()
