#!/usr/bin/env python3
"""Run Scan Link community ISP tests on the network currently in use."""
from __future__ import annotations
import argparse, hashlib, json, platform, shutil, sys
from datetime import datetime, timezone
from pathlib import Path
import monitor

OPERATORS = ("hamrah-aval", "irancell", "mokhaberat")

def main() -> int:
    ap = argparse.ArgumentParser(description="Test VPN configs from your current ISP using Xray.")
    ap.add_argument("--operator", required=True, choices=OPERATORS,
                    help="Select the network you are CURRENTLY connected to.")
    ap.add_argument("--input", default="configs/fastest-tcp.txt", help="Text subscription/config file")
    ap.add_argument("--out", default="community-result", help="Output filename prefix")
    ap.add_argument("--limit", type=int, default=60, help="Maximum configs to test (1..150)")
    args = ap.parse_args()
    if not 1 <= args.limit <= 150:
        ap.error("--limit must be between 1 and 150")
    xray = shutil.which("xray")
    if not xray:
        print("ERROR: Xray not found. Install Xray-core and ensure 'xray' is on PATH.", file=sys.stderr)
        return 2
    source = Path(args.input)
    if not source.is_file():
        print(f"ERROR: input file not found: {source}", file=sys.stderr)
        return 2
    configs = monitor.extract_configs(source.read_text(encoding="utf-8", errors="ignore"))
    unique, seen = [], set()
    for config in configs:
        key = monitor.config_fingerprint(config)
        if key not in seen and monitor.xray_outbound(config):
            seen.add(key)
            unique.append(config)
        if len(unique) >= args.limit:
            break
    if not unique:
        print("No supported configs found in input file.", file=sys.stderr)
        return 1
    results, working = [], []
    for index, config in enumerate(unique, 1):
        result = monitor.tunnel_probe(config, xray)
        ep = monitor.endpoint(config) or ("", 0)
        item = {
            "index": index,
            "fingerprint": hashlib.sha256(monitor.config_fingerprint(config).encode()).hexdigest(),
            "host": ep[0], "port": ep[1],
            "tunnel_ok": bool(result.get("tunnel_ok")),
            "tunnel_ms": result.get("tunnel_ms"),
            "http_status": result.get("http_status"),
            "error": result.get("error"),
        }
        results.append(item)
        if item["tunnel_ok"]:
            working.append(config)
        print(f"[{index}/{len(unique)}] {'PASS' if item['tunnel_ok'] else 'FAIL'} {ep[0]}:{ep[1]} {item['tunnel_ms'] or '-'} ms")
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    prefix = Path(args.out)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    report_path = prefix.with_name(prefix.name + ".json")
    configs_path = prefix.with_name(prefix.name + ".txt")
    report = {
        "schema_version": 1,
        "generated_at_utc": stamp,
        "operator_selected_by_tester": args.operator,
        "network_note": "Operator was self-selected; verify mobile data/Wi-Fi and disable VPN before testing.",
        "environment": {"platform": platform.platform(), "python": platform.python_version()},
        "test_method": "Xray outbound plus HTTPS request through local SOCKS5 to gstatic generate_204",
        "tested_count": len(results),
        "success_count": len(working),
        "results": results,
    }
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    configs_path.write_text("# Community-tested on the tester's selected network; review report before publishing.\n" +
                            "".join(c + "\n" for c in working), encoding="utf-8")
    print(f"\nFinished: {len(working)}/{len(unique)} passed.")
    print(f"Report: {report_path}\nPassing configs: {configs_path}")
    print("Review both files before opening a pull request. Do not submit private or paid subscription links without permission.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
