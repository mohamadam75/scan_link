# scan_link — Daily VPN endpoint monitor

This repository collects public proxy/VPN configuration URIs from the sources in `sources.txt`, deduplicates them, and measures TCP connection latency from a GitHub-hosted Ubuntu runner.

## Daily automation

GitHub Actions runs daily at **06:00 Iran time (UTC+03:30)** and can also be started manually from **Actions → Daily VPN source monitor → Run workflow**.

## Add the subscription URL safely

The fifth subscription URL provided for this project contains a token-like identifier. Rather than publishing it in a public repository, add it as a repository Actions secret:

1. Open **Settings → Secrets and variables → Actions**.
2. Select **New repository secret**.
3. Set the name to `SUBSCRIPTION_URL` and the value to the subscription URL.
4. Save it and run the workflow manually once.

The four public GitHub sources are listed in `sources.txt`.

## Outputs

- `reports/latest.json`: source status, counts, measured endpoint results, and verification caveats.
- `configs/fastest-tcp.txt`: up to 10 endpoints with the lowest successful TCP-connect latency from the GitHub runner.
- `configs/hamrah-aval.txt`, `configs/irancell.txt`, `configs/mokhaberat.txt`: intentionally not populated with unverified configs.

## Important limitations

**TCP reachable does not mean the VPN tunnel works.** This first version checks whether a TCP connection to a parsed endpoint can be established and measures that connection time. It does not validate end-to-end traffic through each proxy.

A GitHub-hosted runner also cannot tell whether a config works on Hamrah Aval, Irancell, or Iran fixed-line internet. Operator-specific lists will remain unverified until probes are run from devices or servers actually connected to those networks. Do not interpret the endpoint list as an ISP-specific ranking.

The collector uses bounded downloads and a limited number of candidate files/tests. Some repositories or formats may not be parsed by this initial version. Sources are third-party and may change, go offline, or contain malicious/untrusted configurations; use care and do not put personal credentials into them.

## Development

Requires Python 3.12; the monitor uses only the Python standard library.

Run locally:

```bash
python monitor.py
```
