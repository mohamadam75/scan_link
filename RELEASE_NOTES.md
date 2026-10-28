# Release notes

## Initial public-ready version

- Collects public proxy/VPN configuration links from the five configured sources.
- Parses and deduplicates discovered configurations.
- Uses Xray to test supported configurations by making an HTTPS request through a local SOCKS5 tunnel.
- Publishes only configurations that pass the tunnel probe to the generated config list.
- Stores a timestamped JSON report with source counts and test results.
- Runs automatically through GitHub Actions on a daily schedule, with manual workflow dispatch available.

### Important limitations

- Tests run on a GitHub-hosted runner, not on Iranian mobile or fixed-line networks.
- The generated operator-named lists are not proof of operator-specific compatibility.
- A successful probe is a point-in-time result; public endpoints can stop working at any time.
- One source may return no parseable configurations in a given run.
