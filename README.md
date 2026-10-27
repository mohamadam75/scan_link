# 🚀 scan_link — Daily VPN Config Scanner

**A small open-source monitor that gathers public VPN/proxy configurations, checks endpoint reachability, and refreshes its results automatically every morning.**

[![Daily update](https://github.com/mohamadam75/scan_link/actions/workflows/daily-update.yml/badge.svg)](https://github.com/mohamadam75/scan_link/actions/workflows/daily-update.yml)

> **Important:** This project currently measures TCP connection reachability from GitHub Actions. A reachable port does **not** prove that a VPN tunnel works, and GitHub's runner cannot determine whether a config works specifically on Hamrah Aval, Irancell, or Mokhaberat. Operator-specific lists are intentionally left unverified rather than filled with guesses.

## ✨ What it does

- 📥 Collects URI-based configs from the sources listed in `sources.txt`
- 🧹 Deduplicates config links
- ⚡ Measures TCP connection time for parsed endpoints
- 🏁 Publishes up to 10 of the fastest TCP-reachable endpoints
- 🔄 Runs automatically every day at **07:00 Iran time** (03:30 UTC)
- 🖱️ Supports a manual run from the **Actions** tab

## 📂 Results

| File | What you'll find |
| --- | --- |
| [`configs/fastest-tcp.txt`](configs/fastest-tcp.txt) | Up to 10 endpoints with the fastest successful TCP connection |
| [`reports/latest.json`](reports/latest.json) | Machine-readable report, source status, endpoint timings, and caveats |
| [`configs/hamrah-aval.txt`](configs/hamrah-aval.txt) | Reserved for results verified on Hamrah Aval |
| [`configs/irancell.txt`](configs/irancell.txt) | Reserved for results verified on Irancell |
| [`configs/mokhaberat.txt`](configs/mokhaberat.txt) | Reserved for results verified on Mokhaberat fixed-line internet |

## ⏰ Schedule

GitHub Actions uses a UTC cron schedule. The workflow is set to **03:30 UTC**, corresponding to **07:00 in Iran (UTC+03:30)**. GitHub may occasionally start scheduled workflows a little later than the exact minute.

To run it manually: open [Actions](https://github.com/mohamadam75/scan_link/actions), choose **Daily VPN source monitor**, then select **Run workflow**.

## 🧪 How testing works

1. Reads the configured public sources.
2. Extracts supported URI formats and removes duplicates.
3. Attempts a TCP connection to each parsed endpoint with a short timeout.
4. Sorts reachable endpoints by measured TCP connection time and writes the daily report.

**Fast TCP ≠ a working VPN.** This does not perform a full proxy handshake or route test traffic through each tunnel. The latency measured from GitHub's infrastructure is also not representative of latency from inside Iran.

## 📡 Operator-specific results and location labels

A GitHub-hosted runner is not connected to the target Iranian operators. Therefore, the project cannot honestly mark a config as working on Hamrah Aval, Irancell, or Mokhaberat until tests run through those networks. Likewise, server country/location should only be shown when it has been looked up from a reliable geolocation source; it should not be guessed from a config name.

To produce genuinely operator-specific rankings, run probes on devices or servers connected to each network and test the complete VPN tunnel, not just its TCP port.

## ⚠️ Safety and reliability

- Configs and subscriptions are third-party and may stop working without notice.
- Treat unknown configs as untrusted. Do not put personal credentials into them.
- Some source formats or repositories may not be supported by this initial collector.
- The daily workflow needs GitHub Actions to be enabled for this repository.

## 🛠️ Run locally

Requires Python 3.12. The collector uses only Python's standard library.

```bash
python monitor.py
```

## 🤝 Contributions

Issues and pull requests are welcome for adding sources, improving parsing, and implementing safe end-to-end tunnel tests.
