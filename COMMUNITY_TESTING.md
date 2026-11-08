# Community ISP tester

This optional tester runs **on the volunteer's own connection**. It starts Xray locally and checks an HTTPS request through each supported VPN tunnel. The selected operator is self-reported; it is not inferred from IP.

## Requirements
- Python 3.10+
- Xray-core installed and available as `xray` on PATH
- curl installed
- A config/subscription text file (one share link per line)

## Run
First clone/download this repository and install Xray-core for your operating system. Then, while connected directly to the network you want to test, disable any existing VPN/proxy and run:

```bash
python community_tester.py --operator hamrah-aval --input configs/fastest-tcp.txt
```

Allowed operator values: `hamrah-aval`, `irancell`, `mokhaberat`.

The tool writes:
- `community-result.json`: test metadata and per-config outcomes (no passwords or full config links)
- `community-result.txt`: only links that passed the tunnel test

Change `--operator` to match the network actually in use. For example, do not select Hamrah Aval while connected to Wi-Fi or another SIM. On Android, use Termux; on Windows/Linux, use a terminal. Install Xray and curl separately before running.

## Submit results
Review the generated files. Create a pull request that adds the JSON report under `reports/community/` and the passing list under `community/`. Include the test date and confirm the selected network. Maintainers must review reports before any result is promoted into an operator subscription. A single volunteer report is provisional; repeated independent reports are preferred.

## Privacy and safety
- Never submit a private/paid subscription or a config you do not have permission to redistribute.
- The JSON report contains endpoint host/port, a one-way config fingerprint, timings and pass/fail details; it intentionally omits credentials and complete share links.
- The passing TXT file contains working share links. Treat it as public if you submit it in a public pull request.
- A self-selected operator is not cryptographic proof of the ISP. Test with VPN/proxy disabled and the target SIM/network active.
- A pass only means the tunnel reached the test HTTPS endpoint at that time; it does not guarantee speed, long-term uptime, or access to every website.
