# Kotivahdit toolkit

🔴 **[Live numbers: kotivahdit.github.io](https://kotivahdit.github.io)**

**Small, dependency-free traps that waste attackers' time – and turn what they do into abuse reports.**
Built and run by *Kotivahdit*, a volunteer honeypot network from Finland (sensors in Stockholm and Iowa).

![license](https://img.shields.io/badge/license-MIT-blue) ![python](https://img.shields.io/badge/python-3.10%2B-blue) ![deps](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen)

> 🇫🇮 [Suomeksi: README_FI.md](README_FI.md)

## What's inside

| Tool | What it does |
|---|---|
| [`tarpit/telnet_tarpit.py`](tarpit/telnet_tarpit.py) | Telnet tarpit for Mirai-style bots: never shows a login prompt, drips one byte every ~10 s. Per-IP limit (5) so one bot cannot fill all slots; logs every trapped connection, also on shutdown; Prometheus metrics. |
| [`tarpit/silent_pit.py`](tarpit/silent_pit.py) | "Silent pit": accepts connections redirected (iptables `REDIRECT`) from MSSQL/MySQL/RDP/Redis/VNC/FTP brute-forcers and never answers. |
| [`web-trap/web_trap.py`](web-trap/web_trap.py) | Router-style web honeypot (80/443). Tags exploit attempts (GPON, HNAP, Hikvision, Log4j, ThinkPHP…), extracts payload URLs, **tarpits exploit requests** (one header line / 10 s, max 15 min) and serves **bait secret files** (`/.env`, `/config.json`, `/.aws/credentials`, `/.git/config`) carrying honeytoken keys. |
| [`docker-trap/docker_trap.py`](docker-trap/docker_trap.py) | Fake open Docker Engine API (2375). Answers like Docker 24 but runs nothing; logs container creates, exec commands, images, payload URLs and Monero wallets. |
| [`llm-shim/llm_shim.py`](llm-shim/llm_shim.py) | **Detection-resistant LLM honeypot shim.** Sits between an LLM honeypot (e.g. Beelzebub) and Ollama. Attackers fingerprint LLM honeypots with deterministic probes (`printf`, arithmetic, `set --` positional args, shell functions). Commands made only of safe shell builtins run in a **real, isolated `dash`** (no network namespace, `nobody`, no-new-privs, 64 MB, 1 s); everything else goes to the LLM. |
| [`phish-watch/phish_watch.py`](phish-watch/phish_watch.py) | Certificate Transparency watch (crt.sh) for brand look-alikes; opens the site and reports pages with login/card forms to Netcraft (Netcraft verifies before takedown). Never reports pages that redirect to the official domain. |

## How it fits together

```
 internet ──► traps (tarpits, web/docker traps, LLM honeypot+shim)   ← sensors never call home
                 │ logs
                 ▼
         collector (pulls over SSH, read-only)  ──►  AbuseIPDB · URLhaus/MalwareBazaar/ThreatFox
                 │                                    SANS ISC/DShield · AlienVault OTX · CrowdSec
                 ▼                                    GreyNoise · Netcraft
           dashboard + impact metrics
```

## Field notes

* 📄 [Attackers are fingerprinting LLM honeypots – a structured probe battery](docs/llm-honeypot-fingerprinting.md)

## What we have seen (first days)

* Credential thieves (Androxgh0st-style) fetched bait `.env` files and tried the honeytoken AWS key **within 2–3 minutes** – mostly SES calls to send spam.
* Cryptojackers on the fake Docker API tried to **steal Oracle Cloud API keys** (`/root/.oci/config`, `*.pem`) and escape to the host with `chroot`.
* LLM honeypots are being **systematically fingerprinted** with deterministic probes – hence `llm-shim`.

## Safety & ethics

* **Passive only.** Traps answer connections made to *our own* machines. No hack-back, no scanning, nothing runs on an attacker's machine.
* Run traps as unprivileged systemd `DynamicUser` with `ProtectSystem=strict`, and **block outbound traffic** from honeypot hosts (egress default-deny) so a compromised trap cannot be used against others.
* Don't expose real services on the same host. Use dedicated, disposable machines.
* IP addresses can be personal data (GDPR) – keep raw logs short-lived and publish only indicators.

## Quick start

```bash
sudo mkdir -p /opt/kotivahdit /var/log/kotivahdit && sudo cp */*.py /opt/kotivahdit/
python3 -I /opt/kotivahdit/telnet_tarpit.py 23 2323     # or as a systemd service (see systemd/)
```
Environment: `TARPIT_LOG`, `SILENT_PIT_LOG`, `REPORT_EMAIL` (Netcraft reports).

## License
MIT – see [LICENSE](LICENSE). Contributions and issue reports welcome.
