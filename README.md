<p align="center">
  <img src="assets/banner.svg" alt="PhantomEye banner" width="900"/>
</p>

<p align="center">
  <a href="https://github.com/Egyan07/PhantomEye/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Egyan07/PhantomEye/ci.yml?label=CI&logo=githubactions&logoColor=white" alt="CI"></a>
  <img src="https://img.shields.io/badge/tests-148%2B%20passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen" alt="Dependencies">
  <a href="https://github.com/Egyan07/PhantomEye/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Egyan07/PhantomEye" alt="License"></a>
  <a href="https://github.com/Egyan07/PhantomEye/releases/latest"><img src="https://img.shields.io/github/v/release/Egyan07/PhantomEye?label=latest&color=blue" alt="Latest release"></a>
</p>

<p align="center">
  <strong>8 threat feeds · 148+ tests · zero dependencies · 3 scan engines · IP geolocation · 40,000+ IOCs</strong>
</p>

<p align="center">
  Author: <a href="https://github.com/Egyan07">Egyan07</a> · Red Parrot Accounting Ltd
</p>

> **Windows Only** — PhantomEye reads Windows Firewall logs, the Windows DNS resolver cache, and registers Windows Scheduled Tasks. It requires Windows 10 or later.

---

## What Is PhantomEye?

PhantomEye is a free, zero-dependency threat intelligence platform for Windows. It automatically downloads indicators of compromise (IOCs) from 8 public threat feeds, then scans your firewall logs, DNS cache, and email headers against 40,000+ known-bad IPs and domains. When a match is found it logs a timestamped alert, displays it in the GUI dashboard, and optionally sends an email notification — giving small businesses and home labs automated threat monitoring without paid subscriptions, cloud accounts, or third-party agents.

---

## How It Works

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  UPDATE   │────▶│   SCAN   │────▶│  ALERT   │────▶│  REVIEW  │
│           │     │          │     │          │     │          │
│ 8 feeds   │     │ Firewall │     │ Desktop  │     │ Dashboard│
│ fetched & │     │ DNS cache│     │ + email  │     │ + CSV    │
│ cached    │     │ Email    │     │ notify   │     │ export   │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
```

---

## Screenshots

| Dashboard | IP / Domain Lookup |
|:-:|:-:|
| ![Dashboard](https://raw.githubusercontent.com/Egyan07/PhantomEye/main/screenshots/Dashboard.png) | ![IP Domain Lookup](https://raw.githubusercontent.com/Egyan07/PhantomEye/main/screenshots/IP-Domain%20Lookup.png) |

| Email Header Analyzer | DNS Cache | Alert History |
|:-:|:-:|:-:|
| ![Email Header Analyzer](https://raw.githubusercontent.com/Egyan07/PhantomEye/main/screenshots/Email%20Header%20Analyzer.png) | ![DNS Cache](https://raw.githubusercontent.com/Egyan07/PhantomEye/main/screenshots/DNS%20Cache.png) | ![Alert History](https://raw.githubusercontent.com/Egyan07/PhantomEye/main/screenshots/Alert%20History.png) |

---

## Comparison

| Capability | PhantomEye | Snort | OSSEC | CrowdStrike Free |
|---|:-:|:-:|:-:|:-:|
| Free & open-source | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| Zero dependencies | :white_check_mark: | :x: | :x: | :x: |
| Windows-native install | :white_check_mark: | :x: | :white_check_mark: | :white_check_mark: |
| Threat-feed IOC matching | :white_check_mark: | :white_check_mark: | :x: | :white_check_mark: |
| Email header analysis | :white_check_mark: | :x: | :x: | :x: |
| DNS cache scanning | :white_check_mark: | :x: | :x: | :x: |
| GUI dashboard | :white_check_mark: | :x: | :white_check_mark: | :white_check_mark: |
| No cloud account needed | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| Setup time | ~2 min | 30+ min | 15+ min | 10+ min |

---

## Features

### Detection

| Feature | Description |
|---|---|
| Firewall Log Scanner | Checks Windows Firewall log for outbound and inbound connections to known malicious IPs |
| DNS Cache Scanner | Reads the Windows DNS resolver cache and flags domains matching threat feeds |
| Email Header Analyzer | Paste raw Outlook headers — extracts and checks all relay IPs and sender domains |
| IP / Domain Lookup | Instant verdict from 40,000+ IOCs — paste any IP, domain, or full URL |
| Multi-feed matching | Each IOC is checked against all 8 feeds; results show which feed flagged it |
| Connection Monitor | Real-time netstat polling checks active TCP connections against threat feeds |
| IP Geolocation | Lookup results show country, city, ISP, and AS number for malicious IPs |

### Monitoring

| Feature | Description |
|---|---|
| Scheduled feed updates | Windows Scheduled Task refreshes all 8 feeds every 6 hours |
| Scheduled morning scan | Daily 6 AM scan runs headlessly and alerts on any new matches |
| Alert deduplication | Same IOC will not re-alert within 24 hours |
| Email notifications | Optional SMTP alerts with TLS and verified server certificates |
| Alert history | Full timestamped log with search, filter, and CSV export |
| Feed status dashboard | Per-feed IOC count, last-update timestamp, and health indicator |
| HTML report export | Generate shareable dark-themed HTML reports from alert history |

### Developer Experience

| Feature | Description |
|---|---|
| 148+ unit tests | Covers utils, feeds, lookup, alerts, database, scanners, geolocation, reports, and monitor |
| Zero runtime dependencies | Runs entirely on the Python standard library |
| Health check CLI | `--check` validates config, DB connectivity, and feed freshness |
| Keyboard shortcuts | F5, Ctrl+U/F/D, Ctrl+1-6 for quick navigation |
| Tooltips | Hover tooltips on every action button |
| CodeQL SAST | Automated security scanning on every push |
| Clean architecture | 14 focused modules — no 1,000-line files |

---

## Threat Feeds

All feeds are free and require no account or API key.

| Feed | Type | Coverage |
|---|---|---|
| Feodo Tracker | IP | Botnet C2 servers |
| Emerging Threats | IP | Compromised hosts |
| CINS Score | IP | Known bad actors |
| Abuse.ch SSL Blacklist | IP | Malicious SSL certificates |
| URLhaus | Domain | Malware download URLs |
| OpenPhish | Domain | Active phishing sites |
| Botvrij.eu | Domain | Malicious domains |
| Botvrij.eu | IP | Malicious IPs |

---

## Quick Start

### Option A — Installer (recommended)

1. Download or clone the repository
2. Open `config.py` and set `ADMIN_PC` to your machine name
3. Right-click `Install_PhantomEye.bat` → **Run as administrator**
4. PhantomEye launches automatically and feeds are downloaded

The installer creates two Windows Scheduled Tasks:
- **Feed update** — every 6 hours
- **Morning scan** — daily at 6:00 AM

Both run as your user account, not SYSTEM.

### Option B — Manual

```bash
git clone https://github.com/Egyan07/PhantomEye.git
cd PhantomEye

# Edit config.py — set ADMIN_PC to your machine name

# Update feeds
python main.py --update-feeds

# Launch the GUI
python main.py --gui
```

---

## Testing

```bash
pip install pytest
pytest tests/ -v
```

| Test suite | File | Tests |
|---|---|---|
| Utilities | `test_utils.py` | IP/domain validation, whitelist, URL stripping |
| Feeds | `test_feeds.py` | Feed parsing, caching, staleness detection |
| Lookup | `test_lookup.py` | IOC lookup engine, edge cases |
| Alerts | `test_alerts.py` | Dispatch, deduplication, email formatting |
| Database | `test_database.py` | Schema creation, read/write, migrations |
| Scanner | `test_scanner.py` | Firewall, DNS, and email scanners |
| Geolocation | `test_geolocation.py` | IP geolocation lookups, caching, error handling |
| Reports | `test_reports.py` | HTML report generation and formatting |
| Monitor | `test_monitor.py` | Netstat parsing, connection monitoring, IOC checks |

---

## Architecture

```
                        ┌─────────────┐
                        │   main.py   │
                        │   (CLI)     │
                        └──────┬──────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
        ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
        │  feeds.py  │   │scanner.py │   │  gui/     │
        │  Download  │   │ Firewall  │   │  app.py   │
        │  & cache   │   │ DNS cache │   │  Tabs     │
        │            │   │ Email hdr │   │  Theme    │
        │ monitor.py │   │           │   │           │
        │ reports.py │   │geolocation│   │           │
        │            │   │  .py      │   │           │
        └─────┬──────┘   └─────┬─────┘   └─────┬─────┘
              │                │               │
        ┌─────▼──────────────▼───────────────▼──┐
        │            lookup.py                    │
        │        O(1) IOC lookup engine           │
        └─────────────────┬───────────────────────┘
                          │
              ┌───────────┼───────────┐
              │           │           │
        ┌─────▼───┐ ┌────▼────┐ ┌────▼─────┐
        │alerts.py│ │database │ │ utils.py │
        │ Dispatch│ │  .py    │ │ Validate │
        │ + email │ │ SQLite  │ │ & parse  │
        └─────────┘ └─────────┘ └──────────┘
```

---

<details>
<summary><strong>CLI Reference</strong></summary>

| Command | Description |
|---|---|
| `python main.py --gui` | Launch the GUI dashboard |
| `python main.py --update-feeds` | Download and cache all 8 threat feeds |
| `python main.py --scan` | Run a headless scan (firewall + DNS + email) |
| `python main.py --lookup <ioc>` | Look up a single IP, domain, or URL |
| `python main.py --check` | Validate config, database, and feed health |
| `python main.py --version` | Print the current version |

All commands can be combined with Windows Task Scheduler or wrapped in batch scripts for automation.

</details>

---

## Configuration

Edit `config.py` to customise PhantomEye for your environment.

| Setting | Default | Description |
|---|---|---|
| `ADMIN_PC` | `""` | Your machine name — required for scheduled tasks |
| `EMAIL_ENABLED` | `False` | Enable SMTP email alerts |
| `SMTP_SERVER` | `"smtp.gmail.com"` | SMTP server address |
| `SMTP_PORT` | `587` | SMTP port (TLS) |
| `ALERT_HISTORY_LIMIT` | `500` | Maximum alerts stored in the database |
| `FEED_UPDATE_HOURS` | `6` | Hours between scheduled feed updates |

### Email password

Store your SMTP password as a Windows environment variable — **never hardcode it**:

```powershell
# Run PowerShell as Administrator
[System.Environment]::SetEnvironmentVariable(
  'PHANTOMEYE_EMAIL_PASSWORD', 'your_app_password', 'Machine')
```

---

## Security

| Area | Measure |
|---|---|
| Network | All feed downloads use HTTPS; no data leaves the machine except optional email alerts |
| Email | SMTP uses TLS with `ssl.create_default_context()` — server certificate is verified |
| Credentials | Email password read from environment variable at runtime; never stored in config or database |
| Database | Local SQLite only; no remote connections; no user data is uploaded |
| Input validation | IPs validated via `ipaddress` stdlib; domains sanitised before lookup; URLs auto-stripped |
| Alert integrity | 24-hour deduplication prevents alert flooding; history capped at configurable limit |
| Resource safety | All database connections wrapped in `try/finally`; SMTP calls use explicit timeout (30 s) |
| SAST scanning | CodeQL analysis on every push/PR and weekly schedule |

For vulnerability reporting, see [SECURITY.md](SECURITY.md).

---

## Enabling Windows Firewall Logging

For the firewall scanner to detect threats, Windows must be configured to log connections:

1. Open **Windows Defender Firewall with Advanced Security**
2. Click **Windows Defender Firewall Properties**
3. On each profile tab (Domain, Private, Public):
   - Logging → Customize
   - Log successful connections: **Yes**
   - Log dropped packets: **Yes**
4. Click **OK** and close the window

---

## Limitations

| Limitation | Detail |
|---|---|
| Windows only | Reads Windows Firewall logs and DNS cache; does not run on Linux or macOS |
| Known-bad detection only | Matches against public threat feeds; does not detect zero-day or novel attacks |
| Feed lag | Public feeds typically lag 24–72 hours behind live threats |
| No real-time blocking | Detects and alerts; does not drop packets or kill processes |
| Single machine | Scans the local machine only; no multi-host or network-wide deployment |
| No auto-update | Feed URLs are hardcoded; new feeds require a code change |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| "No feeds loaded" on first launch | Run `python main.py --update-feeds` or wait for the scheduled task |
| Firewall scan finds nothing | Enable firewall logging — see [Enabling Windows Firewall Logging](#enabling-windows-firewall-logging) |
| Email alerts not sending | Verify `EMAIL_ENABLED = True` in `config.py` and that the environment variable `PHANTOMEYE_EMAIL_PASSWORD` is set |
| `--check` reports stale feeds | Feeds older than 24 hours are flagged; run `--update-feeds` to refresh |
| GUI does not launch | Ensure you are running Python 3.10+ with tkinter (included in the standard Windows installer) |
| Permission errors on install | Right-click `Install_PhantomEye.bat` → **Run as administrator** |

---

## Contributing

### Development setup

```bash
git clone https://github.com/Egyan07/PhantomEye.git
cd PhantomEye
pip install pytest ruff
pytest tests/ -v
```

### Pull request checklist

- [ ] All existing tests pass (`pytest tests/ -v`)
- [ ] New code has corresponding tests
- [ ] No new runtime dependencies (stdlib only)
- [ ] `ruff check .` passes with no errors
- [ ] Commit messages are clear and descriptive

---

## Roadmap

| Item | Status |
|---|---|
| VirusTotal API integration | Planned |
| Scheduled report summaries (HTML email) | Planned |
| Custom feed URL support via config | Under consideration |
| Multi-machine alert aggregation | Under consideration |
| Linux / macOS firewall log support | Future |
| Plugin system for third-party scanners | Future |

---

## Disclaimer

PhantomEye is a **known-bad detector** — it matches your network activity against public threat intelligence feeds that typically lag 24–72 hours behind novel attacks. It is not a replacement for a full EDR, SIEM, or managed security service. It is designed to raise the security floor for small businesses and home labs that currently have no automated threat monitoring.

---

## License

[MIT License](LICENSE) — free to use, modify, and distribute.

---

<p align="center"><em>PhantomEye — See the threats they can't.</em></p>
