# 👁 PhantomEye

**Free threat intelligence platform for Windows**  
Automatically checks your network activity against 8 live threat feeds — malware IPs, C2 servers, phishing domains, and more.

> Built by Egyan | Red Parrot Accounting Ltd

---

## Screenshots

![PhantomEye Dashboard](https://raw.githubusercontent.com/YOUR_USERNAME/PhantomEye/main/screenshots/Dashboard.png)

---

## What It Does

PhantomEye downloads threat intelligence from 8 free public feeds and checks your Windows network activity against them in real time.

It detects:
- Machines connecting to known **malware / C2 servers** (both allowed and blocked connections)
- DNS lookups for known **phishing or malware domains**
- Malicious IPs or domains in **email headers**
- Any IP or domain you want to **manually check**

---

## Features

| Feature | Description |
|---|---|
| 🔍 IP / Domain Lookup | Instant verdict from 40,000+ IOCs — paste any IP or domain |
| 📧 Email Header Analyser | Paste raw Outlook headers — extracts and checks all relay IPs and sender domains |
| 🔥 Firewall Log Scanner | Checks Windows Firewall log against threat feeds — flags both ALLOW and DROP entries |
| 🌐 DNS Cache Scanner | Checks your Windows DNS resolver cache for malicious domains |
| 📊 Alert History | Full timestamped alert log with CSV export |
| 📡 Feed Status | Per-feed IOC count and last-update timestamp |

---

## Threat Feeds (all free, no account needed)

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

## Requirements

- Windows 10 or 11
- Python 3.10 or newer — [python.org](https://www.python.org/downloads/)
- Internet connection for feed updates
- **No extra packages needed** — runs entirely on Python's standard library

---

## Installation

1. Clone or download this repo
2. Open `config.py` and set `ADMIN_PC` to your admin machine name
3. Right-click `Install_PhantomEye.bat` → **Run as administrator**
4. Done — PhantomEye launches automatically and feeds are downloaded

The installer creates two Windows Scheduled Tasks:
- **Feed update** — every 6 hours
- **Morning scan** — daily at 6:00 AM

Both run as your user account, not SYSTEM.

---

## Usage

**Launch the GUI:**
```
python C:\SecurityLogs\PhantomEye\main.py --gui
```

**Update feeds only:**
```
python C:\SecurityLogs\PhantomEye\main.py --update-feeds
```

**Run a scan headlessly (for scripting):**
```
python C:\SecurityLogs\PhantomEye\main.py --scan
```

**Quick lookup from terminal:**
```
python C:\SecurityLogs\PhantomEye\main.py --lookup 185.234.xx.xx
python C:\SecurityLogs\PhantomEye\main.py --lookup evil-domain.ru
```

---

## Email Alerts (optional)

Set `EMAIL_ENABLED = True` in `config.py`.

Store your password as a Windows environment variable — **never hardcode it**:
```powershell
# Run PowerShell as Administrator
[System.Environment]::SetEnvironmentVariable(
  'PHANTOMEYE_EMAIL_PASSWORD', 'your_app_password', 'Machine')
```

---

## Project Structure

```
PhantomEye/
├── main.py              # CLI entry point
├── config.py            # All user settings ← edit this
├── logger.py            # Rotating log handler
├── database.py          # DB schema
├── utils.py             # IP/domain validation, whitelist
├── feeds.py             # Feed download, parsing, in-memory IOC cache
├── lookup.py            # O(1) IOC lookup engine
├── alerts.py            # Alert dispatch + 24h deduplication
├── scanner.py           # Firewall / DNS / email scan engines
├── gui/
│   ├── app.py           # Main window
│   ├── theme.py         # Shared colours and widget helpers
│   ├── tab_dashboard.py
│   ├── tab_lookup.py
│   ├── tab_email.py
│   ├── tab_alerts.py
│   └── tab_feeds.py
├── Install_PhantomEye.bat
└── Uninstall_PhantomEye.bat
```

---

## Enabling Windows Firewall Logging

For the firewall scan to work:

1. Open **Windows Defender Firewall with Advanced Security**
2. Click **Windows Defender Firewall Properties**
3. On each profile tab (Domain, Private, Public):
   - Logging → Customize
   - Log successful connections: **Yes**
   - Log dropped packets: **Yes**
4. Click OK

---

## Disclaimer

PhantomEye is a **known-bad detector** — it matches against public threat intelligence feeds which typically lag 24–72 hours behind novel attacks. It is not a replacement for a full EDR or managed security service. It is designed to raise the security floor for small businesses that currently have no automated threat monitoring.

---

## Changelog

**v1.1** *(current)*
- Refactored into 14 modules (was a 1,512-line single file)
- Fixed: Lookup and email analysis now run in background threads
- Fixed: Firewall scanner checks ALLOW *and* DROP entries
- Fixed: Alert deduplication — same IOC won't re-alert within 24h
- Fixed: Per-alert DB connection overhead eliminated
- Fixed: Variable shadowing in DNS scanner
- Fixed: Zero-feeds warning on lookup when DB is empty
- Fixed: Email password from environment variable
- Fixed: IPv6 validation and checking
- Fixed: Full URL auto-stripping in lookup tab
- New: Export alerts to CSV

**v1.0**
- Initial release

---

## License

MIT License — free to use, modify, and distribute.

---

*Built by Egyan | Red Parrot Accounting Ltd*
