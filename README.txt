============================================================
  PhantomEye v1.1
  Coded by Egyan | Red Parrot Accounting Ltd
  Threat Intelligence Platform
============================================================

WHAT IT DOES
------------
PhantomEye automatically downloads threat intelligence from 8 free
feeds and checks your network activity against them.

It detects:
  - Machines connecting to known malware/C2 servers (ALLOW and DROP)
  - DNS lookups for known phishing or malware domains
  - Malicious IPs or domains in email headers
  - Any IP or domain you want to manually check


THREAT FEEDS (all free, no account needed)
------------------------------------------
  1. Feodo Tracker        — Botnet C2 server IPs
  2. Emerging Threats     — Compromised/blacklisted IPs
  3. CINS Score           — Known bad actor IPs
  4. Abuse.ch SSL BL      — Malicious SSL certificate IPs
  5. URLhaus              — Malware download domains
  6. OpenPhish            — Active phishing domains
  7. Botvrij.eu (domains) — Known malicious domains
  8. Botvrij.eu (IPs)     — Known malicious IPs


HOW TO INSTALL
--------------
1. Open config.py and set ADMIN_PC to your admin machine name.
2. Right-click Install_PhantomEye.bat
3. Select "Run as administrator"


HOW TO USE
----------
Dashboard tab
  - IOC count, alert count, feed status at a glance
  - Update Feeds: download latest threat intelligence
  - Scan Firewall Log: check Windows Firewall log against feeds
    (alerts on both ALLOW and DROP — a blocked C2 connection is an
    infection indicator)
  - Scan DNS Cache: check recently resolved domains

IP / Domain Lookup tab
  - Type or paste any IP or domain → click Lookup
  - Instant verdict from in-memory IOC database (fast, no DB lag)
  - Warns if no feeds have been loaded yet

Email Header Analyser tab
  - Outlook: Open email → File → Properties → copy Internet Headers
  - Paste headers → Analyse
  - Detects malicious relay IPs and From ≠ Reply-To phishing

Alert History tab
  - All threats detected, timestamped
  - Export to CSV button for sharing with IT/management

Feed Status tab
  - Per-feed IOC count and last-update timestamp


BEFORE USING — ENABLE WINDOWS FIREWALL LOGGING
-----------------------------------------------
  1. Open: Windows Defender Firewall with Advanced Security
  2. Click: Windows Defender Firewall Properties
  3. On each profile tab (Domain, Private, Public):
       Logging → Customize
       Log successful connections: Yes
       Log dropped packets: Yes
  4. Click OK

Log appears at:
  C:\Windows\System32\LogFiles\Firewall\pfirewall.log


EMAIL ALERTS (optional)
-----------------------
Set EMAIL_ENABLED = True in config.py.

IMPORTANT: Do NOT put your password in config.py.
Use a Windows environment variable instead:

  PowerShell (run as Administrator):
    [System.Environment]::SetEnvironmentVariable(
      'PHANTOMEYE_EMAIL_PASSWORD', 'your_app_password', 'Machine')

Restart (or log off/on) after setting it.


SCHEDULED TASKS
---------------
  "PhantomEye Feed Update"  — Updates feeds every 6 hours
  "PhantomEye Morning Scan" — Scans firewall + DNS at 6 AM daily

Both run as your user account, NOT as SYSTEM.


MANUAL COMMANDS
---------------
  Launch GUI:
    python C:\SecurityLogs\PhantomEye\main.py --gui

  Update feeds only:
    python C:\SecurityLogs\PhantomEye\main.py --update-feeds

  Run scan (no GUI, for scripting):
    python C:\SecurityLogs\PhantomEye\main.py --scan

  Quick lookup:
    python C:\SecurityLogs\PhantomEye\main.py --lookup 185.234.xx.xx
    python C:\SecurityLogs\PhantomEye\main.py --lookup evil-domain.ru


MODULE LAYOUT
-------------
  main.py         — CLI entry point
  config.py       — All user-editable settings  ← edit this
  logger.py       — Rotating log (10MB / 5 backups)
  database.py     — DB schema
  utils.py        — IP/domain validation, whitelist
  feeds.py        — Feed download, parsing, in-memory IOC cache
  lookup.py       — O(1) IOC lookup engine
  alerts.py       — Alert dispatch + 24h deduplication
  scanner.py      — Firewall / DNS / email scan engines
  gui/
    app.py           — Main window
    theme.py         — Shared colours and widget helpers
    tab_dashboard.py — Dashboard tab
    tab_lookup.py    — IP / Domain Lookup tab
    tab_email.py     — Email Header Analyser tab
    tab_alerts.py    — Alert History tab (includes CSV export)
    tab_feeds.py     — Feed Status tab


FILES & LOCATIONS
-----------------
  Scripts    : C:\SecurityLogs\PhantomEye\
  Database   : C:\SecurityLogs\PhantomEye\phantom_eye.db
  Log        : C:\SecurityLogs\PhantomEye\phantom_eye.log
  Feeds      : C:\SecurityLogs\PhantomEye\feeds\


REQUIREMENTS
------------
  - Windows 10 or 11
  - Python 3.10 or newer (python.org)
  - Internet connection for feed updates
  - No extra packages needed (all built into Python)


CHANGELOG
---------
  v1.1 (current):
    - Refactored into 14 modules (was a 1,512-line single file)
    - FIX: Lookup and email analysis run in background threads (GUI no
            longer freezes)
    - FIX: Firewall scanner checks ALLOW *and* DROP entries
    - FIX: Alert deduplication (same IOC won't re-alert within 24h)
    - FIX: All scan loops share one DB connection (no per-alert overhead)
    - FIX: Variable shadowing in DNS scanner fixed
    - FIX: Zero-feeds warning on lookup when DB is empty
    - FIX: Email password from environment variable
    - FIX: IPv6 validation and checking
    - FIX: CSV column detection for feodo/abuse_ssl feeds
    - FIX: Domain validation now requires proper 2-char TLD
    - NEW: Export alerts to CSV

  v1.0:
    - Initial release


============================================================
  Coded by Egyan | Red Parrot Accounting Ltd
============================================================
