# =============================================================================
#   config.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   All user-editable configuration lives here.
#   Edit this file before first run.
# =============================================================================

import os

# Tool version (referenced by main.py)
VERSION = "1.4.0"

# Admin machine name for msg.exe desktop alerts
ADMIN_PC = "ADMINPC"

# How often to refresh threat feeds (hours)
FEED_REFRESH_HOURS = 6

# Windows Firewall log path
# Enable logging first: Windows Defender Firewall → Advanced Settings →
# Properties → each Profile → Logging → Log dropped/successful connections
FIREWALL_LOG = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

# How many days of firewall log to scan (keep low for performance)
FIREWALL_LOG_DAYS = 1

# Email alert settings
# Set EMAIL_ENABLED = True to receive email alerts on threats.
# SECURITY: Do NOT put your password here. Set it as a Windows environment
# variable:
#   PowerShell (run as Administrator):
#     [System.Environment]::SetEnvironmentVariable(
#       'PHANTOMEYE_EMAIL_PASSWORD', 'your_app_password', 'Machine')
EMAIL_ENABLED = False
EMAIL_FROM = "phantomeye@redparrot.co.uk"
EMAIL_TO = "admin@redparrot.co.uk"
EMAIL_SMTP_SERVER = "smtp.gmail.com"
EMAIL_SMTP_PORT = 587

# IPs to always ignore (private ranges handled automatically in code)
WHITELIST_IPS = [
    "127.0.0.1",
    "0.0.0.0",
]

# Domains to always consider safe (subdomains also matched)
WHITELIST_DOMAINS = [
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "office.com",
    "office365.com",
    "live.com",
    "outlook.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "digicert.com",
    "verisign.com",
    "symantec.com",
    "hmrc.gov.uk",
    "gov.uk",
]

# Alert deduplication window — don't re-alert on the same IOC within this
# many hours (prevents alert storms from beaconing malware)
ALERT_DEDUPE_HOURS = 24

# Maximum alerts shown in the Alert History tab
ALERT_HISTORY_LIMIT = 500

# Storage paths — change only if necessary
LOG_DIR = r"C:\SecurityLogs\PhantomEye"
DB_PATH = os.path.join(LOG_DIR, "phantom_eye.db")
LOG_FILE = os.path.join(LOG_DIR, "phantom_eye.log")
FEEDS_DIR = os.path.join(LOG_DIR, "feeds")

# =============================================================================
#   THREAT FEED DEFINITIONS
#   All free, no API keys needed.
# =============================================================================

THREAT_FEEDS = {
    # ---- IP Feeds ----
    "feodo_ips": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "type": "ip",
        "format": "feodo_csv",
        "label": "Feodo Tracker (Botnet C2 IPs)",
    },
    "emerging_threats": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip",
        "format": "plain_ip",
        "label": "Emerging Threats (Compromised IPs)",
    },
    "cins_score": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "type": "ip",
        "format": "plain_ip",
        "label": "CINS Score (Bad Actor IPs)",
    },
    "abuse_ssl": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "type": "ip",
        "format": "abuse_ssl_csv",
        "label": "Abuse.ch SSL Blacklist (Malicious SSL IPs)",
    },
    # ---- Domain / URL Feeds ----
    "urlhaus_domains": {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "type": "domain",
        "format": "url_extract",
        "label": "URLhaus (Malware Download Domains)",
    },
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "type": "domain",
        "format": "url_extract",
        "label": "OpenPhish (Phishing Domains)",
    },
    "botvrij_domains": {
        "url": "https://www.botvrij.eu/data/ioclist.domain.raw",
        "type": "domain",
        "format": "plain_domain",
        "label": "Botvrij.eu (Malicious Domains)",
    },
    "botvrij_ips": {
        "url": "https://www.botvrij.eu/data/ioclist.ip-dst.raw",
        "type": "ip",
        "format": "plain_ip",
        "label": "Botvrij.eu (Malicious IPs)",
    },
}
