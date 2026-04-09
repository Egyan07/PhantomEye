# Changelog

All notable changes to PhantomEye are documented here.

## v2.1.0

- **New:** Bulk lookup — paste multiple IPs/domains, check all at once
- **New:** IOC blocklist export — export all malicious IPs as a firewall-ready blocklist file
- **New:** Alert search/filter — real-time search box in Alert History tab
- **New:** Right-click context menu on alerts — copy IOC or quick lookup
- **New:** Clickable stat cards on Dashboard (extensible with click handlers)
- **New:** Live status bar clock
- **New:** 47 new tests (222 total) — covers CLI, theme, and expanded edge cases across all modules
- **Improved:** Lookup tab now supports single and bulk modes

## v2.0.0

- **New:** Custom feed support — add/remove your own threat feed URLs via GUI or JSON config
- **New:** Feed update progress bar on Dashboard
- **New:** Database indexes on hot columns (ioc value, alert timestamp) for faster queries
- **New:** 18 input validation security tests (path traversal, injection, oversized input)
- **New:** GitHub Release automation workflow
- **Improved:** 175 total tests (27 new: custom feeds, security validation)

## v1.5.0

- **New:** Tooltips on all buttons across all 6 tabs
- **New:** Keyboard shortcuts — F5 (refresh), Ctrl+U (update feeds), Ctrl+F (firewall scan), Ctrl+D (DNS scan), Ctrl+1-6 (switch tabs)
- **New:** Shortcuts info bar on Dashboard
- **New:** SECURITY.md — vulnerability reporting policy
- **New:** GitHub issue templates (structured bug reports and feature requests)
- **New:** Dependabot — automated dependency update monitoring
- **New:** CodeQL — SAST security scanning in CI

## v1.4.0

- **New:** IP geolocation enrichment — lookup results show country, city, ISP, and AS number (via ip-api.com)
- **New:** HTML report export — generate dark-themed HTML reports from alert history
- **New:** Real-time connection monitor tab — polls netstat and checks active connections against threat feeds
- **New:** Tooltip widget — hover tooltips on dashboard buttons
- **New:** `monitor.py` — netstat parsing and IOC checking module
- **New:** `reports.py` — self-contained HTML report generation
- **New:** `gui/tab_monitor.py` — connection monitor GUI tab
- **New:** `gui/tooltip.py` — reusable tooltip component
- **Improved:** 148 total tests (28 new: geolocation, reports, monitor)

## v1.3.0

- **New:** 28 scanner tests (firewall log, DNS cache, email header analysis) — 120+ total
- **New:** Type hints added to all modules (Python 3.10+ syntax)
- **New:** Ruff linting and format checking in CI
- **New:** README rewrite with banner, badges, comparison table, architecture diagram
- **New:** CHANGELOG.md (this file)
- **Improved:** CI now runs lint and format checks alongside tests

## v1.2.1

- Fixed: `database.py` — `init_database()` connection leak (no `try/finally`)
- Fixed: `alerts.py` — `smtplib.SMTP()` missing `timeout=30` (blocked on unreachable server)
- Fixed: `feeds.py` — `load_ioc_cache()` connection leak (`conn.close()` inside try block)
- Fixed: `feeds.py` — `update_feeds()` connection leak (no `try/finally` wrapper)
- Fixed: `feeds.py` — `check_stale_feeds()` connection leak (same pattern)

## v1.2

- Fixed: IPv6 validation rewritten with stdlib `ipaddress` module
- Fixed: `messagebox` calls moved off background threads (GUI crashes)
- Fixed: `init_database` / `load_ioc_cache` no longer called twice on `--gui`
- Fixed: Empty lookup query returns explicit error
- Fixed: SMTP uses `ssl.create_default_context()` (cert verification)
- Fixed: Email IP extraction restricted to `Received:` headers only
- Fixed: Firewall scanner checks source IP (inbound attacks)
- Fixed: Double whitelist check removed from feed parser
- Fixed: All `except: pass` replaced with logged warnings
- New: `_meta_cache` — zero extra DB connections per lookup
- New: `--version` and `--check` CLI flags
- New: Feed health warning card on Dashboard
- New: 92 unit tests (utils, feeds, lookup, alerts, database)
- Improved: `is_private_ip` catches multicast, reserved, unspecified ranges
- Improved: `parse_feed` builds set directly

## v1.1

- Refactored from single 1,512-line file into 14 modules
- Fixed: Lookup and email analysis run in background threads
- Fixed: Firewall scanner checks ALLOW and DROP entries
- Fixed: Alert deduplication (24-hour window)
- Fixed: Email password from environment variable
- New: Export alerts to CSV

## v1.0

- Initial release
