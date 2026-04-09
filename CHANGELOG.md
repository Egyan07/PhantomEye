# Changelog

All notable changes to PhantomEye are documented here.

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
