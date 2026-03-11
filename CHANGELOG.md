# Changelog

All notable changes to this project will be documented in this file.

## [0.1] - 2026-03-02

Initial public release.

### Added
- Unified CLI (`main.py`) with subcommands: `network`, `linux`, `account`
- Network device collector with SSH and Telnet support (Cisco IOS)
- Linux host collector via SSH
- EOL and CVE status lookups via network-audit.io API
- API account status checker with planned maintenance display
- CSV inventory support alongside JSON
- CSV export with timestamped filenames
- Rich terminal output with progress bars
