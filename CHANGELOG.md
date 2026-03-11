# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-03-02

### Added
- Unified CLI (`main.py`) with aws-cli style subcommands
- Renamed standalone scripts for consistency:
  - `collector.py` → `collector-network.py`
  - `linux-collector.py` → `collector-linux.py`
  - `acct.py` → `collector-account.py`

### Changed
- CLI usage now uses subcommands: `python main.py <command>`
- Backward compatibility maintained with standalone scripts

## [0.1.0] - 2026-02-25

### Added
- Initial release
- Network device collector (Cisco SSH/Telnet)
- Linux host collector (SSH)
- Account status checker
- CSV export functionality
- Rich terminal output with progress bars
