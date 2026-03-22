"""Unit tests for parsing functions in network_audit.commands."""

from network_audit.commands.linux import parse_os_release
from network_audit.commands.network import parse_show_version, parse_show_inventory


# ---------------------------------------------------------------------------
# parse_os_release
# ---------------------------------------------------------------------------

DEBIAN_OS_RELEASE = """\
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
"""

UBUNTU_OS_RELEASE = """\
PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
"""

PROXMOX_OS_RELEASE = """\
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
PVE_VERSION=8.3.2
"""


def test_parse_os_release_debian():
    result = parse_os_release(DEBIAN_OS_RELEASE)
    assert result["distro"] == "debian"
    assert result["version"] == "12"
    assert result["pretty_name"] == "Debian GNU/Linux 12 (bookworm)"


def test_parse_os_release_ubuntu():
    result = parse_os_release(UBUNTU_OS_RELEASE)
    assert result["distro"] == "ubuntu"
    assert result["version"] == "22.04"
    assert result["pretty_name"] == "Ubuntu 22.04.4 LTS"


def test_parse_os_release_proxmox():
    result = parse_os_release(PROXMOX_OS_RELEASE)
    assert result["distro"] == "proxmox"
    assert result["version"] == "8"
    assert result["pretty_name"] == "Proxmox VE 8.3.2"


def test_parse_os_release_proxmox_overrides_debian():
    result = parse_os_release(PROXMOX_OS_RELEASE)
    assert result["distro"] != "debian"
    assert result["distro"] == "proxmox"


def test_parse_os_release_minimal():
    result = parse_os_release("ID=alpine\n")
    assert result["distro"] == "alpine"
    assert result["version"] == "Unknown"
    assert result["pretty_name"] == "Unknown"


def test_parse_os_release_empty():
    result = parse_os_release("")
    assert result["distro"] == "Unknown"
    assert result["version"] == "Unknown"
    assert result["pretty_name"] == "Unknown"


def test_parse_os_release_missing_version():
    result = parse_os_release('ID=rhel\nPRETTY_NAME="Red Hat Enterprise Linux"\n')
    assert result["distro"] == "rhel"
    assert result["version"] == "Unknown"
    assert result["pretty_name"] == "Red Hat Enterprise Linux"


def test_parse_os_release_quoted_values():
    result = parse_os_release('ID="centos"\nVERSION_ID="9"\nPRETTY_NAME="CentOS Stream 9"\n')
    assert result["distro"] == "centos"
    assert result["version"] == "9"


# ---------------------------------------------------------------------------
# parse_show_version
# ---------------------------------------------------------------------------

CISCO_IOS_SHOW_VERSION = """\
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E9, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Tue 14-Mar-23 09:48 by prod_rel_team

ROM: Bootstrap program is C2960X boot loader
BOOTLDR: C2960X Boot Loader (C2960X-HBOOT-M) Version 15.2(7r)E3, RELEASE SOFTWARE (fc1)

switch01 uptime is 142 days, 7 hours, 23 minutes
System returned to ROM by power-on
System image file is "flash:c2960x-universalk9-mz.152-7.E9.bin"

cisco WS-C2960X-48FPD-L (APM86XXX) processor (revision A0) with 524288K bytes of memory.
Processor board ID FCW2143L0AB
Last reset from power-on
2 Virtual Ethernet interfaces
1 FastEthernet interface
52 Gigabit Ethernet interfaces
2 Ten Gigabit Ethernet interfaces
The password-recovery mechanism is enabled.

512K bytes of flash-simulated non-volatile configuration memory.
Model number                    : WS-C2960X-48FPD-L
System serial number            : FCW2143L0AB
Top Assembly Part Number        : 800-40893-07
"""

CISCO_NXOS_SHOW_VERSION = """\
Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
Copyright (c) 2002-2024, Cisco Systems, Inc. All rights reserved.

Software
  NXOS: version 10.3(4a)
  NXOS image file is: bootflash:///nxos64-cs.10.3.4a.M.bin
  NXOS compile time:  12/15/2023 18:00:00

Hardware
  cisco Nexus9000 C93180YC-FX3 (52 Slot) Chassis ("Memory Test")
  Intel(R) Xeon(R) CPU D-1530 @ 2.40GHz with 24576324 kB of memory.
  Processor Board ID FDO25311ABC

  Device name: leaf-01
  bootflash:   116567552 kB

leaf-01 uptime is 87 days 14 hours 32 minutes 11 seconds
"""


def test_parse_show_version_ios_hostname():
    result = parse_show_version(CISCO_IOS_SHOW_VERSION)
    assert result["hostname"] == "switch01"


def test_parse_show_version_ios_version():
    result = parse_show_version(CISCO_IOS_SHOW_VERSION)
    assert result["os_version"] == "15.2(7)E9"


def test_parse_show_version_ios_model():
    result = parse_show_version(CISCO_IOS_SHOW_VERSION)
    assert result["model"] == "WS-C2960X-48FPD-L"


def test_parse_show_version_nxos_hostname():
    result = parse_show_version(CISCO_NXOS_SHOW_VERSION)
    assert result["hostname"] == "leaf-01"


def test_parse_show_version_nxos_version():
    result = parse_show_version(CISCO_NXOS_SHOW_VERSION)
    assert result["os_version"] == "10.3(4a)"


def test_parse_show_version_nxos_model_falls_back_to_unknown():
    # NX-OS "cisco Nexus9000 C93180YC-FX3 (52 Slot)" doesn't match the
    # "cisco MODEL (" regex because there are two tokens before the paren.
    # In practice, scan_device falls back to parse_show_inventory for the PID.
    result = parse_show_version(CISCO_NXOS_SHOW_VERSION)
    assert result["model"] == "Unknown"


def test_parse_show_version_model_from_hardware_line():
    output = (
        "Cisco IOS Software, Version 15.1(4)M4\n"
        "router01 uptime is 30 days\n"
        "cisco ISR4331/K9 (1RU) processor with 1217428K bytes of memory.\n"
    )
    result = parse_show_version(output)
    assert result["model"] == "ISR4331/K9"


def test_parse_show_version_empty():
    result = parse_show_version("")
    assert result["hostname"] == "Unknown"
    assert result["model"] == "Unknown"
    assert result["os_version"] == "Unknown"


def test_parse_show_version_partial_only_hostname():
    result = parse_show_version("router01 uptime is 5 days, 3 hours\n")
    assert result["hostname"] == "router01"
    assert result["model"] == "Unknown"
    assert result["os_version"] == "Unknown"


def test_parse_show_version_prompt_fallback_hostname():
    result = parse_show_version("core-rtr#show version\nSome unrecognized output\n")
    assert result["hostname"] == "core-rtr"


# ---------------------------------------------------------------------------
# parse_show_inventory
# ---------------------------------------------------------------------------

def test_parse_show_inventory_standard():
    output = """\
NAME: "Chassis", DESCR: "Cisco Catalyst 9300 Series Switch"
PID: C9300-48T          , VID: V02  , SN: FCW2345K0AB
"""
    assert parse_show_inventory(output) == "C9300-48T"


def test_parse_show_inventory_no_pid():
    assert parse_show_inventory("No inventory data available\n") is None


def test_parse_show_inventory_empty():
    assert parse_show_inventory("") is None
