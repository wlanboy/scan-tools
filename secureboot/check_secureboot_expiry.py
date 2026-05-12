#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Checks whether this Linux VM is affected by the Microsoft Secure Boot
certificate expiration in 2026 (UEFI CA 2011, KEK CA 2011 expire June 2026;
Windows PCA 2011 expires October 2026).

References:
  https://access.redhat.com/articles/7128933
  https://knowledge.broadcom.com/external/article/423893/

Requires Python 2.7+. No third-party packages needed.
"""
from __future__ import print_function

import os
import subprocess
import sys

# ---------------------------------------------------------------------------
# Colours (disabled automatically when stdout is not a terminal)
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty()

RED    = '\033[0;31m' if _USE_COLOR else ''
YELLOW = '\033[1;33m' if _USE_COLOR else ''
GREEN  = '\033[0;32m' if _USE_COLOR else ''
CYAN   = '\033[0;36m' if _USE_COLOR else ''
BOLD   = '\033[1m'    if _USE_COLOR else ''
RESET  = '\033[0m'    if _USE_COLOR else ''

ISSUES   = [0]
WARNINGS = [0]


def ok(msg):
    print("  {g}[OK  ]{r} {m}".format(g=GREEN, r=RESET, m=msg))


def warn(msg):
    print("  {y}[WARN]{r} {m}".format(y=YELLOW, r=RESET, m=msg))
    WARNINGS[0] += 1


def fail(msg):
    print("  {re}[FAIL]{r} {m}".format(re=RED, r=RESET, m=msg))
    ISSUES[0] += 1


def info(msg):
    print("  {c}[INFO]{r} {m}".format(c=CYAN, r=RESET, m=msg))


def section(title):
    print("\n{b}=== {t} ==={r}".format(b=BOLD, t=title, r=RESET))


# ---------------------------------------------------------------------------
# Helper: run a command and return stdout as a string, or None on error
# ---------------------------------------------------------------------------
def run(args, stdin_text=None):
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, _ = proc.communicate()
        return stdout.decode('utf-8', errors='replace')
    except OSError:
        return None


def cmd_exists(name):
    result = run(['which', name])
    return result is not None and result.strip() != ''


def read_file(path):
    try:
        with open(path, 'r') as fh:
            return fh.read().strip()
    except (IOError, OSError):
        return ''


def _sb_via_efivar():
    """Read SecureBoot EFI variable directly (4-byte attr header + 1-byte value)."""
    path = '/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'
    try:
        with open(path, 'rb') as fh:
            data = fh.read()
        if len(data) >= 5:
            return data[4] == 1
    except (IOError, OSError):
        pass
    return None


def _sb_via_bootctl():
    """Parse 'bootctl status' output for Secure Boot state."""
    if not cmd_exists('bootctl'):
        return None
    out = run(['bootctl', 'status']) or ''
    for line in out.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith('secure boot:'):
            if 'enabled' in stripped:
                return True
            if 'disabled' in stripped:
                return False
    return None


def _sb_via_dmesg():
    """Scan dmesg kernel log for Secure Boot state message."""
    out = run(['dmesg']) or ''
    for line in out.splitlines():
        low = line.lower()
        if 'secure boot' in low:
            if 'enabled' in low:
                return True
            if 'disabled' in low:
                return False
    return None


# ---------------------------------------------------------------------------
# 1. Runtime environment
# ---------------------------------------------------------------------------
section("Runtime Environment")

os_id      = ''
os_version = ''
os_pretty  = 'unknown'

if os.path.isfile('/etc/os-release'):
    for line in read_file('/etc/os-release').splitlines():
        if line.startswith('ID='):
            os_id = line.split('=', 1)[1].strip().strip('"')
        elif line.startswith('VERSION_ID='):
            os_version = line.split('=', 1)[1].strip().strip('"')
        elif line.startswith('PRETTY_NAME='):
            os_pretty = line.split('=', 1)[1].strip().strip('"')

info("OS: {0}".format(os_pretty))

# Detect hypervisor / cloud
hypervisor = 'bare-metal'
virt_out = run(['systemd-detect-virt'])
if virt_out is not None:
    v = virt_out.strip()
    if v and v != 'none':
        hypervisor = v

if hypervisor in ('bare-metal', 'none'):
    sys_vendor = read_file('/sys/class/dmi/id/sys_vendor').lower()
    if 'vmware' in sys_vendor:
        hypervisor = 'vmware'
    elif 'google' in sys_vendor:
        hypervisor = 'gcp'
    elif 'microsoft' in sys_vendor:
        hypervisor = 'azure'
    elif 'amazon' in sys_vendor:
        hypervisor = 'aws'

info("Hypervisor/Cloud: {0}".format(hypervisor))

# GCP instance creation date check
if hypervisor == 'gcp':
    info("Running on GCP – checking instance metadata...")
    try:
        import urllib.request
        req = urllib.request.Request(
            'http://metadata.google.internal/computeMetadata/v1/instance/attributes/creation-timestamp',
            headers={'Metadata-Flavor': 'Google'},
        )
        creation_date = urllib.request.urlopen(req, timeout=3).read().decode('utf-8').strip()
    except Exception:
        creation_date = ''

    if creation_date:
        info("GCP instance creation timestamp: {0}".format(creation_date))
        cutoff = '2025-11-07'
        # Simple lexicographic ISO-date comparison
        if creation_date[:10] < cutoff:
            warn("GCP instance was created before {0} – may need recreation with updated firmware.".format(cutoff))
        else:
            ok("GCP instance created after {0}.".format(cutoff))
    else:
        info("Could not retrieve GCP creation timestamp.")

# ---------------------------------------------------------------------------
# 2. Secure Boot status
# ---------------------------------------------------------------------------
section("Secure Boot Status")

sb_enabled = False
sb_detected = False

# 1. mokutil
if cmd_exists('mokutil'):
    sb_state = run(['mokutil', '--sb-state']) or ''
    if 'enabled' in sb_state.lower():
        sb_enabled = True
        sb_detected = True
        ok("Secure Boot is ENABLED (via mokutil) – certificate expiry is relevant for this system.")
    elif 'disabled' in sb_state.lower():
        sb_detected = True
        ok("Secure Boot is DISABLED (via mokutil) – certificate expiry does NOT affect boot on this system.")
        info("Note: If you plan to enable Secure Boot, certificates must still be updated first.")
    else:
        info("mokutil could not determine Secure Boot state – trying alternatives.")
else:
    info("mokutil not installed – trying alternative detection methods.")

# 2. EFI variable (no extra tools needed, requires readable efivars)
if not sb_detected:
    _efi_result = _sb_via_efivar()
    if _efi_result is not None:
        sb_detected = True
        sb_enabled = _efi_result
        if _efi_result:
            ok("Secure Boot is ENABLED (via EFI variable) – certificate expiry is relevant for this system.")
        else:
            ok("Secure Boot is DISABLED (via EFI variable) – certificate expiry does NOT affect boot on this system.")

# 3. bootctl (systemd-boot)
if not sb_detected:
    _bootctl_result = _sb_via_bootctl()
    if _bootctl_result is not None:
        sb_detected = True
        sb_enabled = _bootctl_result
        if _bootctl_result:
            ok("Secure Boot is ENABLED (via bootctl) – certificate expiry is relevant for this system.")
        else:
            ok("Secure Boot is DISABLED (via bootctl) – certificate expiry does NOT affect boot on this system.")

# 4. dmesg kernel log
if not sb_detected:
    _dmesg_result = _sb_via_dmesg()
    if _dmesg_result is not None:
        sb_detected = True
        sb_enabled = _dmesg_result
        if _dmesg_result:
            ok("Secure Boot is ENABLED (via dmesg) – certificate expiry is relevant for this system.")
        else:
            ok("Secure Boot is DISABLED (via dmesg) – certificate expiry does NOT affect boot on this system.")

if not sb_detected:
    warn("Could not determine Secure Boot state via any available method.")
    warn("Install mokutil (dnf install mokutil / apt install mokutil) for detailed checks.")

# ---------------------------------------------------------------------------
# 3. Certificate database checks
# ---------------------------------------------------------------------------
section("Certificate Database (DB)")

# Certificate name fragments to match
CERT_2011_UEFI = "Microsoft Corporation UEFI CA 2011"
CERT_2011_KEK  = "Microsoft Corporation KEK CA 2011"
CERT_2011_WIN  = "Microsoft Windows Production PCA 2011"
CERT_2023_UEFI_VARIANTS = ("Windows UEFI CA 2023", "Microsoft Corporation UEFI CA 2023")
CERT_2023_KEK_VARIANTS  = ("KEK 2K CA 2023", "Microsoft Corporation KEK 2K CA 2023")
CERT_2023_WIN_VARIANTS  = ("Windows Production PCA 2023",)


def check_certificates(mok_flag, label):
    if not cmd_exists('mokutil'):
        return

    db_output = run(['mokutil', mok_flag])
    if db_output is None:
        warn("Could not read {0} (try running as root).".format(label))
        return
    if not db_output.strip():
        warn("{0} is empty or inaccessible.".format(label))
        return

    found_2011_uefi = CERT_2011_UEFI in db_output
    found_2011_kek  = CERT_2011_KEK  in db_output
    found_2011_win  = CERT_2011_WIN  in db_output
    found_2023_uefi = any(v in db_output for v in CERT_2023_UEFI_VARIANTS)
    found_2023_kek  = any(v in db_output for v in CERT_2023_KEK_VARIANTS)
    found_2023_win  = any(v in db_output for v in CERT_2023_WIN_VARIANTS)

    print("")
    info("{0} certificate summary:".format(label))

    # UEFI CA – expires 2026-06-27
    if found_2011_uefi and found_2023_uefi:
        ok("  Microsoft UEFI CA 2011 present (expires 2026-06-27) AND 2023 replacement present.")
    elif found_2011_uefi and not found_2023_uefi:
        fail("  Microsoft UEFI CA 2011 present (expires 2026-06-27) – 2023 replacement MISSING.")
    elif not found_2011_uefi and found_2023_uefi:
        ok("  Microsoft UEFI CA 2011 absent, 2023 replacement present – already migrated.")
    else:
        info("  Microsoft UEFI CA 2011 not found in {0} (may be in db or firmware).".format(label))

    # KEK CA – expires 2026-06-24
    if found_2011_kek and found_2023_kek:
        ok("  Microsoft KEK CA 2011 present (expires 2026-06-24) AND 2023 replacement present.")
    elif found_2011_kek and not found_2023_kek:
        fail("  Microsoft KEK CA 2011 present (expires 2026-06-24) – 2023 replacement MISSING.")
    elif not found_2011_kek and found_2023_kek:
        ok("  Microsoft KEK CA 2011 absent, 2023 replacement present – already migrated.")

    # Windows PCA – expires 2026-10-19
    if found_2011_win and found_2023_win:
        ok("  Microsoft Windows PCA 2011 present (expires 2026-10-19) AND 2023 replacement present.")
    elif found_2011_win and not found_2023_win:
        warn("  Microsoft Windows PCA 2011 present (expires 2026-10-19) – 2023 replacement missing.")
        info("  (Only relevant if this VM also boots Windows.)")


check_certificates('--db',  'DB (allowed signatures)')
check_certificates('--kek', 'KEK (key exchange keys)')

# ---------------------------------------------------------------------------
# 4. Shim binary check
# ---------------------------------------------------------------------------
section("Shim Bootloader")

_SHIM_DISTRO_DIRS = [
    'redhat', 'centos', 'fedora', 'almalinux', 'rocky', 'oracle', 'amzn',
    'ubuntu', 'debian', 'linuxmint', 'pop', 'pop-os',
    'sles', 'opensuse',
    'arch', 'manjaro',
    'gentoo', 'void',
    'BOOT',
]

_SHIM_NAMES = ['shimx64.efi', 'shimaa64.efi', 'BOOTX64.EFI', 'BOOTAA64.EFI']

# Detect EFI partition mount point dynamically from /proc/mounts
def _find_efi_mountpoints():
    mounts = []
    try:
        with open('/proc/mounts', 'r') as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3 and parts[2].lower() in ('vfat', 'efivarfs'):
                    mp = parts[1]
                    if any(k in mp.lower() for k in ('efi', 'boot')):
                        mounts.append(mp)
    except (IOError, OSError):
        pass
    # Always include common static candidates as fallback
    for candidate in ('/boot/efi', '/boot/EFI', '/efi', '/boot'):
        if candidate not in mounts and os.path.isdir(candidate):
            mounts.append(candidate)
    return mounts

_efi_mounts = _find_efi_mountpoints()

SHIM_PATHS = []
for _mp in _efi_mounts:
    for _distro in _SHIM_DISTRO_DIRS:
        for _name in _SHIM_NAMES:
            SHIM_PATHS.append(os.path.join(_mp, 'EFI', _distro, _name))

shim_found = None
for p in SHIM_PATHS:
    if os.path.isfile(p):
        shim_found = p
        break

if shim_found is None:
    info("No shim binary found (checked {0} paths across {1} EFI mount point(s)).".format(
        len(SHIM_PATHS), len(_efi_mounts)))
else:
    info("Shim binary: {0}".format(shim_found))
    try:
        st = os.stat(shim_found)
        import datetime
        mtime = datetime.datetime.utcfromtimestamp(st.st_mtime).strftime('%Y-%m-%d')
        info("Size: {0} bytes, last modified: {1}".format(st.st_size, mtime))
    except OSError:
        pass

    if cmd_exists('pesign'):
        info("pesign output (certificate chain in shim):")
        pesign_out = run(['pesign', '-S', '-i', shim_found]) or ''
        for line in pesign_out.splitlines():
            if any(kw in line for kw in ('Subject', 'Issuer', 'Not After')):
                print("    " + line.strip())
        if '2023' in pesign_out:
            ok("Shim appears to be signed with 2023-era certificate chain.")
        elif '2011' in pesign_out:
            fail("Shim is signed only with 2011 certificate – update required.")
    elif cmd_exists('sbverify'):
        info("sbverify output:")
        sbv_out = run(['sbverify', '--list', shim_found]) or ''
        for line in sbv_out.splitlines():
            print("    " + line)
    else:
        warn("Neither pesign nor sbverify installed – cannot inspect shim signature.")
        if cmd_exists('apt-get'):
            info("Install via: apt install pesign  or  apt install sbsigntool")
        else:
            info("Install via: dnf install pesign  or  dnf install sbsigntools (EPEL)")

# ---------------------------------------------------------------------------
# 5. Installed package versions
# ---------------------------------------------------------------------------
section("Package Versions")

if cmd_exists('rpm'):
    for pkg in ('shim-x64', 'shim', 'shimx64', 'edk2-ovmf', 'grub2-efi-x64'):
        ver = run(['rpm', '-q', pkg]) or ''
        ver = ver.strip()
        if ver and 'not installed' not in ver:
            info("{0}: {1}".format(pkg, ver))

    # shim version gate: >= 15.8 includes dual-signed 2023 cert support
    shim_ver_raw = run(['rpm', '-q', '--queryformat', '%{VERSION}', 'shim-x64']) or \
                   run(['rpm', '-q', '--queryformat', '%{VERSION}', 'shim'])   or ''
    shim_ver_raw = shim_ver_raw.strip()
    if shim_ver_raw and 'not installed' not in shim_ver_raw:
        try:
            parts = shim_ver_raw.split('.')
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            if major > 15 or (major == 15 and minor >= 8):
                ok("shim {0} >= 15.8 (includes dual-signed 2023 support).".format(shim_ver_raw))
            else:
                fail("shim {0} < 15.8 – update required for 2023 certificate support.".format(shim_ver_raw))
                info("Run: dnf update shim shim-x64")
        except (ValueError, IndexError):
            info("shim version: {0}".format(shim_ver_raw))

    # edk2-ovmf minimum version hints per RHEL major version
    # Source: https://developers.redhat.com/articles/2026/02/04/secure-boot-certificate-changes-2026-guidance-rhel-environments
    # RHEL 8: edk2-ovmf update is "Not applicable" per Red Hat
    edk2_ver = run(['rpm', '-q', '--queryformat', '%{VERSION}-%{RELEASE}', 'edk2-ovmf']) or ''
    edk2_ver = edk2_ver.strip()
    if edk2_ver and 'not installed' not in edk2_ver:
        if os_version.startswith('8'):
            info("edk2-ovmf update not required for RHEL/CentOS 8 (per Red Hat guidance).")
        elif os_version.startswith('9'):
            info("Recommended minimum for RHEL/CentOS 9: edk2-ovmf-20231122-6.el9")
            info("New dual-signed shim available starting with RHEL 9.7 (released 2026-03-25).")
        elif os_version.startswith('10'):
            info("Recommended minimum for RHEL/CentOS 10: edk2-ovmf-20241117-2.el10")

elif cmd_exists('dpkg'):
    for pkg in ('shim', 'shim-signed', 'grub-efi-amd64-signed', 'ovmf'):
        dpkg_out = run(['dpkg', '-l', pkg]) or ''
        for line in dpkg_out.splitlines():
            if line.startswith('ii'):
                cols = line.split()
                info("{0}: {1}".format(pkg, cols[2] if len(cols) > 2 else '?'))

    # shim-signed version gate for Debian/Ubuntu: the upstream shim version
    # is embedded after '+' in the package version (e.g. 1.58+15.8-0ubuntu1)
    shim_signed_ver = run(['dpkg', '-l', 'shim-signed']) or ''
    for line in shim_signed_ver.splitlines():
        if line.startswith('ii'):
            cols = line.split()
            pkg_ver = cols[2] if len(cols) > 2 else ''
            # extract the part after '+' to get upstream shim version
            if '+' in pkg_ver:
                upstream = pkg_ver.split('+', 1)[1].split('-')[0]
                try:
                    parts = upstream.split('.')
                    major = int(parts[0])
                    minor = int(parts[1]) if len(parts) > 1 else 0
                    if major > 15 or (major == 15 and minor >= 8):
                        ok("shim-signed {0} (upstream shim {1}) >= 15.8 – includes 2023 cert support.".format(pkg_ver, upstream))
                    else:
                        fail("shim-signed {0} (upstream shim {1}) < 15.8 – update required.".format(pkg_ver, upstream))
                        info("Run: apt-get install --only-upgrade shim shim-signed")
                except (ValueError, IndexError):
                    info("shim-signed version: {0}".format(pkg_ver))
            break

# ---------------------------------------------------------------------------
# 6. fwupd / LVFS firmware update check
# ---------------------------------------------------------------------------
section("Firmware Update (fwupd/LVFS)")

if cmd_exists('fwupdmgr'):
    info("fwupd is available.")
    devs_out = run(['fwupdmgr', 'get-devices']) or ''
    dev_count = devs_out.count('DeviceId')
    info("Managed devices: {0}".format(dev_count))
    info("To check for firmware updates: fwupdmgr update")
else:
    info("fwupd not installed. For physical hosts, firmware updates via LVFS are recommended.")
    info("Install: dnf install fwupd  or  apt install fwupd")

# ---------------------------------------------------------------------------
# 7. VMware-specific notes
# ---------------------------------------------------------------------------
if hypervisor == 'vmware':
    section("VMware / ESXi Specifics")
    info("This VM runs on VMware/ESXi.")
    info("Key facts:")
    info("  - VMs continue to boot after certificate expiry.")
    info("  - Boot is disrupted only if Microsoft revokes 2011 certs via a dbx update.")
    info("  - An expired KEK prevents UEFI db/dbx updates inside the VM.")
    info("  - ESXi 7.x is End of Support – only manual updates possible.")
    info("  - ESXi 8.x needs a host patch for automatic PK initialisation.")
    info("  - ESXi 9.x already ships correct PK for new VMs (HW version >= 14).")

    if cmd_exists('vmware-toolsd'):
        tools_ver = run(['vmware-toolsd', '--version']) or ''
        info("VMware Tools: {0}".format(tools_ver.strip().splitlines()[0] if tools_ver.strip() else 'unknown'))

    # Hardware version readable without root via DMI
    hw_ver = read_file('/sys/class/dmi/id/product_version')
    if hw_ver:
        info("VM hardware version (DMI): {0}".format(hw_ver))

    # Platform Key check – readable without root via EFI vars / mokutil
    # VMW.NULLPK means the PK was never properly initialised; the new
    # "Windows OEM Devices PK" is required for the 2023 cert chain.
    if cmd_exists('mokutil'):
        pk_out = run(['mokutil', '--pk']) or ''
        if 'VMW.NULLPK' in pk_out or 'NULLPK' in pk_out:
            fail("Platform Key is VMW.NULLPK – PK was never initialised. "
                 "Contact your VMware admin to update the vUEFI firmware.")
        elif 'Windows OEM Devices PK' in pk_out or 'Microsoft' in pk_out:
            ok("Platform Key looks correctly set (not VMW.NULLPK).")
        elif pk_out.strip():
            info("Platform Key present (content not recognised – manual review recommended).")
        else:
            warn("Platform Key is empty or unreadable.")

    warn("Verify with your VMware/ESXi administrator that the vUEFI firmware is updated.")
    info("See: https://knowledge.broadcom.com/external/article/423893/")

# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
section("Summary")

issues   = ISSUES[0]
warnings = WARNINGS[0]

if issues > 0:
    print("\n{r}{b}RESULT: AFFECTED – {i} issue(s) found, {w} warning(s).{reset}".format(
        r=RED, b=BOLD, i=issues, w=warnings, reset=RESET))
    print("")
    if cmd_exists('apt-get'):
        print("  Required actions (Debian/Ubuntu):")
        print("    apt-get update && apt-get install --only-upgrade shim shim-signed")
        print("    apt-get install --only-upgrade grub-efi-amd64-signed ovmf")
    if cmd_exists('dnf'):
        print("  Required actions (RHEL/CentOS 8+/Fedora/AlmaLinux/Rocky):")
        print("    dnf update shim shim-x64 grub2-efi-x64 grub2-efi-x64-modules edk2-ovmf")
    if cmd_exists('yum') and not cmd_exists('dnf'):
        print("  Required actions (CentOS 7 / RHEL 7):")
        print("    yum update shim shim-x64 grub2-efi-x64 edk2-ovmf")
    if not cmd_exists('apt-get') and not cmd_exists('dnf') and not cmd_exists('yum'):
        print("  Required actions: update shim, grub and edk2/ovmf via your package manager.")
    print("  Reboot to load the new shim into EFI.")
    if hypervisor == 'gcp':
        print("  4. GCP: recreate instance from a machine image if firmware is outdated.")
        print("          gcloud compute instances create ... --shielded-secure-boot")
elif warnings > 0:
    print("\n{y}{b}RESULT: POSSIBLY AFFECTED – 0 critical issues, {w} warning(s).{reset}".format(
        y=YELLOW, b=BOLD, w=warnings, reset=RESET))
    print("  Review warnings above. Manual verification recommended.")
else:
    if not sb_enabled:
        print("\n{g}{b}RESULT: NOT AFFECTED – Secure Boot is disabled on this system.{reset}".format(
            g=GREEN, b=BOLD, reset=RESET))
    else:
        print("\n{g}{b}RESULT: NOT AFFECTED – All checks passed.{reset}".format(
            g=GREEN, b=BOLD, reset=RESET))
