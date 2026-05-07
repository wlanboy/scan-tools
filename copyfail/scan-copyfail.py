#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import os
import re
import socket
import subprocess
import sys

VULNERABLE_KERNEL_MIN = (4, 10)
VULNERABLE_KERNEL_MAX = (6, 14)
VULNERABLE_MODULE     = "algif_aead"
SU_PATH               = "/usr/bin/su"

# Known-good SHA-256 hashes of /usr/bin/su per distro package.
# Extend this dict with hashes from your package manager:
#   Debian/Ubuntu: dpkg -L login | grep /su && sha256sum /usr/bin/su
#   RHEL/Fedora:   rpm -V util-linux
KNOWN_SU_HASHES: dict[str, str] = {
    # "ubuntu-24.04": "aabbcc...",
}

findings: list[str] = []


def emit(tag: str, detail: str) -> None:
    line = "{0}: {1}".format(tag, detail)
    print(line)
    if tag.startswith("FINDING"):
        findings.append(line)


# ---------------------------------------------------------------------------
# Kernel & module
# ---------------------------------------------------------------------------

def get_kernel_version() -> str:
    try:
        result = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=5)
        return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        print("ERROR: Could not run uname -r: {0}".format(e))
        sys.exit(2)


def parse_kernel_tuple(version_str: str) -> tuple[int, int] | None:
    m = re.match(r"^(\d+)\.(\d+)", version_str)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)))


def is_kernel_vulnerable(version_tuple: tuple[int, int]) -> bool:
    return VULNERABLE_KERNEL_MIN <= version_tuple <= VULNERABLE_KERNEL_MAX


def check_module_loaded(module_name: str) -> bool:
    try:
        result = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=5)
        loaded = any(
            line.split()[0] == module_name
            for line in result.stdout.splitlines()
            if line.split()
        )
        tag = "FINDING_MODULE_LOADED" if loaded else "MODULE_NOT_LOADED"
        emit(tag, module_name)
        return loaded
    except (OSError, subprocess.TimeoutExpired) as e:
        emit("ERROR", "lsmod failed: {0}".format(e))
        return False


# ---------------------------------------------------------------------------
# Trace 1: AF_ALG socket erreichbar für unprivilegierte Prozesse?
# ---------------------------------------------------------------------------

def check_af_alg_accessible() -> None:
    AF_ALG = 38
    SOCK_SEQPACKET = 5
    try:
        sock = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
        sock.close()
        emit("FINDING_AF_ALG_ACCESSIBLE",
             "AF_ALG socket (family 38) createable without privileges — "
             "exploit prerequisite met")
    except OSError as e:
        emit("AF_ALG_BLOCKED", "socket creation failed ({0})".format(e))


# ---------------------------------------------------------------------------
# Trace 2: Audit-Log auf /usr/bin/su-Zugriffe prüfen
# ---------------------------------------------------------------------------

def check_audit_log() -> None:
    """Sucht im Audit-Log nach Zugriffen auf /usr/bin/su durch Python-Prozesse."""
    if not os.path.exists("/var/log/audit/audit.log"):
        emit("AUDIT_LOG", "not found — auditd not active or no permission")
        return

    try:
        result = subprocess.run(
            ["ausearch", "-f", SU_PATH, "--format", "raw"],
            capture_output=True, text=True, timeout=10,
        )
        lines = [l for l in result.stdout.splitlines() if "python" in l.lower()]
        if lines:
            emit("FINDING_AUDIT_SU_PYTHON",
                 "{0} audit event(s) show python accessing {1}".format(len(lines), SU_PATH))
            for line in lines[:5]:
                print("  " + line[:120])
        else:
            emit("AUDIT_SU_CLEAN", "no python access to {0} in audit log".format(SU_PATH))
    except FileNotFoundError:
        emit("AUDIT_LOG", "ausearch not installed — check /var/log/audit/audit.log manually")
    except subprocess.TimeoutExpired:
        emit("ERROR", "ausearch timed out")


# ---------------------------------------------------------------------------
# Trace 3: Kernel-Log auf AF_ALG / splice-Ereignisse prüfen
# ---------------------------------------------------------------------------

def check_kernel_log() -> None:
    keywords = ["algif_aead", "af_alg", "splice", "CRYPTO_USER"]
    try:
        result = subprocess.run(
            ["dmesg", "--level=warn,err,crit,alert,emerg"],
            capture_output=True, text=True, timeout=10,
        )
        hits = [
            line for line in result.stdout.splitlines()
            if any(kw.lower() in line.lower() for kw in keywords)
        ]
        if hits:
            emit("FINDING_KERNEL_LOG",
                 "{0} suspicious kernel log line(s)".format(len(hits)))
            for line in hits[:5]:
                print("  " + line[:120])
        else:
            emit("KERNEL_LOG_CLEAN", "no relevant entries in dmesg")
    except (OSError, subprocess.TimeoutExpired) as e:
        emit("ERROR", "dmesg failed: {0}".format(e))


# ---------------------------------------------------------------------------
# Trace 4: AppArmor / SELinux — würde der Exploit geblockt oder geloggt?
# ---------------------------------------------------------------------------

def check_mac_policy() -> None:
    # AppArmor
    aa_status = "/sys/kernel/security/apparmor/profiles"
    if os.path.exists(aa_status):
        try:
            result = subprocess.run(
                ["aa-status", "--json"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                emit("APPARMOR", "active — check if su profile enforces network/socket rules")
            else:
                emit("FINDING_APPARMOR_INACTIVE",
                     "AppArmor present but aa-status failed — policies may be permissive")
        except FileNotFoundError:
            emit("APPARMOR", "AppArmor filesystem exists but aa-status not installed")
    else:
        emit("FINDING_NO_APPARMOR", "AppArmor not active — no MAC policy blocking AF_ALG abuse")

    # SELinux
    selinux_status = "/sys/fs/selinux/enforce"
    if os.path.exists(selinux_status):
        try:
            enforcing = open(selinux_status).read().strip() == "1"
            tag = "SELINUX_ENFORCING" if enforcing else "FINDING_SELINUX_PERMISSIVE"
            emit(tag, "SELinux enforce={0}".format(enforcing))
        except OSError:
            pass
    else:
        emit("FINDING_NO_SELINUX", "SELinux not active")


# ---------------------------------------------------------------------------
# Trace 5: Integrität von /usr/bin/su prüfen
# ---------------------------------------------------------------------------

def check_su_integrity() -> None:
    try:
        digest = hashlib.sha256(open(SU_PATH, "rb").read()).hexdigest()
        emit("SU_SHA256", digest)

        if digest in KNOWN_SU_HASHES.values():
            emit("SU_INTEGRITY_OK", "hash matches known-good value")
        elif KNOWN_SU_HASHES:
            emit("FINDING_SU_HASH_UNKNOWN",
                 "hash not in known-good list — verify with package manager")
        else:
            emit("SU_INTEGRITY_HINT",
                 "no reference hashes configured — run: sha256sum {0}".format(SU_PATH))

        # Mtime ungewöhnlich kürzlich?
        stat = os.stat(SU_PATH)
        import time
        age_sec = time.time() - stat.st_mtime
        if age_sec < 3600:
            emit("FINDING_SU_RECENTLY_MODIFIED",
                 "{0} mtime is only {1:.0f}s ago".format(SU_PATH, age_sec))
        else:
            emit("SU_MTIME_OK",
                 "{0} last modified {1:.1f}h ago".format(SU_PATH, age_sec / 3600))

    except OSError as e:
        emit("ERROR", "cannot read {0}: {1}".format(SU_PATH, e))


# ---------------------------------------------------------------------------
# Trace 6: Laufende Prozesse mit /usr/bin/su offen
# ---------------------------------------------------------------------------

def check_open_su_fds() -> None:
    """Prüft via /proc ob ein Prozess aktuell /usr/bin/su geöffnet hat."""
    hits = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            fd_dir = "/proc/{0}/fd".format(pid)
            try:
                for fd in os.listdir(fd_dir):
                    target = os.readlink("{0}/{1}".format(fd_dir, fd))
                    if target == SU_PATH:
                        cmdline = open("/proc/{0}/cmdline".format(pid)).read().replace("\x00", " ")
                        hits.append("pid={0} cmd={1}".format(pid, cmdline[:60]))
            except (OSError, PermissionError):
                continue
    except OSError:
        pass

    if hits:
        for h in hits:
            emit("FINDING_SU_FD_OPEN", h)
    else:
        emit("SU_FD_CLEAN", "no process currently has {0} open".format(SU_PATH))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
    hostname = socket.gethostname()
    kernel_str = get_kernel_version()
    kernel_tuple = parse_kernel_tuple(kernel_str)

    print("=== COPY.FAIL SCAN REPORT: {0} ===".format(hostname))
    print("KERNEL: {0}".format(kernel_str))
    print()

    if kernel_tuple is None:
        print("ERROR: Could not parse kernel version")
        sys.exit(2)

    if not is_kernel_vulnerable(kernel_tuple):
        emit("RESULT_KERNEL", "NOT_AFFECTED — kernel {0} outside vulnerable range {1}.{2}–{3}.{4}".format(
            kernel_str,
            VULNERABLE_KERNEL_MIN[0], VULNERABLE_KERNEL_MIN[1],
            VULNERABLE_KERNEL_MAX[0], VULNERABLE_KERNEL_MAX[1],
        ))
        sys.exit(0)

    emit("KERNEL_RANGE", "vulnerable ({0}.{1}–{2}.{3})".format(
        VULNERABLE_KERNEL_MIN[0], VULNERABLE_KERNEL_MIN[1],
        VULNERABLE_KERNEL_MAX[0], VULNERABLE_KERNEL_MAX[1],
    ))
    print()

    print("--- Module ---")
    check_module_loaded(VULNERABLE_MODULE)
    print()

    print("--- Exploit Prerequisites ---")
    check_af_alg_accessible()
    print()

    print("--- Traces: Audit Log ---")
    check_audit_log()
    print()

    print("--- Traces: Kernel Log ---")
    check_kernel_log()
    print()

    print("--- Traces: MAC Policy (AppArmor/SELinux) ---")
    check_mac_policy()
    print()

    print("--- Traces: su Integrity ---")
    check_su_integrity()
    print()

    print("--- Traces: Live Open File Descriptors ---")
    check_open_su_fds()
    print()

    print("=== SUMMARY ===")
    if findings:
        print("FINDINGS ({0}):".format(len(findings)))
        for f in findings:
            print("  [!] " + f)
        sys.exit(1)
    else:
        print("No significant findings.")
        sys.exit(0)


if __name__ == "__main__":
    main()
