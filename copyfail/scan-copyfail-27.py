#!/usr/bin/env python

import datetime
import hashlib
import os
import re
import socket
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Copy.Fail (CVE-2026-31431) — algif_aead / AF_ALG
# ---------------------------------------------------------------------------
COPYFAIL_KERNEL_MIN = (4, 10)
COPYFAIL_KERNEL_MAX = (6, 14)
COPYFAIL_MODULE     = "algif_aead"

# ---------------------------------------------------------------------------
# Dirty Frag — xfrm-ESP (esp4/esp6) and RxRPC variants (no patch as of 2026-05-08)
# xfrm-ESP : since commit cac2661c53f3 (Jan 2017, ~4.10)
# RxRPC    : since commit 2dc334f1a63a (Jun 2023, ~6.4)
# ---------------------------------------------------------------------------
DIRTYFRAG_ESP_KERNEL_MIN   = (4, 10)
DIRTYFRAG_RXRPC_KERNEL_MIN = (6, 4)
DIRTYFRAG_MODULES          = ["esp4", "esp6", "rxrpc"]

# ---------------------------------------------------------------------------
# Fragnesia — espintcp ULP / TCP_ULP (patch: 2026-05-13, William Bowling / V12)
# Byte-precise page cache write via splice + TCP_ULP espintcp mode switch
# ---------------------------------------------------------------------------
FRAGNESIA_PATCH_DATE = datetime.date(2026, 5, 13)
FRAGNESIA_MODULE     = "espintcp"

SU_PATH     = "/usr/bin/su"
PASSWD_PATH = "/etc/passwd"

# Known-good SHA-256 hashes of /usr/bin/su per distro package.
# Extend this dict with hashes from your package manager:
#   Debian/Ubuntu: dpkg -L login | grep /su && sha256sum /usr/bin/su
#   RHEL/Fedora:   rpm -V util-linux
KNOWN_SU_HASHES = {
    # "ubuntu-24.04": "aabbcc...",
}

findings = []


def emit(tag, detail):
    line = f"{tag}: {detail}"
    print(line)
    if tag.startswith("FINDING"):
        findings.append(line)


# ---------------------------------------------------------------------------
# subprocess.run() wrapper for Python 2.7 (no timeout support)
# ---------------------------------------------------------------------------

def run_cmd(args):
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, _ = proc.communicate()
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", "replace")
    return stdout, proc.returncode


# ---------------------------------------------------------------------------
# Kernel & module helpers
# ---------------------------------------------------------------------------

def get_kernel_version():
    try:
        stdout, _ = run_cmd(["uname", "-r"])
        return stdout.strip()
    except OSError as e:
        print(f"ERROR: Could not run uname -r: {e}")
        sys.exit(2)


def parse_kernel_tuple(version_str):
    m = re.match(r"^(\d+)\.(\d+)", version_str)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)))


def is_copyfail_vulnerable(v):
    return COPYFAIL_KERNEL_MIN <= v <= COPYFAIL_KERNEL_MAX


def is_dirtyfrag_esp_vulnerable(v):
    return v >= DIRTYFRAG_ESP_KERNEL_MIN


def is_dirtyfrag_rxrpc_vulnerable(v):
    return v >= DIRTYFRAG_RXRPC_KERNEL_MIN


def get_kernel_build_date():
    try:
        stdout, _ = run_cmd(["uname", "-v"])
        version_str = stdout.strip()
        # Example: "#1 SMP PREEMPT_DYNAMIC Thu May 13 12:00:00 UTC 2026"
        m = re.search(r"\b\w{3}\s+(\w{3})\s+(\d+)\s+[\d:]+\s+\w+\s+(\d{4})\b", version_str)
        if m:
            month_names = {
                "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
                "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
            }
            month = month_names.get(m.group(1))
            day   = int(m.group(2))
            year  = int(m.group(3))
            if month:
                return datetime.date(year, month, day)
    except (OSError, ValueError):
        pass
    return None


def is_fragnesia_vulnerable(build_date):
    if build_date is None:
        return True  # unknown build date -> assume vulnerable
    return build_date < FRAGNESIA_PATCH_DATE


def check_module_loaded(module_name, finding_tag="FINDING_MODULE_LOADED"):
    try:
        stdout, _ = run_cmd(["lsmod"])
        loaded = any(
            line.split()[0] == module_name
            for line in stdout.splitlines()
            if line.split()
        )
        tag = finding_tag if loaded else "MODULE_NOT_LOADED"
        emit(tag, module_name)
        return loaded
    except OSError as e:
        emit("ERROR", f"lsmod failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Copy.Fail: AF_ALG socket erreichbar fuer unprivilegierte Prozesse?
# ---------------------------------------------------------------------------

def check_af_alg_accessible():
    AF_ALG = 38
    SOCK_SEQPACKET = 5
    try:
        sock = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
        sock.close()
        emit("FINDING_AF_ALG_ACCESSIBLE",
             "AF_ALG socket (family 38) createable without privileges — "
             "CopyFail exploit prerequisite met")
    except OSError as e:
        emit("AF_ALG_BLOCKED", f"socket creation failed ({e})")


# ---------------------------------------------------------------------------
# Fragnesia: espintcp als TCP_ULP nutzbar? (kein Namespace fuer den Check noetig)
# ---------------------------------------------------------------------------

def check_fragnesia_tcp_ulp():
    TCP_ULP = 31
    SOL_TCP = 6
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        try:
            sock.setsockopt(SOL_TCP, TCP_ULP, b"espintcp")
            emit("FINDING_FRAGNESIA_TCP_ULP_ACCESSIBLE",
                 "espintcp TCP_ULP usable without privileges — "
                 "Fragnesia exploit prerequisite met")
        except OSError as e:
            emit("FRAGNESIA_TCP_ULP_BLOCKED",
                 f"setsockopt(TCP_ULP, espintcp) failed ({e})")
        finally:
            sock.close()
    except OSError as e:
        emit("ERROR", f"TCP socket creation failed: {e}")


def check_fragnesia_mitigation():
    modprobe_dirs = ["/etc/modprobe.d", "/usr/lib/modprobe.d"]
    blacklisted = False

    for d in modprobe_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                fpath = os.path.join(d, fname)
                try:
                    with open(fpath) as fh:
                        content = fh.read().lower()
                    if (f"install {FRAGNESIA_MODULE} /bin/false" in content
                            or f"blacklist {FRAGNESIA_MODULE}" in content):
                        blacklisted = True
                except OSError:
                    continue
        except OSError:
            continue

    if blacklisted:
        emit("FRAGNESIA_MITIGATION_ACTIVE",
             f"{FRAGNESIA_MODULE} blacklisted in modprobe.d")
    else:
        emit("FINDING_DIRTYFRAG_NO_MITIGATION",
             f"{FRAGNESIA_MODULE} not blacklisted in modprobe.d — mitigation missing")


# ---------------------------------------------------------------------------
# Dirty Frag: AF_RXRPC socket erreichbar? (RxRPC variant, no namespace needed)
# ---------------------------------------------------------------------------

def check_af_rxrpc_accessible():
    AF_RXRPC = 34
    SOCK_DGRAM = 2
    try:
        sock = socket.socket(AF_RXRPC, SOCK_DGRAM, 0)
        sock.close()
        emit("FINDING_AF_RXRPC_ACCESSIBLE",
             "AF_RXRPC socket (family 34) createable without privileges — "
             "DirtyFrag RxRPC exploit prerequisite met")
    except OSError as e:
        emit("AF_RXRPC_BLOCKED", f"socket creation failed ({e})")


# ---------------------------------------------------------------------------
# Dirty Frag: XFRM (NETLINK_XFRM) erreichbar? (xfrm-ESP variant)
# ---------------------------------------------------------------------------

def check_xfrm_accessible():
    AF_NETLINK   = 16
    SOCK_RAW     = 3
    NETLINK_XFRM = 6
    try:
        sock = socket.socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM)
        sock.close()
        emit("FINDING_XFRM_ACCESSIBLE",
             "NETLINK_XFRM socket createable without privileges — "
             "DirtyFrag xfrm-ESP exploit prerequisite met")
    except OSError as e:
        emit("XFRM_BLOCKED", f"NETLINK_XFRM socket creation failed ({e})")


# ---------------------------------------------------------------------------
# Dirty Frag: Unprivilegierte User-Namespaces? (xfrm-ESP variant erfordert diese)
# ---------------------------------------------------------------------------

def check_namespace_creation():
    userns_clone = "/proc/sys/kernel/unprivileged_userns_clone"  # Debian/Ubuntu
    max_userns   = "/proc/sys/user/max_user_namespaces"

    if os.path.exists(userns_clone):
        try:
            with open(userns_clone) as fh:
                val = fh.read().strip()
            if val == "0":
                emit("NAMESPACE_USERNS_DISABLED",
                     "unprivileged_userns_clone=0 — xfrm-ESP DirtyFrag variant blocked")
            else:
                emit("FINDING_NAMESPACE_USERNS_ENABLED",
                     "unprivileged_userns_clone=1 — xfrm-ESP DirtyFrag and Fragnesia variants possible")
        except OSError:
            pass

    if os.path.exists(max_userns):
        try:
            with open(max_userns) as fh:
                val = int(fh.read().strip())
            if val == 0:
                emit("NAMESPACE_MAX_USERNS_ZERO",
                     "max_user_namespaces=0 — xfrm-ESP DirtyFrag variant blocked")
            else:
                emit("FINDING_NAMESPACE_MAX_USERNS_NONZERO",
                     f"max_user_namespaces={val} — xfrm-ESP DirtyFrag and Fragnesia variants possible")
        except (OSError, ValueError):
            pass


# ---------------------------------------------------------------------------
# Dirty Frag: modprobe.d blacklist fuer esp4/esp6/rxrpc (empfohlene Mitigation)
# ---------------------------------------------------------------------------

def check_dirtyfrag_mitigation():
    modprobe_dirs = ["/etc/modprobe.d", "/usr/lib/modprobe.d"]
    blacklisted: dict[str, bool] = {m: False for m in DIRTYFRAG_MODULES}

    for d in modprobe_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                fpath = os.path.join(d, fname)
                try:
                    with open(fpath) as fh:
                        content = fh.read().lower()
                    for module in DIRTYFRAG_MODULES:
                        if (f"install {module} /bin/false" in content
                                or f"blacklist {module}" in content):
                            blacklisted[module] = True
                except OSError:
                    continue
        except OSError:
            continue

    for module, blocked in blacklisted.items():
        if blocked:
            emit("DIRTYFRAG_MITIGATION_ACTIVE",
                 f"{module} blacklisted in modprobe.d")
        else:
            emit("FINDING_DIRTYFRAG_NO_MITIGATION",
                 f"{module} not blacklisted in modprobe.d — mitigation missing")


# ---------------------------------------------------------------------------
# Dirty Frag: /etc/passwd Integritaet (RxRPC-Variante schreibt in /etc/passwd)
# ---------------------------------------------------------------------------

def check_passwd_integrity():
    try:
        with open(PASSWD_PATH) as f:
            lines = f.readlines()

        for line in lines:
            parts = line.strip().split(":")
            if len(parts) < 7:
                continue
            username, passwd_field, uid_str = parts[0], parts[1], parts[2]

            if passwd_field == "" and username == "root":
                emit("FINDING_PASSWD_ROOT_EMPTY_PW",
                     "/etc/passwd: root entry has empty password field — "
                     "possible RxRPC DirtyFrag exploit (Splice-A/B/C write)")

            try:
                if int(uid_str) == 0 and username != "root":
                    emit("FINDING_PASSWD_SHADOW_ROOT",
                         f"/etc/passwd: user '{username}' has UID 0 — "
                         "possible privilege escalation")
            except ValueError:
                pass

        stat = os.stat(PASSWD_PATH)
        age_sec = time.time() - stat.st_mtime
        if age_sec < 3600:
            emit("FINDING_PASSWD_RECENTLY_MODIFIED",
                 f"{PASSWD_PATH} mtime is only {age_sec:.0f}s ago — "
                 "possible RxRPC DirtyFrag exploit target")
        else:
            emit("PASSWD_MTIME_OK",
                 f"{PASSWD_PATH} last modified {age_sec / 3600.0:.1f}h ago")

    except OSError as e:
        emit("ERROR", f"cannot read {PASSWD_PATH}: {e}")


# ---------------------------------------------------------------------------
# PAM nullok — leeres Passwort per su erlaubt?
# ---------------------------------------------------------------------------

PAM_FILES_SU = [
    "/etc/pam.d/su",
    "/etc/pam.d/su-l",
]
PAM_FILES_COMMON = [
    "/etc/pam.d/common-auth",
    "/etc/pam.d/system-auth",
    "/etc/pam.d/password-auth",
]


def check_pam_nullok():
    nullok_files = []

    for path in PAM_FILES_SU + PAM_FILES_COMMON:
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                for lineno, raw in enumerate(f, 1):
                    line = raw.strip()
                    if line.startswith("#"):
                        continue
                    if "pam_unix.so" in line and "nullok" in line:
                        nullok_files.append(f"{path}:{lineno}")
        except OSError:
            continue

    if nullok_files:
        for loc in nullok_files:
            emit("FINDING_PAM_NULLOK",
                 f"pam_unix.so with nullok found in {loc} — "
                 "su with empty password accepted (exploit prerequisite)")
    else:
        emit("PAM_NULLOK_NOT_FOUND",
             "no pam_unix.so nullok in su/common-auth configs — "
             "empty-password su blocked")


# ---------------------------------------------------------------------------
# Audit-Log auf Zugriffe auf su / passwd pruefen
# ---------------------------------------------------------------------------

def check_audit_log():
    if not os.path.exists("/var/log/audit/audit.log"):
        emit("AUDIT_LOG", "not found — auditd not active or no permission")
        return

    for target_path in [SU_PATH, PASSWD_PATH]:
        try:
            stdout, _ = run_cmd(["ausearch", "-f", target_path, "--format", "raw"])
            lines = [line for line in stdout.splitlines() if "python" in line.lower()]
            if lines:
                emit("FINDING_AUDIT_SU_PYTHON",
                     f"{len(lines)} audit event(s) show python accessing {target_path}")
                for line in lines[:5]:
                    print("  " + line[:120])
            else:
                emit("AUDIT_SU_CLEAN",
                     f"no python access to {target_path} in audit log")
        except OSError:
            emit("AUDIT_LOG", "ausearch not installed — check /var/log/audit/audit.log manually")
            return


# ---------------------------------------------------------------------------
# Kernel-Log auf CopyFail- und DirtyFrag-Ereignisse pruefen
# ---------------------------------------------------------------------------

def check_kernel_log():
    keywords = [
        "algif_aead", "af_alg", "splice", "CRYPTO_USER",           # CopyFail
        "esp4", "esp6", "rxrpc", "xfrm", "pcbc", "fcrypt",         # DirtyFrag
        "espintcp", "tcp_ulp", "esp-in-tcp",                        # Fragnesia
    ]
    try:
        stdout, _ = run_cmd(["dmesg", "--level=warn,err,crit,alert,emerg"])
        hits = [
            line for line in stdout.splitlines()
            if any(kw.lower() in line.lower() for kw in keywords)
        ]
        if hits:
            emit("FINDING_KERNEL_LOG",
                 f"{len(hits)} suspicious kernel log line(s)")
            for line in hits[:5]:
                print("  " + line[:120])
        else:
            emit("KERNEL_LOG_CLEAN", "no relevant entries in dmesg")
    except OSError as e:
        emit("ERROR", f"dmesg failed: {e}")


# ---------------------------------------------------------------------------
# AppArmor / SELinux
# ---------------------------------------------------------------------------

def check_mac_policy():
    aa_status = "/sys/kernel/security/apparmor/profiles"
    if os.path.exists(aa_status):
        try:
            _, returncode = run_cmd(["aa-status", "--json"])
            if returncode == 0:
                emit("APPARMOR",
                     "active — check if su/passwd profiles enforce socket/xfrm rules")
            else:
                emit("FINDING_APPARMOR_INACTIVE",
                     "AppArmor present but aa-status failed — policies may be permissive")
        except OSError:
            emit("APPARMOR", "AppArmor filesystem exists but aa-status not installed")
    else:
        emit("FINDING_NO_APPARMOR",
             "AppArmor not active — no MAC policy blocking AF_ALG/xfrm/rxrpc abuse")

    selinux_status = "/sys/fs/selinux/enforce"
    if os.path.exists(selinux_status):
        try:
            with open(selinux_status) as fh:
                enforcing = fh.read().strip() == "1"
            tag = "SELINUX_ENFORCING" if enforcing else "FINDING_SELINUX_PERMISSIVE"
            emit(tag, f"SELinux enforce={enforcing}")
        except OSError:
            pass
    else:
        emit("FINDING_NO_SELINUX", "SELinux not active")


# ---------------------------------------------------------------------------
# Integritaet von /usr/bin/su pruefen
# ---------------------------------------------------------------------------

def check_su_integrity():
    try:
        with open(SU_PATH, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        emit("SU_SHA256", digest)

        if digest in KNOWN_SU_HASHES.values():
            emit("SU_INTEGRITY_OK", "hash matches known-good value")
        elif KNOWN_SU_HASHES:
            emit("FINDING_SU_HASH_UNKNOWN",
                 "hash not in known-good list — verify with package manager")
        else:
            emit("SU_INTEGRITY_HINT",
                 f"no reference hashes configured — run: sha256sum {SU_PATH}")

        stat = os.stat(SU_PATH)
        age_sec = time.time() - stat.st_mtime
        if age_sec < 3600:
            emit("FINDING_SU_RECENTLY_MODIFIED",
                 f"{SU_PATH} mtime is only {age_sec:.0f}s ago")
        else:
            emit("SU_MTIME_OK",
                 f"{SU_PATH} last modified {age_sec / 3600.0:.1f}h ago")

    except OSError as e:
        emit("ERROR", f"cannot read {SU_PATH}: {e}")


# ---------------------------------------------------------------------------
# Laufende Prozesse mit Zieldatei offen
# ---------------------------------------------------------------------------

def check_open_fds(target_path):
    hits = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            fd_dir = f"/proc/{pid}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    link = os.readlink(f"{fd_dir}/{fd}")
                    if link == target_path:
                        with open(f"/proc/{pid}/cmdline") as fh:
                            cmdline = fh.read().replace("\x00", " ")
                        hits.append(f"pid={pid} cmd={cmdline[:60]}")
            except OSError:
                continue
    except OSError:
        pass

    label = os.path.basename(target_path).upper().replace(".", "_")
    if hits:
        for h in hits:
            emit(f"FINDING_{label}_FD_OPEN", h)
    else:
        emit(f"{label}_FD_CLEAN",
             f"no process currently has {target_path} open")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    hostname     = socket.gethostname()
    kernel_str   = get_kernel_version()
    kernel_tuple = parse_kernel_tuple(kernel_str)

    print(f"=== COPY.FAIL / DIRTY.FRAG SCAN REPORT: {hostname} ===")
    print(f"KERNEL: {kernel_str}")
    print()

    if kernel_tuple is None:
        print("ERROR: Could not parse kernel version")
        sys.exit(2)

    copyfail_vuln  = is_copyfail_vulnerable(kernel_tuple)
    df_esp_vuln    = is_dirtyfrag_esp_vulnerable(kernel_tuple)
    df_rxrpc_vuln  = is_dirtyfrag_rxrpc_vulnerable(kernel_tuple)
    build_date     = get_kernel_build_date()
    fragnesia_vuln = is_fragnesia_vulnerable(build_date)
    any_vuln       = copyfail_vuln or df_esp_vuln or df_rxrpc_vuln or fragnesia_vuln

    print("--- Vulnerability Assessment ---")
    if copyfail_vuln:
        emit("FINDING_KERNEL_COPYFAIL",
             f"in vulnerable range {COPYFAIL_KERNEL_MIN[0]}.{COPYFAIL_KERNEL_MIN[1]}-{COPYFAIL_KERNEL_MAX[0]}.{COPYFAIL_KERNEL_MAX[1]} (CVE-2026-31431)")
    else:
        emit("RESULT_COPYFAIL",
             f"NOT_AFFECTED - kernel outside CopyFail range {COPYFAIL_KERNEL_MIN[0]}.{COPYFAIL_KERNEL_MIN[1]}-{COPYFAIL_KERNEL_MAX[0]}.{COPYFAIL_KERNEL_MAX[1]}")

    if df_esp_vuln:
        emit("FINDING_KERNEL_DIRTYFRAG_ESP",
             f"kernel >= {DIRTYFRAG_ESP_KERNEL_MIN[0]}.{DIRTYFRAG_ESP_KERNEL_MIN[1]} - xfrm-ESP DirtyFrag variant present (no patch available)")
    else:
        emit("RESULT_DIRTYFRAG_ESP",
             f"NOT_AFFECTED - kernel below xfrm-ESP minimum {DIRTYFRAG_ESP_KERNEL_MIN[0]}.{DIRTYFRAG_ESP_KERNEL_MIN[1]}")

    if df_rxrpc_vuln:
        emit("FINDING_KERNEL_DIRTYFRAG_RXRPC",
             f"kernel >= {DIRTYFRAG_RXRPC_KERNEL_MIN[0]}.{DIRTYFRAG_RXRPC_KERNEL_MIN[1]} - RxRPC DirtyFrag variant present (no patch available)")
    else:
        emit("RESULT_DIRTYFRAG_RXRPC",
             f"NOT_AFFECTED - kernel below RxRPC minimum {DIRTYFRAG_RXRPC_KERNEL_MIN[0]}.{DIRTYFRAG_RXRPC_KERNEL_MIN[1]}")

    if fragnesia_vuln:
        if build_date:
            emit("FINDING_KERNEL_FRAGNESIA",
                 f"kernel build date {build_date} is before Fragnesia patch {FRAGNESIA_PATCH_DATE} — "
                 "espintcp ULP variant possible")
        else:
            emit("FINDING_KERNEL_FRAGNESIA",
                 "kernel build date unknown — Fragnesia patch status uncertain (assume vulnerable)")
    else:
        emit("RESULT_FRAGNESIA",
             f"NOT_AFFECTED — kernel build date {build_date} >= Fragnesia patch {FRAGNESIA_PATCH_DATE}")
    print()

    if not any_vuln:
        print("Kernel not in any vulnerable range.")
        sys.exit(0)

    # --- Copy.Fail ---
    if copyfail_vuln:
        print("--- Copy.Fail: Module ---")
        check_module_loaded(COPYFAIL_MODULE)
        print()

        print("--- Copy.Fail: Exploit Prerequisites ---")
        check_af_alg_accessible()
        print()

    # --- Dirty Frag ---
    if df_esp_vuln or df_rxrpc_vuln:
        print("--- DirtyFrag: Modules (esp4, esp6, rxrpc) ---")
        for mod in DIRTYFRAG_MODULES:
            check_module_loaded(mod, finding_tag="FINDING_DIRTYFRAG_MODULE_LOADED")
        print()

        print("--- DirtyFrag: Exploit Prerequisites ---")
        if df_rxrpc_vuln:
            check_af_rxrpc_accessible()
        if df_esp_vuln:
            check_xfrm_accessible()
            check_namespace_creation()
        print()

        print("--- DirtyFrag: Mitigation (modprobe.d blacklist) ---")
        check_dirtyfrag_mitigation()
        print()

    # --- Fragnesia ---
    if fragnesia_vuln:
        print("--- Fragnesia: Module (espintcp) ---")
        check_module_loaded(FRAGNESIA_MODULE, finding_tag="FINDING_FRAGNESIA_MODULE_LOADED")
        print()

        print("--- Fragnesia: Exploit Prerequisites ---")
        check_fragnesia_tcp_ulp()
        check_namespace_creation()
        print()

        print("--- Fragnesia: Mitigation (modprobe.d blacklist) ---")
        check_fragnesia_mitigation()
        print()

    # --- Shared traces ---
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

    print("--- Traces: PAM nullok (empty-password su) ---")
    check_pam_nullok()
    print()

    if df_rxrpc_vuln:
        print("--- Traces: /etc/passwd Integrity (DirtyFrag RxRPC target) ---")
        check_passwd_integrity()
        print()

    print("--- Traces: Live Open File Descriptors ---")
    check_open_fds(SU_PATH)
    if df_rxrpc_vuln:
        check_open_fds(PASSWD_PATH)
    print()

    print("=== SUMMARY ===")
    if findings:
        print(f"FINDINGS ({len(findings)}):")
        for f in findings:
            print("  [!] " + f)
        sys.exit(1)
    else:
        print("No significant findings.")
        sys.exit(0)


if __name__ == "__main__":
    main()
