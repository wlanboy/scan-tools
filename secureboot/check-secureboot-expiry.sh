#!/usr/bin/env bash
# Checks whether this Linux VM is affected by the Microsoft Secure Boot
# certificate expiration in 2026 (UEFI CA 2011, KEK CA 2011 expire June 2026;
# Windows PCA 2011 expires October 2026).
#
# References:
#   https://access.redhat.com/articles/7128933
#   https://knowledge.broadcom.com/external/article/423893/

set -euo pipefail

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}[OK ]${RESET} $*"; }
warn() { echo -e "  ${YELLOW}[WARN]${RESET} $*"; }
fail() { echo -e "  ${RED}[FAIL]${RESET} $*"; }
info() { echo -e "  ${CYAN}[INFO]${RESET} $*"; }
section() { echo -e "\n${BOLD}=== $* ===${RESET}"; }

ISSUES=0
WARNINGS=0

issue() { fail "$*"; (( ISSUES++ )) || true; }
warning() { warn "$*"; (( WARNINGS++ )) || true; }

# ---------------------------------------------------------------------------
# 1. Runtime environment
# ---------------------------------------------------------------------------
section "Runtime Environment"

OS_ID=""
OS_VERSION=""
if [[ -f /etc/os-release ]]; then
    OS_ID=$(. /etc/os-release && echo "${ID:-unknown}")
    OS_VERSION=$(. /etc/os-release && echo "${VERSION_ID:-unknown}")
    OS_PRETTY=$(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")
    info "OS: ${OS_PRETTY}"
else
    info "OS: unknown (no /etc/os-release)"
fi

# Detect hypervisor / cloud
HYPERVISOR="bare-metal"
if systemd-detect-virt --quiet 2>/dev/null; then
    HYPERVISOR=$(systemd-detect-virt 2>/dev/null || echo "unknown-vm")
fi

# Fallback detection without systemd-detect-virt
if [[ "$HYPERVISOR" == "bare-metal" || "$HYPERVISOR" == "none" ]]; then
    if grep -qi "vmware" /sys/class/dmi/id/sys_vendor 2>/dev/null; then
        HYPERVISOR="vmware"
    elif grep -qi "google" /sys/class/dmi/id/sys_vendor 2>/dev/null; then
        HYPERVISOR="gcp"
    elif grep -qi "microsoft" /sys/class/dmi/id/sys_vendor 2>/dev/null; then
        HYPERVISOR="azure"
    elif grep -qi "amazon" /sys/class/dmi/id/sys_vendor 2>/dev/null; then
        HYPERVISOR="aws"
    fi
fi

info "Hypervisor/Cloud: ${HYPERVISOR}"

# Check GCP creation date via metadata (only if on GCP)
if [[ "$HYPERVISOR" == "gcp" ]]; then
    info "Running on GCP – checking instance metadata..."
    CREATION_DATE=$(curl -sf -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/creation-timestamp" \
        2>/dev/null || echo "")
    if [[ -n "$CREATION_DATE" ]]; then
        info "GCP instance creation timestamp: ${CREATION_DATE}"
        CUTOFF="2025-11-07"
        if [[ "$CREATION_DATE" < "$CUTOFF" ]]; then
            warning "GCP instance was created before ${CUTOFF} – may need recreation with updated firmware."
        else
            ok "GCP instance created after ${CUTOFF}."
        fi
    else
        info "Could not retrieve GCP creation timestamp (not GCP or no network access)."
    fi
fi

# ---------------------------------------------------------------------------
# 2. Secure Boot status
# ---------------------------------------------------------------------------
section "Secure Boot Status"

SB_ENABLED=false

if ! command -v mokutil &>/dev/null; then
    warning "mokutil is not installed. Install it with: dnf install mokutil / apt install mokutil"
    warning "Cannot perform detailed certificate checks without mokutil."
else
    SB_STATE=$(mokutil --sb-state 2>/dev/null || echo "unknown")
    if echo "$SB_STATE" | grep -qi "enabled"; then
        SB_ENABLED=true
        ok "Secure Boot is ENABLED – certificate expiry is relevant for this system."
    elif echo "$SB_STATE" | grep -qi "disabled"; then
        ok "Secure Boot is DISABLED – certificate expiry does NOT affect boot on this system."
        info "Note: If you plan to enable Secure Boot, certificates must still be updated first."
    else
        warning "Could not determine Secure Boot state (${SB_STATE})."
    fi
fi

# ---------------------------------------------------------------------------
# 3. Certificate database checks
# ---------------------------------------------------------------------------
section "Certificate Database (DB)"

check_certificates() {
    local db_flag="$1"
    local label="$2"

    if ! command -v mokutil &>/dev/null; then
        return
    fi

    local db_output
    db_output=$(mokutil "${db_flag}" 2>/dev/null) || {
        warning "Could not read ${label} (try running as root)."
        return
    }

    if [[ -z "$db_output" ]]; then
        warning "${label} is empty or inaccessible."
        return
    fi

    # 2011 certificates (expiring)
    local found_2011_uefi=false found_2011_kek=false found_2011_win=false
    # 2023 certificates (updated replacements)
    local found_2023_uefi=false found_2023_kek=false found_2023_win=false

    # Parse each certificate block
    while IFS= read -r line; do
        case "$line" in
            *"Microsoft Corporation UEFI CA 2011"*)   found_2011_uefi=true ;;
            *"Microsoft Corporation KEK CA 2011"*)    found_2011_kek=true ;;
            *"Microsoft Windows Production PCA 2011"*) found_2011_win=true ;;
            *"Windows UEFI CA 2023"*)                 found_2023_uefi=true ;;
            *"Microsoft Corporation UEFI CA 2023"*)   found_2023_uefi=true ;;
            *"KEK 2K CA 2023"*)                       found_2023_kek=true ;;
            *"Microsoft Corporation KEK 2K CA 2023"*) found_2023_kek=true ;;
            *"Windows Production PCA 2023"*)          found_2023_win=true ;;
        esac
    done <<< "$db_output"

    echo ""
    info "${label} certificate summary:"

    # UEFI CA (signs Linux shim) – expires 2026-06-27
    if $found_2011_uefi && $found_2023_uefi; then
        ok "  Microsoft UEFI CA 2011 present (expires 2026-06-27) AND 2023 replacement present."
    elif $found_2011_uefi && ! $found_2023_uefi; then
        issue "  Microsoft UEFI CA 2011 present (expires 2026-06-27) – 2023 replacement MISSING."
    elif ! $found_2011_uefi && $found_2023_uefi; then
        ok "  Microsoft UEFI CA 2011 absent, 2023 replacement present – already migrated."
    else
        info "  Microsoft UEFI CA 2011 not found in ${label} (may be in db or firmware)."
    fi

    # KEK CA (authorises db/dbx updates) – expires 2026-06-24
    if $found_2011_kek && $found_2023_kek; then
        ok "  Microsoft KEK CA 2011 present (expires 2026-06-24) AND 2023 replacement present."
    elif $found_2011_kek && ! $found_2023_kek; then
        issue "  Microsoft KEK CA 2011 present (expires 2026-06-24) – 2023 replacement MISSING."
    elif ! $found_2011_kek && $found_2023_kek; then
        ok "  Microsoft KEK CA 2011 absent, 2023 replacement present – already migrated."
    fi

    # Windows PCA (signs Windows boot manager) – expires 2026-10-19
    if $found_2011_win && $found_2023_win; then
        ok "  Microsoft Windows PCA 2011 present (expires 2026-10-19) AND 2023 replacement present."
    elif $found_2011_win && ! $found_2023_win; then
        warning "  Microsoft Windows PCA 2011 present (expires 2026-10-19) – 2023 replacement missing."
        info "  (Only relevant if this VM also boots Windows.)"
    fi
}

check_certificates "--db"  "DB (allowed signatures)"
check_certificates "--kek" "KEK (key exchange keys)"

# ---------------------------------------------------------------------------
# 4. Shim binary check
# ---------------------------------------------------------------------------
section "Shim Bootloader"

SHIM_PATHS=(
    /boot/efi/EFI/redhat/shimx64.efi
    /boot/efi/EFI/centos/shimx64.efi
    /boot/efi/EFI/fedora/shimx64.efi
    /boot/efi/EFI/ubuntu/shimx64.efi
    /boot/efi/EFI/debian/shimx64.efi
    /boot/efi/EFI/sles/shimx64.efi
    /boot/efi/EFI/opensuse/shimx64.efi
    /boot/efi/EFI/BOOT/BOOTX64.EFI
)

SHIM_FOUND=""
for p in "${SHIM_PATHS[@]}"; do
    if [[ -f "$p" ]]; then
        SHIM_FOUND="$p"
        break
    fi
done

if [[ -z "$SHIM_FOUND" ]]; then
    info "No shim binary found in known EFI paths (system may use BIOS, or EFI partition not mounted)."
else
    info "Shim binary: ${SHIM_FOUND}"
    SHIM_SIZE=$(stat -c '%s' "$SHIM_FOUND" 2>/dev/null || echo "unknown")
    SHIM_DATE=$(stat -c '%y' "$SHIM_FOUND" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
    info "Size: ${SHIM_SIZE} bytes, last modified: ${SHIM_DATE}"

    if command -v pesign &>/dev/null; then
        info "pesign output (certificate chain in shim):"
        pesign -S -i "$SHIM_FOUND" 2>/dev/null | grep -E "(Subject|Issuer|Not After)" | sed 's/^/    /' || true

        # Look for 2023 cert in shim signature
        SHIM_CERTS=$(pesign -S -i "$SHIM_FOUND" 2>/dev/null || "")
        if echo "$SHIM_CERTS" | grep -q "2023"; then
            ok "Shim appears to be signed with 2023-era certificate chain."
        elif echo "$SHIM_CERTS" | grep -q "2011"; then
            issue "Shim is signed only with 2011 certificate – update required."
        fi
    elif command -v sbverify &>/dev/null; then
        info "sbverify output:"
        sbverify --list "$SHIM_FOUND" 2>/dev/null | sed 's/^/    /' || true
    else
        warning "Neither pesign nor sbverify installed – cannot inspect shim signature."
        if command -v apt-get &>/dev/null; then
            info "Install via: apt install pesign  or  apt install sbsigntool"
        else
            info "Install via: dnf install pesign  (or: dnf install sbsigntools from EPEL)"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 5. Installed package versions (RHEL/CentOS/Fedora)
# ---------------------------------------------------------------------------
section "Package Versions"

if command -v rpm &>/dev/null; then
    for pkg in shim-x64 shim shimx64 edk2-ovmf grub2-efi-x64; do
        VER=$(rpm -q "$pkg" 2>/dev/null || true)
        if [[ "$VER" != *"not installed"* && -n "$VER" ]]; then
            info "${pkg}: ${VER}"
        fi
    done

    # Minimum required shim version for RHEL 9 is shim-x64-15.8-* (has 2023 cert dual-signed)
    SHIM_VER=$(rpm -q --queryformat '%{VERSION}-%{RELEASE}' shim-x64 2>/dev/null || \
               rpm -q --queryformat '%{VERSION}-%{RELEASE}' shim     2>/dev/null || echo "")
    if [[ -n "$SHIM_VER" ]]; then
        SHIM_MAJOR=$(echo "$SHIM_VER" | cut -d. -f1)
        SHIM_MINOR=$(echo "$SHIM_VER" | cut -d. -f2 | cut -d- -f1)
        if [[ "$SHIM_MAJOR" -gt 15 ]] || { [[ "$SHIM_MAJOR" -eq 15 ]] && [[ "$SHIM_MINOR" -ge 8 ]]; }; then
            ok "shim version ${SHIM_VER} >= 15.8 (includes dual-signed 2023 support)."
        else
            issue "shim version ${SHIM_VER} < 15.8 – update required to get 2023 certificate support."
            info "Run: dnf update shim shim-x64"
        fi
    fi

    # edk2-ovmf minimum versions
    EDK2_VER=$(rpm -q --queryformat '%{VERSION}-%{RELEASE}' edk2-ovmf 2>/dev/null || echo "")
    if [[ -n "$EDK2_VER" ]]; then
        info "edk2-ovmf: ${EDK2_VER}"
        # RHEL 9 minimum: 20231122-6.el9; RHEL 10 minimum: 20241117-2.el10
        # Source: https://developers.redhat.com/articles/2026/02/04/secure-boot-certificate-changes-2026-guidance-rhel-environments
        # RHEL 8: edk2-ovmf update is "Not applicable" per Red Hat
        case "$OS_ID" in
            rhel|centos|centos-stream|almalinux|rocky)
                if [[ "$OS_VERSION" == 8* ]]; then
                    info "edk2-ovmf update not required for RHEL/CentOS 8 (per Red Hat guidance)."
                elif [[ "$OS_VERSION" == 9* ]]; then
                    info "Recommended minimum for RHEL/CentOS 9: edk2-ovmf-20231122-6.el9"
                    info "New dual-signed shim available starting with RHEL 9.7 (released 2026-03-25)."
                elif [[ "$OS_VERSION" == 10* ]]; then
                    info "Recommended minimum for RHEL/CentOS 10: edk2-ovmf-20241117-2.el10"
                fi
                ;;
        esac
    fi

elif command -v dpkg &>/dev/null; then
    for pkg in shim shim-signed grub-efi-amd64-signed ovmf; do
        VER=$(dpkg -l "$pkg" 2>/dev/null | awk '/^ii/{print $3}' || true)
        if [[ -n "$VER" ]]; then
            info "${pkg}: ${VER}"
        fi
    done

    # shim-signed version gate: upstream shim version embedded after '+' (e.g. 1.58+15.8-0ubuntu1)
    SHIM_SIGNED_VER=$(dpkg -l shim-signed 2>/dev/null | awk '/^ii/{print $3}')
    if [[ -n "$SHIM_SIGNED_VER" && "$SHIM_SIGNED_VER" == *"+"* ]]; then
        UPSTREAM=$(echo "$SHIM_SIGNED_VER" | cut -d'+' -f2 | cut -d'-' -f1)
        SHIM_MAJOR=$(echo "$UPSTREAM" | cut -d. -f1)
        SHIM_MINOR=$(echo "$UPSTREAM" | cut -d. -f2)
        if [[ "$SHIM_MAJOR" -gt 15 ]] || { [[ "$SHIM_MAJOR" -eq 15 ]] && [[ "$SHIM_MINOR" -ge 8 ]]; }; then
            ok "shim-signed ${SHIM_SIGNED_VER} (upstream shim ${UPSTREAM}) >= 15.8 – includes 2023 cert support."
        else
            issue "shim-signed ${SHIM_SIGNED_VER} (upstream shim ${UPSTREAM}) < 15.8 – update required."
            info "Run: apt-get install --only-upgrade shim shim-signed"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 6. fwupd / LVFS firmware update check
# ---------------------------------------------------------------------------
section "Firmware Update (fwupd/LVFS)"

if command -v fwupdmgr &>/dev/null; then
    info "fwupd is available."
    FWUPD_DEVS=$(fwupdmgr get-devices 2>/dev/null | grep -c "DeviceId" 2>/dev/null || true)
    FWUPD_DEVS="${FWUPD_DEVS:-0}"
    info "Managed devices: ${FWUPD_DEVS}"
    info "To check for firmware updates: fwupdmgr update"
else
    info "fwupd not installed. For physical hosts, firmware updates via LVFS are recommended."
    info "Install: dnf install fwupd  or  apt install fwupd"
fi

# ---------------------------------------------------------------------------
# 7. VMware-specific checks
# ---------------------------------------------------------------------------
if [[ "$HYPERVISOR" == "vmware" ]]; then
    section "VMware / ESXi Specifics"
    info "This VM runs on VMware/ESXi."
    info "Key facts:"
    info "  - VMs continue to boot after certificate expiry."
    info "  - Boot is disrupted only if Microsoft revokes 2011 certs via a dbx update."
    info "  - An expired KEK prevents UEFI db/dbx updates inside the VM."
    info "  - ESXi 7.x is End of Support – only manual updates possible."
    info "  - ESXi 8.x needs a host patch for automatic PK initialisation."
    info "  - ESXi 9.x already ships correct PK for new VMs (HW version >= 14)."

    if command -v vmware-toolsd &>/dev/null; then
        TOOLS_VER=$(vmware-toolsd --version 2>/dev/null | head -1 || echo "unknown")
        info "VMware Tools: ${TOOLS_VER}"
    fi

    # Hardware version via DMI (no root needed)
    HW_VER=$(cat /sys/class/dmi/id/product_version 2>/dev/null || echo "")
    if [[ -n "$HW_VER" ]]; then
        info "VM hardware version (DMI): ${HW_VER}"
    fi

    # Platform Key check – VMW.NULLPK means PK was never initialised (critical)
    if command -v mokutil &>/dev/null; then
        PK_OUT=$(mokutil --pk 2>/dev/null || echo "")
        if echo "$PK_OUT" | grep -q "NULLPK"; then
            issue "Platform Key is VMW.NULLPK – PK was never initialised. Contact your VMware admin to update the vUEFI firmware."
        elif echo "$PK_OUT" | grep -qiE "Windows OEM Devices PK|Microsoft"; then
            ok "Platform Key looks correctly set (not VMW.NULLPK)."
        elif [[ -n "$PK_OUT" ]]; then
            info "Platform Key present (content not recognised – manual review recommended)."
        else
            warning "Platform Key is empty or unreadable."
        fi
    fi

    warning "Verify with your VMware/ESXi administrator that the vUEFI firmware is updated."
    info "See: https://knowledge.broadcom.com/external/article/423893/"
fi

# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
section "Summary"

if [[ "$ISSUES" -gt 0 ]]; then
    echo -e "\n${RED}${BOLD}RESULT: AFFECTED – ${ISSUES} issue(s) found, ${WARNINGS} warning(s).${RESET}"
    echo ""
    if command -v apt-get &>/dev/null; then
        echo "  Required actions (Debian/Ubuntu):"
        echo "    apt-get update && apt-get install --only-upgrade shim shim-signed"
        echo "    apt-get install --only-upgrade grub-efi-amd64-signed ovmf"
    fi
    if command -v dnf &>/dev/null; then
        echo "  Required actions (RHEL/CentOS 8+/Fedora/AlmaLinux/Rocky):"
        echo "    dnf update shim shim-x64 grub2-efi-x64 grub2-efi-x64-modules edk2-ovmf"
    fi
    if command -v yum &>/dev/null && ! command -v dnf &>/dev/null; then
        echo "  Required actions (CentOS 7 / RHEL 7):"
        echo "    yum update shim shim-x64 grub2-efi-x64 edk2-ovmf"
    fi
    if ! command -v apt-get &>/dev/null && ! command -v dnf &>/dev/null && ! command -v yum &>/dev/null; then
        echo "  Required actions: update shim, grub and edk2/ovmf via your package manager."
    fi
    echo "  Reboot to load the new shim into EFI."
    if [[ "$HYPERVISOR" == "gcp" ]]; then
        echo "  4. GCP: recreate instance from a machine image if firmware is outdated."
        echo "          gcloud compute instances create ... --shielded-secure-boot"
    fi
elif [[ "$WARNINGS" -gt 0 ]]; then
    echo -e "\n${YELLOW}${BOLD}RESULT: POSSIBLY AFFECTED – 0 critical issues, ${WARNINGS} warning(s).${RESET}"
    echo "  Review warnings above. Manual verification recommended."
else
    if ! $SB_ENABLED; then
        echo -e "\n${GREEN}${BOLD}RESULT: NOT AFFECTED – Secure Boot is disabled on this system.${RESET}"
    else
        echo -e "\n${GREEN}${BOLD}RESULT: NOT AFFECTED – All checks passed.${RESET}"
    fi
fi

