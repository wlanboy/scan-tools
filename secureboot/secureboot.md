# Secure Boot: Ablauf der Microsoft-Zertifikate von 2011

Stand: 25.10.2026

## Worum es geht

Secure Boot startet nur Bootloader, deren Signatur zu einem Zertifikat in der UEFI-Datenbank `db` passt. Auf fast allen x86-Servern und VMs stammen diese Zertifikate von Microsoft, auch bei Linux, denn der erste Bootloader `shim` ist von Microsoft signiert. Die drei Zertifikate aus dem Jahr 2011 sind 2026 abgelaufen:

| Zertifikat | Zweck | Abgelaufen | Nachfolger |
|---|---|---|---|
| Microsoft Corporation KEK CA 2011 | signiert Updates von `db` und der Sperrliste `dbx` | 24.06.2026 | Microsoft Corporation KEK 2K CA 2023 |
| Microsoft Corporation UEFI CA 2011 | signiert Linux-`shim` und andere Drittanbieter-Bootloader | 27.06.2026 | Microsoft UEFI CA 2023 |
| Microsoft Windows Production PCA 2011 | signiert den Windows-Bootmanager | 19.10.2026 | Windows UEFI CA 2023 |

## Warum das ein Sicherheitsproblem ist

Die Firmware prüft beim Start keine Ablaufdaten. Bestehende Systeme booten also weiter, und genau deshalb fällt das Problem nicht auf:

- **Verwundbare Bootloader lassen sich nicht mehr sperren.** Gegen alte, verwundbare Bootloader hilft nur ein Eintrag in `dbx`. So wird zum Beispiel das Bootkit BlackLotus (CVE-2023-24932) blockiert. Updates von `dbx` müssen mit der KEK signiert sein. Fehlt die KEK von 2023, kommen neue Sperren nicht mehr an, und ein Angreifer mit Admin-Rechten kann einen alten, signierten Bootloader einspielen und Secure Boot aushebeln.
- **Updates können den Boot brechen.** Neue `shim`-Versionen werden mit der 2023-CA signiert. Fehlt diese CA in `db`, startet das System nach dem Update nicht mehr.
- **Der Widerruf kommt.** Sobald die 2011-Zertifikate per `dbx` gesperrt werden, starten nur noch Bootloader mit 2023-Signatur.

Betroffen sind nur Systeme mit eingeschaltetem Secure Boot.

## Prüfen und beheben

Die Skripte in diesem Ordner prüfen Secure-Boot-Status, `db`, `KEK`, die Signatur von `shim`, die Paketversionen und auf VMware den Platform Key. Am Ende steht `AFFECTED`, `POSSIBLY AFFECTED` oder `NOT AFFECTED`, zusammen mit den passenden Update-Befehlen.

```bash
sudo bash secureboot/check-secureboot-expiry.sh
sudo python3 secureboot/check_secureboot_expiry.py
```

Kurz von Hand: Steht in `mokutil --db` nur `UEFI CA 2011` und keine `UEFI CA 2023`, ist das System betroffen.

Behoben wird das mit diesen Schritten:

- **Linux:** `shim` (mindestens 15.8), `grub` und bei VMs `edk2-ovmf`/`ovmf` aktualisieren und neu starten.
- **Physische Server:** Firmware-Update vom Hersteller oder per `fwupdmgr update`.
- **VMware:** Ist der Platform Key `VMW.NULLPK`, muss der Admin die vUEFI-Firmware aktualisieren. ESXi 8.x braucht dafür einen Host-Patch.
- **Google Cloud:** Instanzen, die vor dem 07.11.2025 angelegt wurden, aus einem Machine Image neu anlegen.

## Quellen

- [Red Hat: Secure Boot certificate changes in 2026](https://access.redhat.com/articles/7128933)
- [Red Hat Developers: Guidance for RHEL environments](https://developers.redhat.com/articles/2026/02/04/secure-boot-certificate-changes-2026-guidance-rhel-environments)
- [Broadcom KB 423893: Secure Boot certificate expiry on VMware](https://knowledge.broadcom.com/external/article/423893/)
