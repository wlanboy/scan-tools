# Linux-Kernel: Use-after-free im IPv4-TCP-Handshake (CVE-2026-98432)

Stand: 30.10.2026

The Hacker News berichtet über diese Lücke unter dem Titel "Linux Kernel TCP Flaw with 9.8 CVSS". Weil Anthropics Exploit einen Server mit MPTCP-Listener angreift, liegt die Beschreibung hier unter `mptcp/`. Der Fehler selbst steckt aber im normalen IPv4-TCP-Code, nicht in MPTCP.

## Worum es geht

Beim TCP-Handshake übergibt der Kernel die IP-Optionen der Verbindungsanfrage (`ireq->ireq_opt`) an den neuen Socket, ohne sie zu kopieren (`tcp_v4_syn_recv_sock()`). Verarbeitet eine andere CPU gleichzeitig ein wiederholtes SYN für dieselbe Anfrage, baut sie daraus ein SYNACK. Wird der neue Socket in diesem Moment freigegeben, liest `ip_options_build()` freigegebenen Speicher (Use-after-free). Eine ähnliche Race gibt es bei der Migration von Request-Sockets, wenn `net.ipv4.tcp_migrate_req=1` gesetzt ist oder ein BPF-Programm vom Typ `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` läuft.

- Eingeführt mit Commit `079096f103fa` ("tcp/dccp: install syn_recv requests into ehash table", Eric Dumazet, 02.10.2015) in Linux 4.4. Seitdem verarbeitet der Kernel Request-Sockets ohne Listener-Lock.
- Der Fix gibt die Optionen erst nach einer RCU-Grace-Period frei (`kfree_rcu()` in `inet_sock_destruct()` und `tcp_v4_reqsk_destructor()`). Upstream-Commit `e3f33b0a1d89`, laut The Hacker News vom 05.10.2026.
- IPv6 ist vom Hauptfehler nicht betroffen, weil `tcp_v6_syn_recv_sock()` die Optionen kopiert. Das Migrationsproblem gibt es dort ebenfalls, aber nur mit CALIPSO-Optionen. Das soll ein eigener Patch beheben.
- Ausgelöst wird der Fehler laut Kernel-CVE-Team mit einem SYN, das die IPv4-Optionen Record Route oder Timestamp trägt, und einem wiederholten SYN, um die Race zu gewinnen. Ohne IP-Optionen im SYN gibt es keine Optionen, die freigegeben werden könnten.
- Mögliche Folgen: Kernel-Speicher geht an den Angreifer zurück, Kernel-Speicher wird überschrieben, das System stürzt ab.
- Gefunden hat die Lücke laut The Hacker News Xinyang Ge von Anthropic.

### Bewertung

| Quelle | CVSS 3.1 | Vektor bzw. Einstufung |
| --- | --- | --- |
| Kernel-CVE-Team (CNA), NVD, Ubuntu | 9.8 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Red Hat (VEX, Version 3 vom 30.10.) | 8.1 | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`, Important |
| Oracle, SUSE (laut The Hacker News) | 8.1 | wie Red Hat |
| Amazon (laut The Hacker News) | 7.0 | |

Der einzige Unterschied zwischen 9.8 und 8.1 ist die Angriffskomplexität. Das Kernel-CVE-Team setzt sie auf niedrig, weil der Angreifer beide Seiten der Race selbst auslöst. Red Hat setzt sie auf hoch und erwartet vor allem Abstürze, Speicherkorruption hält Red Hat nur für theoretisch möglich.

### Ausnutzung

- Anthropic hat einen Exploit gebaut, der ohne Login und ohne Zutun eines Nutzers Root-Rechte auf einem Linux-Server mit MPTCP-Listener erreicht. Stufe 1 nutzt die Race, damit der Kernel zusätzliche Bytes an den Angreifer schickt. Enthält eine Antwort einen Kernel-Pointer, ist KASLR ausgehebelt. Stufe 2 nutzt denselben Fehler für einen Buffer-Overflow, überschreibt einen Callback-Pointer und springt in eine vorher im Kernel abgelegte Payload, die einen Shell-Befehl als root ausführt.
- Dauer im Test: 48 Minuten bis zum Kernel-Pointer, weitere 5 Minuten bis zur Codeausführung. Eine verlorene Race lässt nur den Handshake scheitern, der Angreifer kann also beliebig oft wiederholen.
- Exploit-Code, Kernel-Version und Testkonfiguration hat Anthropic nicht veröffentlicht. Warum der MPTCP-Listener nötig ist und ob Server ohne MPTCP genauso angreifbar sind, sagt der Beitrag nicht.
- Aktive Angriffe sind nicht bekannt. CISA führt die Lücke nicht im KEV-Katalog (Version 2026.10.29). Der EPSS-Wert liegt am 29.10. bei 0,39 % (Perzentil 32,8).

## Welche Kernel betroffen sind

Betroffen ist jeder Kernel ab 4.4 ohne den Fix. Gefixt sind diese stabilen Versionen:

| Serie | Gefixt in |
| --- | --- |
| 5.10 | 5.10.272 |
| 5.15 | 5.15.223 |
| 6.1 | 6.1.190 |
| 6.6 | 6.6.159 |
| 6.12 | 6.12.113 |
| 6.18 | 6.18.56 |
| 7.2 | 7.2.10 |
| 7.3 | 7.3 |

Kernel vor 4.4 (z. B. 3.10, 3.13, 4.1) enthalten den verursachenden Commit nicht. Distributionskernel mit vielen Backports können davon abweichen, deshalb zählt bei Debian, Ubuntu und Red Hat die Aussage des Herstellers, nicht die Versionsnummer.

## Debian

| Release | Kernel | Status |
| --- | --- | --- |
| 14 forky / sid | 7.2 | gefixt ab `linux` 7.2.10-1 |
| 13 trixie | 6.12 | gefixt in `linux` 6.12.113-1 (DSA-6568-1) |
| 12 bookworm | 6.1 | gefixt in `linux` 6.1.190-1 (DLA-4841-1) |
| 12 bookworm, `linux-6.12` | 6.12 | gefixt in `linux-6.12` 6.12.113-1~deb12u1 (DLA-4850-1) |
| 11 bullseye | 5.10 | kein Eintrag im Security-Tracker |
| 10 buster und älter | 4.19 | kein Eintrag, Support beendet |

Debian 11 bullseye fehlt im Tracker, weil Debian LTS dafür am 31.08.2026 geendet hat. Der Kernel 5.10 liegt im betroffenen Bereich, einen Fix von Debian gibt es nicht mehr. Wer Freexians ELTS nutzt, muss dort nachsehen. Dasselbe gilt für buster mit 4.19.

Die gefixten Pakete in bookworm und trixie liegen bisher nur in `*-security`. Der Point-Release-Stand (`6.1.176-1`, `6.12.107-1`) ist noch verwundbar.

## Ubuntu

Ubuntu stuft die Lücke als High ein (CVSS 9.8). Gefixte Kernel gibt es am 29.10. noch für kein Release.

| Release | Kernel | Status `linux` |
| --- | --- | --- |
| 26.10 stonking | 7.3 | in Arbeit (7.3.0-10.10) |
| 26.04 LTS resolute | 7.0 | in Arbeit (7.0.0-43.43) |
| 24.04 LTS noble | 6.8 | in Arbeit (6.8.0-149.149) |
| 22.04 LTS jammy | 5.15 | in Arbeit (5.15.0-203.213) |
| 20.04 LTS focal (ESM) | 5.4 | verwundbar, kein Fix |
| 18.04 LTS bionic (ESM) | 4.15 | verwundbar, kein Fix |
| 16.04 LTS xenial (ESM) | 4.4 | verwundbar, kein Fix |
| 14.04 LTS trusty | 3.13 | nicht betroffen |

Die Cloud-Kernel (`linux-aws`, `linux-azure`, `linux-gcp`, `linux-oracle`), FIPS-, Realtime-, Lowlatency- und HWE-Kernel haben eigene Zeilen. In 22.04 bis 26.10 sind die meisten in Arbeit, einzelne wie `linux-gcp` in 24.04, `linux-hwe-6.17` und `linux-hwe-7.0` in 24.04 oder `linux-nvidia` noch als verwundbar ohne Fix geführt. Den genauen Stand pro Paket zeigt die [Ubuntu-CVE-Seite](https://ubuntu.com/security/CVE-2026-98432).

## Red Hat

Red Hat stuft die Lücke als Important ein (CVSS 8.1). Stand VEX-Datei Version 3 vom 30.10.2026:

| Produkt | Status |
| --- | --- |
| RHEL 10 | betroffen, kein Fix |
| RHEL 9 | betroffen, kein Fix |
| RHEL 8 | betroffen, kein Fix |
| RHEL 7 | nicht betroffen (`vulnerable_code_not_present`) |
| RHEL 6 | nicht betroffen (`vulnerable_code_not_present`) |
| OpenShift 4 (RHCOS 8 und 9) | betroffen |
| OpenShift 5 (RHCOS 9) | betroffen |

Betroffen sind jeweils alle Kernel-Varianten, auch `kernel-rt` und `kernel-64k`. Eine Mitigation nennt Red Hat nicht: Keine verfügbare Option erfülle die Kriterien einfache Umsetzung, breite Anwendbarkeit und Stabilität.

## CentOS

CentOS hat keine eigenen Advisories. Die Kernel kommen aus den RHEL-Quellen, deshalb gilt die Red-Hat-Bewertung des passenden RHEL-Release.

### CentOS Linux 7.9.2009

Nach Red Hats Aussage nicht betroffen, solange der Standard-Kernel läuft.

- CentOS 7.9.2009 läuft mit `kernel-3.10.0-1160.*.el7` (Basis-Build mit RHEL 7.9 vom 29.09.2020, auf Grundlage von Linux 3.10 aus 2013). Das ist derselbe Kernel wie in RHEL 7, und Red Hat führt RHEL 7 mit `vulnerable_code_not_present`.
- Der verursachende Commit kam erst mit Linux 4.4. Nach meiner Einschätzung hat Red Hat den Umbau auf Request-Sockets ohne Listener-Lock nie in den 3.10-Kernel zurückportiert, das passt zu "Code nicht vorhanden". Eine Begründung nennt Red Hat nicht.
- MPTCP gibt es im RHEL-7-Kernel nicht. Upstream ist es seit Linux 5.6 enthalten, in RHEL erst ab 8.3.
- Wichtige Ausnahme: Läuft auf CentOS 7 ein fremder Kernel, gilt diese Aussage nicht. Das betrifft vor allem `kernel-lt` und `kernel-ml` von ELRepo, selbst gebaute Kernel und Kernel von Hosting-Anbietern. Liegt dessen Version bei 4.4 oder höher und ohne Fix, ist das System betroffen.
- CentOS Linux 7 ist seit 30.06.2024 End of Life. Für die Lücke spielt das keine Rolle, für alle anderen Kernel-Lücken seitdem schon.

### CentOS Linux 8

Betroffen. Der Kernel 4.18 entspricht RHEL 8, und RHEL 8 ist betroffen. CentOS Linux 8 ist seit 31.12.2021 End of Life, einen Fix wird es nicht geben.

### CentOS Stream 9 und 10

Betroffen, bis ein Kernel mit dem Fix erscheint. Stream ist der Entwicklungszweig von RHEL 9 und 10, eine eigene Bewertung gibt es nicht. Ob der installierte Kernel den Fix enthält, zeigt das Changelog (siehe unten).

## Andere Distributionen (kurz)

Laut The Hacker News und den jeweiligen CVE-Seiten am 29.10.:

- Oracle Linux 7 bis 10 mit UEK: gefixt am 16.10. (ELSA-2026-500397, -500398, -500399).
- Amazon Linux 2023: gefixt für `kernel6.18` (ALAS2023-2026-3251) und `kernel6.12` (ALAS2023-2026-3335). `kernel` in AL2023 und Amazon Linux 2 noch offen.
- SUSE: gefixt in SUSE Linux Micro 6.2 und openSUSE Leap 16.0. SLES 15 SP4 bis SP7, SLES 16.0 und SLE Micro 5.3 bis 5.5 noch offen.

## Selbst prüfen

```bash
# Laufender Kernel
uname -r

# Ist MPTCP aktiv, gibt es MPTCP-Listener?
sysctl net.mptcp.enabled
ss -Mltn

# Request-Socket-Migration (Standard: 0)
sysctl net.ipv4.tcp_migrate_req

# Debian/Ubuntu: installierte Kernel-Pakete
dpkg -l 'linux-image-*' | grep '^ii'

# RHEL, CentOS Stream, Oracle Linux: steht der Fix im Changelog?
rpm -q --changelog kernel-core | grep -i 'free inet_opt and ireq_opt'
```

Nach dem Kernel-Update muss das System neu starten. Erst wenn `uname -r` die neue Version zeigt, ist der Fix aktiv.

## Was tun

1. Gefixten Kernel einspielen und neu starten, wo es ihn gibt: Debian bookworm, trixie, forky und sid, Oracle Linux, Teile von Amazon Linux und SUSE.
2. Wer selbst Kernel baut: auf eine der gefixten Stable-Versionen aus der Tabelle oben gehen. Das Kernel-CVE-Team rät davon ab, nur den einzelnen Commit zu übernehmen.
3. Für Ubuntu, RHEL 8 bis 10, CentOS Stream und OpenShift gibt es noch keinen Fix. Bis dahin helfen die folgenden Maßnahmen. Sie stammen von mir, kein Hersteller und kein Advisory empfiehlt sie.

### Eingehende IPv4-Pakete mit IP-Optionen verwerfen

Der Fehler braucht ein SYN mit IPv4-Optionen (Record Route, Timestamp). Normaler Verkehr nutzt keine IP-Optionen, viele Router verwerfen solche Pakete ohnehin. Ein IPv4-Header ohne Optionen hat die Länge 5 (in 32-Bit-Worten), alles darüber enthält Optionen.

```bash
# nftables
nft add rule inet filter input ip hdrlength != 5 drop

# iptables: IHL (untere 4 Bit des ersten Bytes) zwischen 6 und 15
iptables -I INPUT -m u32 --u32 "0>>24&0xF=6:15" -j DROP
```

Die Regel muss vor der ersten Regel stehen, die bestehende oder erlaubte Verbindungen annimmt. Auf Hosts, die Pakete weiterleiten (Kubernetes-Nodes, Router), gehört sie zusätzlich in die `forward`-Chain bzw. `FORWARD`. Gegen das Migrationsproblem hilft die Regel nur bedingt, das ist aber nur bei `tcp_migrate_req=1` oder einem passenden BPF-Programm relevant.

### MPTCP abschalten, wo es nicht gebraucht wird

```bash
sysctl -w net.mptcp.enabled=0
echo 'net.mptcp.enabled = 0' > /etc/sysctl.d/90-disable-mptcp.conf
```

Danach legt der Kernel keine neuen MPTCP-Sockets mehr an, Anwendungen fallen auf normales TCP zurück. Das nimmt Anthropics gezeigten Angriffsweg weg, behebt aber nicht den Fehler im IPv4-TCP-Code. Ob Server ohne MPTCP genauso angreifbar sind, ist offen.

### `tcp_migrate_req` auf 0 lassen

Der Standard ist 0. Wer es auf 1 gesetzt hat, sollte es bis zum Kernel-Update zurücksetzen.

## Quellen

- [The Hacker News: Linux Kernel TCP Flaw with 9.8 CVSS](https://thehackernews.com/2026/10/linux-kernel-tcp-flaw-with-98-cvss.html)
- [Kernel-CVE-Team: CVE-2026-98432 (mbox)](https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/2026/CVE-2026-98432.mbox)
- [Kernel-Fix e3f33b0a1d89](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e3f33b0a1d89d738e2b913dab519226eaf76e15b)
- [CVE.org: CVE-2026-98432](https://www.cve.org/CVERecord?id=CVE-2026-98432)
- [NVD: CVE-2026-98432](https://nvd.nist.gov/vuln/detail/CVE-2026-98432)
- [Anthropic: Discovering vulnerabilities with Claude](https://www.anthropic.com/research/discovering-vulnerabilities-with-claude)
- [Debian Security Tracker: CVE-2026-98432](https://security-tracker.debian.org/tracker/CVE-2026-98432)
- [DSA-6568-1 (linux, trixie)](https://lists.debian.org/debian-security-announce/2026/msg00482.html)
- [DLA-4841-1 (linux, bookworm)](https://lists.debian.org/debian-lts-announce/2026/10/msg00035.html)
- [DLA-4850-1 (linux-6.12, bookworm)](https://lists.debian.org/debian-lts-announce/2026/10/msg00044.html)
- [Ubuntu: CVE-2026-98432](https://ubuntu.com/security/CVE-2026-98432)
- [Red Hat: CVE-2026-98432](https://access.redhat.com/security/cve/cve-2026-98432)
- [Red Hat VEX: cve-2026-98432.json](https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-98432.json)
- [Red Hat Bugzilla 2553390](https://bugzilla.redhat.com/show_bug.cgi?id=2553390)
- [Oracle Linux: CVE-2026-98432](https://linux.oracle.com/cve/CVE-2026-98432.html)
- [Amazon Linux Security Center: CVE-2026-98432](https://explore.alas.aws.amazon.com/CVE-2026-98432.html)
- [SUSE: CVE-2026-98432](https://www.suse.com/security/cve/CVE-2026-98432.html)
- [FIRST EPSS API: CVE-2026-98432](https://api.first.org/data/v1/epss?cve=CVE-2026-98432)
- [CISA KEV-Katalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Kernel-Dokumentation: MPTCP](https://docs.kernel.org/networking/mptcp.html)
