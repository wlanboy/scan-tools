# Bouncy Castle Java: Name-Constraints-Bypass per Punkt am Ende (CVE-2026-8763)

Stand: 31.10.2026

## Worum es geht

Eine Zwischen-CA kann über die Zertifikatserweiterung Name Constraints eingeschränkt werden. Eine Partner-CA darf dann zum Beispiel nur Zertifikate für `partner.example` ausstellen, aber keine für `bank.com`. Der Validator prüft beim Aufbau des Zertifikatspfads, ob die Namen im Endzertifikat in diesen Grenzen liegen.

In Bouncy Castle macht das `PKIXNameConstraintValidator`. Für DNS-Namen (`dNSName`) entfernt die Klasse einen Punkt am Ende, bevor sie vergleicht. `bank.com.` ist laut RFC 1034 derselbe Name wie `bank.com`. Für E-Mail-Adressen (`rfc822Name`) leider nicht, dort ist ein einfaches `equalsIgnoreCase` auf den Host.

Ein Zertifikat mit der SAN-E-Mail `ceo@bank.com.` passt deshalb nicht auf einen ausgeschlossenen Teilbaum `bank.com`. `checkExcludedEmail` wirft keine Exception, der Pfad gilt als gültig. Dasselbe gilt für einen URI wie `https://competitor.example./`. Erreichbar ist der Fehler laut Hersteller über `PKIXCertPathValidatorSpi_8` und `RFC3280CertPathUtilities.processCertBC`, also über die normale PKIX-Pfadvalidierung des BC-Providers.

- Wer den Fehler ausnutzen will, muss eine eingeschränkte Zwischen-CA kontrollieren oder sie dazu bringen, ein passendes Zertifikat auszustellen. Ohne so eine CA im Vertrauenspfad ist man save.
- Fix: Commit [`2c28b253a446`](https://github.com/bcgit/bc-java/commit/2c28b253a44681fbbc562561eab6ad383d2ae558) "Fix directoryName-prefix and email/URI trailing-dot name-constraint bypasses". Eine neue Methode `stripTrailingDot` normalisiert Mailbox, Host und Constraint, bevor verglichen wird.
- Derselbe Commit schließt eine zweite Lücke bei `directoryName`. Der alte Code suchte das erste RDN der Constraint an beliebiger Stelle im Subject-DN. Ein Angreifer konnte also RDNs davorsetzen und lag trotzdem "innerhalb" der Constraint. Jetzt muss der Vergleich bei Index 0 beginnen. Das lockere Verhalten, das GSMA SGP.22 (eSIM) braucht, gibt es nur noch über `Properties.X509_SGP22_NAME_CONSTRAINTS`. Eine eigene CVE-Nummer hat dieser Teil nicht, die CVE-Liste zu 1.85 führt ihn nicht auf.
- CWE-295, Improper Certificate Validation.

### Bewertung

| Quelle | Score | Vektor bzw. Einstufung |
| --- | --- | --- |
| Bouncy Castle (CNA), GHSA | CVSS 4.0: 9.3 | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/U:Amber`, Critical |
| NVD (Analyzed, 02.09.2026), Ubuntu | CVSS 3.1: 9.1 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`, Critical |
| Red Hat (vorläufig) | CVSS 3.1: 7.4 | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`, Important |
| Ubuntu (Priorität) | | Medium |
| CISA ADP (SSVC) | | Exploitation: none, Automatable: yes, Technical Impact: total |

Bewertungen wischen 9.1 und 7.4 sind seltsam. Ich halte Red Hats AC:H für realistischer. Der Angreifer braucht eine eingeschränkte CA, der das Opfer vertraut, und das ist eine echte Hürde. Ubuntu sieht es ähnlich und setzt die eigene Priorität trotz 9.1 auf Medium.

### Ausnutzung

- Öffentliche Exploits oder aktive Angriffe sind nicht bekannt. CISA führt die Lücke nicht im KEV-Katalog (Version 2026.10.30).
- EPSS am 30.10.2026: 0,43 % (Perzentil 37,3).

## Einordnung

Die Lücke ist nur dann ein Problem, wenn alle drei Bedingungen zutreffen:

1. **Bouncy Castle validiert den Pfad.** Das ist der Fall bei `CertPathValidator.getInstance("PKIX", "BC")`, wenn der BC-Provider per `Security.insertProviderAt(new BouncyCastleProvider(), 1)` an erster Stelle steht, oder bei der Pfad-API in `bcpkix` (`org.bouncycastle.cert.path`). Liegt `bcprov` nur auf dem Classpath und der Provider ist mit `Security.addProvider(...)` hinten angehängt, liefert `CertPathValidator.getInstance("PKIX")` den Validator des JDK. Der ist nicht Gegenstand dieser CVE.
2. **Im Vertrauenspfad hängt eine CA mit Name Constraints.** Typisch sind Partner- oder Abteilungs-CAs in Firmen-PKIs und "technically constrained" Sub-CAs. In einer reinen Public-WebPKI-Konfiguration ohne solche CAs gibt es keine Constraint, die man umgehen könnte.
3. **Die Anwendung verlässt sich auf E-Mail- oder URI-SANs.** Beispiele sind S/MIME, mTLS mit Zuordnung der E-Mail-SAN zu einem Benutzer und URI-basierte Identitäten wie SPIFFE-IDs (`spiffe://trust-domain/...`). TLS-Hostnamen stehen im `dNSName`, und diesen Pfad hat Bouncy Castle schon vorher korrekt behandelt.

Dazu kommt ein Punkt, den das Advisory nicht anspricht. Das gefälschte Zertifikat trägt `ceo@bank.com.` mit Punkt. Schaden entsteht erst, wenn die Anwendung danach diesen Namen mit `ceo@bank.com` gleichsetzt, etwa beim Benutzer-Mapping. Vergleicht sie exakt, passt der Name auf keinen echten Benutzer. Das senkt das Risiko in vielen Setups, ich würde mich aber nicht darauf verlassen.

Für die meisten Spring-Boot-Dienste, die Bouncy Castle nur transitiv mitbringen (JWT, PDF, Keycloak-Adapter usw.) und die Standard-Truststores des JDK nutzen, ist der konkrete Angriffsweg also schwer zu erreichen. Release 1.85 behebt 32 CVEs, darunter drei weitere mit 9.3: OCSP-Stapling ohne Bindung an das geprüfte Zertifikat (CVE-2026-58062), CN-Fallback im JSSE-Hostname-Verifier standardmäßig aktiv (CVE-2026-59638) und MTI/A0-DH ohne Prüfung des Peer-Werts (CVE-2026-59650). Außerdem melden Dependency-Scanner jedes `bcprov` unter 1.85 als kritisch, egal ob der Codepfad genutzt wird.

## Betroffene Versionen und Fixes

| Linie | Maven-Artefakt | Betroffen | Gefixt in | Aktuell (Maven Central, 31.10.) |
| --- | --- | --- | --- | --- |
| BC Java | `org.bouncycastle:bcprov-jdk18on` | < 1.85 | 1.85 | 1.86 |
| BC Java (Java 5 bis 8) | `org.bouncycastle:bcprov-jdk15to18` | < 1.85 | 1.85 | 1.86 |
| BC Java (alt) | `org.bouncycastle:bcprov-jdk15on` | alle | **kein Fix** | 1.70 (Dez. 2021) |
| BC LTS | `org.bouncycastle:bcprov-lts8on` | 2.73.0 bis < 2.73.12 | 2.73.12 | 2.73.13 |
| BC FIPS 1.0 | `org.bouncycastle:bc-fips` | < 1.0.2.7 | 1.0.2.7 | |
| BC FIPS 2.0 | `org.bouncycastle:bc-fips` | 2.0.0 bis < 2.0.2 | 2.0.2 | |
| BC FIPS 2.1 | `org.bouncycastle:bc-fips` | 2.1.0 bis < 2.1.3 | 2.1.3 | 2.1.3 |

Version 1.85 ist am 28.07.2026 erschienen, die CVE wurde am 03.08.2026 veröffentlicht.

`bcprov-jdk15on` bekommt seit 1.70 keine Updates mehr. Wer es noch nutzt, direkt oder transitiv, muss auf `bcprov-jdk18on` wechseln. Die Paketnamen bleiben gleich, nur die Maven-Koordinaten ändern sich. Red Hats Bugzilla-Eintrag nennt ausdrücklich `bcprov-jdk15on` und `bcpkix-jdk15on`, dort ist das Problem also noch weit verbreitet.

Die Klasse `PKIXNameConstraintValidator` liegt in `bcprov`. `bcpkix`, `bcutil`, `bctls` und `bcpg` müssen aber dieselbe Version haben wie `bcprov`, sonst gibt es zur Laufzeit `NoSuchMethodError` und ähnliche Fehler.

## Distributionen

Die Pakete der Distributionen betreffen nur Java-Anwendungen, die die System-JARs nutzen. Maven- und Gradle-Builds bringen ihre eigene Version mit, für sie zählt die Tabelle oben.

## Selbst prüfen

```bash
# Maven: welche Bouncy-Castle-Artefakte zieht das Projekt?
mvn -q dependency:tree -Dincludes=org.bouncycastle

# Gradle
./gradlew dependencies --configuration runtimeClasspath | grep bouncycastle

# Spring-Boot-Fat-JAR oder Container-Image
unzip -l app.jar | grep -E 'bc(prov|pkix|util|tls|pg)|bc-fips'
find / \( -name 'bc*-jdk*.jar' -o -name 'bc*-lts8on*.jar' -o -name 'bc-fips-*.jar' \) 2>/dev/null

# Nutzt der Code BC für die Pfadvalidierung?
grep -rnE 'CertPathValidator\.getInstance|insertProviderAt|org\.bouncycastle\.cert\.path|PKIXNameConstraintValidator' src/

# Distributionspakete
dpkg -l 'libbcprov-java'
rpm -q bouncycastle
```

## Was tun

1. Auf `bcprov-jdk18on` 1.85 oder neuer gehen, besser gleich 1.86. Alle BC-Artefakte auf dieselbe Version ziehen. Bei transitiven Abhängigkeiten geht das am einfachsten über `dependencyManagement`:

   ```xml
   <properties>
       <bouncycastle.version>1.86</bouncycastle.version>
   </properties>

   <dependencyManagement>
       <dependencies>
           <dependency>
               <groupId>org.bouncycastle</groupId>
               <artifactId>bcprov-jdk18on</artifactId>
               <version>${bouncycastle.version}</version>
           </dependency>
           <dependency>
               <groupId>org.bouncycastle</groupId>
               <artifactId>bcpkix-jdk18on</artifactId>
               <version>${bouncycastle.version}</version>
           </dependency>
           <dependency>
               <groupId>org.bouncycastle</groupId>
               <artifactId>bcutil-jdk18on</artifactId>
               <version>${bouncycastle.version}</version>
           </dependency>
       </dependencies>
   </dependencyManagement>
   ```

2. `bcprov-jdk15on` und `bcpkix-jdk15on` ausschließen (`<exclusions>`) und durch die `jdk18on`-Varianten ersetzen. Es gibt dafür keinen Fix mehr.
3. LTS-Nutzer gehen auf `bcprov-lts8on` 2.73.12 oder neuer, FIPS-Nutzer auf `bc-fips` 1.0.2.7, 2.0.2 oder 2.1.3.
4. Wer eSIM-Profile nach GSMA SGP.22 verarbeitet und nach dem Update Validierungsfehler bekommt, braucht `Properties.X509_SGP22_NAME_CONSTRAINTS`. Grund ist der verschärfte `directoryName`-Vergleich, nicht der Punkt am Ende.
5. Bis zum Update: prüfen, ob eingeschränkte Zwischen-CAs im Truststore liegen. Wer E-Mail- oder URI-SANs auf Benutzer abbildet, sollte Namen mit einem Punkt am Ende des Hosts ablehnen. Das ist mein Vorschlag, kein Hersteller und kein Advisory empfiehlt eine Mitigation.

## Quellen

- [CVE.org: CVE-2026-8763](https://www.cve.org/CVERecord?id=CVE-2026-8763)
- [NVD: CVE-2026-8763](https://nvd.nist.gov/vuln/detail/CVE-2026-8763)
- [Bouncy Castle Wiki: CVE-2026-8763](https://github.com/bcgit/bc-java/wiki/CVE-2026-8763)
- [Bouncy Castle Wiki: CVE summary 1.85](https://github.com/bcgit/bc-java/wiki/CVE-summary-1.85)
- [Bouncy Castle: New Release Bouncy Castle Java 1.85](https://www.bouncycastle.org/resources/new-release-bouncy-castle-java-1-85/)
- [Fix-Commit 2c28b253a446](https://github.com/bcgit/bc-java/commit/2c28b253a44681fbbc562561eab6ad383d2ae558)
- [GitHub Advisory GHSA-9pwp-9qqc-pr26](https://github.com/advisories/GHSA-9pwp-9qqc-pr26)
- [Red Hat: CVE-2026-8763](https://access.redhat.com/security/cve/cve-2026-8763)
- [Red Hat Bugzilla 2510198](https://bugzilla.redhat.com/show_bug.cgi?id=2510198)
- [Debian Security Tracker: CVE-2026-8763](https://security-tracker.debian.org/tracker/CVE-2026-8763)
- [Ubuntu: CVE-2026-8763](https://ubuntu.com/security/CVE-2026-8763)
- [OSV: UBUNTU-CVE-2026-8763](https://osv.dev/vulnerability/UBUNTU-CVE-2026-8763)
- [FIRST EPSS API: CVE-2026-8763](https://api.first.org/data/v1/epss?cve=CVE-2026-8763)
- [CISA KEV-Katalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Maven Central: org.bouncycastle](https://repo1.maven.org/maven2/org/bouncycastle/)
