# Bouncy Castle Java: Name-Constraints-Bypass per Punkt am Ende (CVE-2026-8763)

Stand: 31.10.2026

## Auf einen Blick

Release 1.85 behebt 32 CVEs, vier davon mit CVSS 4.0 9.3. CVE-2026-8763 ist unten ausführlich beschrieben, die anderen drei im Abschnitt [Weitere kritische CVEs in 1.85](#weitere-kritische-cves-in-185). Die Spalte "Echtes Risiko" ist meine Einschätzung, keine Herstellerangabe.

| CVE | Fehler | Modul | NVD (CVSS 3.1) | Echtes Risiko |
| --- | --- | --- | --- | --- |
| CVE-2026-8763 | Name Constraints umgehen per Punkt am Ende bei E-Mail und URI | `bcprov` | 9.1 | gering bis mittel, nur mit eingeschränkten Zwischen-CAs |
| CVE-2026-58062 | Gestapelte OCSP-Antwort nicht an das geprüfte Zertifikat gebunden | `bcprov`, genutzt von `bctls` | 9.1 | mittel für BCJSSE-Clients mit Revocation-Checking, sonst keins |
| CVE-2026-59638 | CN-Fallback im Hostname-Check von BCJSSE standardmäßig an | `bctls` | 6.5 | gering, nur mit BCJSSE und privaten CAs im Truststore |
| CVE-2026-59650 | MTI/A0-DH prüft den Peer-Wert nicht, statischer Schlüssel leakt | `bcprov` (Lightweight-API) | 9.1 | praktisch keins, außer bei eigenem Protokoll mit `DHAgreement` |

Keine der vier steht im KEV-Katalog, öffentliche Exploits gibt es nicht. Alle vier sind gefixt in BC 1.85 und BC-LTS 2.73.12.

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

Für die meisten Spring-Boot-Dienste, die Bouncy Castle nur transitiv mitbringen (JWT, PDF, Keycloak-Adapter usw.) und die Standard-Truststores des JDK nutzen, ist der konkrete Angriffsweg also schwer zu erreichen. Das Update ist trotzdem nötig, wegen der drei anderen kritischen CVEs im nächsten Abschnitt und weil Dependency-Scanner jedes `bcprov` unter 1.85 als kritisch melden, egal ob der Codepfad genutzt wird.

## Weitere kritische CVEs in 1.85

### CVE-2026-58062: Gestapelte OCSP-Antwort ohne Bindung an das Zertifikat

Bei OCSP-Stapling schickt der TLS-Server die OCSP-Antwort zu seinem Zertifikat gleich im Handshake mit. Der Client gibt sie per `PKIXRevocationChecker.setOcspResponses()` an den Revocation-Checker weiter. `ProvOcspRevocationChecker` prüft die Signatur der Antwort und sucht dann in den `SingleResponse`-Einträgen nach der CertID des Zertifikats. Findet er keine, endet die Schleife ohne Fehler. Das Zertifikat gilt als nicht widerrufen, und einen CRL-Fallback gibt es nicht. Beim Abruf über das Netz prüft `OcspCache.isCertIDFoundAndCurrent()` diese Bindung, auf dem gestapelten Weg fehlte sie.

- Der Angreifer braucht ein widerrufenes Zertifikat samt privatem Schlüssel und irgendeine gültig signierte OCSP-Antwort derselben CA, zum Beispiel ein "good" für eine andere Seriennummer. Solche Antworten kann sich jeder beim OCSP-Responder der CA holen.
- Betroffen: BC 1.66 bis < 1.85, LTS < 2.73.12, bc-fips < 2.0.2 bzw. < 2.1.3.
- Fix: Commit [`add5f822660f`](https://github.com/bcgit/bc-java/commit/add5f822660f3b2c29fd824e2f4095469c42a1c7). Passt keine Antwort zum Zertifikat, wirft der Checker jetzt eine `RecoverableCertPathValidatorException`, und der CRL-Fallback greift.
- Bewertung: CNA 9.3 (CVSS 4.0), NVD 9.1 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`).

**Risiko: echt, aber nur für BCJSSE-Clients mit Revocation-Checking.** BCJSSE nutzt genau diesen Weg. `ProvX509TrustManager` gibt die vom Server gestapelten Antworten über `addStatusResponses` an den PKIX-Builder weiter. Revocation-Checking ist dort aber standardmäßig aus. BCJSSE liest wie SunJSSE `com.sun.net.ssl.checkRevocation` mit Default `false`. Betroffen sind also Clients, die BCJSSE als TLS-Provider nutzen und Revocation über diese Property oder eigene `PKIXBuilderParameters` einschalten. Für die ist die Lücke ernst. Widerruf ist genau dafür da, ein Zertifikat mit gestohlenem Schlüssel aus dem Verkehr zu ziehen, und genau dieses Zertifikat kommt wieder durch. Wer SunJSSE nutzt, also den JDK-Standard, oder Revocation gar nicht prüft, ist nicht betroffen. Der Angreifer braucht außerdem einen gestohlenen Schlüssel und eine Man-in-the-Middle-Position, deshalb halte ich 9.1 für zu hoch.

### CVE-2026-59638: CN-Fallback im BCJSSE-Hostname-Check standardmäßig an

Hat ein TLS-Serverzertifikat keinen `dNSName` im SAN, vergleicht `HostnameUtil` in BCJSSE den Hostnamen mit dem Common Name (CN) im Subject. Laut Javadoc sollte das nur passieren, wenn die Property `org.bouncycastle.jsse.hostname_check_cn_fallback` auf `true` steht. Der Code rief aber `Properties.isOverrideSet(..., true)` auf, und das liefert bei nicht gesetzter Property den Default `true`. Der Fallback war also überall an, wo niemand die Property ausdrücklich auf `false` gesetzt hat.

Zusammen mit Name Constraints wird daraus ein Bypass. Nach RFC 5280 prüfen Name Constraints nur SAN-Einträge des eingeschränkten Typs. Eine auf `partner.example` eingeschränkte CA stellt ein Zertifikat ohne `dNSName`-SAN mit `CN=bank.com` aus. Die Pfadvalidierung findet keinen DNS-Namen, den sie prüfen müsste, und BCJSSE akzeptiert das Zertifikat danach über den CN für `bank.com`.

- Betroffen: BC 1.61 bis < 1.85, LTS < 2.73.12, `bctls-fips` 1.0.7 bis < 1.0.24, < 2.0.24 und < 2.1.24.
- Fix: Commits `799bd15320a6` und `5ac55351cd1a`. Ohne gesetzte Property ist der Fallback jetzt aus.
- Bewertung: CNA 9.3 (CVSS 4.0), NVD 6.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`), Red Hat 7.4 (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`).

**Risiko: gering.** Die Lücke betrifft nur Anwendungen, die BCJSSE als TLS-Provider nutzen. Der Hostname-Check von SunJSSE macht denselben CN-Fallback, das steht sogar im Javadoc von Bouncy Castle ("this matches SunJSSE and historical OpenSSL behaviour"). BCJSSE war also nicht schlechter als der JDK-Standard, nur schlechter als dokumentiert. Öffentliche CAs müssen nach den CA/Browser-Forum Baseline Requirements (7.1.4.2) einen `dNSName`-SAN eintragen. Mit dem Standard-Truststore kommt ein Angreifer deshalb nur über eine CA, die falsch ausstellt. Relevant wird es bei privaten oder eingeschränkten CAs im Truststore, die man nicht voll kontrolliert. Wichtig: `HostnameUtil` liegt in `bctls`, nicht in `bcprov`. Wer nur `bcprov` aktualisiert, behält den Fehler.

### CVE-2026-59650: MTI/A0-DH prüft den Peer-Wert nicht

`DHAgreement` implementiert das Zwei-Pass-Verfahren MTI/A0. `calculateAgreement(pub, message)` potenziert den vom Gegenüber gelieferten Wert `message` mit dem eigenen statischen privaten Schlüssel x. `pub` läuft durch die Prüfung in `DHPublicKeyParameters`, `message` ist ein nackter `BigInteger` ohne Bereichs- oder Untergruppenprüfung. Ein bösartiges Gegenüber schickt Elemente kleiner Ordnung (0, 1, p−1 oder Elemente kleiner Untergruppen) und erfährt bei jedem Austausch x modulo einer kleinen Primzahl. Nach genug Austauschen setzt es x per Chinesischem Restsatz zusammen (Lim und Lee, 1997).

- Betroffen: BC < 1.85, LTS < 2.73.12. Für FIPS nennt das Advisory nichts.
- Fix: Commit [`daeaae9d7075`](https://github.com/bcgit/bc-java/commit/daeaae9d7075d04f40812e68671ebf4c777b5148).
- Nicht betroffen ist laut Hersteller `DHBasicAgreement`, das normale DH. Dessen einziger Eingabewert läuft durch die Prüfung in `DHPublicKeyParameters`.
- Bewertung: CNA 9.3 (CVSS 4.0), NVD 9.1 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`).

**Risiko: für normale Anwendungen praktisch keins.** Die Folge wäre schwer, der statische Schlüssel ist komplett weg. Aber MTI/A0 ist ein Nischenverfahren aus der Lightweight-API (`org.bouncycastle.crypto.agreement.DHAgreement`). TLS, SSH und die JCA-Klasse `KeyAgreement` nutzen es nach dem Advisory nicht, das Advisory nennt nur diese eine Klasse. Betroffen ist nur Code, der `DHAgreement` direkt in einem eigenen Protokoll mit statischem Schlüssel einsetzt. Ein `grep` im Quellcode reicht als Prüfung (siehe unten). Den NVD-Score von 9.1 halte ich für weit übertrieben.

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

Die Klasse `PKIXNameConstraintValidator` liegt in `bcprov`, ebenso `ProvOcspRevocationChecker` und `DHAgreement`. Der CN-Fallback aus CVE-2026-59638 steckt dagegen in `bctls` (`bctls-jdk18on` 1.85, `bctls-lts8on` 2.73.12, `bctls-fips` 1.0.24, 2.0.24 oder 2.1.24). `bcpkix`, `bcutil`, `bctls` und `bcpg` müssen ohnehin dieselbe Version haben wie `bcprov`, sonst gibt es zur Laufzeit `NoSuchMethodError` und ähnliche Fehler.

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

# CVE-2026-58062 und -59638: Ist BCJSSE der TLS-Provider? Ist Revocation an?
grep -rnE 'BouncyCastleJsseProvider|"BCJSSE"|checkRevocation|setRevocationEnabled|hostname_check_cn_fallback' src/
grep -E '^security\.provider\.' "$JAVA_HOME/conf/security/java.security"

# CVE-2026-59650: wird MTI/A0-DH direkt genutzt?
grep -rnw 'DHAgreement' src/

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
           <dependency>
               <groupId>org.bouncycastle</groupId>
               <artifactId>bctls-jdk18on</artifactId>
               <version>${bouncycastle.version}</version>
           </dependency>
       </dependencies>
   </dependencyManagement>
   ```

2. `bcprov-jdk15on` und `bcpkix-jdk15on` ausschließen (`<exclusions>`) und durch die `jdk18on`-Varianten ersetzen. Es gibt dafür keinen Fix mehr.
3. LTS-Nutzer gehen auf `bcprov-lts8on` 2.73.12 oder neuer, FIPS-Nutzer auf `bc-fips` 1.0.2.7, 2.0.2 oder 2.1.3.
4. Wer eSIM-Profile nach GSMA SGP.22 verarbeitet und nach dem Update Validierungsfehler bekommt, braucht `Properties.X509_SGP22_NAME_CONSTRAINTS`. Grund ist der verschärfte `directoryName`-Vergleich, nicht der Punkt am Ende.
5. Bis zum Update: prüfen, ob eingeschränkte Zwischen-CAs im Truststore liegen. Wer E-Mail- oder URI-SANs auf Benutzer abbildet, sollte Namen mit einem Punkt am Ende des Hosts ablehnen. Das ist mein Vorschlag, kein Hersteller und kein Advisory empfiehlt eine Mitigation.
6. CVE-2026-59638 lässt sich ohne Update abstellen, das nennt auch das Advisory. Mit `-Dorg.bouncycastle.jsse.hostname_check_cn_fallback=false` ist der CN-Fallback in BCJSSE aus. Zertifikate ohne `dNSName`-SAN schlagen danach fehl, interne Altzertifikate also vorher prüfen.
7. CVE-2026-58062 vor dem Update: Wer BCJSSE mit Revocation-Checking nutzt, kann für gestapelte Antworten auf SunJSSE ausweichen, bis 1.85 eingespielt ist. Abschalten von Revocation wäre schlechter, dann prüft gar nichts mehr. Das ist meine Einschätzung, das Advisory nennt keine Mitigation.

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
- [Bouncy Castle Wiki: CVE-2026-58062](https://github.com/bcgit/bc-java/wiki/CVE-2026-58062)
- [Bouncy Castle Wiki: CVE-2026-59638](https://github.com/bcgit/bc-java/wiki/CVE-2026-59638)
- [Bouncy Castle Wiki: CVE-2026-59650](https://github.com/bcgit/bc-java/wiki/CVE-2026-59650)
- [NVD: CVE-2026-58062](https://nvd.nist.gov/vuln/detail/CVE-2026-58062)
- [NVD: CVE-2026-59638](https://nvd.nist.gov/vuln/detail/CVE-2026-59638)
- [NVD: CVE-2026-59650](https://nvd.nist.gov/vuln/detail/CVE-2026-59650)
- [Red Hat: CVE-2026-59638](https://access.redhat.com/security/cve/cve-2026-59638)
- [Fix-Commit add5f822660f (OCSP)](https://github.com/bcgit/bc-java/commit/add5f822660f3b2c29fd824e2f4095469c42a1c7)
- [Fix-Commit daeaae9d7075 (MTI/A0)](https://github.com/bcgit/bc-java/commit/daeaae9d7075d04f40812e68671ebf4c777b5148)
- [bc-java: ProvX509TrustManager.java (Stapling, checkRevocation)](https://github.com/bcgit/bc-java/blob/main/tls/src/main/java/org/bouncycastle/jsse/provider/ProvX509TrustManager.java)
- [bc-java: Properties.java (JSSE_HOSTNAME_CHECK_CN_FALLBACK)](https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/util/Properties.java)
