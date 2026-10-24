# eMudhra: kompromittierte Intermediate-CAs und Cross-Signs

Stand: 24.10.2026

## Worum es geht

Die privaten Schlüssel von acht Intermediate-CAs der indischen CA eMudhra sind kompromittiert. eMudhra hat die Schlüssel im April 2025 fehlerhaft erzeugt. Seitdem lässt sich jeder dieser Schlüssel aus dem öffentlichen Zertifikat zurückrechnen. Wer das tut, kann Zertifikate für beliebige Domains ausstellen, etwa für `api.github.com`, `repo.maven.apache.org`, `registry.npmjs.org` oder unseren eigenen IdP.

Der Entdecker hat am 17.10.2026 mit allen acht Schlüsseln die Nachricht "We have a problem here - Wayne" signiert und an die Root-Programme gemeldet. eMudhra hat die Intermediates am 18.10. widerrufen, Sectigo die Cross-Signs am 19.10.

Betroffen sind diese Intermediates, jeweils in Generation G3B und G3C:

- `EM DV TLS CA`, `EM OV TLS CA`, `EM EV TLS CA` für TLS-Serverzertifikate
- `EM OV CS CA` für Code Signing

Die vollständige Liste mit Fingerprints steht in [impacted-intermediates.json](https://emudhra.we-have-a-problem.com/impacted-intermediates.json). Die 16 SHA-256-Fingerprints liegen auch in [emudhra-blocked.certs](emudhra-blocked.certs).

## Warum die Cross-Signs das Problem so groß machen

Ein Intermediate steht in keinem Truststore. Man vertraut ihm nur, weil eine Kette von ihm zu einer Root führt, die im Truststore steht. Bei eMudhra gibt es für jeden der acht Schlüssel zwei Zertifikate mit demselben Public Key, aber unterschiedlichem Aussteller. Zusammen sind das 16 Zertifikate:

```
Pfad 1: Leaf -> EM DV TLS CA - G3B -> emSign Root TLS CA - G3 -> emSign ECC Root CA - G3
                                      (Cross-Sign von eMudhra)   (in Mozilla, Chrome, Apple, Microsoft)

Pfad 2: Leaf -> EM DV TLS CA - G3B -> AAA Certificate Services
                (Cross-Sign von Sectigo) (Apple, Microsoft, ältere Bundles, OpenJDK cacerts)
```

Daraus folgen mehrere Probleme:

1. **Die Root, über die man angreifbar ist, kennt man nicht.** `emSign Root TLS CA - G3` steht nur bei Microsoft im Store. Über den Cross-Sign von `emSign ECC Root CA - G3` ist sie trotzdem in jedem Truststore gültig, der Mozilla-Roots übernimmt. Dazu gehören Node.js, Temurin, Debian, Ubuntu und Alpine.
2. **Eine Root zu entfernen reicht nicht.** Wer nur `emSign ECC Root CA - G3` entfernt, hat Pfad 2 noch offen. Alle acht Intermediates haben zusätzlich einen Sectigo-Cross-Sign von `AAA Certificate Services`, darunter alle sechs TLS-Intermediates.
3. **Die zweite Root lässt sich nicht gefahrlos entfernen.** `AAA Certificate Services` ist eine alte Comodo/Sectigo-Root von 2004. Über sie laufen noch viele legitime Sectigo-Ketten. Wer sie entfernt, bricht Verbindungen zu unbeteiligten Servern.
4. **Sperren per Zertifikats-Fingerprint müssen alle 16 Zertifikate abdecken.** Eine Sperrliste mit nur acht Einträgen lässt den anderen Pfad offen. Robuster ist eine Sperre auf den Public Key (SPKI). Node.js macht das seit dem Patch so.

## Warum Backends stärker gefährdet sind als Browser

Browser sind seit dem 17.10. (Firefox, Chrome) bzw. 20.10. (Microsoft) und 22.10. (Apple) geschützt. Sie bekommen Sperrlisten wie CRLSets und OneCRL zentral nachgeladen. Zusätzlich erzwingen sie Certificate Transparency (CT). Ein gefälschtes Zertifikat ohne CT-Eintrag lehnen sie ab, und mit CT-Eintrag würde der Angriff öffentlich sichtbar.

Unsere Dienste haben beides nicht:

- Java, Node.js, curl, Go und Python prüfen standardmäßig keine Sperrlisten (CRL/OCSP). Der Widerruf vom 18.10. kommt bei ihnen nicht an.
- Keiner dieser Clients erzwingt CT. Ein Angreifer kann ein Zertifikat ausstellen, das nie in einem CT-Log auftaucht. Die Testhosts `*-noct-*` zeigen genau das.
- Java und Node.js bringen ihre Roots selbst mit. Ein OS-Update ändert daran nichts.

Für einen Angriff braucht man eine Position im Netz, zum Beispiel über DNS-Spoofing, einen kompromittierten Proxy, BGP-Hijacking oder einen Nachbarn im selben Netzsegment. Dann ist jeder ausgehende TLS-Call eines ungepatchten Dienstes lesbar und veränderbar. Konkret heißt das:

- **JWT-Validierung.** Spring Security holt mit `issuer-uri` bzw. `jwk-set-uri` die Signaturschlüssel des IdP per HTTPS, in Node.js macht das `jwks-rsa` oder `jose`. Wer diesen Call abfängt, schiebt eigene Schlüssel unter und kann sich beliebige Tokens ausstellen. Das ist ein vollständiger Auth-Bypass.
- **Build und Supply Chain.** Maven, Gradle und npm laufen auf genau den JVMs und Node-Versionen aus unseren Build-Images. Maven prüft Checksums nur gegen denselben Server, von dem es auch das JAR lädt. Ein MITM kann also manipulierte Artefakte ausliefern. npm ist durch die `integrity`-Hashes im Lockfile besser geschützt, aber nur für Pakete, die schon im Lockfile stehen.
- **API-Calls mit Secrets.** Alles, was mit Bearer-Token, Basic Auth oder API-Key nach außen geht, landet beim Angreifer.

Ob jemand die Schwachstelle seit April 2025 ausgenutzt hat, weiß niemand. Wegen der fehlenden CT-Pflicht hinterlässt ein Angriff auf Backends keine öffentlichen Spuren.

## Was ich lokal getestet habe

Am 24.10.2026 gegen die Testhosts von we-have-a-problem.com. "Verwundbar" heißt, der Client hat eine Verbindung über ein kompromittiertes Intermediate aufgebaut.

| Runtime | Pfad 1 (emSign) | Pfad 2 (AAA) |
|---|---|---|
| Node 24.21.0, Node 20 (`node:20-slim`) | verwundbar | abgelehnt |
| Node 24.21.0 mit `--use-system-ca` | verwundbar | abgelehnt |
| Node 24.21.0 mit `--use-openssl-ca`, Ubuntu-Store gepatcht | abgelehnt | abgelehnt |
| Node 20 mit `--use-openssl-ca` (`node:20-slim`) | abgelehnt | abgelehnt |
| Node 22.23.4, 24.22.1 (`CERT_REVOKED`) | abgelehnt | abgelehnt |
| Temurin 25+36 lokal, `eclipse-temurin:25-jdk` (25.0.4.1) | verwundbar | abgelehnt |
| Temurin 25 mit `-Dcom.sun.net.ssl.checkRevocation=true` | abgelehnt | abgelehnt |
| Temurin 25 mit ergänztem `blocked.certs` | abgelehnt | abgelehnt |
| Corretto 25.0.5.0.9 (`amazoncorretto:25`) | abgelehnt | abgelehnt |
| curl mit gepatchtem Ubuntu-Store | abgelehnt | abgelehnt |

Pfad 2 scheitert bei Node und Temurin, weil ihre Mozilla-basierten Stores `AAA Certificate Services` nicht mehr enthalten. Bei Oracle JDK und OpenJDK-Builds mit dem Upstream-`cacerts` ist das anders. Dort steht die Root als `comodoaaaca [jdk]` drin, und Pfad 2 ist offen.

Wichtig: Das offizielle Docker-Image `eclipse-temurin:25-jdk` war am 24.10. noch ungepatcht.

## Selbst prüfen

Die Prüfung muss mit genau der Runtime laufen, die auch die Anwendung nutzt, also im Container. Ein grüner Browser-Test oder ein `curl` auf dem Laptop sagt über den Java- oder Node-Prozess nichts aus.

```bash
# Java 11+, ohne Kompilieren
docker run --rm -v "$PWD":/t -w /t <unser-image> java Check.java

# Node.js 18+
docker run --rm -v "$PWD":/t -w /t <unser-image> node check.mjs
```

[Check.java](Check.java) und [check.mjs](check.mjs) liegen in diesem Ordner. Beide prüfen beide Pfade, jeweils mit und ohne CT, und enden mit Exit-Code 1, wenn die Runtime verwundbar ist. Damit kann man sie auch in die CI-Pipeline hängen.

Mit curl geht es so. Ein Zertifikatsfehler ist hier das gute Ergebnis.

```bash
curl https://dv-g3b-emudhra.we-have-a-problem.com/
curl https://dv-g3b-aaa-emudhra.we-have-a-problem.com/
curl https://dv-g3b-noct-emudhra.we-have-a-problem.com/
curl https://dv-g3b-aaa-noct-emudhra.we-have-a-problem.com/
```

## Spring Boot

Die TLS-Prüfung macht in fast allen Fällen der PKIX-Validator des JDK. Das gilt für `RestClient`, `RestTemplate`, `WebClient` auf Reactor Netty, Feign, den JDK-`HttpClient`, Apache HttpClient 5, Kafka-Clients, JDBC-Treiber und den JWK-Abruf von Spring Security. Ein JDK-Update oder das Ergänzen von `blocked.certs` deckt deshalb alle diese Clients ab.

### 1. JDK im Image aktualisieren

Laut [openjdk.org/emudhra](https://openjdk.org/emudhra) sind diese Versionen gepatcht: 27.0.1, 25.0.5, 21.0.13, 17.0.21, 11.0.33 und 8u511. Corretto 25.0.5.0.9 habe ich getestet, es lehnt alle Ketten ab.

Danach Images neu bauen, auch die Build-Images (`maven:*`, `gradle:*`), und im laufenden Container prüfen:

```bash
docker run --rm <image> java -version
```

### 2. Wenn das Base-Image noch nicht gepatcht ist: blocked.certs ergänzen

Das JDK hat eine eigene Sperrliste, `$JAVA_HOME/lib/security/blocked.certs`. Sie enthält SHA-256-Fingerprints von Zertifikaten, denen die JVM nie vertraut. Die Sperre greift in jeder PKIX-Prüfung, auch bei eigenen Truststores über `javax.net.ssl.trustStore` oder Spring-SSL-Bundles. Das habe ich mit einem Truststore getestet, der nur `emSign ECC Root CA - G3` enthält. Die gepatchten JDKs nutzen denselben Mechanismus. Corretto meldet `Untrusted certificate: CN=EM DV TLS CA - G3B`.

```dockerfile
FROM eclipse-temurin:25-jre
COPY emudhra-blocked.certs /tmp/emudhra-blocked.certs
RUN cat /tmp/emudhra-blocked.certs >> "$JAVA_HOME/lib/security/blocked.certs" \
 && rm /tmp/emudhra-blocked.certs
```

[emudhra-blocked.certs](emudhra-blocked.certs) enthält alle 16 Fingerprints, also beide Pfade. Die Datei ist ein JDK-Internum und kein offizielles Konfigurationsinterface. Als Übergang bis zum gepatchten Base-Image funktioniert sie, danach kann die Zeile wieder raus.

### 3. Alternative: keytool, mit Vorsicht

openjdk.org empfiehlt, die beiden Roots aus `cacerts` zu löschen:

```bash
keytool -delete -cacerts -alias "emsigneccrootcag3 [jdk]"
keytool -delete -cacerts -alias "comodoaaaca [jdk]"
```

Bei Temurin laufen diese Befehle ins Leere, denn Temurin benennt die Aliase anders. Dort heißt die Root `cn_emsign_ecc_root_ca__g3,o_emudhra_technologies_limited,ou_emsign_pki,c_in [jdk]`. Die Fehlermeldung "Alias existiert nicht" soll man laut Anleitung ignorieren. Damit bleibt man verwundbar und hält sich für sicher. Ich würde deshalb `blocked.certs` nehmen. Wer bei keytool bleibt, prüft vorher mit `keytool -list -cacerts | grep -iE 'emsign|aaa'`.

### 4. Alternative: Revocation-Check

```bash
exec java \
  -Dspring.aot.enabled=true \
  -Dcom.sun.net.ssl.checkRevocation=true \
  -Dcom.sun.security.enableCRLDP=true \
  ... weitere Optionen ...
  org.springframework.boot.loader.launch.JarLauncher
```

Das wirkt, hat aber Nebenwirkungen. Die JVM lädt dann für jede Kette CRLs per HTTP nach. Ist der CRL-Server nicht erreichbar, etwa weil der Cluster keinen Egress hat oder der Proxy nicht konfiguriert ist (`-Dhttp.proxyHost`), schlägt die Verbindung fehl. Java bricht dann hart ab. Für Dienste hinter einem Firmen-Proxy ist `blocked.certs` die einfachere Lösung.

### 5. Debian/Ubuntu mit System-Truststore

Images mit `openjdk` aus Debian oder Ubuntu nutzen `/etc/ssl/certs/java/cacerts` aus `ca-certificates-java`. Laut openjdk.org reicht dort ein Paket-Update wegen eines Bugs nicht. Zusätzlich nötig:

```bash
rm -f /etc/ssl/certs/java/cacerts
update-ca-certificates --fresh
```

### 6. Im Code und in der Konfiguration suchen

```bash
# Eigene Truststores im Repo und im Fat-JAR
find . -name '*.jks' -o -name '*.p12' -o -name '*.pfx' -o -name 'cacerts'
unzip -l target/*.jar | grep -iE '\.(jks|p12|pem|crt)$'

# Enthalten sie eine der betroffenen Roots?
keytool -list -v -keystore truststore.p12 | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'

# Abgeschaltete Prüfung, die jede Maßnahme aushebelt
grep -rnE 'InsecureTrustManagerFactory|TrustAllStrategy|TrustSelfSignedStrategy|NoopHostnameVerifier|X509TrustManager' src/
```

Kopierte Truststores sind eine Momentaufnahme. Sie bekommen kein Update, wenn das JDK aktualisiert wird. `blocked.certs` schützt sie trotzdem, ein `keytool -delete` auf `cacerts` dagegen nicht.

### 7. Eingehendes mTLS

Wenn ein Dienst Client-Zertifikate prüft (`server.ssl.client-auth=need`) und dafür einen Truststore mit öffentlichen Roots nutzt, kann ein Angreifer sich ein passendes Client-Zertifikat ausstellen. Für mTLS gehört nur die eigene, private CA in den Truststore.

## Node.js

Node.js bringt die Mozilla-Roots fest im Binary mit. OS-Updates helfen daher nur, wenn man Node ausdrücklich auf den OS-Store umstellt.

### 1. Node aktualisieren

Gepatcht sind 22.23.4, 24.22.1 und 26.12.1. Diese Versionen aktualisieren die Roots auf NSS 3.131.1 und sperren zusätzlich die Public Keys der Intermediates ("tls: reject chains containing blocked public keys"). Die Sperre greift auch, wenn der Code eigene CAs per `ca:`-Option mitgibt. Getestet habe ich das mit `node:24.22.1-slim` und einer `ca`-Option, die nur `emSign ECC Root CA - G3` enthält. Ergebnis: `CERT_REVOKED`.

Mit diesen Updates ist auch Node2Shell (CVE-2026-111497) behoben, siehe [2shell.md](../2shell/2shell.md). Es gibt also zwei Gründe, sofort zu aktualisieren.

Node 20 und älter sowie 23.x und 25.x bekommen keinen Patch. `node:20-slim` war im Test verwundbar.

Docker-Images mit festem Tag neu bauen (`FROM node:24.22.1-slim`), deployen und im laufenden Container `node -v` prüfen. CI-Runner, Bun (1.4.4) und Deno (2.9.8) nicht vergessen.

### 2. Wenn Node nicht sofort aktualisiert werden kann

```bash
NODE_OPTIONS=--use-openssl-ca
```

Damit nutzt Node den OS-Store statt der eingebauten Roots. Das hilft nur, wenn `ca-certificates` im Image aktuell ist. Also `apt-get upgrade ca-certificates` bzw. `apk upgrade ca-certificates` im Dockerfile und danach `check.mjs` laufen lassen. Mit `node:20-slim` hat das im Test funktioniert.

`--use-system-ca` hilft nicht. Diese Option nimmt die System-Roots zusätzlich zu den eingebauten. Im Test blieb Node damit verwundbar. `NODE_EXTRA_CA_CERTS` fügt ebenfalls nur hinzu und entfernt nichts.

### 3. Im Code und in der Konfiguration suchen

```bash
# Abgeschaltete Prüfung
grep -rnE 'rejectUnauthorized:\s*false|NODE_TLS_REJECT_UNAUTHORIZED' --include='*.js' --include='*.ts' --include='*.mjs' --include='*.json' --include='*.yaml' --include='Dockerfile' .

# Eigene CA-Bundles im Projekt
grep -rnE '\bca:\s' --include='*.js' --include='*.ts' --include='*.mjs' src/
find . -path ./node_modules -prune -o \( -name '*.pem' -o -name '*.crt' -o -name 'ca-bundle*' \) -print
```

Pakete mit eigenem Root-Bundle wie `ssl-root-cas` umgehen den Store von Node. Ab den gepatchten Versionen schützt die Public-Key-Sperre trotzdem. Bei Node 20 mit `--use-openssl-ca` nicht.

Electron-Apps wie Slack, Discord oder VS Code sind erst mit einem Release auf Basis von Electron 44.9.1, 43.8.1 oder 42.11.16 sicher. VS Code ab 1.143.1.

## Was nicht hilft

- **Die Prüfung abschalten, wenn nach dem Patch etwas bricht.** Wenn ein Partner ein eMudhra-Zertifikat nutzt, schlägt die Verbindung nach dem Patch fehl. Das ist gewollt. Der Partner braucht ein neues Zertifikat. `rejectUnauthorized: false` oder ein Trust-All-Manager öffnen genau die Lücke, die der Patch schließt.
- **Nur das SDK aktualisieren.** Die Zertifikatsprüfung sitzt in der Runtime, im OS oder in der HTTP-Bibliothek. Ein neues AWS- oder Stripe-SDK ändert daran nichts.
- **Nur das OS patchen.** Java und Node nutzen eigene Stores.
- **Nur die emSign-Root entfernen.** Der AAA-Pfad bleibt offen, siehe oben.
- **Neues Image bauen, aber nicht neu starten.** Laufende JVMs und Node-Prozesse lesen ihren Truststore nur beim Start.

## Eigene Server

Falls wir selbst Zertifikate von eMudhra einsetzen, sind sie widerrufen und müssen ersetzt werden:

```bash
openssl s_client -connect host:443 -servername host </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer | grep -i emudhra
```

## Quellen

- [we-have-a-problem.com: eMudhra Intermediate CA Compromise](https://emudhra.we-have-a-problem.com/)
- [impacted-intermediates.json](https://emudhra.we-have-a-problem.com/impacted-intermediates.json) und [roots.json](https://emudhra.we-have-a-problem.com/roots.json)
- [Cloudflare: eMudhra certificate compromise](https://blog.cloudflare.com/emudhra-certificate-compromise)
- [Mozilla Bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Mozilla dev-security-policy](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0R3XLJL6FuE)
- [OpenJDK: eMudhra](https://openjdk.org/emudhra)
- [Node.js 24.22.1](https://github.com/nodejs/node/releases/tag/v24.22.1), [22.23.4](https://github.com/nodejs/node/releases/tag/v22.23.4), [26.12.1](https://github.com/nodejs/node/releases/tag/v26.12.1)
- [Apple: Hinweise zu eMudhra](https://support.apple.com/en-us/149555)
- [Chromium CRLSets](https://www.chromium.org/Home/chromium-security/crlsets/)
