# Node2Shell / Python2Shell / HTTP2Shell (CVE-2026-111497)

Stand: 24.10.2026

Node2Shell, Python2Shell, HTTP2Shell und Broccoli2Shell sind Namen für dieselbe Lücke. Sie ist nicht zu verwechseln mit PHP2Shell (CVE-2026-109618/-109619), einer davon unabhängigen PHP-Lücke, die bereits aktiv ausgenutzt wird.

## Worum es geht

Der Brotli-Decoder von Google (`c/dec/decode.c`, Versionen 1.0.3 bis 1.2.0) schreibt beim Entpacken manipulierter Daten über das Ende seines Puffers hinaus. Gefixt ist das in Brotli 1.0.10, 1.1.1 und 1.2.1, veröffentlicht am 21.10.2026. Die Lücke hat CVSS 4.0 9.2.

Warum das gefährlich ist:

- Ein Angreifer braucht keinen Login. Ein Request mit `Content-Encoding: br` reicht. Mögliche Folgen sind Absturz, Speicherleck oder Remote Code Execution.
- Ausgehende Requests sind genauso betroffen. Holt der eigene Dienst eine Antwort von einem bösartigen Server und entpackt sie als Brotli, schlägt die Lücke dort zu. Eine Proxy-Regel für eingehenden Traffic hilft dagegen nicht.
- Brotli kommt oft nur als transitive Abhängigkeit ins Projekt, in HTTP-Clients, Sidecars und Base-Images.
- Seit dem 22.10. gibt es einen öffentlichen PoC. Forscher haben damit ein unverändertes Node 24.22.0 angegriffen. Aktive Angriffe sind bis 23.10. nicht bekannt, und CISA führt die Lücke noch nicht im KEV-Katalog.
- pip-audit, Dependabot und Safety melden die betroffenen Versionen noch nicht. Auf grüne Scanner ist also kein Verlass.

Betroffen ist nur nativer C-Code, also die Google-Bibliothek selbst und alles, was sie einbindet. Ein reiner Java-Decoder wie `org.brotli:dec` hat keinen Speicher-Overflow, weil die JVM jeden Array-Zugriff prüft. Das ist meine Einschätzung. Eine offizielle Aussage zu Java habe ich nicht gefunden.

## Spring Boot

Für alle drei Server gilt dieselbe Frage: Liegt `com.aayushatharva.brotli4j` auf dem Classpath? brotli4j bringt die native Google-Bibliothek per JNI mit. Ohne brotli4j gibt es im JVM-Prozess keinen verwundbaren Decoder.

```bash
# Maven
mvn dependency:tree -Dincludes=com.aayushatharva.brotli4j
mvn dependency:tree -Dincludes=org.brotli

# Fertiges Fat-JAR
unzip -l target/*.jar | grep -i brotli
```

Gefixt ist das in [brotli4j v1.24.0](https://github.com/hyperxpro/Brotli4j/releases/tag/v1.24.0) vom 24.10.2026. Dieses Release hebt das mitgelieferte Brotli auf 1.2.1 und nennt CVE-2026-111497 im Security Advisory. Die Version per `dependencyManagement` erzwingen, weil Netty und Jetty ältere Versionen mitziehen. Die nativen Artefakte (`native-linux-x86_64`, `native-linux-aarch64` usw.) müssen dieselbe Version haben, sonst lädt die alte native Bibliothek weiter.

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.aayushatharva.brotli4j</groupId>
      <artifactId>brotli4j</artifactId>
      <version>1.24.0</version>
    </dependency>
    <dependency>
      <groupId>com.aayushatharva.brotli4j</groupId>
      <artifactId>native-linux-x86_64</artifactId>
      <version>1.24.0</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```

### Tomcat (spring-boot-starter-web, Standard)

Tomcat entpackt keine Request-Bodies und kann kein Brotli. `server.compression` komprimiert nur Antworten mit gzip. Der Server selbst ist nach meiner Einschätzung nicht betroffen.

Prüfen muss man trotzdem:

- ob brotli4j über eine andere Abhängigkeit reinkommt, etwa einen eigenen Decompression-Filter oder Netty als HTTP-Client (siehe nächster Abschnitt)
- welche HTTP-Clients ausgehend Brotli entpacken. Der JDK-`HttpClient` kann kein Brotli. OkHttp (`okhttp-brotli`) und Apache HttpClient 5 nutzen den reinen Java-Decoder `org.brotli:dec` und sind damit unkritisch.

### Netty (spring-boot-starter-webflux, Reactor Netty)

Hier ist das Risiko am größten. Netty lädt brotli4j als optionale Abhängigkeit. Liegt es auf dem Classpath, liefert `Brotli.isAvailable()` true, und `HttpContentDecompressor` entpackt `br` automatisch mit dem nativen Code.

- Server: Reactor Netty entpackt Request-Bodies standardmäßig nicht. Betroffen ist man, wenn man selbst einen `HttpContentDecompressor` in die Pipeline hängt.
- Client: `WebClient` auf Reactor Netty mit `.compress(true)` hängt den `HttpContentDecompressor` ein. Eine Brotli-Antwort eines fremden Servers wird dann nativ entpackt, auch wenn man `br` gar nicht angefragt hat.
- gRPC-Java mit Netty-Transport und andere Netty-basierte Bibliotheken bitte genauso prüfen.

Wenn brotli4j drin ist, auf 1.24.0 heben (siehe oben). Wer Brotli gar nicht braucht, schließt brotli4j stattdessen per `<exclusion>` aus. Netty fällt dann still auf gzip/deflate zurück.

### Jetty (spring-boot-starter-jetty)

- Jetty bis 12.0 kennt nur gzip (`GzipHandler`) und ist nicht betroffen.
- Jetty 12.1 hat das neue Modul `org.eclipse.jetty.compression:jetty-compression-brotli`. Es hängt an brotli4j (12.1.1 nutzt brotli4j 1.17.0). Der `CompressionHandler` kann damit auch Request-Bodies entpacken. Wer dieses Modul eingebunden hat, ist betroffen und muss brotli4j auf 1.24.0 heben (siehe oben) oder das Modul entfernen.
- Für den Jetty-`HttpClient` gilt dasselbe, sobald das Brotli-Modul geladen ist.

### Container und Plattform rund um Spring Boot

Auch reine Java-Dienste laufen selten allein:

- Base-Images neu bauen und das Betriebssystem aktualisieren (`apt-get upgrade`), weil `libbrotli` und `curl` aus dem OS kommen.
- Envoy auf 1.37.8, 1.38.6, 1.39.3 oder 1.40.0 aktualisieren.
- Istio auf 1.29.9, 1.30.6 oder 1.31.2 aktualisieren. 1.29 ist end of life.
- Node- oder Python-Tools im selben Image (Build-Steps, Sidecars) mit aktualisieren.

## Node.js

Node.js bündelt Brotli direkt. Betroffen sind jedes eingebaute `fetch()`, `zlib.brotliDecompress*`, `body-parser` und damit Express. Es gibt keinen Konfigurationsschalter, nur das Update.

1. Node aktualisieren auf 22.23.4, 24.22.1 oder 26.12.1. Node 20 und älter sowie 23.x und 25.x bekommen keinen Patch. Diese Versionen müssen auf eine gepatchte LTS-Version.
2. Docker-Images neu bauen (`FROM node:...` mit gepatchtem Tag) und neu deployen. Danach im laufenden Container `node -v` prüfen. CI-Runner nicht vergessen.
3. Bun auf 1.4.4 aktualisieren und mit Bun kompilierte Executables neu bauen.
4. Bis zum Update `br`-Requests vor dem Body-Parser ablehnen:

```js
app.use((req, res, next) => {
  if (/\bbr\b/i.test(req.headers['content-encoding'] ?? '')) {
    return res.status(415).end();
  }
  next();
});
```

Das schützt nur eingehend. Gegen bösartige Antworten bei ausgehendem `fetch()` hilft nur das Update.

## Python

Betroffen sind die Pakete `Brotli` (bis 1.2.0) und `brotlicffi` (1.2.0.x). requests/urllib3, httpx (mit Extra `brotli`), aiohttp und Scrapy laden sie automatisch, sobald sie installiert sind.

```bash
pip list 2>/dev/null | grep -i brotli
```

1. `Brotli` auf 1.2.1 und `brotlicffi` auf 1.2.1.0 aktualisieren.
2. Images und Wheels neu bauen, Prozesse neu starten.
3. Falls das nicht sofort geht, beide Pakete deinstallieren und Extras entfernen, die sie wieder installieren (`httpx[brotli]`, `urllib3[brotli]`, `aiohttp[speedups]`). Die HTTP-Clients fallen dann auf gzip zurück.

## Übergangslösung am Proxy

Gilt für alle Stacks, solange nicht alles gepatcht ist. Eingehend am Reverse-Proxy oder Load Balancer Requests mit `br` im `Content-Encoding` ablehnen, zum Beispiel in nginx:

```nginx
if ($http_content_encoding ~* "\bbr\b") {
    return 415;
}
```

Ausgehend `br` aus `Accept-Encoding` entfernen und Antworten mit `Content-Encoding: br` vor dem Entpacken verwerfen. Nur den Header zu ändern reicht nicht, denn ein bösartiger Server schickt Brotli trotzdem.

Apache `mod_brotli` entpackt kein Brotli. Nginx entpackt standardmäßig auch nicht. Beide sind als Proxy selbst nicht betroffen.

## Quellen

- [Aikido: Node2Shell](https://www.aikido.dev/blog/node2shell-nodejs-brotli-rce-cve-2026-111497)
- [Aikido: HTTP2Shell und Python-Pakete](https://www.aikido.dev/blog/python-packages-vulnerable-node2shell-brotli-cve-2026-111497)
- [Strobes: HTTP2Shell](https://strobes.co/blog/http2shell-brotli-rce-cve-2026-111497/)
- [Brandefense: Fixed Node.js Versions](https://brandefense.io/blog/node2shell-nodejs-brotli-rce-cve-2026-111497/)
- [Miggo: Inside Node2Shell](https://www.miggo.io/post/node2shell-cve-2026-111497-nodejs-vulnerability)
- [Imperva: From Brotli Data to RCE](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/)
- [Qualys](https://blog.qualys.com/product-tech/2026/10/23/node-js-patches-brotli-remote-code-execution-flaw-find-vulnerable-runtimes-before-attackers-do)
- [Vercel KB: Node.js Security Advisory](https://vercel.com/kb/bulletin/node-js-security-advisory)
- [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-111497)
- [cvefeed.io: CVE-2026-111497](https://cvefeed.io/vuln/detail/CVE-2026-111497)
- [Patch the Planet: Brotli](https://patchtheplanet.org/brotli)
- [brotli4j v1.24.0 Release](https://github.com/hyperxpro/Brotli4j/releases/tag/v1.24.0)
- [Netty 4.1: Brotli.isAvailable](https://netty.io/4.1/api/io/netty/handler/codec/compression/Brotli.html)
- [Netty 4.1: HttpContentDecompressor](https://netty.io/4.1/xref/io/netty/handler/codec/http/HttpContentDecompressor.html)
- [Jetty 12.1: BrotliCompression](https://javadoc.jetty.org/jetty-12.1/org/eclipse/jetty/compression/brotli/BrotliCompression.html)
- [Maven: jetty-compression-brotli 12.1.1](https://mvnrepository.com/artifact/org.eclipse.jetty.compression/jetty-compression-brotli/12.1.1)
