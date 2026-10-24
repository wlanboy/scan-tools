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
- Service Mesh prüfen: Envoy und Istio sind betroffen (siehe eigenen Abschnitt [Istio und Envoy](#istio-und-envoy)).
- Node- oder Python-Tools im selben Image (Build-Steps, Sidecars) mit aktualisieren.

## Istio und Envoy

### Warum beide betroffen sind

Envoy ist ein in C++ geschriebener Proxy und linkt die native Google-Brotli-Bibliothek (`decode.c`) statisch ins eigene Binary. Der verwundbare Decoder steckt damit fest im Envoy-Binary jeder betroffenen Version. Das ist dieselbe Ursache wie bei Node und Python, nur in einem anderen Wirt.

Istios Data Plane *ist* Envoy: Jeder Sidecar (Container `istio-proxy`) und jedes Gateway (Ingress/Egress) läuft als Envoy-Prozess. Die Bibliothek liegt also in jedem Proxy-Pod.

Entscheidend ist aber der Unterschied zwischen „Code ist vorhanden" und „Code wird erreicht":

- Der Overflow greift nur, wenn Envoy tatsächlich Brotli **entpackt**. Das macht der HTTP-Filter `envoy.filters.http.decompressor` mit der Brotli-Extension (`envoy.extensions.compression.brotli.decompressor.v3.Brotli`).
- In Istio ist das **nicht Default**. Es wird typischerweise per `EnvoyFilter` eingeschaltet. Ohne eine solche Konfiguration ist der verwundbare Pfad nicht erreichbar.
- Reines ausgehendes **Komprimieren** (`compressor`) ruft den Decoder nicht auf und ist nicht der verwundbare Pfad.
- Entpackt wird: eingehende Request-Bodies mit `Content-Encoding: br` und Antworten von Upstreams. Beides erreicht ein nicht authentifizierter Angreifer.

Kurz: Binary vorhanden = potenziell betroffen. Decompressor konfiguriert = tatsächlich exponiert.

### Prüfen, ob man betroffen ist

Zwei Fragen, zwei Checks. Da viele Istio-Versionen im Einsatz sind, zuerst den Überblick über das ganze Mesh verschaffen.

**1. Welche Istio-/Envoy-Versionen laufen wo?**

```bash
# Control-Plane- und Data-Plane-Versionen im Mesh
istioctl version

# Jeder Proxy mit seiner Istio-Version (zeigt alle Sidecars + Gateways)
istioctl proxy-status

# Envoy-Version eines konkreten Proxys
istioctl proxy-config bootstrap <pod>.<namespace> -o json | grep -i build_version
# oder direkt im Pod
kubectl exec <pod> -c istio-proxy -- pilot-agent request GET server_info | jq -r .version
```

Betroffene Envoy-Versionen: 1.39.2, 1.38.5, 1.37.7, 1.36.11 und jeweils älter. Gefixt in 1.40.0, 1.39.3, 1.38.6, 1.37.8, 1.36.12 (1.36 ist unsupported).

**2. Ist Brotli-Decompression überhaupt konfiguriert?**

```bash
# EnvoyFilter, die Brotli einschalten (clusterweit)
kubectl get envoyfilter -A -o yaml | grep -i brotli

# Laufende Konfiguration eines Proxys durchsuchen
istioctl proxy-config all <pod>.<namespace> -o json | grep -i brotli
```

Auf die Treffer achten:

- `...brotli.decompressor...` → verwundbarer Pfad aktiv → **betroffen**.
- Nur `...brotli.compressor...` oder gar kein Treffer → über diese Lücke nicht exponiert.

Gateways nicht vergessen: dieselben Checks gegen die Ingress-/Egress-Gateway-Pods laufen lassen.

### Was tun

- Istio auf 1.29.9, 1.30.6 oder 1.31.2 aktualisieren. 1.29 ist end of life, also besser auf eine unterstützte Linie wechseln. Der Fix kommt über den Envoy-Bump, ein Istio-Upgrade reicht, Envoy wird nicht separat installiert.
- Wo ein Decompressor konfiguriert ist und das Upgrade nicht sofort geht: als Übergangslösung den `EnvoyFilter` mit der Brotli-Decompression entfernen, oder eingehend am Gateway Requests mit `Content-Encoding: br` ablehnen (siehe [Übergangslösung am Proxy](#übergangslösung-am-proxy)).
- Wo nichts entpackt wird, ist man nicht exponiert. Trotzdem beim nächsten Turnus patchen, weil das verwundbare Binary vorhanden bleibt und eine spätere Konfigurationsänderung den Pfad aktivieren würde.

### Kann man Brotli in Istio deaktivieren?

Einen globalen „Brotli aus"-Schalter gibt es nicht. Die Brotli-Bibliothek ist fest ins Envoy-Binary kompiliert; rausbekommt man sie nur per Envoy-Rebuild, also praktisch per Istio-Upgrade. Abschalten lässt sich nur der Pfad, der sie erreicht:

- **Default ist bereits „aus".** Istio entpackt Brotli nicht von sich aus. Wenn der Check oben keinen `decompressor` findet, ist nichts zu deaktivieren.
- **Falls ein Decompressor konfiguriert ist**, den auslösenden `EnvoyFilter` entfernen (`kubectl delete envoyfilter …`) oder die Brotli-Decompression darin herausnehmen. Envoy fällt dann auf gzip/deflate zurück.

Als zusätzliche Absicherung eingehend am Ingress-Gateway `Content-Encoding: br` hart ablehnen, unabhängig von sonstiger Konfiguration:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: reject-brotli
  namespace: istio-system
spec:
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      context: GATEWAY
      listener:
        filterChain:
          filter:
            name: envoy.filters.network.http_connection_manager
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.lua
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
          inlineCode: |
            function envoy_on_request(handle)
              local ce = handle:headers():get("content-encoding")
              if ce and string.find(string.lower(ce), "br", 1, true) then
                handle:respond({[":status"] = "415"}, "brotli not accepted")
              end
            end
```

Das deckt nur die eingehende Richtung ab. Antworten von Upstreams werden ohnehin nur dann entpackt, wenn dafür ein Response-Decompressor konfiguriert ist — den gegebenenfalls genauso entfernen. Für Sidecars statt des Gateways `context: SIDECAR_INBOUND` verwenden. Das bleibt eine Übergangslösung; der saubere Fix ist das Istio-Upgrade.

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

In HAProxy per ACL im `frontend` (oder `listen`):

```haproxy
http-request deny deny_status 415 if { req.hdr(content-encoding) -m sub -i br }
```

`-m sub -i br` prüft case-insensitiv auf das Teilwort `br`; bei den üblichen Encodings (`gzip`, `deflate`, `compress`, `identity`) gibt es keine Fehltreffer. Wer ganz sauber auf das Token prüfen will, nimmt eine Regex:

```haproxy
http-request deny deny_status 415 if { req.hdr(content-encoding) -m reg -i (^|,)[[:space:]]*br([[:space:]]*(;|,|$)) }
```

Ausgehend `br` aus `Accept-Encoding` entfernen und Antworten mit `Content-Encoding: br` vor dem Entpacken verwerfen. Nur den Header zu ändern reicht nicht, denn ein bösartiger Server schickt Brotli trotzdem.

Apache `mod_brotli` entpackt kein Brotli. Nginx entpackt standardmäßig auch nicht. HAProxy kann Brotli gar nicht (nur gzip/deflate, und nur beim Komprimieren von Antworten). Alle drei sind als Proxy selbst nicht betroffen und taugen damit als Filterpunkt.

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
- [Envoy Security Advisory: Out-of-Bounds Write in Brotli Decompressor (GHSA-3wvj-j6qm-62mr)](https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr)
- [Istio: Announcing Istio 1.30.6](https://istio.io/latest/news/releases/1.30.x/announcing-1.30.6/)
- [Istio Security Bulletin ISTIO-SECURITY-2026-007 (PR)](https://github.com/istio/istio.io/pull/17737)
