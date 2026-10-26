# Node2Shell / Python2Shell / HTTP2Shell (CVE-2026-111497)

Stand: 26.10.2026

Node2Shell, Python2Shell, HTTP2Shell und Broccoli2Shell sind Namen für dieselbe Lücke. Sie ist nicht zu verwechseln mit PHP2Shell (CVE-2026-109618/-109619), einer davon unabhängigen PHP-Lücke, die bereits aktiv ausgenutzt wird.

## Worum es geht

Der Brotli-Decoder von Google (`c/dec/decode.c`, Versionen 1.0.3 bis 1.2.0) schreibt beim Entpacken manipulierter Daten über das Ende seines Puffers hinaus. Gefixt ist das in Brotli 1.0.10, 1.1.1 und 1.2.1, veröffentlicht am 21.10.2026. Die Lücke hat CVSS 4.0 9.2.

Warum das gefährlich ist:

- Ein Angreifer braucht keinen Login. Ein Request mit `Content-Encoding: br` reicht. Mögliche Folgen sind Absturz, Speicherleck oder Remote Code Execution.
- Ausgehende Requests sind genauso betroffen. Holt der eigene Dienst eine Antwort von einem bösartigen Server und entpackt sie als Brotli, schlägt die Lücke dort zu. Eine Proxy-Regel für eingehenden Traffic hilft dagegen nicht.
- Brotli kommt oft nur als transitive Abhängigkeit ins Projekt, in HTTP-Clients, Sidecars und Base-Images.
- Seit dem 22.10. gibt es öffentlichen Exploit-Code. Seit dem 24.10. liegt laut Mallory auch ein öffentlicher Exploit gegen das offizielle, unveränderte Image Node 24.22.0 auf x86_64 vor. Er greift eine Express-5-/body-parser-2.x-Route an, die große Request-Bodies annimmt, und trifft in einem von sieben bis zehn Versuchen. Jeder Fehlversuch bringt den Worker zum Absturz. Startet ein Process Manager ihn neu, versucht es der Exploit einfach wieder. Unabhängig bestätigt hat das bisher niemand: Aikido und Brandefense kennen nur öffentlichen Code, der Abstürze auslöst oder auf einem absichtlich geschwächten Build läuft.
- Mit eigenen, nicht veröffentlichten Exploits haben Forscher Code Execution auf dem offiziellen Image Node 24.22.0 gezeigt: Imperva auf arm64 nach mehreren Versuchen, OtterSec laut Robert Chen auf x86_64 mit ASLR in 50 von 50 Versuchen (geschrieben von einem KI-Agenten in fünf Stunden).
- Aktive Angriffe sind laut Mallory und NCSC-NL bis 25.10. nicht bekannt. Der EPSS-Wert liegt bei 0,7 %. CISA führt die Lücke am 26.10. noch nicht im KEV-Katalog (Version 2026.10.23).
- Assetnote hat mit dem [node2shell-scanner](https://github.com/assetnote/node2shell-scanner) einen kostenlosen Scanner veröffentlicht. Er findet verwundbare HTTP-Endpunkte im Netz, ohne sie auszunutzen. Laut Shodan senden rund 1,41 Mio. Dienste `X-Powered-By: Express` und 878.000 `X-Powered-By: Next.js`, dazu kommen rund 482.000 Envoy-/Istio-Gateways.
- pip-audit, Dependabot und Safety haben die betroffenen Python-Versionen anfangs nicht gemeldet. Inzwischen führt GitHubs Advisory PYSEC-2026-4322 und PYSEC-2026-4323. Bis die Scanner nachweislich anschlagen, trotzdem manuell prüfen (siehe [Python](#python)).

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

- Base-Images neu bauen und das Betriebssystem aktualisieren (`apt-get upgrade`), weil `libbrotli` und `curl` aus dem OS kommen. Gefixte Pakete gibt es bisher nur für Debian bookworm (`1.0.9-2+deb12u1`, DLA-4855-1), trixie (`1.1.0-2+deb13u1`, DSA-6582-1) und sid (`1.2.0-4.1`). Debian forky ist am 26.10. noch offen. Für Red Hat, Ubuntu, SUSE und Amazon Linux gab es am 24.10. noch keine Pakete, einen neueren Stand habe ich nicht gefunden. Dort hilft das OS-Update noch nicht.
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
2. Docker-Images neu bauen (`FROM node:...` mit gepatchtem Tag) und neu deployen. Danach im laufenden Container `node -v` prüfen. CI-Runner nicht vergessen. Die `nodejs`-Pakete von Debian (bookworm bis sid) führt der Debian-Tracker am 26.10. noch als verwundbar.
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

## .NET

Microsoft hat am 25.10. Fixes veröffentlicht ([dotnet/announcements#494](https://github.com/dotnet/announcements/issues/494), CVSS 3.1 8.1). `System.IO.Compression.Brotli` (`BrotliStream`, `BrotliDecoder`) ruft per P/Invoke eine mitgelieferte native Kopie von Google Brotli auf (.NET 10: Version 1.1.0). Betroffen sind alle Plattformen und Architekturen, .NET Framework nicht. Einen Crash unter .NET hat bisher niemand öffentlich gezeigt.

| .NET | Betroffen | Gepatchte Runtime | Gepatchtes SDK |
|---|---|---|---|
| 8.0 | < 8.0.33 | 8.0.33 | 8.0.133, 8.0.427 |
| 9.0 | < 9.0.22 | 9.0.22 | 9.0.123, 9.0.320 |
| 10.0 | < 10.0.14 | 10.0.14 | 10.0.114, 10.0.403 |
| 11.0 Preview | < 11.0.0-rc.3.26522.148 | 11.0.0-rc.3.26522.148 | 11.0.100-rc.3.26522.148 |

Weil .NET seine eigene Kopie mitbringt, hilft ein OS-Update von `libbrotli` bei den offiziellen Microsoft-Builds nicht. Distributions-Builds aus source-build können stattdessen die System-Bibliothek nutzen. Wer .NET selbst aus den GitHub-Quellen baut, ist noch betroffen, bis die Fixes in die öffentlichen Branches portiert sind. [dotnet/runtime#136422](https://github.com/dotnet/runtime/issues/136422) ist dafür wieder offen.

Erreicht wird der Decoder nur, wenn Brotli tatsächlich entpackt wird:

- ASP.NET Core Request Decompression (`AddRequestDecompression()`/`UseRequestDecompression()`) entpackt eingehende Bodies mit `Content-Encoding: br`. Kestrel tut das ohne diese Middleware nicht.
- `HttpClient` mit `AutomaticDecompression = DecompressionMethods.Brotli` oder `DecompressionMethods.All` entpackt Brotli-Antworten fremder Server. Default ist `None`.
- Eigener Code, der `BrotliStream` mit `CompressionMode.Decompress` oder `BrotliDecoder` auf fremde Daten anwendet.
- Response Compression (`AddResponseCompression()`) komprimiert nur und ist nicht der verwundbare Pfad.

Ein installiertes Paket allein macht eine Anwendung laut Microsoft nicht angreifbar.

```bash
dotnet --list-runtimes
dotnet --list-sdks
grep -rnE "RequestDecompression|DecompressionMethods\.(Brotli|All)|BrotliStream|BrotliDecoder" --include=*.cs .
```

Update:

1. Runtime bzw. SDK auf die gepatchte Version heben, Docker-Images neu bauen und Anwendungen neu starten.
2. Self-contained Apps mit der neuen Runtime neu bauen und neu deployen, weil sie die Runtime mitbringen.
3. NativeAOT-Apps: SDK und explizite Referenzen auf `Microsoft.DotNet.ILCompiler` und die Runtime-Packs aktualisieren, dann neu publishen. Ein Update der Shared Runtime ersetzt den Decoder nicht, der schon ins Executable gelinkt ist.
4. Direkte Paketreferenzen auf die gepatchten Versionen heben.

Bis zum Update:

1. In der Request Decompression den Brotli-Provider entfernen: `services.AddRequestDecompression(o => o.DecompressionProviders.Remove("br"));`
2. Bei `HttpClient` nur `DecompressionMethods.GZip | DecompressionMethods.Deflate` setzen statt `All`.
3. Eingehend `br` am Proxy ablehnen (siehe [Übergangslösung am Proxy](#übergangslösung-am-proxy)).

Microsoft rät, dabei keine Decompression neu einzuschalten, die die Anwendung bisher nicht nutzt. Automatisches Entpacken birgt auch ohne Brotli ein DoS-Risiko.

Der offene PR [dotnet/runtime#136430](https://github.com/dotnet/runtime/pull/136430) ersetzt den nativen Code durch eine verwaltete C#-Portierung von Brotli 1.2.1. Laut Autor ist das ein Experiment und kein Security-Fix.

## Grafana

Grafana hat bis 26.10. kein Advisory zu CVE-2026-111497 veröffentlicht. Der Grafana-Server ist nach meiner Einschätzung nicht betroffen, das Image des Grafana Image Renderer schon.

### Grafana-Server

- Das Backend ist in Go geschrieben. Brotli kommt über `github.com/andybalholm/brotli` (v1.2.3) ins Projekt. Das ist eine reine Go-Portierung ohne nativen Code. Go prüft wie die JVM jeden Array-Zugriff, ein Speicher-Overflow kann so nicht entstehen. Das ist meine Einschätzung, eine Aussage von Grafana dazu habe ich nicht gefunden.
- Das Frontend wird beim Build mit Node gebaut und als statisches Bundle ausgeliefert. Im fertigen Image läuft kein Node.js.
- Das Alpine-Image installiert `curl`, und `libcurl` zieht `brotli-libs` mit. Der Grafana-Prozess nutzt diese Bibliothek nicht, nur `curl` im Container. Scanner melden sie trotzdem.
- Backend-Plugins von Drittanbietern laufen als eigene Binaries. Plugins, die nativen Code per cgo einbinden oder nicht in Go geschrieben sind, einzeln prüfen.

### Grafana Image Renderer

- Der Renderer ist in Go geschrieben und steuert einen Chromium. Das Image basiert auf `debian:trixie` und installiert Chromium aus den Debian-Paketen.
- Das aktuelle Release v5.12.9 vom 23.10. enthält noch `libbrotli1 1.1.0-2+b7` und ist damit verwundbar. Gefixt ist `1.1.0-2+deb13u1` (DSA-6582-1). PR [#1069](https://github.com/grafana/grafana-image-renderer/pull/1069) baut das Image mit dem gefixten Paket neu, ist am 26.10. aber noch nicht gemergt.
- Das Debian-Paket `chromium` hängt nicht von `libbrotli1` ab und nutzt damit eine eigene, mitkompilierte Brotli-Kopie. Chromium entpackt Brotli bei HTTP-Antworten mit `Content-Encoding: br` und in WOFF2-Schriften. Ob diese Kopie betroffen und schon gefixt ist, habe ich nicht gefunden. Der Debian-Tracker führt Chromium bei dieser CVE nicht.
- Der Renderer lädt normalerweise nur Grafana-Seiten. Bindet ein Dashboard aber fremde Inhalte ein (Bilder oder iframes im Text-Panel, externe Webfonts), entpackt Chromium deren Antworten.
- Ältere Versionen des Renderers liefen als Node-Plugin. Wer die noch nutzt, hat zusätzlich Node.js mit gebündeltem Brotli im Prozess (siehe [Node.js](#nodejs)).

### Prüfen

```bash
# Grafana-Image (Alpine): OS-Bibliothek
docker run --rm --entrypoint sh grafana/grafana -c 'apk info -v | grep -i brotli'

# Renderer-Image: libbrotli1 muss 1.1.0-2+deb13u1 oder neuer sein
docker run --rm --entrypoint sh grafana/grafana-image-renderer -c 'dpkg -l | grep -iE "brotli|chromium"'
```

### Was tun

1. Bis ein gefixtes Renderer-Release erscheint, das Image selbst nachziehen:

```dockerfile
FROM grafana/grafana-image-renderer:5.12.9
USER root
RUN apt-get update \
 && apt-get install -y --only-upgrade --no-install-recommends libbrotli1 chromium chromium-shell chromium-driver chromium-sandbox \
 && rm -rf /var/lib/apt/lists/*
USER 65532
```

2. Den Renderer nur intern erreichbar machen, sodass nur Grafana ihn aufruft, und das Auth-Token (`rendering.renderer_token` in Grafana) setzen.
3. Keine fremden Inhalte in Dashboards einbinden, die gerendert werden, solange der Chromium-Status unklar ist.
4. Grafana-Server und dessen Image beim nächsten Turnus aktualisieren. Nötig ist das wegen dieser Lücke nicht.

## Weitere Projekte mit eigener Brotli-Kopie

Viele Projekte bringen eine eigene Kopie von `decode.c` mit. Ein OS-Update erreicht diese Kopien nicht. Stand 26.10. laut [broccoli2shell.com](https://broccoli2shell.com/):

- Gefixt mit Release: Ruby-Gem `brotli` 0.9.1, PHP-Extension `brotli` 0.21.1, UEFITool A76, MuPDF 1.28.x (1.27.x ist weiter betroffen).
- Fix gemergt, aber noch kein Release: ClickHouse (Backport auf 26.10 gemergt, Backports auf 26.9, 26.8 und 26.3 LTS offen), NanaZip, GraalJS, YDB, libjxl.
- Noch ungefixt: DuckDB (PR offen), Apache Arrow (gebündeltes Brotli 1.0.9, PR approved, aber nicht gemergt), v8-jsi, 7-Zip-zstd, p7zip, EDK II, woff2 (nur der Makefile-Build; der CMake-Build linkt die System-Bibliothek).

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
- [Mallory: Node2Shell / HTTP2Shell Rapid Response](https://mallory.ai/blog/node2shell-rapid-response)
- [broccoli2shell.com: Fix-Status weiterer Projekte](https://broccoli2shell.com/)
- [CISA KEV Feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- [dotnet/runtime#136422: Does CVE-2026-111497 affect System.IO.Compression.Brotli?](https://github.com/dotnet/runtime/issues/136422)
- [dotnet/runtime#136430: Managed C#-Port von Brotli 1.2.1](https://github.com/dotnet/runtime/pull/136430)
- [dotnet/announcements#211: Advisory zu CVE-2020-8927](https://github.com/dotnet/announcements/issues/211)
- [dotnet/announcements#494: Microsoft Security Advisory CVE-2026-111497](https://github.com/dotnet/announcements/issues/494)
- [Assetnote: node2shell-scanner](https://github.com/assetnote/node2shell-scanner)
- [brotli4j v1.24.0 Release](https://github.com/hyperxpro/Brotli4j/releases/tag/v1.24.0)
- [Netty 4.1: Brotli.isAvailable](https://netty.io/4.1/api/io/netty/handler/codec/compression/Brotli.html)
- [Netty 4.1: HttpContentDecompressor](https://netty.io/4.1/xref/io/netty/handler/codec/http/HttpContentDecompressor.html)
- [Jetty 12.1: BrotliCompression](https://javadoc.jetty.org/jetty-12.1/org/eclipse/jetty/compression/brotli/BrotliCompression.html)
- [Maven: jetty-compression-brotli 12.1.1](https://mvnrepository.com/artifact/org.eclipse.jetty.compression/jetty-compression-brotli/12.1.1)
- [Envoy Security Advisory: Out-of-Bounds Write in Brotli Decompressor (GHSA-3wvj-j6qm-62mr)](https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr)
- [Istio: Announcing Istio 1.30.6](https://istio.io/latest/news/releases/1.30.x/announcing-1.30.6/)
- [Istio Security Bulletin ISTIO-SECURITY-2026-007 (PR)](https://github.com/istio/istio.io/pull/17737)
- [grafana/grafana-image-renderer#1068: libbrotli1 in v5.12.9](https://github.com/grafana/grafana-image-renderer/pull/1068)
- [grafana/grafana-image-renderer#1069: Cachebuster-Bump für libbrotli1](https://github.com/grafana/grafana-image-renderer/pull/1069)
- [grafana-image-renderer: Dockerfile](https://github.com/grafana/grafana-image-renderer/blob/master/Dockerfile)
- [Grafana: Dockerfile](https://github.com/grafana/grafana/blob/main/Dockerfile)
- [Grafana: go.mod](https://github.com/grafana/grafana/blob/main/go.mod)
- [Debian: Paket chromium (trixie)](https://packages.debian.org/trixie/chromium)
