#!/usr/bin/env python3
"""
OSSM Migration Scanner: Service Mesh 2.x -> 3.0
Scannt Namespaces nach veralteten Istio-Ressourcen und Labels,
um die Migration von OSSM 2.6.x auf 3.0.x vorzubereiten.

Quellen:
  Red Hat OSSM 3.0 Migrating from Service Mesh 2 to Service Mesh 3
  https://docs.redhat.com/en/documentation/red_hat_openshift_service_mesh/3.0/
"""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional


# ==============================================================================
# Felddaten aus configuration.txt (Kapitel 7.1.2 + 7.1.1)
# ==============================================================================

# Felder die in OSSM 3.0 NICHT mehr unterstützt werden -> Blocker
# Format: (smcp_path, kategorie, aktion)
UNSUPPORTED_SMCP_FIELDS: list[tuple[str, str, str]] = [
    # 7.1.2.2 Cluster
    ("spec.cluster.meshExpansion.ilbGateway",
     "Cluster",
     "Feld entfernen - ILB Gateway hat keine Entsprechung in OSSM 3.0"),
    ("spec.cluster.multiCluster.meshNetworks.gateways.service",
     "Cluster",
     "Feld entfernen - kein Equivalent in OSSM 3.0"),
    # 7.1.2.4 Policy (Mixer entfernt)
    ("spec.policy.type",
     "Policy",
     "Feld entfernen - Mixer/Policy komplett aus OSSM 3.0 entfernt"),
    ("spec.policy.mixer",
     "Policy",
     "Feld entfernen - Mixer komplett aus OSSM 3.0 entfernt"),
    ("spec.policy.remote",
     "Policy",
     "Feld entfernen - Remote Policy in OSSM 3.0 nicht unterstützt"),
    # 7.1.2.5 Proxy networking
    ("spec.proxy.networking.initialization.type",
     "Proxy Networking",
     "Feld entfernen - Initialization type nicht unterstützt"),
    ("spec.proxy.networking.initialization.initContainer.runtime.env",
     "Proxy Networking",
     "Feld entfernen - initContainer env nicht unterstützt. "
     "Proxy-Umgebungsvariablen via spec.values.meshConfig.defaultConfig.proxyMetadata setzen"),
    ("spec.proxy.networking.protocol.autoDetect",
     "Proxy Networking",
     "Feld entfernen - Protocol autoDetect nicht unterstützt"),
    ("spec.proxy.networking.protocol.inbound",
     "Proxy Networking",
     "Feld entfernen - Protocol inbound nicht unterstützt"),
    ("spec.proxy.networking.protocol.outbound",
     "Proxy Networking",
     "Feld entfernen - Protocol outbound nicht unterstützt"),
    # 7.1.2.6 Runtime
    ("spec.runtime.components.deployment.strategy.type",
     "Runtime",
     "Feld entfernen - Deployment strategy.type nicht konfigurierbar in OSSM 3.0"),
    ("spec.runtime.defaults.deployment.podDisruption.maxUnavailable",
     "Runtime",
     "Feld entfernen - PodDisruptionBudget maxUnavailable nicht unterstützt in OSSM 3.0"),
    ("spec.runtime.defaults.deployment.podDisruption.minAvailable",
     "Runtime",
     "Feld entfernen - PodDisruptionBudget minAvailable nicht unterstützt in OSSM 3.0"),
    # 7.1.2.7 Security - cert-manager
    ("spec.security.certificateAuthority.cert-manager.pilotSecretName",
     "Security / cert-manager",
     "Feld entfernen - pilotSecretName nicht in OSSM 3.0 unterstützt"),
    ("spec.security.certificateAuthority.cert-manager.rootCAConfigMapName",
     "Security / cert-manager",
     "Feld entfernen - rootCAConfigMapName nicht in OSSM 3.0 unterstützt"),
    # 7.1.2.7 Security - istiod CA
    ("spec.security.certificateAuthority.istiod.privateKey.rootCADir",
     "Security / Istiod CA",
     "Feld entfernen - rootCADir nicht in OSSM 3.0 unterstützt"),
    ("spec.security.certificateAuthority.istiod.selfSigned.checkPeriod",
     "Security / Istiod CA",
     "Feld entfernen - selfSigned.checkPeriod nicht in OSSM 3.0 unterstützt"),
    ("spec.security.certificateAuthority.istiod.selfSigned.enableJitter",
     "Security / Istiod CA",
     "Feld entfernen - selfSigned.enableJitter nicht in OSSM 3.0 unterstützt"),
    ("spec.security.certificateAuthority.istiod.selfSigned.gracePeriod",
     "Security / Istiod CA",
     "Feld entfernen - selfSigned.gracePeriod nicht in OSSM 3.0 unterstützt"),
    ("spec.security.certificateAuthority.istiod.selfSigned.ttl",
     "Security / Istiod CA",
     "Feld entfernen - selfSigned.ttl nicht in OSSM 3.0 unterstützt"),
    ("spec.security.certificateAuthority.istiod.workloadCertTTLDefault",
     "Security / Istiod CA",
     "Feld entfernen - workloadCertTTLDefault nicht in OSSM 3.0 unterstützt"),
    ("spec.security.certificateAuthority.istiod.workloadCertTTLMax",
     "Security / Istiod CA",
     "Feld entfernen - workloadCertTTLMax nicht in OSSM 3.0 unterstützt"),
    # 7.1.2.7 Security - control plane TLS
    ("spec.security.controlPlane.tls.maxProtocolVersion",
     "Security / TLS",
     "Feld entfernen - maxProtocolVersion in OSSM 3.0 nicht unterstützt "
     "(minProtocolVersion bleibt: -> spec.values.meshConfig.tlsDefaults.minProtocolVersion)"),
    # 7.1.2.7 Security - identity
    ("spec.security.identity.thirdParty.issuer",
     "Security / Identity",
     "Feld entfernen - thirdParty.issuer nicht in OSSM 3.0 unterstützt"),
    ("spec.security.identity.type",
     "Security / Identity",
     "Feld entfernen - identity.type nicht in OSSM 3.0 unterstützt"),
    # 7.1.2.8 Telemetry (Mixer entfernt)
    ("spec.telemetry.type",
     "Telemetry",
     "Feld entfernen - Telemetry type (Mixer) komplett aus OSSM 3.0 entfernt"),
    ("spec.telemetry.mixer",
     "Telemetry",
     "Feld entfernen - Mixer komplett aus OSSM 3.0 entfernt"),
    ("spec.telemetry.remote",
     "Telemetry",
     "Feld entfernen - Remote Telemetry in OSSM 3.0 nicht unterstützt"),
]

# Felder die in OSSM 3.0 an NEUEN Pfaden konfiguriert werden -> Warnung
# Format: (smcp_path, ossm3_path, beschreibung)
MIGRATED_SMCP_FIELDS: list[tuple[str, str, str]] = [
    # 7.1.1.1 Cluster
    ("spec.cluster.name",
     "spec.values.global.multiCluster.clusterName",
     "Cluster Name (Multi-Cluster)"),
    ("spec.cluster.network",
     "spec.values.global.network",
     "Cluster Network"),
    ("spec.cluster.multiCluster.enabled",
     "spec.values.global.multiCluster.enabled",
     "Multi-Cluster aktiviert"),
    # 7.1.1.2 General
    ("spec.general.logging.componentLevels",
     "spec.values.global.logging.levels",
     "Logging Component Levels"),
    ("spec.general.logging.logAsJSON",
     "spec.values.global.logAsJson",
     "Log als JSON"),
    ("spec.general.validationMessages",
     "spec.values.global.istiod.enableAnalysis",
     "Validation Messages / Analysis"),
    # 7.1.1.6 Proxy - Access Logging
    ("spec.proxy.accessLogging.file.name",
     "spec.values.meshConfig.accessLogFile",
     "Access Log Dateiname"),
    ("spec.proxy.accessLogging.file.format",
     "spec.values.meshConfig.accessLogFormat",
     "Access Log Format"),
    ("spec.proxy.accessLogging.file.encoding",
     "spec.values.meshConfig.accessLogEncoding",
     "Access Log Encoding"),
    ("spec.proxy.accessLogging.envoyService.enabled",
     "spec.values.meshConfig.enableEnvoyAccessLogService",
     "Envoy Access Log Service aktiviert"),
    ("spec.proxy.accessLogging.envoyService.address",
     "spec.values.meshConfig.defaultConfig.envoyAccessLogService.address",
     "Envoy Access Log Service Adresse"),
    # 7.1.1.6 Proxy - Envoy Metrics
    ("spec.proxy.envoyMetricsService.address",
     "spec.values.meshConfig.defaultConfig.envoyMetricsService.address",
     "Envoy Metrics Service Adresse"),
    # 7.1.1.6 Proxy - Injection
    ("spec.proxy.injection.autoInject",
     "spec.values.global.proxy.autoInject",
     "Auto Inject (global)"),
    ("spec.proxy.injection.alwaysInjectSelector",
     "spec.values.sidecarInjectorWebhook.alwaysInjectSelector",
     "Always Inject Selector"),
    ("spec.proxy.injection.neverInjectSelector",
     "spec.values.sidecarInjectorWebhook.neverInjectSelector",
     "Never Inject Selector"),
    ("spec.proxy.injection.injectedAnnotations",
     "spec.values.sidecarInjectorWebhook.injectedAnnotations",
     "Injected Annotations"),
    # 7.1.1.6 Proxy - Logging
    ("spec.proxy.logging.componentLevels",
     "spec.values.global.proxy.componentLogLevel",
     "Proxy Component Log Level"),
    ("spec.proxy.logging.level",
     "spec.values.global.logging.level",
     "Proxy Log Level"),
    # 7.1.1.6 Proxy - Networking
    ("spec.proxy.networking.clusterDomain",
     "spec.values.global.proxy.clusterDomain",
     "Cluster Domain"),
    ("spec.proxy.networking.connectionTimeout",
     "spec.values.meshConfig.connectTimeout",
     "Connection Timeout"),
    ("spec.proxy.networking.dns.refreshRate",
     "spec.values.meshConfig.dnsRefreshRate",
     "DNS Refresh Rate"),
    ("spec.proxy.networking.dns.searchSuffixes",
     "spec.values.global.podDNSSearchNamespaces",
     "DNS Search Suffixes"),
    ("spec.proxy.networking.maxConnectionAge",
     "spec.values.pilot.keepaliveMaxServerConnectionAge",
     "Max Connection Age"),
    ("spec.proxy.networking.protocol.timeout",
     "spec.values.meshConfig.protocolDetectionTimeout",
     "Protocol Detection Timeout"),
    # 7.1.1.6 Proxy - Traffic Control
    ("spec.proxy.networking.trafficControl.inbound.excludedPorts",
     "spec.values.global.proxy.excludeInboundPorts",
     "Excluded Inbound Ports"),
    ("spec.proxy.networking.trafficControl.inbound.includedPorts",
     "spec.values.global.proxy.includeInboundPorts",
     "Included Inbound Ports"),
    ("spec.proxy.networking.trafficControl.inbound.interceptionMode",
     "spec.values.meshConfig.defaultConfig.interceptionMode",
     "Interception Mode"),
    ("spec.proxy.networking.trafficControl.outbound.excludedIPRanges",
     "spec.values.global.proxy.excludeIPRanges",
     "Excluded Outbound IP Ranges"),
    ("spec.proxy.networking.trafficControl.outbound.excludedPorts",
     "spec.values.global.proxy.excludeOutboundPorts",
     "Excluded Outbound Ports"),
    ("spec.proxy.networking.trafficControl.outbound.includedIPRanges",
     "spec.values.global.proxy.includeIPRanges",
     "Included Outbound IP Ranges"),
    ("spec.proxy.networking.trafficControl.outbound.policy",
     "spec.values.meshConfig.outboundTrafficPolicy.mode",
     "Outbound Traffic Policy"),
    # 7.1.1.6 Proxy - Runtime / Env (WICHTIG: DNS Capture!)
    ("spec.proxy.runtime.container.env",
     "spec.values.meshConfig.defaultConfig.proxyMetadata",
     "Proxy Container Env-Vars inkl. DNS Capture (ISTIO_META_DNS_CAPTURE)"),
    ("spec.proxy.runtime.container.resources",
     "spec.values.global.proxy.resources",
     "Proxy Resource Limits/Requests"),
    # 7.1.1.6 Proxy - Readiness
    ("spec.proxy.runtime.readiness.rewriteApplicationProbes",
     "spec.values.sidecarInjectorWebhook.rewriteAppHTTPProbe",
     "Rewrite Application HTTP Probes"),
    # 7.1.1.7 Runtime - Pilot
    ("spec.runtime.components.container.env",
     "spec.values.pilot.env",
     "Pilot (Istiod) Container Env-Vars"),
    ("spec.runtime.components.container.resources",
     "spec.values.pilot.resources",
     "Pilot Resource Limits/Requests"),
    ("spec.runtime.components.deployment.replicas",
     "spec.values.pilot.replicaCount",
     "Pilot Replica Count"),
    ("spec.runtime.components.deployment.autoScaling.enabled",
     "spec.values.pilot.autoscaleEnabled",
     "Pilot Autoscaling"),
    ("spec.runtime.components.deployment.autoScaling.minReplicas",
     "spec.values.pilot.autoscaleMin",
     "Pilot Autoscale Min Replicas"),
    ("spec.runtime.components.deployment.autoScaling.maxReplicas",
     "spec.values.pilot.autoscaleMax",
     "Pilot Autoscale Max Replicas"),
    ("spec.runtime.components.deployment.strategy.rollingUpdate.maxSurge",
     "spec.values.pilot.rollingMaxSurge",
     "Pilot Rolling Update Max Surge"),
    ("spec.runtime.components.deployment.strategy.rollingUpdate.maxUnavailable",
     "spec.values.pilot.rollingMaxUnavailable",
     "Pilot Rolling Update Max Unavailable"),
    ("spec.runtime.components.pod.nodeSelector",
     "spec.values.pilot.nodeSelector",
     "Pilot Node Selector"),
    ("spec.runtime.components.pod.tolerations",
     "spec.values.pilot.tolerations",
     "Pilot Tolerations"),
    ("spec.runtime.components.pod.affinity",
     "spec.values.pilot.affinity",
     "Pilot Pod Affinity"),
    ("spec.runtime.components.pod.metadata.annotations",
     "spec.values.pilot.podAnnotations",
     "Pilot Pod Annotations"),
    ("spec.runtime.components.pod.metadata.labels",
     "spec.values.pilot.podLabels",
     "Pilot Pod Labels"),
    # 7.1.1.7 Runtime - Defaults
    ("spec.runtime.defaults.container.resources",
     "spec.values.global.defaultResources",
     "Default Container Resources"),
    ("spec.runtime.defaults.deployment.podDisruption.enabled",
     "spec.values.global.defaultPodDisruptionBudget.enabled",
     "Default PodDisruptionBudget aktiviert"),
    ("spec.runtime.defaults.pod.nodeSelector",
     "spec.values.global.defaultNodeSelector",
     "Default Node Selector"),
    ("spec.runtime.defaults.pod.tolerations",
     "spec.values.global.defaultTolerations",
     "Default Tolerations"),
    # 7.1.1.8 Security - TLS
    ("spec.security.controlPlane.tls.minProtocolVersion",
     "spec.values.meshConfig.tlsDefaults.minProtocolVersion",
     "TLS Min Protocol Version"),
    ("spec.security.controlPlane.tls.cipherSuites",
     "spec.values.meshConfig.tlsDefaults.cipherSuites",
     "TLS Cipher Suites"),
    ("spec.security.controlPlane.tls.ecdhCurves",
     "spec.values.meshConfig.tlsDefaults.ecdhCurves",
     "TLS ECDH Curves"),
    ("spec.security.controlPlane.mtls",
     "spec.values.meshConfig.enableAutoMtls",
     "Control Plane Auto mTLS"),
    ("spec.security.controlPlane.certProvider",
     "spec.values.global.pilotCertProvider",
     "Cert Provider"),
    # 7.1.1.8 Security - Data Plane
    ("spec.security.dataPlane.automtls",
     "spec.values.meshConfig.enableAutoMtls",
     "Data Plane Auto mTLS"),
    ("spec.security.dataPlane.mtls",
     "spec.values.meshConfig.meshMTLS (+ PeerAuthentication und DestinationRule Ressourcen erstellen!)",
     "mTLS Strict Mode"),
    # 7.1.1.8 Security - Trust
    ("spec.security.trust.domain",
     "spec.values.meshConfig.trustDomain",
     "Trust Domain"),
    ("spec.security.trust.additionalDomains",
     "spec.values.meshConfig.trustDomainAliases",
     "Trust Domain Aliases"),
    # 7.1.1.8 Security - CA
    ("spec.security.certificateAuthority.istiod.type",
     "spec.values.global.pilotCertProvider",
     "Istiod CA Type"),
    ("spec.security.certificateAuthority.certmanager.address",
     "spec.values.meshConfig.ca.address",
     "cert-manager CA Adresse"),
    ("spec.security.certificateAuthority.custom.address",
     "spec.values.meshConfig.ca.address",
     "Custom CA Adresse"),
    # 7.1.1.8 Security - Identity
    ("spec.security.identity.thirdParty.audience",
     "spec.values.global.sds.token.aud",
     "Token Audience (Third Party JWT)"),
    # 7.1.1.8 Security - Other
    ("spec.security.jwksResolverCA",
     "spec.values.pilot.jwksResolverExtraRootCA",
     "JWKS Resolver CA"),
    # 7.1.1.9 Tracing
    ("spec.tracing.sampling",
     "spec.values.pilot.traceSampling",
     "Tracing Sampling Rate"),
]

# -- Farben für Terminal-Ausgabe -----------------------------------------------
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# -- Datenklassen --------------------------------------------------------------
@dataclass
class Finding:
    severity: str      # "deprecation" | "warning" | "info"
    namespace: str
    resource_type: str
    resource_name: str
    message: str
    action: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    scanned_namespaces: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, severity, namespace, resource_type, resource_name, message, action):
        self.findings.append(
            Finding(severity, namespace, resource_type, resource_name, message, action)
        )


# -- kubectl / oc Helper -------------------------------------------------------
def run_kubectl(args: list[str], tool: str = "kubectl") -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [tool] + args, capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        return False, result.stderr.strip()
    except FileNotFoundError:
        return False, f"{tool} not found"
    except subprocess.TimeoutExpired:
        return False, "timeout"


def get_json(resource: str, namespace: Optional[str], tool: str) -> Optional[dict]:
    args = ["get", resource, "-o", "json"]
    if namespace:
        args += ["-n", namespace]
    else:
        args += ["--all-namespaces"]
    ok, out = run_kubectl(args, tool)
    if not ok:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def crd_exists(crd_name: str, tool: str) -> bool:
    ok, _ = run_kubectl(["get", "crd", crd_name, "--ignore-not-found"], tool)
    return ok


def detect_tool() -> str:
    for t in ("oc", "kubectl"):
        ok, _ = run_kubectl(["version", "--client"], t)
        if ok:
            return t
    print(f"{RED}Fehler: Weder 'oc' noch 'kubectl' gefunden.{RESET}")
    sys.exit(1)


def get_namespaces(tool: str, namespace_filter: Optional[str]) -> list[str]:
    if namespace_filter:
        return [namespace_filter]
    ok, out = run_kubectl(
        ["get", "namespaces", "-o", "jsonpath={.items[*].metadata.name}"], tool
    )
    if not ok:
        print(f"{RED}Konnte Namespaces nicht abrufen: {out}{RESET}")
        sys.exit(1)
    return [ns for ns in out.split() if ns != "istio-system"]


def _nested_get(data: dict, *keys):
    """Sicherer verschachtelter dict-Zugriff."""
    current: object = data
    for k in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(k)
    return current


def _path_exists(spec: dict, smcp_path: str) -> tuple[bool, object]:
    """
    Prüft ob ein SMCP-Pfad wie 'spec.proxy.networking.protocol.autoDetect'
    im spec-dict existiert. Gibt (gefunden, wert) zurück.
    Funktioniert auch mit Schlüsseln die Bindestriche enthalten (z.B. cert-manager).
    """
    parts = smcp_path.split(".")
    if parts and parts[0] == "spec":
        parts = parts[1:]
    current = spec
    for part in parts:
        if not isinstance(current, dict):
            return False, None
        if part not in current:
            return False, None
        current = current[part]
    return True, current


# -- Cluster-weite Checks ------------------------------------------------------
def check_ossm2_crds(result: ScanResult, tool: str):
    """OSSM 2.x CRDs -> Blocker, da OSSM 3.0 Operator diese ablöst."""
    deprecated = {
        "servicemeshcontrolplanes.maistra.io": (
            "ServiceMeshControlPlane (maistra.io) CRD noch installiert",
            "Durch 'Istio' CRD (sailoperator.io/v1alpha1) ersetzen - "
            "kein In-Place-Upgrade möglich, Neuinstallation des Operators erforderlich",
        ),
        "servicemeshmemberrolls.maistra.io": (
            "ServiceMeshMemberRoll (maistra.io) CRD noch installiert",
            "Namespace-Mitgliedschaft jetzt über Labels: "
            "'istio-injection=enabled' oder 'istio.io/rev=<name>'",
        ),
        "servicemeshmembers.maistra.io": (
            "ServiceMeshMember (maistra.io) CRD noch installiert",
            "Namespace-Labels direkt setzen statt ServiceMeshMember verwenden",
        ),
    }
    for crd, (msg, action) in deprecated.items():
        if crd_exists(crd, tool):
            result.add("deprecation", "cluster", "CRD", crd, msg, action)


def check_ossm3_crds_present(result: ScanResult, tool: str):
    """Prüft ob OSSM 3.0 (Sail Operator) CRDs bereits vorhanden sind."""
    ossm3 = {
        "istios.sailoperator.io":             "Istio (Sail Operator) Haupt-CRD",
        "istiocnis.sailoperator.io":          "IstioCNI CRD",
        "istiorevisions.sailoperator.io":     "IstioRevision CRD",
        "istiorevisiontags.sailoperator.io":  "IstioRevisionTag CRD",
        "ztunnels.sailoperator.io":           "ZTunnel CRD (Ambient Mode)",
    }
    for crd, desc in ossm3.items():
        if crd_exists(crd, tool):
            result.add(
                "info", "cluster", "CRD", crd,
                f"OSSM 3.0 CRD vorhanden: {desc}",
                "Sail Operator bereits installiert - parallele Koexistenz während Migration möglich",
            )


# -- SMCP Feldebenen-Check (configuration.txt Kapitel 7) ----------------------
def check_smcp_fields(result: ScanResult, tool: str, namespace: str):
    """
    Prüft alle SMCP-Instanzen auf:
    - UNSUPPORTED_SMCP_FIELDS (7.1.2): Felder die in OSSM 3.0 komplett entfallen -> DEPRECATION
    - MIGRATED_SMCP_FIELDS   (7.1.1): Felder mit neuem Pfad in OSSM 3.0 -> WARNING mit Migrationspfad
    """
    data = get_json("servicemeshcontrolplanes.maistra.io", namespace, tool)
    if not data or not data.get("items"):
        return

    for item in data["items"]:
        name = item.get("metadata", {}).get("name", "unknown")
        spec = item.get("spec", {})

        # Unsupported -> DEPRECATION
        for smcp_path, kategorie, aktion in UNSUPPORTED_SMCP_FIELDS:
            found, val = _path_exists(spec, smcp_path)
            if found:
                result.add(
                    "deprecation", namespace, "ServiceMeshControlPlane", name,
                    f"[{kategorie}] Feld '{smcp_path}' in OSSM 3.0 nicht unterstützt "
                    f"(Wert: {repr(val)!s:.60})",
                    aktion,
                )

        # Migriert -> WARNING mit neuem Pfad
        for smcp_path, ossm3_path, beschreibung in MIGRATED_SMCP_FIELDS:
            found, val = _path_exists(spec, smcp_path)
            if found:
                result.add(
                    "warning", namespace, "ServiceMeshControlPlane", name,
                    f"[{beschreibung}] Feld '{smcp_path}' muss migriert werden "
                    f"(aktueller Wert: {repr(val)!s:.60})",
                    f"In OSSM 3.0 Istio-Resource: '{ossm3_path}'",
                )


# -- SMCP (ServiceMeshControlPlane) Strukturelle Analyse -----------------------
def check_smcp(result: ScanResult, tool: str, namespace: str):
    """
    Analysiert ServiceMeshControlPlane auf:
    - Addon-Konfigurationen die in OSSM 3.0 entfallen
    - IOR (auto-routes)
    - Gateway-Konfiguration in SMCP (muss zu Gateway-Injection migriert werden)
    - TLS-Einstellungen die sich geändert haben
    - DNS Capture (war in 2.6 Standard, in 3.0 muss explizit aktiviert werden)
    - Network Policy Management
    - Unsupported Felder
    - Deployment-Modell (Multitenant vs. Cluster-Wide)
    - cert-manager Nutzung
    """
    data = get_json("servicemeshcontrolplanes.maistra.io", namespace, tool)
    if not data or not data.get("items"):
        return

    for item in data["items"]:
        name = item.get("metadata", {}).get("name", "unknown")
        spec = item.get("spec", {})

        # -- Deployment-Modell -------------------------------------------------
        mode = spec.get("mode", "MultiTenant")
        result.add(
            "info", namespace, "ServiceMeshControlPlane", name,
            f"Deployment-Modell: '{mode}' "
            f"({'Standard' if not spec.get('mode') else 'explizit gesetzt'})",
            f"Für OSSM 3.0: {'discoverySelectors konfigurieren für MultiTenant-ähnliches Verhalten' if 'Multi' in mode else 'Cluster-wide ist OSSM 3.0 Standard'}",
        )

        # -- Version ----------------------------------------------------------
        version = spec.get("version", "nicht gesetzt")
        result.add(
            "info", namespace, "ServiceMeshControlPlane", name,
            f"SMCP Version: '{version}' - muss vor Migration auf 2.6.14 sein",
            "Update auf OSSM 2.6.14 vor der Migration zu 3.0 erforderlich",
        )

        addons = spec.get("addons", {})

        # -- Add-ons: Prometheus -----------------------------------------------
        prom = _nested_get(addons, "prometheus", "enabled")
        if prom is True or (prom is None and addons.get("prometheus") is not None):
            result.add(
                "deprecation", namespace, "ServiceMeshControlPlane", name,
                "spec.addons.prometheus ist aktiviert (oder Standard)",
                "Vor Migration deaktivieren: spec.addons.prometheus.enabled=false. "
                "Ersatz: OpenShift User Workload Monitoring (separater Operator)",
            )

        # -- Add-ons: Grafana --------------------------------------------------
        grafana = _nested_get(addons, "grafana", "enabled")
        if grafana is True or (grafana is None and addons.get("grafana") is not None):
            result.add(
                "deprecation", namespace, "ServiceMeshControlPlane", name,
                "spec.addons.grafana ist aktiviert (oder Standard)",
                "Vor Migration deaktivieren: spec.addons.grafana.enabled=false. "
                "Grafana wird in OSSM 3.0 nicht mehr unterstützt.",
            )

        # -- Add-ons: Kiali ----------------------------------------------------
        kiali = _nested_get(addons, "kiali", "enabled")
        if kiali is True or (kiali is None and addons.get("kiali") is not None):
            result.add(
                "deprecation", namespace, "ServiceMeshControlPlane", name,
                "spec.addons.kiali ist aktiviert (oder Standard)",
                "Vor Migration deaktivieren: spec.addons.kiali.enabled=false. "
                "Kiali separat über 'Kiali Operator provided by Red Hat' installieren.",
            )

        # -- Add-ons: Jaeger / Tracing -----------------------------------------
        tracing_type = _nested_get(spec, "tracing", "type")
        if isinstance(tracing_type, str) and tracing_type.lower() != "none":
            result.add(
                "deprecation", namespace, "ServiceMeshControlPlane", name,
                f"spec.tracing.type='{tracing_type}' (Jaeger/Tracing aktiviert)",
                "Vor Migration deaktivieren: spec.tracing.type=None. "
                "Ersatz: Red Hat OpenShift distributed tracing platform (Tempo)",
            )

        # -- Add-ons: 3scale / Stackdriver -------------------------------------
        for unsupported_addon in ("3scale", "stackdriver"):
            if unsupported_addon in addons:
                result.add(
                    "deprecation", namespace, "ServiceMeshControlPlane", name,
                    f"spec.addons.{unsupported_addon} konfiguriert - nicht in OSSM 3.0 unterstützt",
                    f"Add-on '{unsupported_addon}' entfernen und separat konfigurieren",
                )

        # -- IOR (Istio OpenShift Routing) -------------------------------------
        gateways_spec = spec.get("gateways", {})
        ior = _nested_get(gateways_spec, "openshiftRoute", "enabled")
        gateways_enabled = gateways_spec.get("enabled", None)
        if ior is True:
            result.add(
                "deprecation", namespace, "ServiceMeshControlPlane", name,
                "IOR (gateways.openshiftRoute.enabled=true) ist aktiv",
                "IOR wurde in OSSM 2.5 deprecated, in 3.0 entfernt. "
                "Alle Routes vor Migration explizit als OpenShift Route-Objekte erstellen. "
                "Dann: spec.gateways.openshiftRoute.enabled=false setzen.",
            )
        elif gateways_enabled is not False and ior is not False:
            result.add(
                "warning", namespace, "ServiceMeshControlPlane", name,
                "IOR-Status unklar (gateways.openshiftRoute.enabled nicht explizit false)",
                "Sicherstellen, dass IOR deaktiviert ist (spec.gateways.openshiftRoute.enabled=false) "
                "und alle Routes explizit existieren.",
            )

        # -- Gateways in SMCP (müssen zu Gateway-Injection migriert werden) ----
        if gateways_enabled is not False:
            result.add(
                "deprecation", namespace, "ServiceMeshControlPlane", name,
                "Gateways werden über SMCP verwaltet (spec.gateways.enabled nicht false)",
                "OSSM 3.0 verwaltet Gateways nicht mehr im Control Plane. "
                "Zu Gateway-Injection oder Kubernetes Gateway API migrieren "
                "BEVOR der Umstieg auf OSSM 3.0 erfolgt.",
            )

        # -- Network Policy Management -----------------------------------------
        manage_np = _nested_get(spec, "security", "manageNetworkPolicy")
        if manage_np is True or manage_np is None:
            result.add(
                "deprecation", namespace, "ServiceMeshControlPlane", name,
                "spec.security.manageNetworkPolicy ist aktiv (Standard: true)",
                "OSSM 3.0 erstellt keine NetworkPolicies mehr. "
                "Vor Migration: spec.security.manageNetworkPolicy=false setzen, "
                "dann NetworkPolicies manuell neu erstellen.",
            )

        # -- TLS-Konfiguration -------------------------------------------------
        mtls = _nested_get(spec, "security", "dataPlane", "mtls")
        if mtls is True:
            result.add(
                "warning", namespace, "ServiceMeshControlPlane", name,
                "mTLS Strict-Mode über spec.security.dataPlane.mtls=true konfiguriert",
                "In OSSM 3.0 mTLS über PeerAuthentication und DestinationRule Ressourcen aktivieren. "
                "Das SMCP-Feld wird nicht mehr unterstützt.",
            )

        tls_max = _nested_get(spec, "security", "controlPlane", "tls", "maxProtocolVersion")
        tls_min = _nested_get(spec, "security", "controlPlane", "tls", "minProtocolVersion")
        if tls_max:
            result.add(
                "deprecation", namespace, "ServiceMeshControlPlane", name,
                f"spec.security.controlPlane.tls.maxProtocolVersion='{tls_max}' - nicht in OSSM 3.0 unterstützt",
                "Dieses Feld entfernen. In OSSM 3.0 wird maxProtocolVersion nicht unterstützt.",
            )
        if tls_min:
            result.add(
                "warning", namespace, "ServiceMeshControlPlane", name,
                f"spec.security.controlPlane.tls.minProtocolVersion='{tls_min}' gesetzt",
                "In OSSM 3.0: spec.meshConfig.tlsDefaults.minProtocolVersion im Istio-Resource setzen.",
            )

        # -- DNS Capture (war in OSSM 2.6 Standard, in 3.0 nicht mehr) --------
        dns_capture = _nested_get(
            spec, "proxy", "runtime", "container", "env"
        )
        if dns_capture:
            env_dict = {e.get("name"): e.get("value") for e in (dns_capture or []) if isinstance(e, dict)}
            for dns_key in ("ISTIO_META_DNS_CAPTURE", "ISTIO_META_DNS_AUTO_ALLOCATE"):
                if dns_key in env_dict:
                    result.add(
                        "info", namespace, "ServiceMeshControlPlane", name,
                        f"DNS-Capture Konfiguration gefunden: {dns_key}={env_dict[dns_key]}",
                        "In OSSM 3.0 unter spec.values.meshConfig.defaultConfig.proxyMetadata setzen. "
                        "DNS Capture war in OSSM 2.6 Standard - in 3.0 muss es explizit aktiviert werden!",
                    )
        else:
            result.add(
                "warning", namespace, "ServiceMeshControlPlane", name,
                "DNS Capture Konfiguration nicht explizit gesetzt",
                "ACHTUNG: OSSM 2.6 aktivierte DNS Capture (ISTIO_META_DNS_CAPTURE) standardmäßig. "
                "OSSM 3.0 tut dies NICHT mehr. Falls ServiceEntries mit DNS-Auflösung vorhanden: "
                "In Istio-Resource setzen: spec.values.meshConfig.defaultConfig.proxyMetadata: "
                "{ISTIO_META_DNS_CAPTURE: 'true', ISTIO_META_DNS_AUTO_ALLOCATE: 'true'}",
            )

        # -- cert-manager Nutzung ----------------------------------------------
        ca_type = _nested_get(spec, "security", "certificateAuthority", "type")
        if ca_type and "cert-manager" in str(ca_type).lower():
            result.add(
                "warning", namespace, "ServiceMeshControlPlane", name,
                f"cert-manager als Certificate Authority konfiguriert (type={ca_type})",
                "cert-manager Nutzung erfordert zusätzliche Migrationsschritte. "
                "Siehe 'Migrating a cluster-wide deployment by using the Istio revision label with cert-manager'. "
                "Felder spec.security.certificateAuthority.cert-manager.pilotSecretName und "
                "rootCAConfigMapName werden in OSSM 3.0 NICHT unterstützt.",
            )

        # -- Unsupported Policy Felder -----------------------------------------
        policy = spec.get("policy", {})
        for unsupported in ("mixer", "remote"):
            if unsupported in policy:
                result.add(
                    "deprecation", namespace, "ServiceMeshControlPlane", name,
                    f"spec.policy.{unsupported} konfiguriert - in OSSM 3.0 nicht unterstützt",
                    f"Feld spec.policy.{unsupported} entfernen vor Migration",
                )

        # -- Unsupported Telemetry Felder --------------------------------------
        telemetry = spec.get("telemetry", {})
        for unsupported in ("mixer", "remote", "type"):
            if unsupported in telemetry:
                result.add(
                    "deprecation", namespace, "ServiceMeshControlPlane", name,
                    f"spec.telemetry.{unsupported} konfiguriert - in OSSM 3.0 nicht unterstützt",
                    f"Feld spec.telemetry.{unsupported} entfernen vor Migration",
                )

        # -- Unsupported Proxy-Networking Felder -------------------------------
        proxy_net = _nested_get(spec, "proxy", "networking") or {}
        unsupported_proxy_fields = [
            ("initialization", "type"),
            ("protocol", "autoDetect"),
            ("protocol", "inbound"),
            ("protocol", "outbound"),
        ]
        for path in unsupported_proxy_fields:
            val = _nested_get(proxy_net, *path)
            if val is not None:
                field_path = ".".join(path)
                result.add(
                    "deprecation", namespace, "ServiceMeshControlPlane", name,
                    f"spec.proxy.networking.{field_path} gesetzt - in OSSM 3.0 nicht unterstützt",
                    "Feld entfernen. OSSM 3.0 basiert direkt auf Istio-Helm-Werten.",
                )


# -- ServiceEntry Checks -------------------------------------------------------
def check_service_entries(result: ScanResult, tool: str, namespace: str):
    """
    Prüft ServiceEntries auf:
    - >256 Hosts (OSSM 3.0 Installation schlägt fehl!)
    - Fehlende Port-Spezifikation (OSSM 3.0 Installation schlägt fehl!)
    - Nutzung von DNS-Auflösung (braucht explizite DNS Capture Konfiguration in 3.0)
    """
    data = get_json("serviceentries.networking.istio.io", namespace, tool)
    if not data or not data.get("items"):
        return

    for item in data["items"]:
        name = item.get("metadata", {}).get("name", "unknown")
        spec = item.get("spec", {})
        hosts = spec.get("hosts", [])
        ports = spec.get("ports", [])
        resolution = spec.get("resolution", "")

        # Kritisch: >256 Hosts - OSSM 3.0 Operator-Installation schlägt fehl
        if len(hosts) > 256:
            result.add(
                "deprecation", namespace, "ServiceEntry", name,
                f"ServiceEntry hat {len(hosts)} Hosts - LIMIT: 256 (Istio 1.24 Schema-Änderung)",
                "KRITISCH: OSSM 3.0 Operator-Installation schlägt fehl! "
                "ServiceEntry VOR Migration in mehrere Ressourcen mit je <=256 Hosts aufteilen. "
                "Prüfen: oc get serviceentries -A -o json | jq -r '.items[] | "
                "select(.spec.hosts | length > 256) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'",
            )
        elif len(hosts) > 200:
            result.add(
                "warning", namespace, "ServiceEntry", name,
                f"ServiceEntry hat {len(hosts)} Hosts (nahe am 256er-Limit)",
                "Aufteilen empfohlen um das Limit nicht zu überschreiten",
            )

        # Kritisch: Fehlende Ports - OSSM 3.0 Installation schlägt fehl
        if not ports:
            result.add(
                "deprecation", namespace, "ServiceEntry", name,
                "ServiceEntry hat keine Port-Spezifikation (spec.ports fehlt oder leer)",
                "KRITISCH: OSSM 3.0 Operator-Installation schlägt fehl! "
                "Port-Spezifikation hinzufügen. "
                "Prüfen: oc get serviceentries -A -o json | jq -r '.items[] | "
                "select(.spec.ports == null or (.spec.ports | length == 0)) | "
                "\"\\(.metadata.namespace)/\\(.metadata.name)\"'",
            )

        # DNS-Auflösung -> DNS Capture Warnung
        if resolution in ("DNS", "DNS_ROUND_ROBIN") or any(
            not host.startswith("*") for host in hosts
        ):
            result.add(
                "warning", namespace, "ServiceEntry", name,
                f"ServiceEntry mit resolution='{resolution or 'STATIC'}' und externen Hosts "
                "- DNS Capture prüfen",
                "OSSM 2.6 aktivierte DNS Capture standardmäßig, OSSM 3.0 nicht. "
                "Falls die App auf DNS-Auflösung angewiesen ist: "
                "ISTIO_META_DNS_CAPTURE=true und ISTIO_META_DNS_AUTO_ALLOCATE=true "
                "in spec.values.meshConfig.defaultConfig.proxyMetadata des Istio-Resources setzen.",
            )


# -- Namespace Label Checks ----------------------------------------------------
def check_namespace_labels(result: ScanResult, tool: str, namespace: str):
    """
    Prüft Namespace-Labels auf:
    - maistra.io/member-of (OSSM 2.x, wird bei Migration entfernt)
    - maistra.io/ignore-namespace (Migrations-Label)
    - maistra.io/expose-route (für NetworkPolicy, muss nach Migration bereinigt werden)
    - Fehlende Injection-Labels
    - Korrekte OSSM 3.0 Labels
    """
    ok, out = run_kubectl(["get", "namespace", namespace, "-o", "json"], tool)
    if not ok:
        result.errors.append(f"Namespace '{namespace}' nicht abrufbar: {out}")
        return
    try:
        ns_data = json.loads(out)
    except json.JSONDecodeError:
        return

    labels      = ns_data.get("metadata", {}).get("labels", {})
    annotations = ns_data.get("metadata", {}).get("annotations", {})

    # maistra.io/member-of -> deprecated
    if "maistra.io/member-of" in labels:
        cp = labels["maistra.io/member-of"]
        result.add(
            "deprecation", namespace, "Namespace", namespace,
            f"Label 'maistra.io/member-of: {cp}' ist OSSM 2.x spezifisch",
            "Nach Migration durch 'istio-injection=enabled' oder 'istio.io/rev=<revision>' ersetzen. "
            "Wird bei Namespace-Migration automatisch entfernt.",
        )

    # maistra.io/ignore-namespace -> Migrations-Label
    if "maistra.io/ignore-namespace" in labels:
        val = labels["maistra.io/ignore-namespace"]
        result.add(
            "warning", namespace, "Namespace", namespace,
            f"Label 'maistra.io/ignore-namespace: {val}' - Namespace in laufender Migration?",
            "Dieses Label signalisiert OSSM 2.x, die Injection zu ignorieren. "
            "Nach abgeschlossener Migration (OSSM 2.x entfernt) dieses Label entfernen: "
            f"oc label namespace {namespace} maistra.io/ignore-namespace-",
        )

    # maistra.io/expose-route -> NetworkPolicy Relevanz
    if "maistra.io/expose-route" in labels:
        val = labels["maistra.io/expose-route"]
        result.add(
            "warning", namespace, "Namespace", namespace,
            f"Label 'maistra.io/expose-route: {val}' - wird für OSSM 2.x NetworkPolicies verwendet",
            "OSSM 3.0 erstellt keine NetworkPolicies mehr. Nach Migration prüfen ob Label "
            "noch benötigt wird und ggf. entfernen.",
        )

    # Injection-Status
    has_injection = (
        "istio-injection" in labels
        or "istio.io/rev" in labels
        or "maistra.io/member-of" in labels
    )
    if not has_injection:
        result.add(
            "info", namespace, "Namespace", namespace,
            "Kein Injection-Label - Namespace wahrscheinlich nicht im Mesh",
            "Für OSSM 3.0 Mesh-Mitgliedschaft: 'istio-injection=enabled' (nur wenn IstioRevision name='default') "
            "oder 'istio.io/rev=<revision-name>' setzen.",
        )
    else:
        if "istio.io/rev" in labels:
            rev = labels["istio.io/rev"]
            result.add(
                "info", namespace, "Namespace", namespace,
                f"Label 'istio.io/rev={rev}' gesetzt (OSSM 3.0 kompatibel)",
                f"IstioRevision oder IstioRevisionTag mit Name '{rev}' sicherstellen: "
                "oc get istiorevision",
            )

    # Alle maistra.io Annotations
    maistra_annotations = {k: v for k, v in annotations.items() if "maistra.io" in k}
    for key, val in maistra_annotations.items():
        result.add(
            "warning", namespace, "Namespace", namespace,
            f"Annotation '{key}: {val}' ist maistra.io-spezifisch",
            "Prüfen ob Annotation in OSSM 3.0 noch benötigt wird - ggf. nach Migration entfernen",
        )


# -- Pod Annotation / Label Checks ---------------------------------------------
def check_pod_annotations(result: ScanResult, tool: str, namespace: str):
    """
    Prüft Pods auf:
    - sidecar.istio.io/inject als Annotation (veraltet -> soll Label sein)
    - maistra.io Labels/Annotations
    - sidecar.istio.io/inject="true" als Label (korrekte OSSM 3.0 Methode)
    """
    data = get_json("pods", namespace, tool)
    if not data or not data.get("items"):
        return

    # Deduplizierung pro Deployment (nur ersten Pod melden)
    seen_annotations: set[str] = set()

    for pod in data["items"]:
        pod_name  = pod.get("metadata", {}).get("name", "unknown")
        pod_labels = pod.get("metadata", {}).get("labels", {})
        annotations = pod.get("metadata", {}).get("annotations", {})

        # sidecar.istio.io/inject als ANNOTATION (deprecated - soll Label sein)
        if "sidecar.istio.io/inject" in annotations:
            val = annotations["sidecar.istio.io/inject"]
            dedup_key = f"{namespace}/annotation/sidecar.istio.io/inject"
            if dedup_key not in seen_annotations:
                seen_annotations.add(dedup_key)
                result.add(
                    "warning", namespace, "Pod", pod_name,
                    f"Pod-Annotation 'sidecar.istio.io/inject: {val}' ist veraltet",
                    "Istio Project hat Pod-Annotations zugunsten von Labels deprecated. "
                    "Als Label setzen: 'sidecar.istio.io/inject: \"true\"' in spec.template.metadata.labels",
                )

        # proxy.istio.io Annotations prüfen
        proxy_annotations = {k: v for k, v in annotations.items() if "proxy.istio.io" in k}
        for key, val in proxy_annotations.items():
            result.add(
                "info", namespace, "Pod", pod_name,
                f"Pod-Annotation '{key}: {val}' - proxy.istio.io Konfiguration",
                "proxy.istio.io Annotations werden in OSSM 3.0 grundsätzlich unterstützt, "
                "aber Kompatibilität im Einzelfall prüfen.",
            )

        # maistra.io Annotations/Labels auf Pods
        for key, val in annotations.items():
            if "maistra.io" in key:
                result.add(
                    "warning", namespace, "Pod", pod_name,
                    f"Pod-Annotation '{key}: {val}' ist maistra.io-spezifisch",
                    "Prüfen ob diese Annotation in OSSM 3.0 noch unterstützt wird",
                )
        for key, val in pod_labels.items():
            if "maistra.io" in key:
                result.add(
                    "warning", namespace, "Pod", pod_name,
                    f"Pod-Label '{key}: {val}' ist maistra.io-spezifisch",
                    "Prüfen ob dieses Label in OSSM 3.0 noch unterstützt wird",
                )


# -- VirtualService / Gateway Checks ------------------------------------------
def check_virtual_services_gateways(result: ScanResult, tool: str, namespace: str):
    """
    Prüft VirtualServices auf IOR-Abhängigkeiten (externe Gateways ohne explizite Routes).
    Prüft Gateways auf SMCP-definierte Gateways vs. Gateway-Injection.
    """
    vs_data = get_json("virtualservices.networking.istio.io", namespace, tool)
    if vs_data and vs_data.get("items"):
        for vs in vs_data["items"]:
            name     = vs.get("metadata", {}).get("name", "unknown")
            gateways = vs.get("spec", {}).get("gateways", [])

            if gateways and "mesh" not in gateways:
                result.add(
                    "warning", namespace, "VirtualService", name,
                    f"VirtualService nutzt externen Gateway: {gateways}",
                    "IOR (auto-Route-Erstellung) wurde entfernt. "
                    "Sicherstellen, dass für alle Hosts explizite OpenShift Routes existieren. "
                    "Alternativ: Gateway über LoadBalancer Service exponieren.",
                )

    gw_data = get_json("gateways.networking.istio.io", namespace, tool)
    if gw_data and gw_data.get("items"):
        for gw in gw_data["items"]:
            name   = gw.get("metadata", {}).get("name", "unknown")
            labels = gw.get("metadata", {}).get("labels", {})

            # Prüfen ob Gateway über Gateway-Injection managed (hat istio Label)
            is_gateway_injection = "istio" in labels or "app" in labels
            result.add(
                "info", namespace, "Gateway", name,
                f"Gateway '{name}' gefunden - "
                f"{'Gateway-Injection erkannt' if is_gateway_injection else 'SMCP-Gateway?'}",
                "OSSM 3.0 verwaltet keine SMCP-Gateways mehr. "
                "Zu Gateway-Injection oder Kubernetes Gateway API migrieren. "
                "Zugehörige OpenShift Routes müssen explizit existieren.",
            )


# -- Observability Checks ------------------------------------------------------
def check_observability_resources(result: ScanResult, tool: str, namespace: str):
    """
    Prüft ob Observability-Komponenten durch OSSM 2.x verwaltet werden.
    In OSSM 3.0 werden diese durch separate Operatoren bereitgestellt.
    """
    obs_apps = {"prometheus", "grafana", "jaeger", "kiali", "elasticsearch", "jaeger-collector"}
    data = get_json("deployments", namespace, tool)
    if not data or not data.get("items"):
        return

    for dep in data["items"]:
        name       = dep.get("metadata", {}).get("name", "")
        labels     = dep.get("metadata", {}).get("labels", {})
        owner_refs = dep.get("metadata", {}).get("ownerReferences", [])

        is_maistra = any(
            ref.get("apiVersion", "").startswith("maistra.io") for ref in owner_refs
        )
        app_label = labels.get("app", "").lower()

        if any(obs in app_label for obs in obs_apps):
            if is_maistra:
                result.add(
                    "deprecation", namespace, "Deployment", name,
                    f"'{name}' wird durch OSSM 2.x Operator verwaltet",
                    "OSSM 3.0 verwaltet Prometheus/Grafana/Jaeger/Kiali/Elasticsearch nicht mehr. "
                    "Separate Operatoren installieren: "
                    "Kiali Operator, Red Hat build of OpenTelemetry, Tempo Operator, "
                    "Red Hat OpenShift Observability.",
                )
            else:
                result.add(
                    "info", namespace, "Deployment", name,
                    f"'{name}' ist eine Observability-Komponente - Verwaltungsmodell prüfen",
                    "Sicherstellen dass diese Komponente nach Migration durch unabhängige Operatoren verwaltet wird",
                )


# -- OSSM 2.x Ressourcen (SMCP, SMMR, SMM) ------------------------------------
def check_ossm2_resources(result: ScanResult, tool: str, namespace: str):
    """Prüft auf vorhandene OSSM 2.x Ressourcen."""
    resources = [
        (
            "servicemeshmemberrolls.maistra.io",
            "ServiceMeshMemberRoll",
            "Durch Namespace-Labels ersetzen: 'istio-injection=enabled' oder 'istio.io/rev=<name>'",
        ),
        (
            "servicemeshmembers.maistra.io",
            "ServiceMeshMember",
            "Namespace-Labels direkt setzen statt ServiceMeshMember verwenden",
        ),
    ]
    for resource_type, display_name, action in resources:
        data = get_json(resource_type, namespace, tool)
        if data and data.get("items"):
            for item in data["items"]:
                name = item.get("metadata", {}).get("name", "unknown")
                result.add(
                    "deprecation", namespace, display_name, name,
                    f"Veraltete OSSM 2.x Ressource '{display_name}' vorhanden",
                    action,
                )


# -- Hauptroutine --------------------------------------------------------------
def scan(namespaces: list[str], tool: str) -> ScanResult:
    result = ScanResult()

    print(f"\n{BOLD}=== OSSM Migration Scanner (2.6.x -> 3.0.x) ==={RESET}")
    print(f"  Tool      : {tool}")
    print(f"  Namespaces: {len(namespaces)}\n")

    print(f"{BOLD}[Cluster] CRD-Analyse...{RESET}")
    check_ossm2_crds(result, tool)
    check_ossm3_crds_present(result, tool)

    for ns in namespaces:
        result.scanned_namespaces.append(ns)
        print(f"{BOLD}[Namespace: {ns}]{RESET}")
        check_namespace_labels(result, tool, ns)
        check_smcp(result, tool, ns)
        check_smcp_fields(result, tool, ns)
        check_ossm2_resources(result, tool, ns)
        check_service_entries(result, tool, ns)
        check_pod_annotations(result, tool, ns)
        check_observability_resources(result, tool, ns)
        check_virtual_services_gateways(result, tool, ns)

    return result


# -- Report Ausgabe ------------------------------------------------------------
def print_report(result: ScanResult):
    deprecations = [f for f in result.findings if f.severity == "deprecation"]
    warnings     = [f for f in result.findings if f.severity == "warning"]
    infos        = [f for f in result.findings if f.severity == "info"]

    print(f"\n{BOLD}{'=' * 72}{RESET}")
    print(f"{BOLD}  OSSM Migrations-Report: 2.6.x -> 3.0.x{RESET}")
    print(f"{BOLD}{'=' * 72}{RESET}")
    print(f"  Namespaces gescannt : {len(result.scanned_namespaces)}")
    print(f"  {RED}Deprecations (Blocker): {len(deprecations)}{RESET}")
    print(f"  {YELLOW}Warnungen             : {len(warnings)}{RESET}")
    print(f"  {BLUE}Informationen         : {len(infos)}{RESET}")
    if result.errors:
        print(f"  {RED}Scan-Fehler           : {len(result.errors)}{RESET}")

    def print_section(title, findings, color, prefix):
        if not findings:
            return
        print(f"\n{BOLD}{color}{'-' * 72}")
        print(f"  {title} ({len(findings)})")
        print(f"{'-' * 72}{RESET}")
        for f in findings:
            loc = f"[{f.namespace}/{f.resource_type}/{f.resource_name}]"
            print(f"\n  {color}{prefix}{RESET} {BOLD}{loc}{RESET}")
            print(f"      Problem : {f.message}")
            print(f"      Aktion  : {f.action}")

    print_section(
        "DEPRECATIONS - Müssen VOR Migration behoben werden",
        deprecations, RED, "[DEPR]",
    )
    print_section(
        "WARNUNGEN - Sollten vor Migration geprüft werden",
        warnings, YELLOW, "[WARN]",
    )
    print_section(
        "INFORMATIONEN - Zur Kenntnis nehmen",
        infos, BLUE, "[INFO]",
    )

    if result.errors:
        print(f"\n{BOLD}{RED}{'-' * 72}")
        print("  SCAN-FEHLER")
        print(f"{'-' * 72}{RESET}")
        for err in result.errors:
            print(f"  {RED}[ERR]{RESET} {err}")

    print(f"\n{BOLD}{'=' * 72}{RESET}")
    print(f"\n{BOLD}Migrations-Pflichtliste (aus Red Hat OSSM 3.0 Migrationsdokumentation):{RESET}")
    checklist = [
        # (Farbe, Pflicht/optional, Text)
        ("Rot",  "MUSS", "Auf OSSM 2.6.14 updaten (Voraussetzung für Migration)"),
        ("Rot",  "MUSS", "ServiceEntries mit >256 Hosts aufteilen (Blocker!)"),
        ("Rot",  "MUSS", "ServiceEntries ohne Port-Spezifikation reparieren (Blocker!)"),
        ("Rot",  "MUSS", "spec.addons.prometheus.enabled=false im SMCP setzen"),
        ("Rot",  "MUSS", "spec.addons.grafana.enabled=false im SMCP setzen"),
        ("Rot",  "MUSS", "spec.addons.kiali.enabled=false im SMCP setzen"),
        ("Rot",  "MUSS", "spec.tracing.type=None im SMCP setzen"),
        ("Rot",  "MUSS", "IOR deaktivieren: gateways.openshiftRoute.enabled=false"),
        ("Rot",  "MUSS", "Alle OpenShift Routes explizit erstellen (IOR-Ersatz)"),
        ("Rot",  "MUSS", "SMCP-Gateways zu Gateway-Injection migrieren"),
        ("Rot",  "MUSS", "spec.security.manageNetworkPolicy=false im SMCP setzen"),
        ("Gelb", "SOLL", "DNS Capture explizit konfigurieren (war in 2.6 Standard)"),
        ("Gelb", "SOLL", "mTLS Strict-Mode zu PeerAuthentication/DestinationRule migrieren"),
        ("Gelb", "SOLL", "TLS minProtocolVersion zu Istio-Resource migrieren"),
        ("Gelb", "SOLL", "Pod-Annotations 'sidecar.istio.io/inject' durch Labels ersetzen"),
        ("Gelb", "SOLL", "maistra.io Labels nach Migration von Namespaces entfernen"),
        ("Gelb", "SOLL", "cert-manager Integration prüfen (eigene Migrationspfade)"),
        ("Blau", "INFO", "Kiali Operator (by Red Hat) separat installieren"),
        ("Blau", "INFO", "Tempo Operator für Distributed Tracing installieren"),
        ("Blau", "INFO", "IstioCNI Resource im Sail Operator konfigurieren"),
        ("Blau", "INFO", "IstioRevision-Strategie wählen: InPlace vs. RevisionBased"),
        ("Blau", "INFO", "discoverySelectors für Namespace-Scoping konfigurieren"),
    ]
    icons = {"Rot": f"{RED}x{RESET}", "Gelb": f"{YELLOW}!{RESET}", "Blau": f"{BLUE}i{RESET}"}
    for color, pflicht, item in checklist:
        print(f"  {icons[color]} [{pflicht}] {item}")
    print()


def export_json(result: ScanResult, path: str):
    data = {
        "scanned_namespaces": result.scanned_namespaces,
        "summary": {
            "deprecations": sum(1 for f in result.findings if f.severity == "deprecation"),
            "warnings":     sum(1 for f in result.findings if f.severity == "warning"),
            "infos":        sum(1 for f in result.findings if f.severity == "info"),
        },
        "findings": [
            {
                "severity":      f.severity,
                "namespace":     f.namespace,
                "resource_type": f.resource_type,
                "resource_name": f.resource_name,
                "message":       f.message,
                "action":        f.action,
            }
            for f in result.findings
        ],
        "errors": result.errors,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    print(f"{GREEN}Report exportiert: {path}{RESET}")


# -- Mapping-Tabelle -----------------------------------------------------------
def _print_mapping_table():
    """Gibt die vollständige Feldmapping-Tabelle aus (--show-mapping)."""
    print(f"\n{BOLD}{'=' * 72}{RESET}")
    print(f"{BOLD}  SMCP 2.6 -> Istio 3.0: Vollständige Feldmappings{RESET}")
    print(f"{BOLD}  Quelle: OSSM 3.0 Migrationsdokumentation Kapitel 7.1.1{RESET}")
    print(f"{BOLD}{'=' * 72}{RESET}\n")

    print(f"{BOLD}{YELLOW}  MIGRIERTE FELDER (neuer Pfad in OSSM 3.0 Istio-Resource):{RESET}")
    print(f"  {'SMCP 2.6 Pfad':<55} {'Istio 3.0 Pfad'}")
    print(f"  {'-' * 55} {'-' * 50}")
    for smcp, ossm3, desc in MIGRATED_SMCP_FIELDS:
        smcp_short  = smcp.replace("spec.", "")
        ossm3_short = ossm3.replace("spec.", "")
        print(f"  {smcp_short:<55} -> {ossm3_short}")

    print(f"\n{BOLD}{RED}  NICHT UNTERSTÜTZTE FELDER (aus SMCP entfernen):{RESET}")
    print(f"  {'SMCP 2.6 Pfad':<55} {'Kategorie'}")
    print(f"  {'-' * 55} {'-' * 20}")
    for smcp, kategorie, _ in UNSUPPORTED_SMCP_FIELDS:
        smcp_short = smcp.replace("spec.", "")
        print(f"  {smcp_short:<55} [{kategorie}]")
    print()


# -- CLI -----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="OSSM Migration Scanner - Service Mesh 2.6.x -> 3.0.x",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
----------------------------------------------------------------------------
USE CASES
----------------------------------------------------------------------------

  1. Alle Applikations-Namespaces scannen (ohne istio-system)
     python ossm_migration_scan.py

  2. Nur istio-system scannen (Control-Plane-Check)
     python ossm_migration_scan.py -n istio-system

  3. istio-system + Applikations-Namespaces gemeinsam scannen
     python ossm_migration_scan.py -n istio-system -n bookinfo -n myapp

  4. Nur Blocker (Deprecations) prüfen - Exit-Code 1 wenn vorhanden
     python ossm_migration_scan.py --only-deprecations

  5. Scan mit JSON-Export für CI/CD-Pipelines
     python ossm_migration_scan.py --json report.json

  6. Spezifisches CLI-Tool erzwingen (kubectl statt oc)
     python ossm_migration_scan.py --tool kubectl

  7. Vollständige SMCP 2.6 -> Istio 3.0 Feldmappings anzeigen
     python ossm_migration_scan.py --show-mapping

----------------------------------------------------------------------------
BEISPIELE (kombiniert)
----------------------------------------------------------------------------

  # Control-Plane + zwei App-Namespaces, nur Blocker, JSON-Export
  python ossm_migration_scan.py -n istio-system -n bookinfo -n frontend \\
    --only-deprecations --json blockers.json

  # Alle App-Namespaces mit kubectl, Report als Datei
  python ossm_migration_scan.py --tool kubectl --json full-report.json

----------------------------------------------------------------------------
HINWEISE
----------------------------------------------------------------------------

  - istio-system wird im Standard-Scan NICHT eingeschlossen.
    Explizit mit -n istio-system angeben, um ihn zu scannen.
  - -n kann beliebig oft wiederholt werden.
  - --only-deprecations setzt Exit-Code 1 wenn Blocker gefunden wurden
    (geeignet für CI-Gates).
  - --tool auto bevorzugt oc, fällt auf kubectl zurück wenn oc fehlt.

----------------------------------------------------------------------------
JQ-SCHNELLPRÜFUNGEN (vor dem Scan)
----------------------------------------------------------------------------

  # ServiceEntries mit mehr als 256 Hosts:
  oc get serviceentries -A -o json | jq -r \\
    '.items[] | select(.spec.hosts | length > 256) | "\\(.metadata.namespace)/\\(.metadata.name)"'

  # ServiceEntries ohne Ports:
  oc get serviceentries -A -o json | jq -r \\
    '.items[] | select(.spec.ports == null or (.spec.ports | length == 0)) | "\\(.metadata.namespace)/\\(.metadata.name)"'

  # Namespaces mit maistra.io Labels:
  oc get ns --show-labels | grep maistra
        """,
    )
    parser.add_argument(
        "-n", "--namespace", action="append", dest="namespaces", metavar="NS",
        help="Namespace scannen (wiederholbar). Standard: alle Namespaces außer istio-system.",
    )
    parser.add_argument(
        "--tool", choices=["kubectl", "oc", "auto"], default="auto",
        help="CLI-Tool (Standard: auto - oc bevorzugt)",
    )
    parser.add_argument(
        "--json", metavar="FILE",
        help="Report zusätzlich als JSON-Datei exportieren",
    )
    parser.add_argument(
        "--only-deprecations", action="store_true",
        help="Nur Deprecations (Blocker) ausgeben",
    )
    parser.add_argument(
        "--show-mapping", action="store_true",
        help="Vollständige Feldmappings (SMCP 2.6 -> Istio 3.0) ausgeben und beenden",
    )
    args = parser.parse_args()

    if args.show_mapping:
        _print_mapping_table()
        sys.exit(0)

    tool       = detect_tool() if args.tool == "auto" else args.tool
    namespaces = get_namespaces(tool, None) if not args.namespaces else args.namespaces

    result = scan(namespaces, tool)

    if args.only_deprecations:
        result.findings = [f for f in result.findings if f.severity == "deprecation"]

    print_report(result)

    if args.json:
        export_json(result, args.json)

    deprecation_count = sum(1 for f in result.findings if f.severity == "deprecation")
    sys.exit(1 if deprecation_count > 0 else 0)


if __name__ == "__main__":
    main()
