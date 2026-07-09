#!/usr/bin/env python3
"""Dependency health and lifecycle intelligence analysis.

This module is conservative by design. It separates authoritative lifecycle
signals (for example registry deprecation or product EOL data) from heuristic
maintenance-risk signals (for example no observed releases for N days).

Network enrichment is opt-in. Offline operation still works with SBOM metadata,
a tiny built-in lifecycle cache for smoke tests, and user-provided cache files.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

UTC = dt.timezone.utc
DEFAULT_STALE_DAYS = 365
HTTP_TIMEOUT = 8

# Small built-in examples of widely-known deprecated/unmaintained package names.
# This is intentionally tiny. Real decisions should prefer registry metadata,
# maintainer statements, vendor EOL feeds, or project policy exceptions.
KNOWN_DEPRECATED = {
    "npm:request": "The npm request package is deprecated/unmaintained; migrate to maintained HTTP clients.",
    "npm:left-pad": "Package is historically abandoned/minimal; verify if use is intentional.",
    "pypi:django-cors-headers-old": "Example deprecated package marker; verify against registry metadata.",
}

# Common SBOM component names/images mapped to endoflife.date product slugs.
# The list is deliberately conservative and user-extendable through JSON cache files.
EOL_PRODUCT_ALIASES = {
    "node": "nodejs", "nodejs": "nodejs", "node.js": "nodejs",
    "python": "python", "cpython": "python",
    "ubuntu": "ubuntu", "debian": "debian", "alpine": "alpine", "alpine linux": "alpine",
    "amazon linux": "amazon-linux", "amazonlinux": "amazon-linux",
    "centos": "centos", "rhel": "rhel", "red hat enterprise linux": "rhel",
    "postgres": "postgresql", "postgresql": "postgresql", "mysql": "mysql", "mariadb": "mariadb",
    "redis": "redis", "mongodb": "mongodb", "nginx": "nginx", "apache http server": "apache",
    "kubernetes": "kubernetes", "k8s": "kubernetes", "terraform": "terraform",
    "go": "go", "golang": "go", "ruby": "ruby", "php": "php",
    "java": "java", "openjdk": "java", "eclipse temurin": "java",
    "dotnet": "dotnet", ".net": "dotnet", "dotnet runtime": "dotnet",
    "django": "django", "angular": "angular", "spring boot": "spring-boot",
}

# Tiny offline cache used for deterministic smoke tests and examples. The live
# provider/cache should be preferred for real decisions.
BUILTIN_EOL_CACHE = {
    "python": [
        {"cycle": "3.8", "eol": "2024-10-07", "latest": "3.8.20", "lts": False},
        {"cycle": "3.9", "eol": "2025-10-31", "latest": "3.9.23", "lts": False},
    ],
    "nodejs": [
        {"cycle": "16", "eol": "2023-09-11", "latest": "16.20.2", "lts": "Gallium"},
        {"cycle": "18", "eol": "2025-04-30", "latest": "18.20.8", "lts": "Hydrogen"},
    ],
    "ubuntu": [
        {"cycle": "20.04", "eol": "2025-05-29", "latest": "20.04.6", "lts": True},
        {"cycle": "22.04", "eol": "2027-04-01", "latest": "22.04.5", "lts": True},
    ],
}

@dataclass
class ComponentHealth:
    name: str
    version: str = ""
    purl: str = ""
    ecosystem: str = "unknown"
    scope: str = ""
    status: str = "unknown"
    risk: str = "unknown"
    confidence: str = "unknown"
    stale_days: Optional[int] = None
    latest_version: str = ""
    last_release_date: str = ""
    deprecation_message: str = ""
    lifecycle_source: str = ""
    lifecycle_product: str = ""
    lifecycle_cycle: str = ""
    lifecycle_eol: str = ""
    lifecycle_latest: str = ""
    lifecycle_status: str = "unknown"
    signals: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


def now() -> dt.datetime:
    return dt.datetime.now(UTC)


def parse_dt(value: str) -> Optional[dt.datetime]:
    if not value:
        return None
    value = str(value).strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d", "%Y/%m/%d"):
        try:
            if fmt:
                return dt.datetime.strptime(value[:10], fmt).replace(tzinfo=UTC)
            d = dt.datetime.fromisoformat(value)
            if d.tzinfo is None:
                d = d.replace(tzinfo=UTC)
            return d.astimezone(UTC)
        except Exception:
            continue
    return None


def days_since(value: str) -> Optional[int]:
    d = parse_dt(value)
    if not d:
        return None
    return max(0, (now() - d).days)


def http_json(url: str, token: str = "") -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "sbom-security-toolkit/lifecycle-intelligence"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            if resp.status >= 400:
                return None
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


def strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def properties_from_cdx(c: Dict[str, Any]) -> Dict[str, str]:
    props: Dict[str, str] = {}
    for p in c.get("properties") or []:
        if isinstance(p, dict) and p.get("name"):
            props[str(p.get("name"))] = str(p.get("value", ""))
    for key in ["deprecated", "deprecation", "eol", "endOfLife", "supportStatus", "lastReleaseDate", "latestReleaseDate", "latestVersion", "repository", "lifecycleProduct", "lifecycleCycle", "sst:lifecycle_product", "sst:lifecycle_cycle"]:
        if key in c:
            props[key] = str(c.get(key, ""))
    return props


def load_json_components(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(errors="replace"))
    if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
        out = []
        for c in data.get("components") or []:
            if isinstance(c, dict):
                props = properties_from_cdx(c)
                out.append({"name": c.get("name", ""), "version": c.get("version", ""), "purl": c.get("purl", ""), "scope": c.get("scope", ""), "properties": props})
        return out
    if isinstance(data, dict) and ("packages" in data or "SPDXID" in data):
        out = []
        for p in data.get("packages") or []:
            if isinstance(p, dict):
                purl = ""
                for ext in p.get("externalRefs") or []:
                    if isinstance(ext, dict) and str(ext.get("referenceType", "")).lower() == "purl":
                        purl = str(ext.get("referenceLocator", ""))
                out.append({"name": p.get("name", ""), "version": p.get("versionInfo", ""), "purl": purl, "properties": {}})
        return out
    if isinstance(data, dict) and "components" in data:
        return [c for c in data.get("components") or [] if isinstance(c, dict)]
    return []


def load_xml_components(path: Path) -> List[Dict[str, Any]]:
    root = ET.parse(path).getroot()
    out: List[Dict[str, Any]] = []
    for comp in root.iter():
        if strip_ns(comp.tag) != "component":
            continue
        item: Dict[str, Any] = {"name": "", "version": "", "purl": "", "scope": comp.attrib.get("scope", ""), "properties": {}}
        for child in comp:
            t = strip_ns(child.tag)
            if t in {"name", "version", "purl"}:
                item[t] = child.text or ""
            elif t == "properties":
                for prop in child:
                    if strip_ns(prop.tag) == "property":
                        n = prop.attrib.get("name", "")
                        if n:
                            item["properties"][n] = prop.text or ""
        if item.get("name") or item.get("purl"):
            out.append(item)
    return out


def load_components(path: Path) -> List[Dict[str, Any]]:
    raw = path.read_text(errors="replace").lstrip()[:50]
    if raw.startswith("<"):
        return load_xml_components(path)
    return load_json_components(path)


def parse_purl(purl: str) -> Tuple[str, str, str]:
    if not purl or not purl.startswith("pkg:"):
        return "unknown", "", ""
    body = purl[4:]
    version = ""
    if "@" in body:
        body, version = body.rsplit("@", 1)
        version = version.split("?", 1)[0]
    parts = body.split("/", 1)
    ecosystem = parts[0].lower()
    name = parts[1] if len(parts) > 1 else ""
    return ecosystem, urllib.parse.unquote(name), version


def ecosystem_from_component(c: Dict[str, Any]) -> Tuple[str, str, str]:
    purl = str(c.get("purl") or "")
    eco, pname, pver = parse_purl(purl)
    name = pname or str(c.get("name") or "")
    version = pver or str(c.get("version") or "")
    return eco, name, version


def npm_metadata(name: str) -> Dict[str, Any]:
    data = http_json("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@/")) or {}
    latest = ((data.get("dist-tags") or {}).get("latest")) or ""
    times = data.get("time") or {}
    last_date = times.get(latest) or times.get("modified") or ""
    deprecated = ""
    if latest and isinstance(data.get("versions"), dict):
        deprecated = str(((data["versions"].get(latest) or {}).get("deprecated")) or "")
    return {"latest_version": latest, "last_release_date": last_date, "deprecation_message": deprecated}


def pypi_metadata(name: str) -> Dict[str, Any]:
    data = http_json("https://pypi.org/pypi/" + urllib.parse.quote(name) + "/json") or {}
    info = data.get("info") or {}
    latest = str(info.get("version") or "")
    releases = data.get("releases") or {}
    files = releases.get(latest) or []
    dates = [f.get("upload_time_iso_8601") or f.get("upload_time") for f in files if isinstance(f, dict)]
    dates = [d for d in dates if d]
    last = sorted(dates)[-1] if dates else ""
    return {"latest_version": latest, "last_release_date": last, "deprecation_message": ""}


def crates_metadata(name: str) -> Dict[str, Any]:
    data = http_json("https://crates.io/api/v1/crates/" + urllib.parse.quote(name)) or {}
    crate = data.get("crate") or {}
    latest = str(crate.get("newest_version") or crate.get("max_version") or "")
    last = str(crate.get("updated_at") or "")
    return {"latest_version": latest, "last_release_date": last, "deprecation_message": ""}


def packagist_metadata(name: str) -> Dict[str, Any]:
    data = http_json("https://repo.packagist.org/p2/" + urllib.parse.quote(name, safe="/") + ".json") or {}
    pkgs = data.get("packages") or {}
    versions = pkgs.get(name) or []
    latest = ""; last = ""; abandoned = ""
    if versions:
        first = versions[0]
        latest = str(first.get("version_normalized") or first.get("version") or "")
        last = str(first.get("time") or "")
        abandoned_val = first.get("abandoned")
        if abandoned_val:
            abandoned = "Package is marked abandoned" + (f"; suggested replacement: {abandoned_val}" if isinstance(abandoned_val, str) else "")
    return {"latest_version": latest, "last_release_date": last, "deprecation_message": abandoned}


def network_metadata(ecosystem: str, name: str) -> Dict[str, Any]:
    if ecosystem == "npm": return npm_metadata(name)
    if ecosystem == "pypi": return pypi_metadata(name)
    if ecosystem == "cargo": return crates_metadata(name)
    if ecosystem == "composer": return packagist_metadata(name)
    return {}


def major_minor(version: str) -> str:
    m = re.search(r"(\d+)(?:\.(\d+))?", version or "")
    if not m:
        return ""
    return m.group(1) + (("." + m.group(2)) if m.group(2) is not None else "")


def major_only(version: str) -> str:
    m = re.search(r"(\d+)", version or "")
    return m.group(1) if m else ""


def load_lifecycle_cache(cache_path: str = "") -> Dict[str, List[Dict[str, Any]]]:
    cache: Dict[str, List[Dict[str, Any]]] = {k: list(v) for k, v in BUILTIN_EOL_CACHE.items()}
    if cache_path:
        try:
            data = json.loads(Path(cache_path).read_text(errors="replace"))
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, list):
                        cache[k] = [x for x in v if isinstance(x, dict)]
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("product") and isinstance(item.get("cycles"), list):
                        cache[str(item["product"])] = [x for x in item["cycles"] if isinstance(x, dict)]
        except Exception:
            pass
    return cache


def product_candidates(name: str, props: Dict[str, str]) -> List[str]:
    explicit = props.get("sst:lifecycle_product") or props.get("lifecycleProduct") or props.get("lifecycle_product")
    if explicit:
        return [explicit.strip().lower()]
    n = (name or "").strip().lower()
    base = n.split("/", 1)[-1].replace("_", "-")
    candidates = []
    for key in [n, base, base.replace("-", " ")]:
        if key in EOL_PRODUCT_ALIASES:
            candidates.append(EOL_PRODUCT_ALIASES[key])
    return list(dict.fromkeys(candidates))


def fetch_eol_cycles(product: str) -> List[Dict[str, Any]]:
    # Old/stable API path first; fallback to v1 shape if present.
    for url in [f"https://endoflife.date/api/{urllib.parse.quote(product)}.json", f"https://endoflife.date/api/v1/products/{urllib.parse.quote(product)}/"]:
        data = http_json(url)
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            if isinstance(data.get("cycles"), list):
                return [x for x in data["cycles"] if isinstance(x, dict)]
            if isinstance(data.get("result"), list):
                return [x for x in data["result"] if isinstance(x, dict)]
    return []


def cycle_matches(version: str, cycle: str) -> bool:
    v = major_minor(version)
    c = str(cycle or "").strip()
    if not v or not c:
        return False
    if v == c:
        return True
    if major_only(version) == c:
        return True
    # For products with major-only cycles, 16.20.2 should match 16.
    return v.startswith(c + ".") or c.startswith(v + ".")


def lifecycle_lookup(name: str, version: str, props: Dict[str, str], *, network: bool, cache: Dict[str, List[Dict[str, Any]]], sources: Iterable[str]) -> Dict[str, Any]:
    srcs = {s.strip().lower() for s in sources if s.strip()}
    if "endoflife" not in srcs and "eol" not in srcs:
        return {}
    explicit_cycle = props.get("sst:lifecycle_cycle") or props.get("lifecycleCycle") or props.get("lifecycle_cycle")
    for product in product_candidates(name, props):
        cycles = cache.get(product) or []
        source = "builtin-or-user-cache"
        if network and "endoflife" in srcs:
            live = fetch_eol_cycles(product)
            if live:
                cycles = live
                source = "endoflife.date"
        for cy in cycles:
            cycle = str(cy.get("cycle") or cy.get("name") or "")
            if explicit_cycle and cycle != explicit_cycle:
                continue
            if not explicit_cycle and not cycle_matches(version, cycle):
                continue
            eol = cy.get("eol")
            latest = str(cy.get("latest") or cy.get("latestRelease") or "")
            eol_str = str(eol or "")
            eol_dt = parse_dt(eol_str) if eol_str and eol_str.lower() not in {"false", "none"} else None
            if isinstance(eol, bool) and eol is False:
                status = "supported"
            elif eol_dt and eol_dt.date() < now().date():
                status = "eol"
            elif eol_dt:
                status = "supported_until_eol_date"
            else:
                status = "lifecycle_known"
            return {"source": source, "product": product, "cycle": cycle, "eol": eol_str, "latest": latest, "status": status}
    return {}


def confidence_for(status: str, signals: List[str]) -> str:
    joined = " ".join(signals)
    if status in {"eol", "deprecated_or_abandoned"} and any(x in joined for x in ["endoflife.date", "builtin-or-user-cache", "registry:", "metadata:"]):
        return "high"
    if status in {"metadata_eol_or_unsupported", "supported_until_eol_date"}:
        return "high"
    if status in {"very_stale_update_signal", "stale_update_signal"}:
        return "medium"
    if status in {"range_or_unpinned_version", "version_unknown"}:
        return "low"
    return "unknown"


def analyze_component(c: Dict[str, Any], *, stale_days: int, network: bool, lifecycle_sources: Iterable[str], lifecycle_cache: Dict[str, List[Dict[str, Any]]]) -> ComponentHealth:
    eco, name, version = ecosystem_from_component(c)
    props = c.get("properties") or {}
    h = ComponentHealth(name=name or "unknown", version=version, purl=str(c.get("purl") or ""), ecosystem=eco, scope=str(c.get("scope") or ""))
    key = f"{eco}:{name}".lower()

    for k in ["deprecated", "deprecation", "sst:deprecated"]:
        if str(props.get(k, "")).lower() in {"true", "yes", "1"} or props.get(k):
            h.deprecation_message = str(props.get(k) or "Component is marked deprecated")
            h.signals.append(f"metadata:{k}")
    for k in ["eol", "endOfLife", "end-of-life", "sst:eol", "supportStatus"]:
        val = str(props.get(k, "")).strip()
        if val and val.lower() not in {"false", "supported", "active", "unknown", "0"}:
            h.signals.append(f"metadata:{k}={val}")
            if not h.deprecation_message:
                h.deprecation_message = f"Component metadata indicates possible EOL/support issue: {val}"

    for k in ["lastReleaseDate", "latestReleaseDate", "sst:last_release_date", "sst:latest_release_date", "registry:last_release_date"]:
        if props.get(k):
            h.last_release_date = str(props[k]); h.signals.append(f"metadata:{k}"); break
    for k in ["latestVersion", "sst:latest_version", "registry:latest_version"]:
        if props.get(k):
            h.latest_version = str(props[k]); break

    if key in KNOWN_DEPRECATED and not h.deprecation_message:
        h.deprecation_message = KNOWN_DEPRECATED[key]
        h.signals.append("built-in-known-deprecated-list")

    srcs = {x.strip().lower() for x in lifecycle_sources if x.strip()}
    if network and ("registry" in srcs or "registries" in srcs) and eco in {"npm", "pypi", "cargo", "composer"} and name:
        meta = network_metadata(eco, name)
        if meta.get("latest_version"):
            h.latest_version = str(meta["latest_version"])
        if meta.get("last_release_date"):
            h.last_release_date = str(meta["last_release_date"])
            h.signals.append(f"registry:{eco}:last_release_date")
        if meta.get("deprecation_message"):
            h.deprecation_message = str(meta["deprecation_message"])
            h.signals.append(f"registry:{eco}:deprecation")

    life = lifecycle_lookup(name, version, props, network=network, cache=lifecycle_cache, sources=srcs)
    if life:
        h.lifecycle_source = life.get("source", "")
        h.lifecycle_product = life.get("product", "")
        h.lifecycle_cycle = life.get("cycle", "")
        h.lifecycle_eol = life.get("eol", "")
        h.lifecycle_latest = life.get("latest", "")
        h.lifecycle_status = life.get("status", "")
        h.signals.append(f"lifecycle:{h.lifecycle_source}:{h.lifecycle_product}:{h.lifecycle_cycle}:{h.lifecycle_status}")
        if h.lifecycle_latest and not h.latest_version:
            h.latest_version = h.lifecycle_latest

    if h.last_release_date:
        h.stale_days = days_since(h.last_release_date)

    if h.lifecycle_status == "eol":
        h.status = "eol"
        h.risk = "high"
        h.recommendations.append(f"{h.lifecycle_product or h.name} {h.lifecycle_cycle or h.version} appears past EOL ({h.lifecycle_eol}). Upgrade to a supported cycle and verify compatibility.")
    elif h.deprecation_message:
        h.status = "deprecated_or_abandoned"
        h.risk = "high"
        h.recommendations.append("Treat as unsupported unless maintainers explicitly document continued support; plan migration or compensating controls.")
    elif h.lifecycle_status == "supported_until_eol_date":
        h.status = "supported_until_eol_date"
        h.risk = "low"
        h.recommendations.append(f"Lifecycle data found. Track EOL date {h.lifecycle_eol} and plan upgrades before support ends.")
    elif h.stale_days is not None and h.stale_days >= stale_days * 2:
        h.status = "very_stale_update_signal"
        h.risk = "high"
        h.recommendations.append(f"No observed update/release for {h.stale_days} days; verify maintainer support and migration options.")
    elif h.stale_days is not None and h.stale_days >= stale_days:
        h.status = "stale_update_signal"
        h.risk = "medium"
        h.recommendations.append(f"No observed update/release for {h.stale_days} days; review project activity and support expectations.")
    elif not version:
        h.status = "version_unknown"
        h.risk = "medium"
        h.recommendations.append("Pin or identify the exact version before making support/EOL decisions.")
    elif version.strip() in {"*", "latest"} or any(x in version for x in [">=", "<", "~", "^"]):
        h.status = "range_or_unpinned_version"
        h.risk = "low"
        h.recommendations.append("Resolve the dependency to an exact version for repeatable support and vulnerability analysis.")
    else:
        h.status = "no_eol_signal_found"
        h.risk = "unknown"
        h.recommendations.append("No explicit unsupported/EOL signal was found. Absence of evidence is not evidence of support.")

    if h.latest_version and version and h.latest_version != version and not any(op in version for op in [">", "<", "~", "^"]):
        h.signals.append(f"latest_version_available:{h.latest_version}")
    h.confidence = confidence_for(h.status, h.signals)
    return h


def summarize(items: List[ComponentHealth]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}; risk_counts: Dict[str, int] = {}; confidence_counts: Dict[str, int] = {}; lifecycle_counts: Dict[str, int] = {}
    for i in items:
        counts[i.status] = counts.get(i.status, 0) + 1
        risk_counts[i.risk] = risk_counts.get(i.risk, 0) + 1
        confidence_counts[i.confidence] = confidence_counts.get(i.confidence, 0) + 1
        lifecycle_counts[i.lifecycle_status or "unknown"] = lifecycle_counts.get(i.lifecycle_status or "unknown", 0) + 1
    order = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    top = [asdict(x) for x in sorted(items, key=lambda h: (order.get(h.risk, 9), {"high":0,"medium":1,"low":2,"unknown":3}.get(h.confidence,9), -(h.stale_days or -1), h.name))[:25]]
    return {"generated_at": now().isoformat(), "component_count": len(items), "status_counts": counts, "risk_counts": risk_counts, "confidence_counts": confidence_counts, "lifecycle_counts": lifecycle_counts, "top_risks": top}


def write_markdown(summary: Dict[str, Any], items: List[ComponentHealth], out: Path, stale_days: int, network: bool, lifecycle_sources: List[str]) -> None:
    lines = [
        "# Dependency Health / Lifecycle Intelligence Report", "",
        f"Generated: {summary['generated_at']}",
        f"Stale-maintenance threshold: {stale_days} days",
        f"Network enrichment: {'enabled' if network else 'disabled'}",
        f"Lifecycle sources: {', '.join(lifecycle_sources) if lifecycle_sources else 'none'}", "",
        "## How unsupported/EOL is detected", "",
        "The toolkit separates explicit lifecycle signals from heuristics:", "",
        "- **EOL / unsupported:** vendor, maintainer, SBOM metadata, or lifecycle-provider data indicates support has ended.",
        "- **Deprecated / abandoned:** registry or maintainer metadata marks the package deprecated or abandoned.",
        "- **Possibly unmaintained:** heuristic signal such as no observed release/update for the configured stale threshold.",
        "- **Stale:** review trigger, not automatic EOL. Some stable libraries intentionally change rarely.",
        "- **Unknown:** no reliable lifecycle signal found.", "",
        "## Summary", "", f"- Components analyzed: {summary['component_count']}",
    ]
    for k, v in sorted(summary.get("risk_counts", {}).items()): lines.append(f"- Risk {k}: {v}")
    lines.append("")
    lines.append("## Confidence counts")
    for k, v in sorted(summary.get("confidence_counts", {}).items()): lines.append(f"- {k}: {v}")
    lines += ["", "## Top review items", "", "| Risk | Confidence | Status | Component | Version | Ecosystem | Lifecycle | EOL | Stale days | Signals |", "|---|---|---|---|---|---|---|---|---:|---|"]
    for i in summary.get("top_risks", []):
        lifecycle = ":".join([x for x in [i.get('lifecycle_source',''), i.get('lifecycle_product',''), i.get('lifecycle_cycle','')] if x])
        lines.append(f"| {i['risk']} | {i.get('confidence','')} | {i['status']} | `{i['name']}` | `{i.get('version','')}` | {i.get('ecosystem','')} | {lifecycle} | {i.get('lifecycle_eol','')} | {i.get('stale_days') or ''} | {', '.join(i.get('signals') or [])} |")
    lines += ["", "## Recommended handling", "", "- Confirm lifecycle status from upstream maintainers or vendors before declaring a package unsupported unless high-confidence lifecycle metadata exists.", "- Prioritize EOL/deprecated components, very stale direct dependencies, and components with known vulnerabilities.", "- Document exceptions and expiration dates for stale but intentionally stable libraries.", "- Prefer exact versions and package URLs so lifecycle and vulnerability matching can be repeated."]
    out.write_text("\n".join(lines) + "\n")


def write_lifecycle_markdown(summary: Dict[str, Any], items: List[ComponentHealth], out: Path) -> None:
    lines = ["# Lifecycle Intelligence Findings", "", f"Generated: {summary['generated_at']}", "", "| Status | Confidence | Product | Cycle | EOL | Component | Version | Recommendation |", "|---|---|---|---|---|---|---|---|"]
    matched = [x for x in items if x.lifecycle_status and x.lifecycle_status != "unknown"]
    for h in sorted(matched, key=lambda x: ({"eol":0,"supported_until_eol_date":1,"supported":2}.get(x.lifecycle_status,9), x.lifecycle_product, x.name)):
        lines.append(f"| {h.lifecycle_status} | {h.confidence} | {h.lifecycle_product} | {h.lifecycle_cycle} | {h.lifecycle_eol} | `{h.name}` | `{h.version}` | {'; '.join(h.recommendations)} |")
    if not matched:
        lines.append("| no lifecycle matches | unknown |  |  |  |  |  | No product lifecycle matches found. |")
    out.write_text("\n".join(lines) + "\n")


def write_csv(items: List[ComponentHealth], out: Path) -> None:
    fields = ["risk","confidence","status","ecosystem","name","version","purl","stale_days","latest_version","last_release_date","lifecycle_source","lifecycle_product","lifecycle_cycle","lifecycle_eol","lifecycle_status","signals"]
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for i in items:
            row = {k: getattr(i, k) for k in fields if k != "signals"}
            row["signals"] = ";".join(i.signals)
            w.writerow(row)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Identify deprecated, abandoned, stale, unpinned, or unsupported/EOL open source dependencies from an SBOM.")
    ap.add_argument("sbom", help="CycloneDX JSON/XML or SPDX JSON SBOM")
    ap.add_argument("--out-dir", default="reports/dependency-health")
    ap.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS, help="Heuristic stale update threshold; default 365")
    ap.add_argument("--network", action="store_true", help="Enable optional registry and lifecycle-provider network enrichment")
    ap.add_argument("--lifecycle-sources", default="sbom,known,registry,endoflife", help="Comma list: sbom,known,registry,endoflife. Network is still required for live calls.")
    ap.add_argument("--lifecycle-cache", default="", help="Optional JSON cache of lifecycle cycles keyed by product slug")
    ap.add_argument("--offline-cache-only", action="store_true", help="Use built-in/user lifecycle cache only; ignore network even if --network is supplied")
    args = ap.parse_args(argv)
    sbom = Path(args.sbom)
    out_dir = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    sources = [x.strip() for x in args.lifecycle_sources.split(",") if x.strip()]
    cache = load_lifecycle_cache(args.lifecycle_cache)
    network = bool(args.network and not args.offline_cache_only)
    components = load_components(sbom)
    items = [analyze_component(c, stale_days=args.stale_days, network=network, lifecycle_sources=sources, lifecycle_cache=cache) for c in components]
    summary = summarize(items)
    payload = {"summary": summary, "settings": {"stale_days": args.stale_days, "network": network, "lifecycle_sources": sources, "lifecycle_cache": bool(args.lifecycle_cache), "offline_cache_only": args.offline_cache_only}, "components": [asdict(i) for i in items]}
    (out_dir / "dependency-health.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    (out_dir / "lifecycle-intelligence.json").write_text(json.dumps({"summary": summary, "components": [asdict(i) for i in items if i.lifecycle_status and i.lifecycle_status != "unknown"]}, indent=2, sort_keys=True) + "\n")
    write_markdown(summary, items, out_dir / "dependency-health.md", args.stale_days, network, sources)
    write_lifecycle_markdown(summary, items, out_dir / "lifecycle-intelligence.md")
    write_csv(items, out_dir / "dependency-health.csv")
    print(out_dir)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
