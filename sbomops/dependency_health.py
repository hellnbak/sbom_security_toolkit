#!/usr/bin/env python3
"""Dependency health and unsupported/EOL risk analysis.

This module is conservative by design. It separates authoritative signals
(e.g., deprecation/EOL metadata when present) from heuristic stale-maintenance
risk (e.g., no observed releases/updates for N days).
"""
from __future__ import annotations

import argparse
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

@dataclass
class ComponentHealth:
    name: str
    version: str = ""
    purl: str = ""
    ecosystem: str = "unknown"
    scope: str = ""
    status: str = "unknown"
    risk: str = "unknown"
    stale_days: Optional[int] = None
    latest_version: str = ""
    last_release_date: str = ""
    deprecation_message: str = ""
    signals: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


def now() -> dt.datetime:
    return dt.datetime.now(UTC)


def parse_dt(value: str) -> Optional[dt.datetime]:
    if not value:
        return None
    value = str(value).strip()
    for repl in [("Z", "+00:00")]:
        value = value.replace(*repl)
    # Date-only fallback.
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


def http_json(url: str, token: str = "") -> Optional[Dict[str, Any]]:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "sbom-security-toolkit/dependency-health"})
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
    for key in ["deprecated", "deprecation", "eol", "endOfLife", "supportStatus", "lastReleaseDate", "latestReleaseDate", "latestVersion", "repository"]:
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
                out.append({
                    "name": c.get("name", ""),
                    "version": c.get("version", ""),
                    "purl": c.get("purl", ""),
                    "scope": c.get("scope", ""),
                    "properties": props,
                })
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
    """Return ecosystem, name, version from a package-url-ish string."""
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
    url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@/")
    data = http_json(url) or {}
    latest = ((data.get("dist-tags") or {}).get("latest")) or ""
    times = data.get("time") or {}
    last_date = times.get(latest) or times.get("modified") or ""
    deprecated = ""
    if latest and isinstance(data.get("versions"), dict):
        deprecated = str(((data["versions"].get(latest) or {}).get("deprecated")) or "")
    return {"latest_version": latest, "last_release_date": last_date, "deprecation_message": deprecated}


def pypi_metadata(name: str) -> Dict[str, Any]:
    url = "https://pypi.org/pypi/" + urllib.parse.quote(name) + "/json"
    data = http_json(url) or {}
    info = data.get("info") or {}
    latest = str(info.get("version") or "")
    releases = data.get("releases") or {}
    files = releases.get(latest) or []
    dates = [f.get("upload_time_iso_8601") or f.get("upload_time") for f in files if isinstance(f, dict)]
    dates = [d for d in dates if d]
    last = sorted(dates)[-1] if dates else ""
    # PyPI does not have a universal deprecation field. Project classifiers and description are not authoritative.
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
            abandoned = f"Package is marked abandoned" + (f"; suggested replacement: {abandoned_val}" if isinstance(abandoned_val, str) else "")
    return {"latest_version": latest, "last_release_date": last, "deprecation_message": abandoned}


def network_metadata(ecosystem: str, name: str) -> Dict[str, Any]:
    if ecosystem == "npm":
        return npm_metadata(name)
    if ecosystem == "pypi":
        return pypi_metadata(name)
    if ecosystem == "cargo":
        return crates_metadata(name)
    if ecosystem == "composer":
        return packagist_metadata(name)
    return {}


def analyze_component(c: Dict[str, Any], *, stale_days: int, network: bool) -> ComponentHealth:
    eco, name, version = ecosystem_from_component(c)
    props = c.get("properties") or {}
    h = ComponentHealth(name=name or "unknown", version=version, purl=str(c.get("purl") or ""), ecosystem=eco, scope=str(c.get("scope") or ""))
    key = f"{eco}:{name}".lower()

    # Official/authoritative-ish signals when present in SBOM metadata or registry metadata.
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

    # Last-release metadata from SBOM or registry.
    for k in ["lastReleaseDate", "latestReleaseDate", "sst:last_release_date", "sst:latest_release_date", "registry:last_release_date"]:
        if props.get(k):
            h.last_release_date = str(props[k]); h.signals.append(f"metadata:{k}"); break
    for k in ["latestVersion", "sst:latest_version", "registry:latest_version"]:
        if props.get(k):
            h.latest_version = str(props[k]); break

    if key in KNOWN_DEPRECATED and not h.deprecation_message:
        h.deprecation_message = KNOWN_DEPRECATED[key]
        h.signals.append("built-in-known-deprecated-list")

    if network and eco in {"npm", "pypi", "cargo", "composer"} and name:
        meta = network_metadata(eco, name)
        if meta.get("latest_version"):
            h.latest_version = str(meta["latest_version"])
        if meta.get("last_release_date"):
            h.last_release_date = str(meta["last_release_date"])
            h.signals.append(f"registry:{eco}:last_release_date")
        if meta.get("deprecation_message"):
            h.deprecation_message = str(meta["deprecation_message"])
            h.signals.append(f"registry:{eco}:deprecation")

    if h.last_release_date:
        h.stale_days = days_since(h.last_release_date)

    if h.deprecation_message:
        h.status = "deprecated_or_abandoned"
        h.risk = "high"
        h.recommendations.append("Treat as unsupported unless maintainers explicitly document continued support; plan migration or compensating controls.")
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
    return h


def summarize(items: List[ComponentHealth]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    risk_counts: Dict[str, int] = {}
    for i in items:
        counts[i.status] = counts.get(i.status, 0) + 1
        risk_counts[i.risk] = risk_counts.get(i.risk, 0) + 1
    top = [asdict(x) for x in sorted(items, key=lambda h: ({"high": 0, "medium": 1, "low": 2, "unknown": 3}.get(h.risk, 9), -(h.stale_days or -1), h.name))[:25]]
    return {"generated_at": now().isoformat(), "component_count": len(items), "status_counts": counts, "risk_counts": risk_counts, "top_risks": top}


def write_markdown(summary: Dict[str, Any], items: List[ComponentHealth], out: Path, stale_days: int, network: bool) -> None:
    lines = [
        "# Dependency Health / Unsupported Dependency Report",
        "",
        f"Generated: {summary['generated_at']}",
        f"Stale-maintenance threshold: {stale_days} days",
        f"Network registry enrichment: {'enabled' if network else 'disabled'}",
        "",
        "## How unsupported/EOL is detected",
        "",
        "The toolkit separates explicit support signals from heuristics:",
        "",
        "- **Explicit/stronger signals:** package registry deprecation/abandonment metadata, SBOM properties that mark a component deprecated/EOL, or known project-maintainer statements encoded into metadata.",
        "- **Heuristic signals:** no observed release/update for the configured stale threshold, missing exact version, or unpinned/range versions that make support decisions unreliable.",
        "- **Important:** no updates in a year is not automatically EOL. It is a review trigger. Some stable libraries intentionally change rarely.",
        "",
        "## Summary",
        "",
        f"- Components analyzed: {summary['component_count']}",
    ]
    for k, v in sorted(summary.get("risk_counts", {}).items()):
        lines.append(f"- Risk {k}: {v}")
    lines += ["", "## Top review items", "", "| Risk | Status | Component | Version | Ecosystem | Stale days | Signals |", "|---|---|---|---|---|---:|---|"]
    for i in summary.get("top_risks", []):
        lines.append(f"| {i['risk']} | {i['status']} | `{i['name']}` | `{i.get('version','')}` | {i.get('ecosystem','')} | {i.get('stale_days') or ''} | {', '.join(i.get('signals') or [])} |")
    lines += ["", "## Recommended handling", "", "- Confirm package support status from the upstream maintainer or vendor before declaring a dependency unsupported.", "- Prioritize deprecated/abandoned components, very stale direct dependencies, and components with known vulnerabilities.", "- For stale but stable libraries, document the exception and verify activity such as issue response, security policy, or recent commits.", "- Prefer exact versions and package URLs so support and vulnerability matching can be repeated."]
    out.write_text("\n".join(lines) + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Identify deprecated, abandoned, stale, unpinned, or unsupported-risk open source dependencies from an SBOM.")
    ap.add_argument("sbom", help="CycloneDX JSON/XML or SPDX JSON SBOM")
    ap.add_argument("--out-dir", default="reports/dependency-health")
    ap.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS, help="Heuristic stale update threshold; default 365")
    ap.add_argument("--network", action="store_true", help="Enable optional registry metadata enrichment for npm, PyPI, crates.io, and Packagist")
    args = ap.parse_args(argv)
    sbom = Path(args.sbom)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    components = load_components(sbom)
    items = [analyze_component(c, stale_days=args.stale_days, network=args.network) for c in components]
    summary = summarize(items)
    (out_dir / "dependency-health.json").write_text(json.dumps({"summary": summary, "components": [asdict(i) for i in items]}, indent=2, sort_keys=True) + "\n")
    write_markdown(summary, items, out_dir / "dependency-health.md", args.stale_days, args.network)
    csv = out_dir / "dependency-health.csv"
    csv.write_text("risk,status,ecosystem,name,version,purl,stale_days,latest_version,last_release_date,signals\n" + "".join(
        f"{i.risk},{i.status},{i.ecosystem},{json.dumps(i.name)[1:-1]},{json.dumps(i.version)[1:-1]},{json.dumps(i.purl)[1:-1]},{i.stale_days or ''},{json.dumps(i.latest_version)[1:-1]},{json.dumps(i.last_release_date)[1:-1]},{json.dumps(';'.join(i.signals))[1:-1]}\n" for i in items
    ))
    print(out_dir)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
