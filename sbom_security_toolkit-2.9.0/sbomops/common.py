#!/usr/bin/env python3
"""Common SBOM parsing helpers for toolkit scripts.

These helpers intentionally avoid third-party dependencies so the examples run
on a stock Python installation. They are not full CycloneDX/SPDX validators;
they provide enough normalized data for quality scoring, policy examples, VEX
examples, and demo reporting.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

PURL_RE = re.compile(r"^pkg:[A-Za-z0-9.+_-]+/[A-Za-z0-9._~%!$&'()*+,;=:@/-]+")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

@dataclass
class Component:
    name: str
    version: str = ""
    purl: str = ""
    cpe: str = ""
    license: str = ""
    supplier: str = ""
    hashes: int = 0
    bom_ref: str = ""
    ecosystem: str = "unknown"
    direct: bool = False

    def key(self) -> str:
        return f"{self.name}@{self.version}".lower()

@dataclass
class Vulnerability:
    cve: str
    component: str = ""
    severity: str = "unknown"
    cvss: float = 0.0
    epss: float = 0.0
    kev: bool = False
    fix_available: bool = False
    scanner: str = "unknown"
    source: str = ""


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def load_json(path: str | Path) -> Any:
    return json.loads(read_text(path))


def detect_format(path: str | Path) -> str:
    p = Path(path)
    raw = read_text(p).lstrip()
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
            if "bomFormat" in data and str(data.get("bomFormat", "")).lower() == "cyclonedx":
                return "cyclonedx-json"
            if "spdxVersion" in data or "SPDXID" in data:
                return "spdx-json"
            if "vex" in p.name.lower() or "vulnerabilities" in data:
                return "json"
        except Exception:
            return "json-invalid"
    if raw.startswith("<"):
        if "cyclonedx" in raw[:1000].lower() or "<bom" in raw[:500].lower():
            return "cyclonedx-xml"
        return "xml"
    if "SPDXVersion:" in raw or "PackageName:" in raw:
        return "spdx-tag-value"
    return "unknown"


def _normalize_license(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("id") or value.get("name") or value.get("expression") or ""
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, dict):
                lic = item.get("license", item)
                out.append(_normalize_license(lic))
            else:
                out.append(_normalize_license(item))
        return ", ".join(x for x in out if x)
    return str(value)


def ecosystem_from_purl(purl: str) -> str:
    if not purl.startswith("pkg:"):
        return "unknown"
    return purl.split("/", 1)[0].replace("pkg:", "") or "unknown"


def parse_components(path: str | Path) -> Tuple[str, List[Component], Dict[str, Any]]:
    fmt = detect_format(path)
    metadata: Dict[str, Any] = {"format": fmt, "sha256": sha256_file(path), "path": str(path)}
    components: List[Component] = []

    if fmt == "cyclonedx-json":
        data = load_json(path)
        metadata.update({"specVersion": data.get("specVersion"), "serialNumber": data.get("serialNumber")})
        refs_in_dependencies = {d.get("ref") for d in data.get("dependencies", []) if isinstance(d, dict)}
        deps_children = {c for d in data.get("dependencies", []) if isinstance(d, dict) for c in d.get("dependsOn", []) if isinstance(c, str)}
        direct_refs = refs_in_dependencies - deps_children
        for c in data.get("components", []) or []:
            if not isinstance(c, dict):
                continue
            purl = c.get("purl", "") or ""
            comp = Component(
                name=c.get("name", "") or c.get("group", "") or "unknown",
                version=str(c.get("version", "") or ""),
                purl=purl,
                cpe=(c.get("cpe") or ""),
                license=_normalize_license(c.get("licenses")),
                supplier=(c.get("supplier", {}) or {}).get("name", "") if isinstance(c.get("supplier"), dict) else str(c.get("supplier", "") or ""),
                hashes=len(c.get("hashes", []) or []),
                bom_ref=c.get("bom-ref", "") or c.get("bom_ref", "") or "",
                ecosystem=ecosystem_from_purl(purl),
                direct=(c.get("bom-ref") in direct_refs) if c.get("bom-ref") else False,
            )
            components.append(comp)
        metadata["dependency_graph_present"] = bool(data.get("dependencies"))
        metadata["vulnerability_count"] = len(data.get("vulnerabilities", []) or [])
        return fmt, components, metadata

    if fmt == "cyclonedx-xml":
        root = ET.parse(path).getroot()
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}", 1)[0] + "}"
        metadata["specVersion"] = root.attrib.get("version") or root.attrib.get("specVersion")
        dep_refs = {d.attrib.get("ref") for d in root.findall(f".//{ns}dependency")}
        child_refs = {c.attrib.get("ref") for d in root.findall(f".//{ns}dependency") for c in d.findall(f"{ns}dependency")}
        direct_refs = dep_refs - child_refs
        for c in root.findall(f".//{ns}component"):
            name = c.findtext(f"{ns}name") or "unknown"
            version = c.findtext(f"{ns}version") or ""
            purl = c.findtext(f"{ns}purl") or ""
            cpe = c.findtext(f"{ns}cpe") or ""
            supplier_el = c.find(f"{ns}supplier")
            supplier = supplier_el.attrib.get("name", "") if supplier_el is not None else ""
            lic_texts = []
            for lic in c.findall(f".//{ns}license"):
                lic_texts.append(lic.findtext(f"{ns}id") or lic.findtext(f"{ns}name") or "")
            comp = Component(
                name=name, version=version, purl=purl, cpe=cpe, license=", ".join(x for x in lic_texts if x),
                supplier=supplier, hashes=len(c.findall(f".//{ns}hash")), bom_ref=c.attrib.get("bom-ref", ""),
                ecosystem=ecosystem_from_purl(purl), direct=c.attrib.get("bom-ref", "") in direct_refs,
            )
            components.append(comp)
        metadata["dependency_graph_present"] = bool(dep_refs)
        metadata["vulnerability_count"] = len(root.findall(f".//{ns}vulnerability"))
        return fmt, components, metadata

    if fmt == "spdx-json":
        data = load_json(path)
        metadata.update({"spdxVersion": data.get("spdxVersion"), "documentNamespace": data.get("documentNamespace")})
        rel_targets = {r.get("relatedSpdxElement") for r in data.get("relationships", []) if isinstance(r, dict)}
        rel_sources = {r.get("spdxElementId") for r in data.get("relationships", []) if isinstance(r, dict)}
        direct = rel_sources - rel_targets
        for p in data.get("packages", []) or []:
            if not isinstance(p, dict):
                continue
            purl = ""
            for ext in p.get("externalRefs", []) or []:
                if ext.get("referenceType") == "purl":
                    purl = ext.get("referenceLocator", "")
            comp = Component(
                name=p.get("name", "unknown"), version=str(p.get("versionInfo", "") or ""), purl=purl,
                cpe="", license=p.get("licenseConcluded") or p.get("licenseDeclared") or "",
                supplier=str(p.get("supplier", "") or ""), hashes=len(p.get("checksums", []) or []),
                bom_ref=p.get("SPDXID", ""), ecosystem=ecosystem_from_purl(purl), direct=p.get("SPDXID") in direct,
            )
            components.append(comp)
        metadata["dependency_graph_present"] = bool(data.get("relationships"))
        return fmt, components, metadata

    if fmt == "spdx-tag-value":
        current: Dict[str, str] = {}
        for line in read_text(path).splitlines():
            if line.startswith("PackageName:") and current:
                components.append(Component(name=current.get("PackageName", "unknown"), version=current.get("PackageVersion", ""), license=current.get("PackageLicenseDeclared", ""), supplier=current.get("PackageSupplier", ""), bom_ref=current.get("SPDXID", "")))
                current = {}
            if ":" in line:
                k, v = line.split(":", 1)
                if k.startswith("Package") or k == "SPDXID":
                    current[k.strip()] = v.strip()
        if current and current.get("PackageName"):
            components.append(Component(name=current.get("PackageName", "unknown"), version=current.get("PackageVersion", ""), license=current.get("PackageLicenseDeclared", ""), supplier=current.get("PackageSupplier", ""), bom_ref=current.get("SPDXID", "")))
        return fmt, components, metadata

    return fmt, components, metadata


def component_stats(components: List[Component], metadata: Dict[str, Any]) -> Dict[str, Any]:
    total = len(components)
    def pct(count: int) -> float:
        return round((count / total * 100), 2) if total else 0.0
    duplicates = total - len({c.key() for c in components})
    invalid_purls = [c for c in components if c.purl and not PURL_RE.match(c.purl)]
    return {
        "component_count": total,
        "with_versions": sum(1 for c in components if c.version),
        "with_purl": sum(1 for c in components if c.purl),
        "with_cpe": sum(1 for c in components if c.cpe),
        "with_license": sum(1 for c in components if c.license and c.license.upper() not in {"NOASSERTION", "NONE"}),
        "with_supplier": sum(1 for c in components if c.supplier),
        "with_hashes": sum(1 for c in components if c.hashes > 0),
        "direct_dependencies": sum(1 for c in components if c.direct),
        "duplicate_components": duplicates,
        "invalid_purls": len(invalid_purls),
        "dependency_graph_present": bool(metadata.get("dependency_graph_present")),
        "version_percent": pct(sum(1 for c in components if c.version)),
        "purl_percent": pct(sum(1 for c in components if c.purl)),
        "license_percent": pct(sum(1 for c in components if c.license and c.license.upper() not in {"NOASSERTION", "NONE"})),
        "hash_percent": pct(sum(1 for c in components if c.hashes > 0)),
        "supplier_percent": pct(sum(1 for c in components if c.supplier)),
        "ecosystems": sorted({c.ecosystem for c in components if c.ecosystem != "unknown"}),
    }


def write_json(path: str | Path, data: Any) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: str | Path, text: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8")


def write_csv(path: str | Path, rows: List[Dict[str, Any]], fields: Optional[List[str]] = None) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if not fields:
        fields = sorted({k for row in rows for k in row.keys()}) if rows else []
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def load_policy(path: str | Path) -> Dict[str, Any]:
    # Small YAML subset loader. Supports nested mappings, booleans, ints, floats, strings.
    data: Dict[str, Any] = {}
    stack: List[Tuple[int, Dict[str, Any]]] = [(-1, data)]
    for raw in read_text(path).splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if val == "":
            child: Dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            low = val.lower()
            if low == "true": parsed: Any = True
            elif low == "false": parsed = False
            else:
                try:
                    parsed = int(val)
                except ValueError:
                    try:
                        parsed = float(val)
                    except ValueError:
                        parsed = val.strip('"\'')
            parent[key] = parsed
    return data


def severity_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(sev).lower(), 0)


def parse_vuln_report(path: str | Path) -> List[Vulnerability]:
    if not path or not Path(path).exists():
        return []
    data = load_json(path)
    vulns: List[Vulnerability] = []
    items = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        if "Results" in data:  # Trivy-like
            for result in data.get("Results", []) or []:
                for v in result.get("Vulnerabilities", []) or []:
                    vv = dict(v)
                    vv.setdefault("Target", result.get("Target", ""))
                    items.append(vv)
        elif "matches" in data:  # Grype-like
            for m in data.get("matches", []) or []:
                v = m.get("vulnerability", {})
                artifact = m.get("artifact", {})
                items.append({**v, "PkgName": artifact.get("name", ""), "InstalledVersion": artifact.get("version", "")})
        elif "vulnerabilities" in data:
            items = data.get("vulnerabilities", []) or []
    for i in items:
        if not isinstance(i, dict):
            continue
        cve = i.get("VulnerabilityID") or i.get("id") or i.get("cve") or i.get("name") or ""
        if not cve:
            m = CVE_RE.search(json.dumps(i))
            cve = m.group(0) if m else "UNKNOWN"
        cvss = i.get("CVSS") or i.get("cvss") or i.get("score") or 0
        if isinstance(cvss, dict):
            cvss = max([x.get("V3Score", 0) or x.get("V2Score", 0) or 0 for x in cvss.values()] or [0])
        try:
            cvss_f = float(cvss or 0)
        except Exception:
            cvss_f = 0.0
        vulns.append(Vulnerability(
            cve=str(cve).upper(), component=i.get("PkgName") or i.get("package") or i.get("component") or i.get("artifact") or "",
            severity=str(i.get("Severity") or i.get("severity") or "unknown").lower(), cvss=cvss_f,
            epss=float(i.get("epss", 0) or 0), kev=bool(i.get("kev") or i.get("cisa_kev") or False),
            fix_available=bool(i.get("FixedVersion") or i.get("fix_available") or i.get("fixAvailable") in {"YES", "PARTIAL", True}),
            scanner=str(i.get("scanner") or "unknown"), source=str(path),
        ))
    return vulns
