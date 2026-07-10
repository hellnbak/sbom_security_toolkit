#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_doc(path: str | Path, default: Any = None) -> Any:
    p = Path(path)
    if not p.exists():
        return default
    text = p.read_text(encoding="utf-8", errors="replace")
    try:
        if p.suffix.lower() in {".yml", ".yaml"} and yaml:
            return yaml.safe_load(text)
        return json.loads(text)
    except Exception:
        return default


def write_doc(path: str | Path, data: Any) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.suffix.lower() in {".yml", ".yaml"} and yaml:
        p.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    else:
        p.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return p


@dataclass(frozen=True)
class Capabilities:
    project_discovery: bool = False
    sbom_import: bool = False
    sbom_export: bool = False
    finding_import: bool = False
    finding_export: bool = False
    exception_import: bool = False
    exception_export: bool = False
    remediation_pr: bool = False
    notifications: bool = False


@dataclass
class ConnectorResult:
    ok: bool
    connector: str
    operation: str
    mode: str = "dry-run"
    records: int = 0
    details: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    started_at: str = field(default_factory=utcnow)
    finished_at: str = field(default_factory=utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HttpClient:
    def __init__(self, timeout: int = 30, retries: int = 3, backoff: float = 0.5, verify_tls: bool = True):
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.verify_tls = verify_tls

    def request(self, url: str, method: str = "GET", headers: Optional[Mapping[str, str]] = None,
                payload: Any = None) -> Dict[str, Any]:
        if not self.verify_tls and not url.startswith("http://localhost") and not url.startswith("http://127.0.0.1"):
            raise ValueError("TLS verification may only be disabled for localhost test endpoints")
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method, headers={"Accept": "application/json", "Content-Type": "application/json", **dict(headers or {})})
        last_error = ""
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    parsed: Any
                    try:
                        parsed = json.loads(body) if body else {}
                    except Exception:
                        parsed = {"raw": body}
                    return {"status": getattr(resp, "status", 200), "headers": dict(resp.headers.items()), "body": parsed}
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                if exc.code in {429, 500, 502, 503, 504} and attempt + 1 < self.retries:
                    time.sleep(self.backoff * (2 ** attempt))
                    continue
                raise RuntimeError(f"HTTP {exc.code}: {body[:500]}") from exc
            except Exception as exc:
                last_error = str(exc)
                if attempt + 1 < self.retries:
                    time.sleep(self.backoff * (2 ** attempt))
                    continue
                raise RuntimeError(last_error) from exc
        raise RuntimeError(last_error or "request failed")


class Connector:
    kind = "base"
    capabilities = Capabilities()

    def __init__(self, name: str, config: Mapping[str, Any]):
        self.name = name
        self.config = dict(config)
        self.read_only = bool(self.config.get("read_only", True))
        self.client = HttpClient(
            timeout=int(self.config.get("timeout_seconds", 30)),
            retries=int(self.config.get("retries", 3)),
            backoff=float(self.config.get("backoff_seconds", 0.5)),
            verify_tls=bool(self.config.get("verify_tls", True)),
        )

    def secret(self, key: str, default_env: str = "") -> str:
        ref = str(self.config.get(key, default_env))
        if ref.startswith("env:"):
            return os.environ.get(ref.split(":", 1)[1], "")
        return os.environ.get(ref, "") if ref else ""

    def describe(self) -> Dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "read_only": self.read_only, "capabilities": asdict(self.capabilities)}

    def test_connection(self, send: bool = False) -> ConnectorResult:
        return ConnectorResult(True, self.name, "test", "dry-run", details={"configured": True, **self.describe()})

    def discover_projects(self, send: bool = False) -> ConnectorResult:
        return ConnectorResult(False, self.name, "discover-projects", error="not supported")

    def sync(self, send: bool = False, sbom: str = "", findings: str = "") -> ConnectorResult:
        return ConnectorResult(True, self.name, "sync", "dry-run", details={"plan": self.describe(), "sbom": sbom, "findings": findings})


class SnykConnector(Connector):
    kind = "snyk"
    capabilities = Capabilities(project_discovery=True, sbom_import=True, sbom_export=True, finding_import=True, exception_import=True, exception_export=True)

    def _headers(self) -> Dict[str, str]:
        token = self.secret("token_ref", "SNYK_TOKEN")
        return {"Authorization": f"token {token}"} if token else {}

    def _base(self) -> str:
        return str(self.config.get("base_url", "https://api.snyk.io")).rstrip("/")

    def _version(self) -> str:
        return str(self.config.get("api_version", "2024-10-15"))

    def test_connection(self, send: bool = False) -> ConnectorResult:
        org = str(self.config.get("org_id", ""))
        if not send:
            return ConnectorResult(True, self.name, "test", details={"org_id_configured": bool(org), "token_configured": bool(self._headers()), **self.describe()})
        if not org or not self._headers():
            return ConnectorResult(False, self.name, "test", "sent", error="org_id and token_ref are required")
        url = f"{self._base()}/rest/orgs/{urllib.parse.quote(org)}?version={self._version()}"
        data = self.client.request(url, headers=self._headers())
        return ConnectorResult(True, self.name, "test", "sent", 1, {"status": data["status"]})

    def discover_projects(self, send: bool = False) -> ConnectorResult:
        org = str(self.config.get("org_id", ""))
        if not send:
            return ConnectorResult(True, self.name, "discover-projects", details={"endpoint": f"/rest/orgs/{org}/projects", "pagination": True})
        url = f"{self._base()}/rest/orgs/{urllib.parse.quote(org)}/projects?version={self._version()}&limit=100"
        projects: List[Any] = []
        while url:
            data = self.client.request(url, headers=self._headers())["body"]
            projects.extend(data.get("data", []))
            nxt = data.get("links", {}).get("next")
            url = urllib.parse.urljoin(self._base(), nxt) if nxt else ""
        return ConnectorResult(True, self.name, "discover-projects", "sent", len(projects), {"projects": projects})


class DependencyTrackConnector(Connector):
    kind = "dependency-track"
    capabilities = Capabilities(project_discovery=True, sbom_import=True, sbom_export=True, finding_import=True, finding_export=True, exception_import=True)

    def _headers(self) -> Dict[str, str]:
        token = self.secret("token_ref", "DEPENDENCY_TRACK_API_KEY")
        return {"X-Api-Key": token} if token else {}

    def _base(self) -> str:
        return str(self.config.get("base_url", "http://localhost:8081")).rstrip("/")

    def test_connection(self, send: bool = False) -> ConnectorResult:
        if not send:
            return ConnectorResult(True, self.name, "test", details={"base_url": self._base(), "token_configured": bool(self._headers()), **self.describe()})
        data = self.client.request(f"{self._base()}/api/version", headers=self._headers())
        return ConnectorResult(True, self.name, "test", "sent", 1, data["body"] if isinstance(data["body"], dict) else {"body": data["body"]})

    def discover_projects(self, send: bool = False) -> ConnectorResult:
        if not send:
            return ConnectorResult(True, self.name, "discover-projects", details={"endpoint": "/api/v1/project", "pagination": True})
        page = 1
        projects: List[Any] = []
        while True:
            response = self.client.request(f"{self._base()}/api/v1/project?pageNumber={page}&pageSize=100", headers=self._headers())
            body = response["body"]
            batch = body if isinstance(body, list) else body.get("data", [])
            projects.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return ConnectorResult(True, self.name, "discover-projects", "sent", len(projects), {"projects": projects})

    def sync(self, send: bool = False, sbom: str = "", findings: str = "") -> ConnectorResult:
        project_name = str(self.config.get("project_name", "SBOM Security Toolkit Project"))
        project_version = str(self.config.get("project_version", "latest"))
        if not send:
            return ConnectorResult(True, self.name, "sync", details={"upload_sbom": bool(sbom), "project_name": project_name, "project_version": project_version, "read_only": self.read_only})
        if self.read_only:
            return ConnectorResult(False, self.name, "sync", "sent", error="connector is read-only; set read_only: false to upload")
        if not sbom:
            return ConnectorResult(False, self.name, "sync", "sent", error="--sbom is required")
        payload = {"projectName": project_name, "projectVersion": project_version, "autoCreate": True, "bom": Path(sbom).read_text(encoding="utf-8")}
        data = self.client.request(f"{self._base()}/api/v1/bom", method="PUT", headers=self._headers(), payload=payload)
        return ConnectorResult(True, self.name, "sync", "sent", 1, data["body"] if isinstance(data["body"], dict) else {"body": data["body"]})


class DefectDojoConnector(Connector):
    kind = "defectdojo"
    capabilities = Capabilities(project_discovery=True, finding_import=True, finding_export=True, exception_import=True, exception_export=True)

    def _headers(self) -> Dict[str, str]:
        token = self.secret("token_ref", "DEFECTDOJO_TOKEN")
        return {"Authorization": f"Token {token}"} if token else {}

    def _base(self) -> str:
        return str(self.config.get("base_url", "http://localhost:8080")).rstrip("/")

    def test_connection(self, send: bool = False) -> ConnectorResult:
        if not send:
            return ConnectorResult(True, self.name, "test", details={"base_url": self._base(), "token_configured": bool(self._headers()), **self.describe()})
        data = self.client.request(f"{self._base()}/api/v2/system_settings/", headers=self._headers())
        return ConnectorResult(True, self.name, "test", "sent", 1, {"status": data["status"]})


class GitHubConnector(Connector):
    kind = "github"
    capabilities = Capabilities(project_discovery=True, finding_import=True, finding_export=True, remediation_pr=True, notifications=True)

    def _headers(self) -> Dict[str, str]:
        token = self.secret("token_ref", "GITHUB_TOKEN")
        return {"Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28"} if token else {}

    def _base(self) -> str:
        return str(self.config.get("base_url", "https://api.github.com")).rstrip("/")

    def test_connection(self, send: bool = False) -> ConnectorResult:
        if not send:
            return ConnectorResult(True, self.name, "test", details={"repository": self.config.get("repository", ""), "token_configured": bool(self._headers()), **self.describe()})
        data = self.client.request(f"{self._base()}/user", headers=self._headers())
        return ConnectorResult(True, self.name, "test", "sent", 1, {"login": data["body"].get("login", "")})


class WebhookConnector(Connector):
    kind = "webhook"
    capabilities = Capabilities(finding_export=True, notifications=True)

    def test_connection(self, send: bool = False) -> ConnectorResult:
        url = str(self.config.get("url_ref", "env:SST_WEBHOOK_URL"))
        resolved = os.environ.get(url.split(":", 1)[1], "") if url.startswith("env:") else url
        return ConnectorResult(True, self.name, "test", "dry-run" if not send else "sent", details={"url_configured": bool(resolved), **self.describe()})

    def sync(self, send: bool = False, sbom: str = "", findings: str = "") -> ConnectorResult:
        url_ref = str(self.config.get("url_ref", "env:SST_WEBHOOK_URL"))
        url = os.environ.get(url_ref.split(":", 1)[1], "") if url_ref.startswith("env:") else url_ref
        payload = {"connector": self.name, "event": "sync", "sbom": sbom, "findings": load_doc(findings, {}) if findings else {}, "timestamp": utcnow()}
        if not send:
            return ConnectorResult(True, self.name, "sync", details={"payload": payload, "url_configured": bool(url)})
        if self.read_only:
            return ConnectorResult(False, self.name, "sync", "sent", error="connector is read-only; set read_only: false to send")
        if not url:
            return ConnectorResult(False, self.name, "sync", "sent", error="webhook URL is not configured")
        data = self.client.request(url, method="POST", payload=payload)
        return ConnectorResult(True, self.name, "sync", "sent", 1, {"status": data["status"]})


CONNECTOR_TYPES = {
    "snyk": SnykConnector,
    "dependency-track": DependencyTrackConnector,
    "dependencytrack": DependencyTrackConnector,
    "defectdojo": DefectDojoConnector,
    "github": GitHubConnector,
    "webhook": WebhookConnector,
}


def default_registry() -> Dict[str, Any]:
    return {"apiVersion": "sbom-toolkit.io/v1", "kind": "ConnectorRegistry", "connectors": []}


def load_registry(path: str | Path) -> Dict[str, Any]:
    doc = load_doc(path, default_registry()) or default_registry()
    doc.setdefault("connectors", [])
    return doc


def connector_from_entry(entry: Mapping[str, Any]) -> Connector:
    kind = str(entry.get("type", "")).lower()
    cls = CONNECTOR_TYPES.get(kind)
    if not cls:
        raise ValueError(f"unsupported connector type: {kind}")
    return cls(str(entry.get("name", kind)), entry.get("config", {}))


def find_connector(registry: Mapping[str, Any], name: str) -> Connector:
    for entry in registry.get("connectors", []):
        if entry.get("name") == name:
            return connector_from_entry(entry)
    raise KeyError(f"connector not found: {name}")


def add_connector(args: argparse.Namespace) -> Dict[str, Any]:
    registry = load_registry(args.registry)
    if args.type not in CONNECTOR_TYPES:
        raise SystemExit(f"Unsupported connector type: {args.type}")
    config = load_doc(args.config, {}) if args.config else {}
    config = dict(config or {})
    config.setdefault("read_only", not args.allow_write)
    config.setdefault("verify_tls", not args.insecure_skip_tls_verify)
    config.setdefault("timeout_seconds", args.timeout_seconds)
    config.setdefault("retries", args.retries)
    replacement = {"name": args.name, "type": args.type, "enabled": True, "config": config, "created_at": utcnow()}
    registry["connectors"] = [x for x in registry["connectors"] if x.get("name") != args.name] + [replacement]
    write_doc(args.registry, registry)
    return {"path": str(args.registry), "connector": replacement}


def list_connectors(args: argparse.Namespace) -> Dict[str, Any]:
    registry = load_registry(args.registry)
    rows = []
    for entry in registry.get("connectors", []):
        try:
            connector = connector_from_entry(entry)
            rows.append({**connector.describe(), "enabled": entry.get("enabled", True)})
        except Exception as exc:
            rows.append({"name": entry.get("name", "unknown"), "kind": entry.get("type", "unknown"), "enabled": entry.get("enabled", True), "error": str(exc)})
    return {"connectors": rows, "count": len(rows)}


def execute(args: argparse.Namespace, operation: str) -> Dict[str, Any]:
    registry = load_registry(args.registry)
    connector = find_connector(registry, args.name)
    if operation == "test":
        result = connector.test_connection(args.send)
    elif operation == "discover":
        result = connector.discover_projects(args.send)
    else:
        result = connector.sync(args.send, getattr(args, "sbom", ""), getattr(args, "findings", ""))
    state = {"connector": connector.describe(), "result": result.to_dict(), "updated_at": utcnow()}
    write_doc(args.out, state)
    return {"path": str(args.out), **state}


def smoke(args: argparse.Namespace) -> Dict[str, Any]:
    base = Path(args.out_dir)
    base.mkdir(parents=True, exist_ok=True)
    registry_path = base / "connectors.yml"
    sample = {
        "apiVersion": "sbom-toolkit.io/v1",
        "kind": "ConnectorRegistry",
        "connectors": [
            {"name": "snyk-demo", "type": "snyk", "enabled": True, "config": {"org_id": "demo", "token_ref": "env:SNYK_TOKEN", "read_only": True}},
            {"name": "dtrack-demo", "type": "dependency-track", "enabled": True, "config": {"base_url": "http://localhost:8081", "token_ref": "env:DEPENDENCY_TRACK_API_KEY", "read_only": True}},
            {"name": "dojo-demo", "type": "defectdojo", "enabled": True, "config": {"base_url": "http://localhost:8080", "token_ref": "env:DEFECTDOJO_TOKEN", "read_only": True}},
            {"name": "github-demo", "type": "github", "enabled": True, "config": {"repository": "hellnbak/sbom_security_toolkit", "token_ref": "env:GITHUB_TOKEN", "read_only": True}},
            {"name": "webhook-demo", "type": "webhook", "enabled": True, "config": {"url_ref": "env:SST_WEBHOOK_URL", "read_only": True}},
        ],
    }
    write_doc(registry_path, sample)
    results = []
    for entry in sample["connectors"]:
        connector = connector_from_entry(entry)
        results.append(connector.test_connection(False).to_dict())
        results.append(connector.sync(False, args.sbom, args.findings).to_dict())
    summary = {"ok": all(r["ok"] for r in results), "registry": str(registry_path), "checks": len(results), "results": results, "created_at": utcnow()}
    write_doc(base / "summary.json", summary)
    return {"path": str(base / "summary.json"), **summary}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Unified connector platform for SBOM Security Toolkit")
    ap.add_argument("--registry", default="configs/connectors.yml")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("add")
    p.add_argument("--name", required=True)
    p.add_argument("--type", required=True, choices=sorted(CONNECTOR_TYPES))
    p.add_argument("--config", default="")
    p.add_argument("--allow-write", action="store_true")
    p.add_argument("--insecure-skip-tls-verify", action="store_true")
    p.add_argument("--timeout-seconds", type=int, default=30)
    p.add_argument("--retries", type=int, default=3)

    sub.add_parser("list")

    for command in ("test", "discover", "sync"):
        p = sub.add_parser(command)
        p.add_argument("--name", required=True)
        p.add_argument("--out", default=f"reports/connectors/{command}.json")
        p.add_argument("--send", action="store_true")
        if command == "sync":
            p.add_argument("--sbom", default="")
            p.add_argument("--findings", default="")

    p = sub.add_parser("smoke")
    p.add_argument("--out-dir", default="reports/connector-smoke")
    p.add_argument("--sbom", default="test-sboms/example-spdx-2.3.json")
    p.add_argument("--findings", default="")

    args = ap.parse_args(argv)
    if args.cmd == "add": out = add_connector(args)
    elif args.cmd == "list": out = list_connectors(args)
    elif args.cmd == "test": out = execute(args, "test")
    elif args.cmd == "discover": out = execute(args, "discover")
    elif args.cmd == "sync": out = execute(args, "sync")
    elif args.cmd == "smoke": out = smoke(args)
    else: raise SystemExit(2)
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
