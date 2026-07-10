#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "configs" / "generated" / "enterprise"
STORAGE = ROOT / "ui" / "storage" / "enterprise"
USERS = GENERATED / "users.yml"
ROLES = GENERATED / "roles.yml"
AUTH = GENERATED / "auth.yml"
SCHEDULES = GENERATED / "schedules.yml"
NOTIFICATIONS = GENERATED / "notifications.yml"
SECRETS = GENERATED / "secrets.yml"
API_TOKENS = GENERATED / "api-tokens.yml"
AUDIT_LOG = STORAGE / "audit.log.jsonl"

DEFAULT_ROLES = {
    "admin": ["*"],
    "maintainer": ["project:create", "project:update", "scan:run", "scan:view", "evidence:view", "policy:update", "schedule:update"],
    "analyst": ["scan:run", "scan:view", "evidence:view", "release:view"],
    "read-only": ["scan:view", "evidence:view", "release:view", "project:view"],
    "service-account": ["scan:run", "scan:view", "evidence:write", "release:view"],
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dirs() -> None:
    GENERATED.mkdir(parents=True, exist_ok=True)
    STORAGE.mkdir(parents=True, exist_ok=True)


def _read_yaml(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    text = path.read_text(encoding="utf-8")
    if yaml:
        return yaml.safe_load(text) or default
    return json.loads(text)


def _write_yaml(path: Path, data: Any) -> Path:
    ensure_dirs()
    if yaml:
        text = yaml.safe_dump(data, sort_keys=False)
    else:
        text = json.dumps(data, indent=2, sort_keys=False)
    path.write_text(text, encoding="utf-8")
    return path


def audit(action: str, actor: str = "system", resource: str = "", status: str = "success", detail: Dict[str, Any] | None = None) -> Dict[str, Any]:
    ensure_dirs()
    entry = {"ts": now(), "actor": actor, "action": action, "resource": resource, "status": status, "detail": detail or {}}
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def load_audit(limit: int = 100) -> List[Dict[str, Any]]:
    if not AUDIT_LOG.exists():
        return []
    lines = AUDIT_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    rows = []
    for line in lines:
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    return rows


def credential_hash(secret_phrase: str) -> Dict[str, str]:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", secret_phrase.encode(), salt, 200_000)
    return {"algorithm": "pbkdf2_sha256", "iterations": "200000", "salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(dk).decode()}


def verify_credential(secret_phrase: str, ph: Dict[str, str]) -> bool:
    salt = base64.b64decode(ph["salt"])
    expected = base64.b64decode(ph["hash"])
    iterations = int(ph.get("iterations", "200000"))
    actual = hashlib.pbkdf2_hmac("sha256", secret_phrase.encode(), salt, iterations)
    return hmac.compare_digest(actual, expected)


def init_auth(args: argparse.Namespace) -> Dict[str, Any]:
    ensure_dirs()
    roles = {"roles": [{"name": k, "permissions": v} for k, v in DEFAULT_ROLES.items()], "updated_at": now()}
    _write_yaml(ROLES, roles)
    auth = {
        "mode": args.mode,
        "session_ttl_minutes": int(args.session_ttl_minutes),
        "password_policy": {"min_length": 12, "require_rotation": False},
        "oidc": {"enabled": args.mode == "oidc", "issuer": args.oidc_issuer or "", "client_id_env": "SST_OIDC_CLIENT_ID", "client_secret_env": "SST_OIDC_CLIENT_SECRET"},
        "created_at": now(),
    }
    _write_yaml(AUTH, auth)
    audit("auth.initialized", actor=args.actor, resource=str(AUTH.relative_to(ROOT)), detail={"mode": args.mode})
    return {"auth": str(AUTH.relative_to(ROOT)), "roles": str(ROLES.relative_to(ROOT))}


def create_user(args: argparse.Namespace) -> Dict[str, Any]:
    users = _read_yaml(USERS, {"users": []})
    pwd = args.password or secrets.token_urlsafe(18)
    existing = [u for u in users.get("users", []) if u.get("username") != args.username]
    user = {
        "username": args.username,
        "display_name": args.display_name or args.username,
        "email": args.email or "",
        "role": args.role,
        "active": True,
        "credential_hash": credential_hash(pwd),
        "created_at": now(),
    }
    users["users"] = existing + [user]
    _write_yaml(USERS, users)
    audit("user.upserted", actor=args.actor, resource=args.username, detail={"role": args.role})
    result = {"path": str(USERS.relative_to(ROOT)), "username": args.username, "role": args.role}
    if not args.password:
        result["generated_password"] = pwd
    return result


def create_role(args: argparse.Namespace) -> Dict[str, Any]:
    roles = _read_yaml(ROLES, {"roles": []})
    perms = [p.strip() for p in args.permissions.split(",") if p.strip()]
    roles["roles"] = [r for r in roles.get("roles", []) if r.get("name") != args.name] + [{"name": args.name, "permissions": perms, "updated_at": now()}]
    _write_yaml(ROLES, roles)
    audit("role.upserted", actor=args.actor, resource=args.name, detail={"permissions": perms})
    return {"path": str(ROLES.relative_to(ROOT)), "name": args.name, "permissions": perms}


def create_schedule(args: argparse.Namespace) -> Dict[str, Any]:
    schedules = _read_yaml(SCHEDULES, {"schedules": []})
    item = {
        "name": args.name,
        "project_id": args.project_id,
        "workflow": args.workflow,
        "cadence": args.cadence,
        "enabled": not args.disabled,
        "policy": args.policy,
        "fuzzing_profile": args.fuzzing_profile,
        "ai_provider": args.ai_provider,
        "created_at": now(),
    }
    schedules["schedules"] = [s for s in schedules.get("schedules", []) if s.get("name") != args.name] + [item]
    _write_yaml(SCHEDULES, schedules)
    audit("schedule.upserted", actor=args.actor, resource=args.name, detail={"workflow": args.workflow, "cadence": args.cadence})
    return {"path": str(SCHEDULES.relative_to(ROOT)), "schedule": item}


def create_notification(args: argparse.Namespace) -> Dict[str, Any]:
    notifications = _read_yaml(NOTIFICATIONS, {"notifications": []})
    item = {"name": args.name, "type": args.type, "target_ref": args.target_ref, "events": [e.strip() for e in args.events.split(",") if e.strip()], "enabled": not args.disabled, "created_at": now()}
    notifications["notifications"] = [n for n in notifications.get("notifications", []) if n.get("name") != args.name] + [item]
    _write_yaml(NOTIFICATIONS, notifications)
    audit("notification.upserted", actor=args.actor, resource=args.name, detail={"type": args.type, "events": item["events"]})
    return {"path": str(NOTIFICATIONS.relative_to(ROOT)), "notification": item}


def create_secret_ref(args: argparse.Namespace) -> Dict[str, Any]:
    secrets_cfg = _read_yaml(SECRETS, {"secrets": []})
    item = {"name": args.name, "provider": args.provider, "reference": args.reference, "purpose": args.purpose, "created_at": now()}
    secrets_cfg["secrets"] = [s for s in secrets_cfg.get("secrets", []) if s.get("name") != args.name] + [item]
    _write_yaml(SECRETS, secrets_cfg)
    audit("secret_ref.upserted", actor=args.actor, resource=args.name, detail={"provider": args.provider, "purpose": args.purpose})
    return {"path": str(SECRETS.relative_to(ROOT)), "secret": item}


def create_api_token(args: argparse.Namespace) -> Dict[str, Any]:
    tokens = _read_yaml(API_TOKENS, {"tokens": []})
    raw = "sst_" + secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    item = {"name": args.name, "owner": args.owner, "role": args.role, "token_hash_sha256": token_hash, "active": True, "created_at": now(), "expires_at": args.expires_at or ""}
    tokens["tokens"] = [t for t in tokens.get("tokens", []) if t.get("name") != args.name] + [item]
    _write_yaml(API_TOKENS, tokens)
    audit("api_token.created", actor=args.actor, resource=args.name, detail={"owner": args.owner, "role": args.role})
    return {"path": str(API_TOKENS.relative_to(ROOT)), "name": args.name, "token_once": raw, "note": "Store this token now. Only its SHA-256 hash is saved."}


def health(args: argparse.Namespace) -> Dict[str, Any]:
    ensure_dirs()
    checks = []
    for label, path in [("auth", AUTH), ("roles", ROLES), ("users", USERS), ("schedules", SCHEDULES), ("notifications", NOTIFICATIONS), ("secrets", SECRETS), ("api_tokens", API_TOKENS), ("audit_log", AUDIT_LOG)]:
        checks.append({"name": label, "path": str(path.relative_to(ROOT)), "exists": path.exists(), "bytes": path.stat().st_size if path.exists() else 0})
    configured = sum(1 for c in checks if c["exists"])
    status = "ok" if configured >= 2 else "needs-setup"
    return {"status": status, "generated_dir": str(GENERATED.relative_to(ROOT)), "storage_dir": str(STORAGE.relative_to(ROOT)), "checks": checks}


def setup_wizard(args: argparse.Namespace) -> Dict[str, Any]:
    init_auth(argparse.Namespace(mode=args.mode, session_ttl_minutes=args.session_ttl_minutes, oidc_issuer=args.oidc_issuer, actor=args.actor))
    user_result = create_user(argparse.Namespace(**{"username": args.admin_username, "display_name": args.admin_display_name or args.admin_username, "email": args.admin_email or "", "role": "admin", "password": args.admin_password, "actor": args.actor}))
    create_schedule(argparse.Namespace(name="daily-repo-intake", project_id=args.project_id, workflow="repo-intake", cadence="daily", disabled=False, policy="policies/generated/release-policy.yml", fuzzing_profile="configs/generated/fuzzing-profiles/release-smoke.yml", ai_provider="configs/generated/ai-providers/default-ai.yml", actor=args.actor))
    create_notification(argparse.Namespace(name="default-webhook", type="webhook", target_ref="SST_WEBHOOK_URL", events="policy_failed,release_blocked,scan_failed,evidence_ready", disabled=True, actor=args.actor))
    audit("setup.completed", actor=args.actor, resource=args.project_id, detail={"mode": args.mode})
    return {"auth": str(AUTH.relative_to(ROOT)), "roles": str(ROLES.relative_to(ROOT)), "users": str(USERS.relative_to(ROOT)), "admin": {k: v for k, v in user_result.items() if k != "generated_password"}, "generated_admin_password": user_result.get("generated_password"), "schedule": str(SCHEDULES.relative_to(ROOT)), "notification": str(NOTIFICATIONS.relative_to(ROOT))}


def list_all(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "auth": _read_yaml(AUTH, {}),
        "roles": _read_yaml(ROLES, {}),
        "users": [{k: v for k, v in u.items() if k != "credential_hash"} for u in _read_yaml(USERS, {"users": []}).get("users", [])],
        "schedules": _read_yaml(SCHEDULES, {}),
        "notifications": _read_yaml(NOTIFICATIONS, {}),
        "secrets": _read_yaml(SECRETS, {}),
        "api_tokens": [{k: v for k, v in t.items() if k != "token_hash_sha256"} for t in _read_yaml(API_TOKENS, {"tokens": []}).get("tokens", [])],
        "audit_tail": load_audit(args.audit_limit),
    }


def add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--actor", default="cli")


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Enterprise cloud hardening helper for auth, RBAC, audit, schedules, notifications, secrets, and service accounts")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init-auth"); add_common(p); p.add_argument("--mode", choices=["local", "oidc", "disabled"], default="local"); p.add_argument("--session-ttl-minutes", default="480"); p.add_argument("--oidc-issuer", default="")
    p = sub.add_parser("create-user"); add_common(p); p.add_argument("--username", required=True); p.add_argument("--display-name", default=""); p.add_argument("--email", default=""); p.add_argument("--role", default="analyst"); p.add_argument("--password", default="")
    p = sub.add_parser("create-role"); add_common(p); p.add_argument("--name", required=True); p.add_argument("--permissions", required=True)
    p = sub.add_parser("schedule"); add_common(p); p.add_argument("--name", required=True); p.add_argument("--project-id", default="default-project"); p.add_argument("--workflow", default="analyze-everything"); p.add_argument("--cadence", default="daily"); p.add_argument("--policy", default="policies/generated/release-policy.yml"); p.add_argument("--fuzzing-profile", default="configs/generated/fuzzing-profiles/release-smoke.yml"); p.add_argument("--ai-provider", default="configs/generated/ai-providers/default-ai.yml"); p.add_argument("--disabled", action="store_true")
    p = sub.add_parser("notification"); add_common(p); p.add_argument("--name", required=True); p.add_argument("--type", choices=["webhook", "slack", "email"], default="webhook"); p.add_argument("--target-ref", default="SST_WEBHOOK_URL"); p.add_argument("--events", default="policy_failed,release_blocked,scan_failed,evidence_ready"); p.add_argument("--disabled", action="store_true")
    p = sub.add_parser("secret-ref"); add_common(p); p.add_argument("--name", required=True); p.add_argument("--provider", choices=["env", "aws-secrets-manager", "docker-secret", "kubernetes-secret", "local-encrypted"], default="env"); p.add_argument("--reference", required=True); p.add_argument("--purpose", default="generic")
    p = sub.add_parser("api-token"); add_common(p); p.add_argument("--name", required=True); p.add_argument("--owner", default="service-account"); p.add_argument("--role", default="service-account"); p.add_argument("--expires-at", default="")
    p = sub.add_parser("audit-log"); add_common(p); p.add_argument("--action", required=True); p.add_argument("--resource", default=""); p.add_argument("--status", default="success"); p.add_argument("--detail", default="{}")
    p = sub.add_parser("audit-list"); p.add_argument("--limit", type=int, default=100)
    p = sub.add_parser("health")
    p = sub.add_parser("setup-wizard"); add_common(p); p.add_argument("--mode", choices=["local", "oidc", "disabled"], default="local"); p.add_argument("--session-ttl-minutes", default="480"); p.add_argument("--oidc-issuer", default=""); p.add_argument("--admin-username", default="admin"); p.add_argument("--admin-display-name", default=""); p.add_argument("--admin-email", default=""); p.add_argument("--admin-password", default=""); p.add_argument("--project-id", default="default-project")
    p = sub.add_parser("list"); p.add_argument("--audit-limit", type=int, default=20)

    args = ap.parse_args(argv)
    if args.cmd == "init-auth": out = init_auth(args)
    elif args.cmd == "create-user": out = create_user(args)
    elif args.cmd == "create-role": out = create_role(args)
    elif args.cmd == "schedule": out = create_schedule(args)
    elif args.cmd == "notification": out = create_notification(args)
    elif args.cmd == "secret-ref": out = create_secret_ref(args)
    elif args.cmd == "api-token": out = create_api_token(args)
    elif args.cmd == "audit-log": out = audit(args.action, args.actor, args.resource, args.status, json.loads(args.detail))
    elif args.cmd == "audit-list": out = {"audit": load_audit(args.limit)}
    elif args.cmd == "health": out = health(args)
    elif args.cmd == "setup-wizard": out = setup_wizard(args)
    elif args.cmd == "list": out = list_all(args)
    else: raise SystemExit(2)
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
