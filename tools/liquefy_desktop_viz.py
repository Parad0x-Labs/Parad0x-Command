#!/usr/bin/env python3
"""
liquefy_desktop_viz.py
======================
Galactic Desktop — live filesystem & system visualization.

Commands:
    scan   <path>    Scan directory and generate graph JSON
    render <path>    Scan + generate interactive HTML visualization
    serve  <path>    Scan + render + launch local web server
    live   <path>    Full system organism — hardware core, processes, agents,
                     files, all connected with live-updating flows and
                     hologram inspectors. The real deal.
    commanddeck [path] Browser-native cockpit: desktop clone + history telemetry
"""
from __future__ import annotations

import argparse
import collections
import configparser
import csv
import hashlib
import http.server
import mimetypes
import json
import math
import os
import platform
import re
import shutil
import subprocess
import random
import secrets
import signal
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
CLI_SCHEMA = "liquefy.desktop-viz.v1"

TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

try:
    from liquefy_token_ledger import _estimate_cost as _estimate_token_cost
except Exception:  # pragma: no cover - fallback for minimal environments
    def _estimate_token_cost(model: str, input_tokens: int, output_tokens: int) -> float:
        return 0.0

try:
    from liquefy_policy_enforcer import verify_halt_signal, _write_kill_signal
except Exception:  # pragma: no cover - fallback when tool imports fail
    verify_halt_signal = None
    _write_kill_signal = None

SKIP_DIRS: Set[str] = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", ".pytest_cache",
    ".Trash", ".Spotlight-V100", ".fseventsd", ".DS_Store", "Library",
    "System", ".cache", ".npm", ".yarn",
}

MAX_FILES = 5000
MAX_DEPTH = 8
_NETWORK_PANIC_STATE: Dict[str, Any] = {}


def _allowed_local_api_hosts(port: int) -> Set[str]:
    return {
        f"127.0.0.1:{int(port)}",
        f"localhost:{int(port)}",
    }


def _header_origin_host(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        return str(parsed.netloc or "").strip().lower()
    return raw.rstrip("/")


def _validate_local_api_request(headers: Any, port: int, api_token: str) -> Optional[str]:
    allowed_hosts = _allowed_local_api_hosts(port)
    host = _header_origin_host(getattr(headers, "get", lambda *_: "")("Host", ""))
    if host not in allowed_hosts:
        return "Request host rejected"

    if api_token:
        header_token = str(getattr(headers, "get", lambda *_: "")("X-Parad0x-Token", "") or "")
        if header_token != api_token:
            return "Invalid API token"

    origin = _header_origin_host(getattr(headers, "get", lambda *_: "")("Origin", ""))
    if origin and origin not in allowed_hosts:
        return "Request origin rejected"

    referer = _header_origin_host(getattr(headers, "get", lambda *_: "")("Referer", ""))
    if referer and referer not in allowed_hosts:
        return "Request referer rejected"

    return None


def _send_json_response(handler: http.server.BaseHTTPRequestHandler, status: int, payload: Dict[str, Any], extra_headers: Optional[Dict[str, str]] = None) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    for key, value in (extra_headers or {}).items():
        handler.send_header(str(key), str(value))
    handler.end_headers()
    handler.wfile.write(json.dumps(payload).encode("utf-8"))


def _read_json_request_body(handler: http.server.BaseHTTPRequestHandler) -> Dict[str, Any]:
    try:
        length = int(handler.headers.get("Content-Length", "0") or 0)
    except Exception:
        length = 0
    raw = handler.rfile.read(length) if length > 0 else b"{}"
    if not raw:
        return {}
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}

FILE_TYPE_MAP: Dict[str, str] = {
    ".py": "python", ".js": "javascript", ".ts": "typescript", ".jsx": "react",
    ".tsx": "react", ".rs": "rust", ".go": "golang", ".java": "java",
    ".c": "c", ".cpp": "cpp", ".h": "header", ".hpp": "header",
    ".json": "data", ".jsonl": "data", ".ndjson": "data", ".csv": "data",
    ".tsv": "data", ".xml": "data", ".yaml": "config", ".yml": "config",
    ".toml": "config", ".ini": "config", ".cfg": "config", ".conf": "config",
    ".env": "secret", ".pem": "secret", ".key": "secret", ".p12": "secret",
    ".md": "docs", ".txt": "docs", ".rst": "docs", ".pdf": "docs",
    ".html": "web", ".htm": "web", ".css": "web", ".scss": "web",
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
    ".svg": "image", ".ico": "image", ".webp": "image",
    ".mp4": "video", ".webm": "video", ".mov": "video",
    ".mp3": "audio", ".wav": "audio", ".ogg": "audio",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".fish": "shell",
    ".sql": "database", ".db": "database", ".sqlite": "database",
    ".log": "logs", ".out": "logs",
    ".zip": "archive", ".tar": "archive", ".gz": "archive", ".bz2": "archive",
    ".7z": "archive", ".rar": "archive", ".null": "vault",
    ".lock": "lockfile", ".sum": "lockfile",
    ".sol": "solidity", ".vy": "vyper",
    ".wasm": "binary", ".exe": "binary", ".dll": "binary", ".so": "binary",
    ".dylib": "binary",
}

TYPE_COLORS: Dict[str, str] = {
    "python": "#3572A5", "javascript": "#f1e05a", "typescript": "#3178c6",
    "react": "#61dafb", "rust": "#dea584", "golang": "#00ADD8",
    "java": "#b07219", "c": "#555555", "cpp": "#f34b7d", "header": "#888888",
    "data": "#4ec9b0", "config": "#e6db74", "secret": "#ff4444",
    "docs": "#aaaaaa", "web": "#e34c26", "image": "#a855f7",
    "video": "#ec4899", "audio": "#8b5cf6", "shell": "#89e051",
    "database": "#e38c00", "logs": "#6b7280", "archive": "#9ca3af",
    "vault": "#00ff88", "lockfile": "#555555", "solidity": "#AA6746",
    "vyper": "#2980b9", "binary": "#333333", "folder": "#fbbf24",
    "unknown": "#666666",
}

SENSITIVITY_PATTERNS = [
    ".env", ".pem", ".key", ".p12", ".pfx", "credentials", "secret",
    "password", "token", "auth", ".ssh", "id_rsa", "id_ed25519",
]

AGENT_PATTERNS = [
    "SOUL.md", "HEARTBEAT.md", "auth-profiles.json", "agent", "openclaw",
    ".liquefy", "task.md", "skill", "session", "trace",
]

LOG_PATTERNS = [".log", "audit", "trace", "event", ".jsonl", ".ndjson"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit(command: str, ok: bool, result: Dict[str, Any]) -> None:
    payload = {
        "schema_version": CLI_SCHEMA,
        "tool": "liquefy_desktop_viz",
        "command": command,
        "ok": ok,
        "generated_at_utc": _utc_now(),
        "result": result,
    }
    print(json.dumps(payload, indent=2))


def _safe_load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_history_guard_summary(workspace: Optional[Path]) -> Dict[str, Any]:
    if workspace is None:
        return {
            "enabled": False,
            "workspace": None,
            "providers": [],
            "active_provider": None,
            "last_action": None,
            "risky_actions_24h": 0,
            "alerts": [],
        }

    ws = workspace.expanduser().resolve()
    cfg_path = ws / ".liquefy" / "history_guard.json"
    state_path = ws / ".liquefy" / "history_guard_state.json"
    cfg = _safe_load_json(cfg_path) if cfg_path.exists() else {}
    state = _safe_load_json(state_path) if state_path.exists() else {}
    providers_cfg = {str(p.get("id", "")).strip(): p for p in cfg.get("providers", []) if str(p.get("id", "")).strip()}
    provider_state = state.get("providers", {}) if isinstance(state.get("providers", {}), dict) else {}
    actions = state.get("actions", []) if isinstance(state.get("actions", []), list) else []

    provider_rows: List[Dict[str, Any]] = []
    active_provider: Optional[str] = None
    active_provider_ts = -1
    alerts: List[str] = []

    all_provider_ids = sorted(set(list(providers_cfg.keys()) + list(provider_state.keys())))
    for pid in all_provider_ids:
        cfg_item = providers_cfg.get(pid, {})
        st = provider_state.get(pid, {}) if isinstance(provider_state.get(pid, {}), dict) else {}
        last_pull_unix = int(st.get("last_pull_unix", 0) or 0)
        row = {
            "id": pid,
            "enabled": bool(cfg_item.get("enabled", False)),
            "type": str(cfg_item.get("type", "unknown")),
            "last_ok": st.get("last_ok"),
            "last_pull_utc": st.get("last_pull_utc"),
            "last_pull_unix": last_pull_unix,
            "last_error": st.get("last_error"),
            "last_exported_bytes": int(st.get("last_exported_bytes", 0) or 0),
        }
        if row["last_ok"] is False:
            alerts.append(f"provider {pid} last pull failed")
        if row["last_error"]:
            alerts.append(f"provider {pid}: {row['last_error']}")
        if last_pull_unix > active_provider_ts:
            active_provider_ts = last_pull_unix
            active_provider = pid
        provider_rows.append(row)

    now_ts = int(time.time())
    day_ago = now_ts - 86400
    risky_actions_24h = 0
    last_action: Optional[Dict[str, Any]] = None
    last_action_ts = -1
    for a in actions[-300:]:
        ts = str(a.get("ts", ""))
        parsed = 0
        try:
            parsed = int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
        except Exception:
            parsed = 0
        if bool(a.get("risky", False)) and parsed >= day_ago:
            risky_actions_24h += 1
        if parsed >= last_action_ts:
            last_action_ts = parsed
            last_action = {
                "ts": ts,
                "type": str(a.get("type", "action")),
                "command": str(a.get("command", ""))[:240],
                "risky": bool(a.get("risky", False)),
                "approval_ok": a.get("approval_ok"),
                "action_rc": a.get("action_rc"),
            }

    if risky_actions_24h > 0:
        alerts.append(f"{risky_actions_24h} risky actions in last 24h")

    return {
        "enabled": True,
        "workspace": str(ws),
        "config_path": str(cfg_path),
        "state_path": str(state_path),
        "providers": provider_rows,
        "active_provider": active_provider,
        "last_action": last_action,
        "risky_actions_24h": risky_actions_24h,
        "alerts": alerts[:8],
        "generated_at_utc": _utc_now(),
    }


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None
    return None


def _load_ledger_entries(ledger_path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        with ledger_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    rows.append(obj)
    except OSError:
        pass
    return rows


def _load_codex_session_entries(limit_files: int = 80) -> List[Dict[str, Any]]:
    roots = [
        Path.home() / ".codex" / "sessions",
        Path.home() / ".codex" / "archived_sessions",
    ]
    files: List[Path] = []
    for root in roots:
        if not root.exists():
            continue
        try:
            files.extend(p for p in root.rglob("*.jsonl") if p.is_file())
        except OSError:
            continue
    files = sorted(files, key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)[:limit_files]
    out: List[Dict[str, Any]] = []
    seen_events: set[Tuple[str, str, int, int, int]] = set()
    for path in files:
        last_model = "unknown"
        last_usage_sig = None
        last_total_usage = None
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    payload = obj.get("payload", {})
                    if obj.get("type") == "turn_context" and isinstance(payload, dict):
                        last_model = str(payload.get("model") or payload.get("model_name") or last_model).strip().lower()
                        continue
                    if obj.get("type") != "event_msg" or payload.get("type") != "token_count":
                        continue
                    info = payload.get("info", {}) if isinstance(payload.get("info", {}), dict) else {}
                    rate_limits = payload.get("rate_limits", {}) if isinstance(payload.get("rate_limits", {}), dict) else {}
                    last_usage = info.get("last_token_usage", {}) if isinstance(info.get("last_token_usage", {}), dict) else {}
                    total_usage = info.get("total_token_usage", {}) if isinstance(info.get("total_token_usage", {}), dict) else {}
                    inp = 0
                    outp = 0
                    total = 0
                    if last_usage:
                        inp = int(last_usage.get("input_tokens", 0) or 0)
                        outp = int(last_usage.get("output_tokens", 0) or 0)
                        total = int(last_usage.get("total_tokens", inp + outp) or (inp + outp))
                    elif total_usage:
                        curr_in = int(total_usage.get("input_tokens", 0) or 0)
                        curr_out = int(total_usage.get("output_tokens", 0) or 0)
                        curr_total = int(total_usage.get("total_tokens", curr_in + curr_out) or (curr_in + curr_out))
                        if last_total_usage is None:
                            last_total_usage = (curr_in, curr_out, curr_total)
                            continue
                        prev_in, prev_out, prev_total = last_total_usage
                        inp = max(0, curr_in - prev_in)
                        outp = max(0, curr_out - prev_out)
                        total = max(0, curr_total - prev_total)
                        last_total_usage = (curr_in, curr_out, curr_total)
                    if total <= 0:
                        continue
                    usage_sig = (inp, outp, total)
                    if usage_sig == last_usage_sig:
                        continue
                    last_usage_sig = usage_sig
                    # Local Codex total_token_usage is cumulative for the whole session and can reach
                    # absurd values; prefer per-event last_token_usage and discard obvious outliers.
                    if total > 5_000_000:
                        continue
                    model = str(
                        info.get("model")
                        or info.get("model_name")
                        or payload.get("model")
                        or payload.get("model_name")
                        or rate_limits.get("limit_name")
                        or last_model
                        or "unknown"
                    ).strip().lower()
                    event_ts = str(obj.get("timestamp") or "")
                    event_key = (event_ts, model, inp, outp, total)
                    if event_key in seen_events:
                        continue
                    seen_events.add(event_key)
                    out.append(
                        {
                            "ts": event_ts,
                            "model": model,
                            "input_tokens": inp,
                            "output_tokens": outp,
                            "total_tokens": total,
                            "source": str(path),
                        }
                    )
        except OSError:
            continue
    return out


def _load_ai_billing_profile(workspace: Optional[Path]) -> Dict[str, Any]:
    profile: Dict[str, Any] = {
        "mode": "",
        "label": "",
        "quota_used": None,
        "quota_limit": None,
        "reset_at": None,
        "spend_limit_usd": None,
        "profile_source": "",
    }
    candidates: List[Path] = []
    if workspace:
        candidates.append(workspace / ".liquefy-tokens" / "billing.json")
    candidates.append(Path.home() / ".liquefy-ai-billing.json")

    for candidate in candidates:
        data = _safe_load_json(candidate)
        if isinstance(data, dict) and data:
            profile.update({
                "mode": str(data.get("mode", profile["mode"]) or "").strip().lower(),
                "label": str(data.get("label", profile["label"]) or "").strip(),
                "quota_used": data.get("quota_used", profile["quota_used"]),
                "quota_limit": data.get("quota_limit", profile["quota_limit"]),
                "reset_at": data.get("reset_at", profile["reset_at"]),
                "spend_limit_usd": data.get("spend_limit_usd", profile["spend_limit_usd"]),
                "profile_source": str(candidate),
            })
            break

    env_mode = str(os.environ.get("LIQUEFY_AI_BILLING_MODE", "") or "").strip().lower()
    if env_mode:
        profile["mode"] = env_mode
        profile["profile_source"] = "env"
    for env_key, profile_key in (
        ("LIQUEFY_AI_BILLING_LABEL", "label"),
        ("LIQUEFY_AI_BILLING_RESET_AT", "reset_at"),
    ):
        value = str(os.environ.get(env_key, "") or "").strip()
        if value:
            profile[profile_key] = value
    for env_key, profile_key in (
        ("LIQUEFY_AI_QUOTA_USED", "quota_used"),
        ("LIQUEFY_AI_QUOTA_LIMIT", "quota_limit"),
        ("LIQUEFY_AI_SPEND_LIMIT_USD", "spend_limit_usd"),
    ):
        value = str(os.environ.get(env_key, "") or "").strip()
        if value:
            try:
                profile[profile_key] = float(value)
            except ValueError:
                pass
    return profile


def _http_json_get(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 6.0) -> Optional[Dict[str, Any]]:
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except Exception:
        return None
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def _provider_hint(ai_usage: Dict[str, Any], profile: Dict[str, Any]) -> str:
    explicit = str(os.environ.get("LIQUEFY_AI_PROVIDER", "") or "").strip().lower()
    if explicit:
        return explicit
    label = str(profile.get("label") or "").strip().lower()
    if "openai" in label or "chatgpt" in label or "codex" in label:
        return "openai"
    if "anthropic" in label or "claude" in label:
        return "anthropic"
    if "gemini" in label or "google" in label:
        return "gemini"
    for model_name, _count in ai_usage.get("top_models", []) or []:
        model_lower = str(model_name or "").lower()
        if any(k in model_lower for k in ("gpt", "codex", "o1", "o3", "o4")):
            return "openai"
        if "claude" in model_lower:
            return "anthropic"
        if "gemini" in model_lower:
            return "gemini"
    return "unknown"


def _sum_openai_usage_buckets(payload: Dict[str, Any]) -> Dict[str, Any]:
    out = {"requests": 0, "input_tokens": 0, "output_tokens": 0, "top_models": collections.Counter()}
    for bucket in payload.get("data", []) or []:
        if not isinstance(bucket, dict):
            continue
        for result in bucket.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            out["requests"] += int(result.get("num_model_requests", 0) or 0)
            out["input_tokens"] += int(result.get("input_tokens", 0) or 0)
            out["output_tokens"] += int(result.get("output_tokens", 0) or 0)
            model = str(result.get("model") or result.get("model_name") or "unknown").strip().lower()
            if model and model != "unknown":
                out["top_models"][model] += int(result.get("num_model_requests", 0) or 1)
    return out


def _sum_openai_cost_buckets(payload: Dict[str, Any]) -> float:
    total = 0.0
    for bucket in payload.get("data", []) or []:
        if not isinstance(bucket, dict):
            continue
        for result in bucket.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            amount = result.get("amount")
            if isinstance(amount, dict):
                value = amount.get("value")
                if value is not None:
                    try:
                        total += float(value)
                        continue
                    except Exception:
                        pass
            for key in ("cost_usd", "amount_usd", "usd", "value"):
                if result.get(key) is not None:
                    try:
                        total += float(result.get(key))
                        break
                    except Exception:
                        continue
    return round(total, 6)


def _fetch_openai_provider_status() -> Dict[str, Any]:
    admin_key = str(os.environ.get("OPENAI_ADMIN_KEY", "") or "").strip()
    if not admin_key:
        return {
            "provider": "openai",
            "provider_api_status": "unconfigured",
            "provider_api_note": "Set OPENAI_ADMIN_KEY to fetch exact OpenAI org usage/cost.",
            "provider_exact_usage": False,
            "provider_exact_billing": False,
            "provider_exact_plan": False,
        }
    now = datetime.now(timezone.utc)
    today_start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    month_start = now - timedelta(days=30)
    headers = {
        "Authorization": f"Bearer {admin_key}",
        "Content-Type": "application/json",
    }
    day_usage = _http_json_get(
        "https://api.openai.com/v1/organization/usage/completions?" + urllib.parse.urlencode({
            "start_time": int(today_start.timestamp()),
            "bucket_width": "1d",
            "limit": 1,
        }),
        headers=headers,
    )
    month_usage = _http_json_get(
        "https://api.openai.com/v1/organization/usage/completions?" + urllib.parse.urlencode({
            "start_time": int(month_start.timestamp()),
            "bucket_width": "1d",
            "limit": 31,
        }),
        headers=headers,
    )
    day_costs = _http_json_get(
        "https://api.openai.com/v1/organization/costs?" + urllib.parse.urlencode({
            "start_time": int(today_start.timestamp()),
            "bucket_width": "1d",
            "limit": 1,
        }),
        headers=headers,
    )
    month_costs = _http_json_get(
        "https://api.openai.com/v1/organization/costs?" + urllib.parse.urlencode({
            "start_time": int(month_start.timestamp()),
            "bucket_width": "1d",
            "limit": 31,
        }),
        headers=headers,
    )
    if not day_usage and not month_usage and not day_costs and not month_costs:
        return {
            "provider": "openai",
            "provider_api_status": "error",
            "provider_api_note": "OpenAI provider API request failed or returned no data.",
            "provider_exact_usage": False,
            "provider_exact_billing": False,
            "provider_exact_plan": False,
        }
    day_usage_sum = _sum_openai_usage_buckets(day_usage or {})
    month_usage_sum = _sum_openai_usage_buckets(month_usage or {})
    return {
        "provider": "openai",
        "provider_api_status": "ok",
        "provider_api_note": "Exact OpenAI org usage/cost via admin endpoints.",
        "provider_exact_usage": True,
        "provider_exact_billing": True,
        "provider_exact_plan": False,
        "provider_requests_today": day_usage_sum["requests"],
        "provider_input_tokens_today": day_usage_sum["input_tokens"],
        "provider_output_tokens_today": day_usage_sum["output_tokens"],
        "provider_total_tokens_today": day_usage_sum["input_tokens"] + day_usage_sum["output_tokens"],
        "provider_cost_usd_today": _sum_openai_cost_buckets(day_costs or {}),
        "provider_month_cost_usd": _sum_openai_cost_buckets(month_costs or {}),
        "provider_top_models": month_usage_sum["top_models"].most_common(3),
        "provider_source": "openai_admin_api",
    }


def _sum_anthropic_usage_buckets(payload: Dict[str, Any]) -> Dict[str, Any]:
    out = {"requests": 0, "input_tokens": 0, "output_tokens": 0, "top_models": collections.Counter()}
    for bucket in payload.get("data", []) or []:
        if not isinstance(bucket, dict):
            continue
        out["requests"] += int(bucket.get("num_requests", 0) or 0)
        input_total = 0
        for key in ("uncached_input_tokens", "cached_input_tokens", "cache_creation_input_tokens", "input_tokens"):
            input_total += int(bucket.get(key, 0) or 0)
        out["input_tokens"] += input_total
        out["output_tokens"] += int(bucket.get("output_tokens", 0) or 0)
        model = str(bucket.get("model") or "unknown").strip().lower()
        if model and model != "unknown":
            out["top_models"][model] += int(bucket.get("num_requests", 0) or 1)
    return out


def _sum_anthropic_cost_buckets(payload: Dict[str, Any]) -> float:
    total = 0.0
    for bucket in payload.get("data", []) or []:
        if not isinstance(bucket, dict):
            continue
        amount = bucket.get("amount")
        if isinstance(amount, dict):
            value = amount.get("value")
            if value is not None:
                try:
                    total += float(value)
                    continue
                except Exception:
                    pass
        for key in ("cost_usd", "amount_usd", "usd", "value"):
            if bucket.get(key) is not None:
                try:
                    total += float(bucket.get(key))
                    break
                except Exception:
                    continue
    return round(total, 6)


def _fetch_anthropic_provider_status() -> Dict[str, Any]:
    admin_key = str(os.environ.get("ANTHROPIC_ADMIN_KEY", "") or os.environ.get("ANTHROPIC_X_API_KEY", "") or "").strip()
    if not admin_key:
        return {
            "provider": "anthropic",
            "provider_api_status": "unconfigured",
            "provider_api_note": "Set ANTHROPIC_ADMIN_KEY to fetch exact Anthropic org usage/cost.",
            "provider_exact_usage": False,
            "provider_exact_billing": False,
            "provider_exact_plan": False,
        }
    now = datetime.now(timezone.utc)
    today_start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    month_start = now - timedelta(days=30)
    headers = {
        "x-api-key": admin_key,
        "anthropic-version": "2023-06-01",
    }
    day_usage = _http_json_get(
        "https://api.anthropic.com/v1/organizations/usage_report/messages?" + urllib.parse.urlencode({
            "starting_at": today_start.isoformat().replace("+00:00", "Z"),
            "ending_at": now.isoformat().replace("+00:00", "Z"),
            "bucket_width": "1d",
        }),
        headers=headers,
    )
    month_usage = _http_json_get(
        "https://api.anthropic.com/v1/organizations/usage_report/messages?" + urllib.parse.urlencode({
            "starting_at": month_start.isoformat().replace("+00:00", "Z"),
            "ending_at": now.isoformat().replace("+00:00", "Z"),
            "bucket_width": "1d",
            "group_by[]": "model",
        }),
        headers=headers,
    )
    day_costs = _http_json_get(
        "https://api.anthropic.com/v1/organizations/cost_report?" + urllib.parse.urlencode({
            "starting_at": today_start.isoformat().replace("+00:00", "Z"),
            "ending_at": now.isoformat().replace("+00:00", "Z"),
        }),
        headers=headers,
    )
    month_costs = _http_json_get(
        "https://api.anthropic.com/v1/organizations/cost_report?" + urllib.parse.urlencode({
            "starting_at": month_start.isoformat().replace("+00:00", "Z"),
            "ending_at": now.isoformat().replace("+00:00", "Z"),
        }),
        headers=headers,
    )
    if not day_usage and not month_usage and not day_costs and not month_costs:
        return {
            "provider": "anthropic",
            "provider_api_status": "error",
            "provider_api_note": "Anthropic Admin API request failed or returned no data.",
            "provider_exact_usage": False,
            "provider_exact_billing": False,
            "provider_exact_plan": False,
        }
    day_usage_sum = _sum_anthropic_usage_buckets(day_usage or {})
    month_usage_sum = _sum_anthropic_usage_buckets(month_usage or {})
    return {
        "provider": "anthropic",
        "provider_api_status": "ok",
        "provider_api_note": "Exact Anthropic org usage/cost via Admin API.",
        "provider_exact_usage": True,
        "provider_exact_billing": True,
        "provider_exact_plan": False,
        "provider_requests_today": day_usage_sum["requests"],
        "provider_input_tokens_today": day_usage_sum["input_tokens"],
        "provider_output_tokens_today": day_usage_sum["output_tokens"],
        "provider_total_tokens_today": day_usage_sum["input_tokens"] + day_usage_sum["output_tokens"],
        "provider_cost_usd_today": _sum_anthropic_cost_buckets(day_costs or {}),
        "provider_month_cost_usd": _sum_anthropic_cost_buckets(month_costs or {}),
        "provider_top_models": month_usage_sum["top_models"].most_common(3),
        "provider_source": "anthropic_admin_api",
    }


def _fetch_gemini_provider_status(profile: Dict[str, Any]) -> Dict[str, Any]:
    tier = str(os.environ.get("GEMINI_USAGE_TIER", "") or profile.get("label") or "").strip()
    return {
        "provider": "gemini",
        "provider_api_status": "partial",
        "provider_api_note": "Gemini docs expose billing tiers and rate limits, but not a comparable exact usage/cost org API in the Gemini API docs. Use manual billing profile data for quota/reset.",
        "provider_exact_usage": False,
        "provider_exact_billing": False,
        "provider_exact_plan": bool(profile.get("quota_limit") is not None or profile.get("reset_at") or tier),
        "provider_source": "manual_profile",
        "provider_plan_tier": tier or "unknown",
    }


def _load_provider_adapter_status(workspace: Optional[Path], ai_usage: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
    provider = _provider_hint(ai_usage, profile)
    billing_mode = str(profile.get("mode") or "").strip().lower()
    if provider == "openai":
        status = _fetch_openai_provider_status()
        if billing_mode == "subscription":
            status["provider_exact_plan"] = False
            status["provider_api_note"] = (
                "ChatGPT/Codex local subscription remaining is not exposed through OpenAI org billing APIs. "
                + ("OpenAI org API usage/cost is shown separately." if status.get("provider_api_status") == "ok" else "Local telemetry is the only exact source here.")
            )
            if status.get("provider_api_status") == "error":
                status["provider_api_status"] = "unavailable"
        return status
    if provider == "anthropic":
        return _fetch_anthropic_provider_status()
    if provider == "gemini":
        return _fetch_gemini_provider_status(profile)
    return {
        "provider": provider or "unknown",
        "provider_api_status": "unknown",
        "provider_api_note": "No provider adapter matched current telemetry/model signals.",
        "provider_exact_usage": False,
        "provider_exact_billing": False,
        "provider_exact_plan": False,
    }


def _billing_exactness_label(ai_usage: Dict[str, Any]) -> str:
    if not ai_usage.get("enabled"):
        return "unknown"
    if ai_usage.get("provider_exact_billing"):
        return "exact"
    if ai_usage.get("provider_exact_plan") or ai_usage.get("provider_api_status") == "partial":
        return "partial"
    billing_mode = str(ai_usage.get("billing_mode") or "").strip().lower()
    if billing_mode in {"quota", "subscription"} and ai_usage.get("billing_profile_source"):
        return "manual"
    if ai_usage.get("cost_confidence") == "estimated":
        return "estimated"
    return "unknown"


def _load_ai_usage_summary(workspace: Optional[Path]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    month_ago = now - timedelta(days=30)
    today = now.date()
    ledger_path = workspace / ".liquefy-tokens" / "ledger.jsonl" if workspace else None
    entries: List[Dict[str, Any]] = []
    source = "none"
    reason = "No token usage data found"

    if ledger_path and ledger_path.exists():
        entries = _load_ledger_entries(ledger_path)
        source = "workspace_ledger"
        reason = f"Loaded workspace ledger from {ledger_path}"
    if not entries:
        entries = _load_codex_session_entries()
        if entries:
            source = "codex_sessions"
            reason = f"Using local Codex session logs from {len(entries)} telemetry events"
        elif ledger_path:
            reason = f"No token ledger found at {ledger_path}"

    if not entries:
        return {
            "enabled": False,
            "source": source,
            "reason": reason,
            "ledger_path": str(ledger_path) if ledger_path else None,
        }

    calls_today = 0
    input_today = 0
    output_today = 0
    total_today = 0
    spend_today = 0.0
    month_spend = 0.0
    top_models: collections.Counter[str] = collections.Counter()
    top_sources: collections.Counter[str] = collections.Counter()

    for entry in entries:
        ts = _parse_ts(entry.get("ts"))
        model = str(entry.get("model") or "unknown")
        inp = int(entry.get("input_tokens", 0) or 0)
        outp = int(entry.get("output_tokens", 0) or 0)
        total = int(entry.get("total_tokens", inp + outp) or (inp + outp))
        explicit_cost = entry.get("cost_usd")
        cost = float(explicit_cost if explicit_cost is not None else (_estimate_token_cost(model, inp, outp) if model != "unknown" else 0.0))
        if ts and ts >= month_ago:
            month_spend += cost
            top_models[model] += 1
            top_sources[str(entry.get("source") or "unknown")] += 1
        if ts and ts.date() == today:
            calls_today += 1
            input_today += inp
            output_today += outp
            total_today += total
            spend_today += cost

    profile = _load_ai_billing_profile(workspace)
    billing_mode = str(profile.get("mode") or "").strip().lower()
    if not billing_mode:
        billing_mode = "metered" if source == "workspace_ledger" else "usage_only"
    quota_used = profile.get("quota_used")
    quota_limit = profile.get("quota_limit")
    quota_pct = None
    quota_remaining = None
    try:
        if quota_used is not None and quota_limit not in (None, 0):
            quota_pct = round((float(quota_used) / float(quota_limit)) * 100.0, 2)
            quota_remaining = round(float(quota_limit) - float(quota_used), 2)
    except Exception:
        quota_pct = None
        quota_remaining = None

    cost_confidence = "exact" if source == "workspace_ledger" else ("estimated" if source == "codex_sessions" else "none")
    telemetry_label = "Model requests logged today" if source == "workspace_ledger" else "Token telemetry events today"
    avg_tokens_label = "Avg tokens / request" if source == "workspace_ledger" else "Avg tokens / event"
    telemetry_source_label = "workspace token ledger" if source == "workspace_ledger" else ("local Codex session logs" if source == "codex_sessions" else "unknown")
    if billing_mode == "metered" and cost_confidence == "exact":
        billing_status_label = "Provider billing"
        today_cost_label = "Provider spend today"
        month_cost_label = "Provider 30d spend"
    else:
        billing_status_label = "Billing interpretation"
        today_cost_label = "Estimated API-equiv today"
        month_cost_label = "Estimated API-equiv 30d"

    provider_plan_available = billing_mode in {"quota", "subscription", "metered"} and bool(profile.get("profile_source") or source == "workspace_ledger")
    if billing_mode == "quota":
        provider_plan_note = "Quota status comes from local billing profile data, not live provider polling."
    elif billing_mode == "subscription":
        provider_plan_note = "Subscription remaining quota is not available unless you supply it in billing.json or env."
    elif billing_mode == "metered":
        provider_plan_note = "Metered plan details come from workspace ledger or local billing profile configuration."
    else:
        provider_plan_note = "No provider-side billing profile configured. Showing local telemetry only."

    summary = {
        "enabled": True,
        "source": source,
        "reason": reason,
        "ledger_path": str(ledger_path) if ledger_path else None,
        "billing_mode": billing_mode,
        "billing_label": str(profile.get("label") or ""),
        "billing_profile_source": str(profile.get("profile_source") or ""),
        "quota_used": quota_used,
        "quota_limit": quota_limit,
        "quota_pct": quota_pct,
        "quota_remaining": quota_remaining,
        "reset_at": profile.get("reset_at"),
        "spend_limit_usd": profile.get("spend_limit_usd"),
        "cost_confidence": cost_confidence,
        "telemetry_label": telemetry_label,
        "avg_tokens_label": avg_tokens_label,
        "telemetry_source_label": telemetry_source_label,
        "billing_status_label": billing_status_label,
        "today_cost_label": today_cost_label,
        "month_cost_label": month_cost_label,
        "provider_plan_available": provider_plan_available,
        "provider_plan_note": provider_plan_note,
        "calls_today": calls_today,
        "requests_logged_today": calls_today,
        "input_tokens_today": input_today,
        "output_tokens_today": output_today,
        "total_tokens_today": total_today,
        "estimated_cost_usd_today": round(spend_today, 6),
        "avg_tokens_per_call": round(total_today / calls_today, 1) if calls_today else 0.0,
        "month_cost_usd": round(month_spend, 6),
        "top_models": top_models.most_common(3),
        "top_sources": top_sources.most_common(3),
    }
    provider_status = _load_provider_adapter_status(workspace, summary, profile)
    if isinstance(provider_status, dict) and provider_status:
        summary.update(provider_status)
        provider_exact_plan = bool(provider_status.get("provider_exact_plan"))
        if provider_exact_plan:
            summary["provider_plan_available"] = True
        provider_api_note = str(provider_status.get("provider_api_note") or "").strip()
        if provider_api_note:
            if billing_mode == "usage_only":
                summary["provider_plan_note"] = provider_api_note
            elif provider_exact_plan:
                summary["provider_plan_note"] = provider_api_note
    summary["billing_exactness"] = _billing_exactness_label(summary)
    return summary


def _billing_doctor_result(workspace: Optional[Path]) -> Dict[str, Any]:
    ai_usage = _load_ai_usage_summary(workspace)
    supported_adapters = [
        {"provider": "workspace-ledger", "mode": "exact local ledger", "activation": ".liquefy-tokens/ledger.jsonl"},
        {"provider": "codex-sessions", "mode": "local telemetry", "activation": "~/.codex/sessions"},
        {"provider": "openai", "mode": "exact org usage/cost", "activation": "OPENAI_ADMIN_KEY"},
        {"provider": "anthropic", "mode": "exact org usage/cost", "activation": "ANTHROPIC_ADMIN_KEY"},
        {"provider": "gemini", "mode": "manual/partial quota profile", "activation": "billing.json or ~/.liquefy-ai-billing.json"},
    ]
    if not ai_usage.get("enabled"):
        return {
            "workspace": str(workspace) if workspace else None,
            "status": "unconfigured",
            "telemetry_source": ai_usage.get("source"),
            "telemetry_reason": ai_usage.get("reason"),
            "billing_exactness": "unknown",
            "supported_adapters": supported_adapters,
        }
    return {
        "workspace": str(workspace) if workspace else None,
        "status": "ok",
        "telemetry_source": ai_usage.get("source"),
        "telemetry_source_label": ai_usage.get("telemetry_source_label"),
        "telemetry_reason": ai_usage.get("reason"),
        "billing_mode": ai_usage.get("billing_mode"),
        "billing_label": ai_usage.get("billing_label"),
        "billing_profile_source": ai_usage.get("billing_profile_source"),
        "billing_exactness": ai_usage.get("billing_exactness"),
        "provider": ai_usage.get("provider"),
        "provider_source": ai_usage.get("provider_source"),
        "provider_api_status": ai_usage.get("provider_api_status"),
        "provider_api_note": ai_usage.get("provider_api_note"),
        "provider_exact_usage": bool(ai_usage.get("provider_exact_usage")),
        "provider_exact_billing": bool(ai_usage.get("provider_exact_billing")),
        "provider_exact_plan": bool(ai_usage.get("provider_exact_plan")),
        "provider_plan_available": bool(ai_usage.get("provider_plan_available")),
        "provider_plan_note": ai_usage.get("provider_plan_note"),
        "quota_used": ai_usage.get("quota_used"),
        "quota_limit": ai_usage.get("quota_limit"),
        "quota_remaining": ai_usage.get("quota_remaining"),
        "quota_pct": ai_usage.get("quota_pct"),
        "reset_at": ai_usage.get("reset_at"),
        "spend_limit_usd": ai_usage.get("spend_limit_usd"),
        "requests_logged_today": ai_usage.get("requests_logged_today"),
        "input_tokens_today": ai_usage.get("input_tokens_today"),
        "output_tokens_today": ai_usage.get("output_tokens_today"),
        "total_tokens_today": ai_usage.get("total_tokens_today"),
        "estimated_cost_usd_today": ai_usage.get("estimated_cost_usd_today"),
        "provider_cost_usd_today": ai_usage.get("provider_cost_usd_today"),
        "month_cost_usd": ai_usage.get("month_cost_usd"),
        "provider_month_cost_usd": ai_usage.get("provider_month_cost_usd"),
        "top_models": ai_usage.get("top_models"),
        "provider_top_models": ai_usage.get("provider_top_models"),
        "supported_adapters": supported_adapters,
    }


def _build_agent_ops_summary(processes: List[Dict[str, Any]], history_summary: Dict[str, Any], threat: Dict[str, Any]) -> Dict[str, Any]:
    providers = history_summary.get("providers", []) if isinstance(history_summary, dict) else []
    enabled = [p for p in providers if p.get("enabled")]
    failing = [p for p in enabled if p.get("last_ok") is False]
    agents = [p for p in processes if p.get("category") == "agent"]
    hot_agents = sorted(agents, key=lambda p: (float(p.get("cpu_pct", 0) or 0) + float(p.get("mem_pct", 0) or 0)), reverse=True)[:4]
    status = "CLEAR"
    if failing or int(threat.get("risky_actions_24h", 0) or 0) > 0:
        status = "WATCH"
    if len(failing) >= 2:
        status = "ALARM"
    return {
        "status": status,
        "agent_count": len(agents),
        "hot_agents": [
            {
                "name": str(p.get("name") or "unknown"),
                "pid": int(p.get("pid", 0) or 0),
                "cpu_pct": float(p.get("cpu_pct", 0) or 0),
                "mem_pct": float(p.get("mem_pct", 0) or 0),
                "category": str(p.get("category") or "agent"),
            }
            for p in hot_agents
        ],
        "providers_enabled": len(enabled),
        "providers_failing": len(failing),
        "active_provider": history_summary.get("active_provider"),
        "halt_present": bool(threat.get("halt_present", False)),
    }


def _build_task_progress_summary(history_summary: Dict[str, Any]) -> Dict[str, Any]:
    providers = history_summary.get("providers", []) if isinstance(history_summary, dict) else []
    enabled = [p for p in providers if p.get("enabled")]
    healthy = [p for p in enabled if p.get("last_ok") is not False]
    sync_pct = round((len(healthy) / len(enabled)) * 100.0, 1) if enabled else 0.0
    last_action = history_summary.get("last_action") if isinstance(history_summary, dict) else None
    phase = "idle"
    if last_action:
        phase = str(last_action.get("type") or "idle")
    elif enabled:
        phase = "watching"
    return {
        "phase": phase,
        "sync_pct": sync_pct,
        "providers_enabled": len(enabled),
        "providers_healthy": len(healthy),
        "active_provider": history_summary.get("active_provider"),
        "last_action": last_action,
    }


def _build_activity_feed(history_summary: Dict[str, Any], monitor_rows: List[Dict[str, Any]], threat: Dict[str, Any]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    last_action = history_summary.get("last_action") if isinstance(history_summary, dict) else None
    if last_action:
        items.append({
            "kind": "history",
            "label": str(last_action.get("type") or "action"),
            "detail": str(last_action.get("command") or "")[:120],
            "ts": str(last_action.get("ts") or ""),
        })
    for row in sorted(monitor_rows or [], key=lambda r: float(r.get("cpu", 0) or 0), reverse=True)[:2]:
        items.append({
            "kind": "hot",
            "label": str(row.get("name") or "process"),
            "detail": f"CPU {float(row.get('cpu', 0) or 0):.1f}% · RAM {float(row.get('ram', 0) or 0):.1f}%",
            "ts": "",
        })
    for alert in (threat.get("alerts") or [])[:3]:
        items.append({
            "kind": "alert",
            "label": "alert",
            "detail": str(alert),
            "ts": "",
        })
    return items[:6]


def _build_monitor_rows(procs: List[Dict[str, Any]], net_type: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    label = "WIFI" if "wifi" in net_type.lower() or "wi-fi" in net_type.lower() else "ETHERNET"
    for p in procs:
        cpu = float(p.get("cpu_pct", 0) or 0)
        mem = float(p.get("mem_pct", 0) or 0)
        category = str(p.get("category") or "system")
        gpu = round(min(100.0, cpu * (0.9 if category in {"browser", "ide"} else 0.35)), 1)
        ssd = round(min(100.0, mem * 0.25 + cpu * (0.45 if category in {"database", "ide", "agent"} else 0.15)), 1)
        net = round(min(100.0, cpu * (0.55 if category in {"browser", "agent", "terminal"} else 0.12)), 1)
        rows.append({
            "id": f"proc_{p.get('_group')}",
            "pid": int(p.get("pid", 0) or 0),
            "name": str(p.get("name") or "unknown"),
            "category": category,
            "_group": p.get("_group"),
            "pids": list(p.get("_pids", [int(p.get("pid", 0) or 0)])),
            "cpu": round(cpu, 1),
            "ram": round(mem, 1),
            "gpu": gpu,
            "ssd": ssd,
            "net": net,
            "net_label": label,
        })
    return rows


def _heartbeat_status(workspace: Optional[Path]) -> Dict[str, Any]:
    if workspace is None:
        return {"present": False, "fresh": False, "age_s": None, "armed": False}
    hb = workspace / ".liquefy-heartbeat"
    if not hb.exists():
        return {"present": False, "fresh": False, "age_s": None, "armed": False}
    age_s = round(max(0.0, time.time() - hb.stat().st_mtime), 1)
    return {"present": True, "fresh": age_s <= 15.0, "age_s": age_s, "armed": True}


def _build_threat_summary(history_summary: Dict[str, Any], file_graph: Dict[str, Any], ai_usage: Dict[str, Any], workspace: Optional[Path]) -> Dict[str, Any]:
    providers = history_summary.get("providers", []) if isinstance(history_summary, dict) else []
    provider_failures = sum(1 for p in providers if p.get("last_ok") is False)
    risky_actions = int(history_summary.get("risky_actions_24h", 0) or 0)
    sensitive_count = int(file_graph.get("stats", {}).get("sensitive_count", 0) or 0)
    agent_related_count = int(file_graph.get("stats", {}).get("agent_related_count", 0) or 0)
    heartbeat = _heartbeat_status(workspace)
    halt_present = bool(workspace and (workspace / ".liquefy-halt").exists())
    spend_today = float(ai_usage.get("estimated_cost_usd_today", 0.0) or 0.0)
    alerts: List[str] = list(history_summary.get("alerts", [])[:4]) if isinstance(history_summary, dict) else []
    if heartbeat["present"] and not heartbeat["fresh"]:
        alerts.append(f"heartbeat stale ({heartbeat['age_s']}s)")
    if halt_present:
        alerts.append("halt signal present")
    if ai_usage.get("source") == "workspace_ledger" and spend_today > 10:
        alerts.append(f"AI spend today elevated (${spend_today:.2f})")
    level = "green"
    status = "CLEAR"
    if provider_failures or risky_actions or halt_present or (heartbeat["present"] and not heartbeat["fresh"]):
        level = "amber"
        status = "WATCH"
    if provider_failures >= 2 or risky_actions >= 2:
        level = "red"
        status = "ALARM"
    return {
        "status": status,
        "level": level,
        "provider_failures": provider_failures,
        "risky_actions_24h": risky_actions,
        "sensitive_count": sensitive_count,
        "agent_related_count": agent_related_count,
        "heartbeat": heartbeat,
        "halt_present": halt_present,
        "ai_spend_today": round(spend_today, 6),
        "alerts": alerts[:6],
    }


def _process_action_result(pid: int, action: str) -> Dict[str, Any]:
    if pid <= 0:
        return {"ok": False, "error": "invalid pid"}
    sig = signal.SIGKILL if action == "kill" else signal.SIGTERM
    try:
        os.kill(pid, sig)
        return {"ok": True, "pid": pid, "action": action}
    except ProcessLookupError:
        return {"ok": False, "error": "process not found", "pid": pid}
    except PermissionError:
        return {"ok": False, "error": "permission denied", "pid": pid}
    except OSError as exc:
        return {"ok": False, "error": str(exc), "pid": pid}


APP_QUIT_NAME_MAP: Dict[str, str] = {
    "spotify": "Spotify",
    "discord": "Discord",
    "telegram": "Telegram",
    "whatsapp": "WhatsApp",
    "slack": "Slack",
    "chrome": "Google Chrome",
    "safari": "Safari",
    "firefox": "Firefox",
    "cursor": "Cursor",
    "codex": "Codex",
    "finder": "Finder",
    "terminal": "Terminal",
    "iterm": "iTerm",
    "vscode": "Visual Studio Code",
    "xcode": "Xcode",
}


def _quit_app_result(app_name: str) -> Dict[str, Any]:
    if not app_name:
        return {"ok": False, "error": "app name required"}
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.run(
                ["osascript", "-e", f'tell application "{app_name}" to quit'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=True,
            )
            return {"ok": True, "method": "osascript-quit", "app": app_name}
        if system == "Linux":
            subprocess.run(["pkill", "-TERM", "-x", app_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            return {"ok": True, "method": "pkill-term", "app": app_name}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "app": app_name}
    return {"ok": False, "error": f"unsupported platform: {system}", "app": app_name}


def _find_group_process(group_key: str) -> Optional[Dict[str, Any]]:
    key = str(group_key or "").strip().lower()
    if not key:
        return None
    return next((p for p in _get_processes() if str(p.get("_group", "")).lower() == key), None)


def _group_pids(proc: Optional[Dict[str, Any]]) -> List[int]:
    if not proc:
        return []
    pids = [int(pid) for pid in proc.get("_pids", []) if int(pid or 0) > 0]
    if not pids and int(proc.get("pid", 0) or 0) > 0:
        pids = [int(proc["pid"])]
    unique_pids: List[int] = []
    seen: Set[int] = set()
    for pid in pids:
        if pid not in seen:
            seen.add(pid)
            unique_pids.append(pid)
    return unique_pids


def _get_process_children_map() -> Dict[int, List[int]]:
    children: Dict[int, List[int]] = collections.defaultdict(list)
    system = platform.system()
    if system == "Darwin":
        ps_out = _run_cmd(["ps", "-Ao", "pid,ppid,comm"])
    else:
        ps_out = _run_cmd(["ps", "-Ao", "pid,ppid,comm", "--no-headers"])
    lines = ps_out.splitlines()
    if system == "Darwin" and lines:
        lines = lines[1:]
    for line in lines:
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
        except ValueError:
            continue
        if pid > 0 and ppid >= 0:
            children[ppid].append(pid)
    return dict(children)


def _expand_pid_tree(root_pids: List[int]) -> List[int]:
    children = _get_process_children_map()
    out: List[int] = []
    seen: Set[int] = set()
    stack: List[int] = [int(pid) for pid in root_pids if int(pid or 0) > 0]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        out.append(pid)
        for child in children.get(pid, []):
            if child not in seen:
                stack.append(child)
    return out


def _agent_process_action_result(action: str) -> Dict[str, Any]:
    agent_procs = [p for p in _get_processes() if p.get("category") == "agent" and int(p.get("pid", 0) or 0) > 0]
    if not agent_procs:
        return {"ok": False, "error": "no agent processes found", "action": action, "count": 0}
    groups: List[str] = []
    seen_groups: Set[str] = set()
    for proc in agent_procs:
        group_key = str(proc.get("_group") or "").strip().lower()
        if group_key and group_key not in seen_groups:
            seen_groups.add(group_key)
            groups.append(group_key)
    if not groups:
        return {"ok": False, "error": "no grouped agent processes found", "action": action, "count": 0}
    results = [_group_process_action_result(group, action) for group in groups]
    ok_count = sum(1 for r in results if r.get("ok"))
    total_pids = sum(int(r.get("count", 0) or 0) for r in results)
    survivor_count = sum(int(r.get("survivor_count", 0) or 0) for r in results)
    return {
        "ok": ok_count > 0,
        "action": action,
        "count": total_pids,
        "ok_count": ok_count,
        "survivor_count": survivor_count,
        "results": results[:8],
    }


def _group_process_action_result(group: str, action: str) -> Dict[str, Any]:
    group_key = str(group or "").strip().lower()
    if not group_key:
        return {"ok": False, "error": "group required", "action": action}
    proc = _find_group_process(group_key)
    if not proc:
        return {"ok": False, "error": "group not found", "action": action, "group": group_key}
    app_name = APP_QUIT_NAME_MAP.get(group_key, str(proc.get("name") or "").strip())
    quit_result: Optional[Dict[str, Any]] = None
    if action == "term" and app_name:
        quit_result = _quit_app_result(app_name)
        time.sleep(0.35)
        if _find_group_process(group_key) is None:
            return {
                "ok": True,
                "action": action,
                "group": group_key,
                "label": proc.get("name"),
                "count": 0,
                "ok_count": 0,
                "quit_result": quit_result,
                "survivor_count": 0,
                "survivor_pids": [],
                "results": [],
            }

    def _kill_pass() -> Tuple[List[Dict[str, Any]], int]:
        current = _find_group_process(group_key)
        current_pids = _expand_pid_tree(_group_pids(current))
        pass_results = [_process_action_result(pid, action) for pid in current_pids]
        return pass_results, len(current_pids)

    results: List[Dict[str, Any]] = []
    count = 0
    pass_results, pass_count = _kill_pass()
    results.extend(pass_results)
    count += pass_count
    if action == "kill":
        time.sleep(0.2)
        pass_results_2, pass_count_2 = _kill_pass()
        results.extend(pass_results_2)
        count += pass_count_2
    ok_count = sum(1 for r in results if r.get("ok"))
    survivors = _expand_pid_tree(_group_pids(_find_group_process(group_key)))
    return {
        "ok": ok_count > 0 or not survivors,
        "action": action,
        "group": group_key,
        "label": proc.get("name"),
        "count": count,
        "ok_count": ok_count,
        "quit_result": quit_result,
        "survivor_count": len(survivors),
        "survivor_pids": survivors[:12],
        "results": results[:12],
    }


def _halt_action(workspace: Optional[Path], history_summary: Dict[str, Any]) -> Dict[str, Any]:
    if workspace is None:
        return {"ok": False, "error": "workspace required for halt"}
    signal_path = workspace / ".liquefy-halt"
    payload = [{"type": "operator_halt", "severity": "critical", "message": "Manual panic halt from Parad0x Command"}]
    if _write_kill_signal is not None:
        try:
            data = _write_kill_signal(signal_path, payload, trace_id="galactic-command")
            return {"ok": True, "signal_path": str(signal_path), "signal": data}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "signal_path": str(signal_path)}
    try:
        signal_path.write_text(json.dumps({
            "schema": CLI_SCHEMA,
            "action": "HALT",
            "reason": "Manual panic halt from Parad0x Command",
            "timestamp": _utc_now(),
            "violations": payload,
        }, indent=2), encoding="utf-8")
        return {"ok": True, "signal_path": str(signal_path)}
    except OSError as exc:
        return {"ok": False, "error": str(exc), "signal_path": str(signal_path)}


def _verify_halt_action(workspace: Optional[Path]) -> Dict[str, Any]:
    if workspace is None:
        return {"ok": False, "error": "workspace required for verify"}
    signal_path = workspace / ".liquefy-halt"
    if verify_halt_signal is None:
        return {"ok": signal_path.exists(), "valid": signal_path.exists(), "signal_path": str(signal_path)}
    result = verify_halt_signal(signal_path, os.environ.get("LIQUEFY_SECRET"))
    return {"ok": bool(result.get("valid")), "signal_path": str(signal_path), **result}


def _open_url_result(url: str) -> Dict[str, Any]:
    url = str(url or "").strip()
    if not url:
        return {"ok": False, "error": "missing url"}
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return {"ok": False, "error": "invalid url"}
    if parsed.scheme not in {"http", "https"}:
        return {"ok": False, "error": "unsupported scheme"}
    try:
        if platform.system() == "Darwin":
            subprocess.Popen(["open", "-a", "Safari", url])
        elif platform.system() == "Linux":
            subprocess.Popen(["xdg-open", url])
        else:
            webbrowser.open(url)
        return {"ok": True, "url": url}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "url": url}


def _resolve_background_image(desktop_dir: Path, mode: str, workspace: Optional[Path] = None) -> Optional[Path]:
    mode_norm = str(mode or "none").strip()
    if not mode_norm or mode_norm.lower() == "none":
        return None
    if mode_norm.lower() == "screenshot":
        if platform.system() != "Darwin" or shutil.which("screencapture") is None:
            return None
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        bg_dir = (workspace / ".liquefy" / "desktop-viz" if workspace else desktop_dir / ".liquefy-desktop-viz").expanduser()
        bg_dir.mkdir(parents=True, exist_ok=True)
        bg_path = bg_dir / f"desktop_bg_{stamp}.png"
        try:
            subprocess.run(["screencapture", "-x", str(bg_path)], check=True, capture_output=True, text=True)
            if bg_path.exists() and bg_path.stat().st_size > 0:
                return bg_path
        except Exception:
            return None
        return None
    candidate = Path(mode_norm).expanduser().resolve()
    if candidate.exists() and candidate.is_file():
        return candidate
    return None


def _classify_file(path: Path) -> str:
    name = path.name.lower()
    if name in FILE_TYPE_MAP:
        return FILE_TYPE_MAP[name]
    ext = path.suffix.lower()
    return FILE_TYPE_MAP.get(ext, "unknown")


def _is_sensitive(path: Path) -> bool:
    name_lower = path.name.lower()
    path_lower = str(path).lower()
    return any(p in name_lower or p in path_lower for p in SENSITIVITY_PATTERNS)


def _is_agent_related(path: Path) -> bool:
    name_lower = path.name.lower()
    path_lower = str(path).lower()
    return any(p.lower() in name_lower or p.lower() in path_lower for p in AGENT_PATTERNS)


def _is_log_file(path: Path) -> bool:
    name_lower = path.name.lower()
    return any(p in name_lower for p in LOG_PATTERNS)


def _importance_score(path: Path, size: int, file_type: str) -> int:
    score = 10
    if _is_sensitive(path):
        score += 40
    if _is_agent_related(path):
        score += 25
    if file_type == "secret":
        score += 50
    if file_type in ("python", "javascript", "typescript", "rust", "golang", "solidity"):
        score += 15
    if file_type == "vault":
        score += 20
    if _is_log_file(path):
        score += 10
    if size > 10 * 1024 * 1024:
        score += 15
    elif size > 1024 * 1024:
        score += 8
    return min(score, 100)


def _scan_directory(
    root: Path,
    max_files: int = MAX_FILES,
    max_depth: int = MAX_DEPTH,
) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    folder_ids: Dict[str, str] = {}
    file_count = 0
    total_bytes = 0
    type_counts: Dict[str, int] = {}

    root = root.resolve()
    root_id = "root"
    nodes.append({
        "id": root_id,
        "label": root.name or str(root),
        "kind": "folder",
        "file_type": "folder",
        "path": str(root),
        "size": 0,
        "importance": 50,
        "sensitive": False,
        "agent_related": False,
        "is_log": False,
        "depth": 0,
        "children_count": 0,
    })
    folder_ids[str(root)] = root_id

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in sorted(dirnames) if d not in SKIP_DIRS and not d.startswith(".")]
        depth = str(dirpath).count(os.sep) - str(root).count(os.sep)
        if depth >= max_depth:
            dirnames.clear()
            continue

        current_dir = Path(dirpath)
        parent_id = folder_ids.get(str(current_dir), root_id)

        for dname in dirnames:
            dpath = current_dir / dname
            did = hashlib.md5(str(dpath).encode()).hexdigest()[:12]
            folder_ids[str(dpath)] = did
            nodes.append({
                "id": did,
                "label": dname,
                "kind": "folder",
                "file_type": "folder",
                "path": str(dpath),
                "size": 0,
                "importance": 20 + (10 if _is_agent_related(dpath) else 0),
                "sensitive": _is_sensitive(dpath),
                "agent_related": _is_agent_related(dpath),
                "is_log": False,
                "depth": depth + 1,
                "children_count": 0,
            })
            edges.append({"source": parent_id, "target": did, "kind": "contains"})

        for fname in sorted(filenames):
            if file_count >= max_files:
                break
            fpath = current_dir / fname
            try:
                fsize = fpath.stat().st_size
                fmtime = fpath.stat().st_mtime
            except OSError:
                continue

            ftype = _classify_file(fpath)
            fid = hashlib.md5(str(fpath).encode()).hexdigest()[:12]
            imp = _importance_score(fpath, fsize, ftype)

            nodes.append({
                "id": fid,
                "label": fname,
                "kind": "file",
                "file_type": ftype,
                "path": str(fpath),
                "size": fsize,
                "importance": imp,
                "sensitive": _is_sensitive(fpath),
                "agent_related": _is_agent_related(fpath),
                "is_log": _is_log_file(fpath),
                "depth": depth + 1,
                "mtime": fmtime,
                "extension": fpath.suffix.lower(),
            })
            edges.append({"source": parent_id, "target": fid, "kind": "contains"})

            type_counts[ftype] = type_counts.get(ftype, 0) + 1
            total_bytes += fsize
            file_count += 1

            if parent_id in folder_ids.values():
                for n in nodes:
                    if n["id"] == parent_id:
                        n["children_count"] = n.get("children_count", 0) + 1
                        break

        if file_count >= max_files:
            break

    return {
        "root": str(root),
        "root_name": root.name or str(root),
        "generated_at_utc": _utc_now(),
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "total_files": file_count,
            "total_folders": len(folder_ids),
            "total_bytes": total_bytes,
            "type_breakdown": dict(sorted(type_counts.items(), key=lambda x: -x[1])),
            "sensitive_count": sum(1 for n in nodes if n.get("sensitive")),
            "agent_related_count": sum(1 for n in nodes if n.get("agent_related")),
        },
    }


def _render_galactic_html(graph: Dict[str, Any], title: str) -> str:
    graph_json = json.dumps(graph)
    type_colors_json = json.dumps(TYPE_COLORS)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html, body {{ width: 100%; height: 100%; overflow: hidden; background: #05050a; font-family: 'SF Mono', 'Fira Code', monospace; color: #ccc; }}
  canvas {{ display: block; width: 100%; height: 100%; cursor: grab; }}
  canvas.dragging {{ cursor: grabbing; }}
  #hud {{
    position: fixed; top: 12px; left: 12px; z-index: 10;
    background: rgba(5,5,15,0.85); border: 1px solid rgba(100,200,255,0.15);
    border-radius: 8px; padding: 10px 14px; font-size: 11px; line-height: 1.5;
    backdrop-filter: blur(8px); max-width: 280px; pointer-events: none;
  }}
  #hud .title {{ color: #64dfff; font-size: 13px; font-weight: 700; margin-bottom: 4px; }}
  #hud .stat {{ color: #8899aa; }}
  #hud .val {{ color: #ddeeff; }}
  #inspector {{
    position: fixed; bottom: 12px; right: 12px; z-index: 10;
    background: rgba(5,5,15,0.9); border: 1px solid rgba(100,200,255,0.2);
    border-radius: 8px; padding: 12px 16px; font-size: 11px; line-height: 1.6;
    backdrop-filter: blur(12px); max-width: 360px; display: none;
  }}
  #inspector .name {{ color: #64dfff; font-size: 13px; font-weight: 700; }}
  #inspector .meta {{ color: #8899aa; }}
  #inspector .tag {{
    display: inline-block; padding: 1px 6px; border-radius: 3px;
    font-size: 10px; margin: 1px 2px; font-weight: 600;
  }}
  #legend {{
    position: fixed; bottom: 12px; left: 12px; z-index: 10;
    background: rgba(5,5,15,0.85); border: 1px solid rgba(100,200,255,0.1);
    border-radius: 8px; padding: 8px 12px; font-size: 10px;
    backdrop-filter: blur(8px); pointer-events: none;
  }}
  #legend .row {{ display: flex; align-items: center; gap: 6px; margin: 2px 0; }}
  #legend .dot {{ width: 8px; height: 8px; border-radius: 50%; }}
  #controls {{
    position: fixed; top: 12px; right: 12px; z-index: 10;
    display: flex; flex-direction: column; gap: 6px;
  }}
  #controls button {{
    background: rgba(20,20,40,0.9); border: 1px solid rgba(100,200,255,0.2);
    color: #aabbcc; padding: 5px 10px; border-radius: 4px; cursor: pointer;
    font-size: 10px; font-family: inherit;
  }}
  #controls button:hover {{ background: rgba(40,60,100,0.9); color: #ddeeff; }}
  #search {{
    position: fixed; top: 12px; left: 50%; transform: translateX(-50%); z-index: 10;
  }}
  #search input {{
    background: rgba(10,10,25,0.9); border: 1px solid rgba(100,200,255,0.2);
    color: #ddeeff; padding: 6px 14px; border-radius: 16px; width: 280px;
    font-size: 11px; font-family: inherit; outline: none;
  }}
  #search input:focus {{ border-color: rgba(100,200,255,0.5); }}
  #search input::placeholder {{ color: #556677; }}
</style>
</head>
<body>

<div id="hud">
  <div class="title" id="hud-title">Galactic Desktop</div>
  <div><span class="stat">Files:</span> <span class="val" id="hud-files">0</span></div>
  <div><span class="stat">Folders:</span> <span class="val" id="hud-folders">0</span></div>
  <div><span class="stat">Size:</span> <span class="val" id="hud-size">0</span></div>
  <div><span class="stat">Sensitive:</span> <span class="val" id="hud-sensitive">0</span></div>
  <div><span class="stat">Agent:</span> <span class="val" id="hud-agent">0</span></div>
  <div style="margin-top:4px;color:#556677;font-size:9px;">Click node = inspect | Empty = reset | Scroll = zoom | Drag = move</div>
</div>

<div id="inspector"></div>

<div id="legend">
  <div class="row"><div class="dot" style="background:#ff4444;box-shadow:0 0 6px #ff4444"></div><span>Sensitive / Secret</span></div>
  <div class="row"><div class="dot" style="background:#00ff88;box-shadow:0 0 6px #00ff88"></div><span>Vault (.null)</span></div>
  <div class="row"><div class="dot" style="background:#64dfff;box-shadow:0 0 6px #64dfff"></div><span>Agent-related</span></div>
  <div class="row"><div class="dot" style="background:#a855f7;box-shadow:0 0 6px #a855f7"></div><span>Media</span></div>
  <div class="row"><div class="dot" style="background:#fbbf24;box-shadow:0 0 6px #fbbf24"></div><span>Folder</span></div>
  <div class="row"><div class="dot" style="background:#3572A5;box-shadow:0 0 6px #3572A5"></div><span>Code</span></div>
  <div class="row"><div class="dot" style="background:#6b7280"></div><span>Other</span></div>
</div>

<div id="search"><input type="text" placeholder="Search files..." id="search-input"></div>

<div id="controls">
  <button onclick="resetView()">Reset View</button>
  <button onclick="toggleFolders()">Toggle Folders</button>
  <button onclick="highlightSensitive()">Show Sensitive</button>
  <button onclick="highlightAgent()">Show Agent Files</button>
  <button onclick="reLayout()">Re-Layout</button>
</div>

<canvas id="galaxy"></canvas>

<script>
const graph = {graph_json};
const TYPE_COLORS = {type_colors_json};
const canvas = document.getElementById("galaxy");
const ctx = canvas.getContext("2d");
const inspector = document.getElementById("inspector");

let nodes = graph.nodes || [];
let edges = graph.edges || [];
const nodeMap = {{}};
nodes.forEach(n => {{ nodeMap[n.id] = n; }});

document.getElementById("hud-title").textContent = graph.root_name || "Galactic Desktop";
document.getElementById("hud-files").textContent = (graph.stats||{{}}).total_files || 0;
document.getElementById("hud-folders").textContent = (graph.stats||{{}}).total_folders || 0;
document.getElementById("hud-size").textContent = formatBytes((graph.stats||{{}}).total_bytes || 0);
document.getElementById("hud-sensitive").textContent = (graph.stats||{{}}).sensitive_count || 0;
document.getElementById("hud-agent").textContent = (graph.stats||{{}}).agent_related_count || 0;

function formatBytes(b) {{
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b/1024).toFixed(1) + " KB";
  if (b < 1073741824) return (b/1048576).toFixed(1) + " MB";
  return (b/1073741824).toFixed(2) + " GB";
}}

// Layout: force-directed with depth-based rings
const W = () => canvas.clientWidth || 1200;
const H = () => canvas.clientHeight || 720;
let camX = 0, camY = 0, camZoom = 1;

function initPositions() {{
  const cx = 0, cy = 0;
  nodes.forEach(n => {{
    const depth = n.depth || 0;
    const angle = Math.random() * Math.PI * 2;
    const radius = 80 + depth * 120 + Math.random() * 60;
    n.x = cx + Math.cos(angle) * radius;
    n.y = cy + Math.sin(angle) * radius;
    n.vx = 0; n.vy = 0;
    n.fixed = false;
    n.hidden = false;
    n.highlight = false;
    n.searchMatch = false;
  }});
}}
initPositions();

// Physics
function simulate() {{
  const repulsion = 800;
  const springLen = 60;
  const springK = 0.02;
  const damping = 0.85;
  const gravity = 0.01;

  for (let i = 0; i < nodes.length; i++) {{
    if (nodes[i].hidden || nodes[i].fixed) continue;
    let fx = 0, fy = 0;
    for (let j = 0; j < nodes.length; j++) {{
      if (i === j || nodes[j].hidden) continue;
      const dx = nodes[i].x - nodes[j].x;
      const dy = nodes[i].y - nodes[j].y;
      const dist = Math.sqrt(dx*dx + dy*dy) + 1;
      const f = repulsion / (dist * dist);
      fx += (dx/dist) * f;
      fy += (dy/dist) * f;
    }}
    fx -= nodes[i].x * gravity;
    fy -= nodes[i].y * gravity;
    nodes[i].vx = (nodes[i].vx + fx) * damping;
    nodes[i].vy = (nodes[i].vy + fy) * damping;
  }}

  edges.forEach(e => {{
    const s = nodeMap[e.source], t = nodeMap[e.target];
    if (!s || !t || s.hidden || t.hidden) return;
    const dx = t.x - s.x, dy = t.y - s.y;
    const dist = Math.sqrt(dx*dx + dy*dy) + 1;
    const f = (dist - springLen) * springK;
    const fx = (dx/dist)*f, fy = (dy/dist)*f;
    if (!s.fixed) {{ s.vx += fx; s.vy += fy; }}
    if (!t.fixed) {{ t.vx -= fx; t.vy -= fy; }}
  }});

  nodes.forEach(n => {{
    if (n.hidden || n.fixed) return;
    n.x += n.vx; n.y += n.vy;
  }});
}}

// Drawing
let selectedNode = null;
let frameTime = 0;
let showFolders = true;
let highlightMode = null;

function nodeColor(n) {{
  if (n.sensitive) return "#ff4444";
  if (n.file_type === "vault") return "#00ff88";
  if (n.agent_related) return "#64dfff";
  return TYPE_COLORS[n.file_type] || TYPE_COLORS["unknown"];
}}

function nodeRadius(n) {{
  if (n.kind === "folder") return 4 + Math.min(n.children_count || 0, 20) * 0.3;
  const base = 2;
  const imp = (n.importance || 10) / 100;
  return base + imp * 4;
}}

function worldToScreen(wx, wy) {{
  return {{
    sx: (wx - camX) * camZoom + W()/2,
    sy: (wy - camY) * camZoom + H()/2,
  }};
}}
function screenToWorld(sx, sy) {{
  return {{
    wx: (sx - W()/2) / camZoom + camX,
    wy: (sy - H()/2) / camZoom + camY,
  }};
}}

function draw() {{
  frameTime = performance.now() / 1000;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.floor(canvas.clientWidth * dpr);
  canvas.height = Math.floor(canvas.clientHeight * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  ctx.fillStyle = "#05050a";
  ctx.fillRect(0, 0, W(), H());

  // Stars background
  if (!draw._stars) {{
    draw._stars = [];
    for (let i = 0; i < 200; i++) {{
      draw._stars.push({{ x: Math.random(), y: Math.random(), s: Math.random() * 1.5 + 0.3, b: Math.random() }});
    }}
  }}
  draw._stars.forEach(st => {{
    const flicker = 0.5 + 0.5 * Math.sin(frameTime * (1 + st.b * 3) + st.x * 100);
    ctx.globalAlpha = 0.15 + 0.15 * flicker;
    ctx.fillStyle = "#aaccff";
    ctx.fillRect(st.x * W(), st.y * H(), st.s, st.s);
  }});
  ctx.globalAlpha = 1;

  const dimAll = highlightMode !== null;

  // Edges
  edges.forEach(e => {{
    const s = nodeMap[e.source], t = nodeMap[e.target];
    if (!s || !t || s.hidden || t.hidden) return;
    const sp = worldToScreen(s.x, s.y), tp = worldToScreen(t.x, t.y);

    let edgeDim = dimAll;
    if (selectedNode && (s.id === selectedNode.id || t.id === selectedNode.id)) edgeDim = false;

    ctx.globalAlpha = edgeDim ? 0.03 : 0.08;
    ctx.strokeStyle = "#334455";
    ctx.lineWidth = 0.5;
    ctx.beginPath(); ctx.moveTo(sp.sx, sp.sy); ctx.lineTo(tp.sx, tp.sy); ctx.stroke();

    // Flow dots on edges connected to agent/sensitive nodes
    if (!edgeDim && (s.agent_related || t.agent_related || s.sensitive || t.sensitive)) {{
      const flowT = (frameTime * 0.3) % 1;
      const fx = sp.sx + (tp.sx - sp.sx) * flowT;
      const fy = sp.sy + (tp.sy - sp.sy) * flowT;
      ctx.globalAlpha = 0.4;
      ctx.fillStyle = s.sensitive ? "#ff6666" : "#64dfff";
      ctx.beginPath(); ctx.arc(fx, fy, 1.5, 0, Math.PI*2); ctx.fill();
    }}
  }});
  ctx.globalAlpha = 1;

  // Nodes
  nodes.forEach(n => {{
    if (n.hidden) return;
    if (n.kind === "folder" && !showFolders) return;

    const p = worldToScreen(n.x, n.y);
    const r = nodeRadius(n) * camZoom;
    const color = nodeColor(n);
    const dimThis = dimAll && !n.highlight && !n.searchMatch && n !== selectedNode;

    // Aura: sensitive
    if (n.sensitive && !dimThis) {{
      const pulse = 0.3 + 0.3 * Math.sin(frameTime * 2.5 + n.x * 0.01);
      const auraR = r + 8 * camZoom;
      const grad = ctx.createRadialGradient(p.sx, p.sy, r, p.sx, p.sy, auraR);
      grad.addColorStop(0, `rgba(255,60,60,${{pulse.toFixed(2)}})`);
      grad.addColorStop(1, "rgba(255,60,60,0)");
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, auraR, 0, Math.PI*2); ctx.fill();
    }}

    // Aura: agent-related
    if (n.agent_related && !n.sensitive && !dimThis) {{
      const pulse = 0.2 + 0.3 * Math.sin(frameTime * 3.2 + n.y * 0.01);
      const auraR = r + 6 * camZoom;
      const grad = ctx.createRadialGradient(p.sx, p.sy, r, p.sx, p.sy, auraR);
      grad.addColorStop(0, `rgba(100,223,255,${{pulse.toFixed(2)}})`);
      grad.addColorStop(1, "rgba(100,223,255,0)");
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, auraR, 0, Math.PI*2); ctx.fill();
    }}

    // Aura: vault
    if (n.file_type === "vault" && !dimThis) {{
      const pulse = 0.25 + 0.25 * Math.sin(frameTime * 1.8 + n.x * 0.02);
      const auraR = r + 10 * camZoom;
      const grad = ctx.createRadialGradient(p.sx, p.sy, r, p.sx, p.sy, auraR);
      grad.addColorStop(0, `rgba(0,255,136,${{pulse.toFixed(2)}})`);
      grad.addColorStop(1, "rgba(0,255,136,0)");
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, auraR, 0, Math.PI*2); ctx.fill();
    }}

    // Search match glow
    if (n.searchMatch) {{
      const pulse = 0.5 + 0.5 * Math.sin(frameTime * 5);
      ctx.globalAlpha = pulse;
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, r + 4 * camZoom, 0, Math.PI*2); ctx.stroke();
      ctx.globalAlpha = 1;
    }}

    // Node body
    ctx.globalAlpha = dimThis ? 0.08 : 1;
    const brightness = 0.4 + (n.importance || 10) / 100 * 0.6;
    ctx.fillStyle = color;
    ctx.globalAlpha *= brightness;
    ctx.beginPath();
    if (n.kind === "folder") {{
      ctx.rect(p.sx - r, p.sy - r*0.7, r*2, r*1.4);
      ctx.fill();
    }} else {{
      ctx.arc(p.sx, p.sy, r, 0, Math.PI*2);
      ctx.fill();
    }}

    // Glow
    if (!dimThis && r * camZoom > 2) {{
      ctx.globalAlpha = 0.15 * brightness;
      ctx.fillStyle = color;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, r * 1.8, 0, Math.PI*2); ctx.fill();
    }}

    // Selected ring
    if (n === selectedNode) {{
      ctx.globalAlpha = 1;
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, r + 3 * camZoom, 0, Math.PI*2); ctx.stroke();
    }}

    // Label (only when zoomed in)
    if (camZoom > 1.5 && !dimThis) {{
      ctx.globalAlpha = Math.min(1, (camZoom - 1.5) * 2);
      ctx.fillStyle = "#aabbcc";
      ctx.font = `${{Math.max(8, 10 * camZoom)}}px monospace`;
      ctx.textAlign = "center";
      ctx.fillText(n.label, p.sx, p.sy + r + 10 * camZoom);
    }}

    ctx.globalAlpha = 1;
  }});

  requestAnimationFrame(() => {{ simulate(); draw(); }});
}}

// Interaction
let dragMode = null, dragStart = null, draggedNode = null;
let pointerDown = false, pointerTravel = 0;

canvas.addEventListener("mousedown", e => {{
  pointerDown = true; pointerTravel = 0;
  dragStart = {{ x: e.clientX, y: e.clientY }};
  const w = screenToWorld(e.clientX, e.clientY);

  let closest = null, closestDist = Infinity;
  nodes.forEach(n => {{
    if (n.hidden || (n.kind === "folder" && !showFolders)) return;
    const dx = n.x - w.wx, dy = n.y - w.wy;
    const d = Math.sqrt(dx*dx + dy*dy);
    const pickR = nodeRadius(n) / camZoom + 8 / camZoom;
    if (d < pickR && d < closestDist) {{ closest = n; closestDist = d; }}
  }});

  if (closest) {{
    dragMode = "node";
    draggedNode = closest;
    draggedNode.fixed = true;
    canvas.classList.add("dragging");
  }} else {{
    dragMode = "pan";
  }}
}});

canvas.addEventListener("mousemove", e => {{
  if (!pointerDown) return;
  const dx = e.clientX - dragStart.x, dy = e.clientY - dragStart.y;
  pointerTravel += Math.abs(dx) + Math.abs(dy);
  dragStart = {{ x: e.clientX, y: e.clientY }};

  if (dragMode === "node" && draggedNode) {{
    draggedNode.x += dx / camZoom;
    draggedNode.y += dy / camZoom;
  }} else if (dragMode === "pan") {{
    camX -= dx / camZoom;
    camY -= dy / camZoom;
  }}
}});

canvas.addEventListener("mouseup", e => {{
  if (pointerDown && pointerTravel < 5) {{
    if (dragMode === "node" && draggedNode) {{
      selectNode(draggedNode);
    }} else {{
      selectedNode = null;
      highlightMode = null;
      inspector.style.display = "none";
      nodes.forEach(n => n.highlight = false);
    }}
  }}
  if (dragMode === "node" && draggedNode) draggedNode.fixed = true;
  pointerDown = false; dragMode = null; draggedNode = null;
  canvas.classList.remove("dragging");
}});

canvas.addEventListener("wheel", e => {{
  e.preventDefault();
  const factor = e.deltaY > 0 ? 0.9 : 1.1;
  camZoom = Math.max(0.1, Math.min(20, camZoom * factor));
}}, {{ passive: false }});

function selectNode(n) {{
  selectedNode = n;
  const imp = n.importance || 0;
  let tags = `<span class="tag" style="background:${{nodeColor(n)}};color:#000">${{n.file_type}}</span>`;
  if (n.sensitive) tags += `<span class="tag" style="background:#ff4444;color:#fff">SENSITIVE</span>`;
  if (n.agent_related) tags += `<span class="tag" style="background:#64dfff;color:#000">AGENT</span>`;
  if (n.is_log) tags += `<span class="tag" style="background:#6b7280;color:#fff">LOG</span>`;

  inspector.innerHTML = `
    <div class="name">${{n.label}}</div>
    <div class="meta">${{n.kind}} &middot; ${{formatBytes(n.size || 0)}} &middot; importance: ${{imp}}/100</div>
    <div style="margin:4px 0">${{tags}}</div>
    <div class="meta" style="font-size:9px;word-break:break-all;color:#556677">${{n.path || ''}}</div>
  `;
  inspector.style.display = "block";
}}

function resetView() {{
  camX = 0; camY = 0; camZoom = 1;
  selectedNode = null; highlightMode = null;
  inspector.style.display = "none";
  nodes.forEach(n => {{ n.highlight = false; n.searchMatch = false; }});
}}

function toggleFolders() {{
  showFolders = !showFolders;
}}

function highlightSensitive() {{
  highlightMode = highlightMode === "sensitive" ? null : "sensitive";
  nodes.forEach(n => {{ n.highlight = highlightMode === "sensitive" && n.sensitive; }});
}}

function highlightAgent() {{
  highlightMode = highlightMode === "agent" ? null : "agent";
  nodes.forEach(n => {{ n.highlight = highlightMode === "agent" && n.agent_related; }});
}}

function reLayout() {{
  nodes.forEach(n => {{ n.fixed = false; }});
  initPositions();
}}

document.getElementById("search-input").addEventListener("input", e => {{
  const q = e.target.value.toLowerCase().trim();
  nodes.forEach(n => {{
    n.searchMatch = q.length > 0 && (n.label.toLowerCase().includes(q) || (n.path || "").toLowerCase().includes(q));
  }});
  if (q.length > 0) {{
    highlightMode = "search";
    nodes.forEach(n => {{ n.highlight = n.searchMatch; }});
  }} else {{
    highlightMode = null;
    nodes.forEach(n => {{ n.highlight = false; n.searchMatch = false; }});
  }}
}});

simulate();
draw();
</script>
</body>
</html>"""


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path).expanduser().resolve()
    if not target.is_dir():
        if args.json:
            _emit("scan", False, {"error": f"Not a directory: {target}"})
        else:
            print(f"ERROR: not a directory: {target}", file=sys.stderr)
        return 1

    graph = _scan_directory(target, max_files=args.max_files, max_depth=args.max_depth)

    if args.out:
        out = Path(args.out).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(graph, indent=2), encoding="utf-8")

    if args.json:
        _emit("scan", True, {
            "graph_path": str(args.out) if args.out else "(stdout)",
            "stats": graph["stats"],
        })
    else:
        s = graph["stats"]
        print(f"Scanned: {s['total_files']} files, {s['total_folders']} folders")
        print(f"  Size: {s['total_bytes']:,} bytes")
        print(f"  Sensitive: {s['sensitive_count']}")
        print(f"  Agent-related: {s['agent_related_count']}")

    return 0


def cmd_render(args: argparse.Namespace) -> int:
    target = Path(args.path).expanduser().resolve()
    if not target.is_dir():
        if args.json:
            _emit("render", False, {"error": f"Not a directory: {target}"})
        else:
            print(f"ERROR: not a directory: {target}", file=sys.stderr)
        return 1

    graph = _scan_directory(target, max_files=args.max_files, max_depth=args.max_depth)
    title = f"Galactic Desktop — {target.name}"
    html_content = _render_galactic_html(graph, title)

    out = Path(args.out).expanduser().resolve() if args.out else target / ".liquefy-galactic.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_content, encoding="utf-8")

    if args.json:
        _emit("render", True, {
            "html_path": str(out),
            "stats": graph["stats"],
        })
    else:
        print(f"Rendered: {out}")
        print(f"  {graph['stats']['total_files']} files, {graph['stats']['total_folders']} folders")

    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    target = Path(args.path).expanduser().resolve()
    if not target.is_dir():
        print(f"ERROR: not a directory: {target}", file=sys.stderr)
        return 1

    graph = _scan_directory(target, max_files=args.max_files, max_depth=args.max_depth)
    title = f"Galactic Desktop — {target.name}"
    html_content = _render_galactic_html(graph, title)

    port = args.port

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html_content.encode("utf-8"))

        def log_message(self, fmt, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"Galactic Desktop live at {url}")
    print(f"  {graph['stats']['total_files']} files, {graph['stats']['total_folders']} folders")
    print("  Ctrl+C to stop")

    threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0



# ---------------------------------------------------------------------------
# System info gathering (cross-platform, zero deps)
# ---------------------------------------------------------------------------

PROCESS_CATEGORIES: Dict[str, List[str]] = {
    "browser": ["safari", "chrome", "firefox", "brave", "edge", "msedge", "opera", "arc", "webkit"],
    "ide": ["cursor", "code", "codium", "xcode", "intellij", "pycharm", "webstorm", "sublime", "atom", "neovim", "vim", "emacs"],
    "terminal": ["terminal", "iterm", "kitty", "alacritty", "warp", "hyper", "wezterm", "zsh", "bash", "fish"],
    "agent": ["openclaw", "antigravity", "codex", "copilot", "aider", "gpt", "claude", "liquefy"],
    "database": ["postgres", "mysql", "mongod", "redis", "sqlite"],
    "docker": ["docker", "containerd", "dockerd", "colima", "podman"],
    "media": ["spotify", "music", "vlc", "mpv", "quicktime"],
    "comms": ["slack", "discord", "telegram", "zoom", "teams", "signal"],
    "git": ["git", "gh"],
    "node": ["node", "npm", "yarn", "pnpm", "bun", "deno"],
    "python": ["python", "python3", "pip", "conda"],
}

CATEGORY_COLORS: Dict[str, str] = {
    "browser": "#4285f4", "ide": "#a855f7", "terminal": "#22c55e",
    "agent": "#00ffcc", "database": "#e38c00", "docker": "#2496ed",
    "media": "#ec4899", "comms": "#818cf8", "git": "#f97316",
    "node": "#68a063", "python": "#3572A5", "system": "#6b7280",
    "hardware": "#fbbf24",
}


def _run_cmd(cmd: List[str], default: str = "") -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=5).decode().strip()
    except Exception:
        return default


def _powershell_executable() -> str:
    for candidate in ("powershell", "pwsh"):
        if shutil.which(candidate):
            return candidate
    return "powershell"


def _parse_windows_mem_usage_kb(raw: str) -> int:
    digits = re.sub(r"[^0-9]", "", str(raw or ""))
    if not digits:
        return 0
    try:
        return int(digits)
    except ValueError:
        return 0


def _load_json_cmd(cmd: List[str], default: Any = None) -> Any:
    raw = _run_cmd(cmd, default="")
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


def _windows_is_admin() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _normalize_json_rows(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    return []


def _parse_safari_tabs_json(raw: str) -> List[Dict[str, Any]]:
    try:
        rows = json.loads(raw or "[]")
    except Exception:
        return []
    if not isinstance(rows, list):
        return []
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            win = int(row.get("window", 0) or 0)
            idx = int(row.get("index", 0) or 0)
        except Exception:
            continue
        if win <= 0 or idx <= 0:
            continue
        url = str(row.get("url", "") or "").strip()
        if not url:
            continue
        host = ""
        try:
            host = urllib.parse.urlparse(url).hostname or ""
        except Exception:
            host = ""
        title = str(row.get("title", "") or "").strip()
        tab_id = f"safari_tab_{win}_{idx}"
        if tab_id in seen:
            continue
        seen.add(tab_id)
        out.append(
            {
                "id": tab_id,
                "browser": "safari",
                "window": win,
                "index": idx,
                "active": bool(row.get("active", False)),
                "title": title,
                "url": url,
                "host": host,
                "label": title or host or f"tab {idx}",
            }
        )
    return out


def _load_json_url(url: str, timeout: float = 0.6) -> Any:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _browser_key_from_process_name(name: str) -> str:
    lower = str(name or "").strip().lower()
    if lower.endswith(".exe"):
        lower = lower[:-4]
    lower = lower.replace("_", "-")
    if lower in {"chrome", "chromium", "chromium-browser", "brave", "brave-browser", "google-chrome", "google-chrome-stable"}:
        return "chrome"
    if lower in {"msedge", "edge", "microsoft-edge", "microsoft-edge-stable"}:
        return "edge"
    if lower == "firefox" or lower.startswith("firefox-"):
        return "firefox"
    if lower == "safari":
        return "safari"
    return ""


def _browser_key_from_debug_version(version_data: Any) -> str:
    if not isinstance(version_data, dict):
        return ""
    browser = str(version_data.get("Browser") or version_data.get("browser") or "").lower()
    web_socket = str(version_data.get("webSocketDebuggerUrl") or "").lower()
    combined = f"{browser} {web_socket}"
    if "edg" in combined or "edge" in combined:
        return "edge"
    if "chrome" in combined or "chromium" in combined or "brave" in combined:
        return "chrome"
    if "firefox" in combined:
        return "firefox"
    return ""


def _debug_browser_ports() -> List[int]:
    ports: List[int] = []
    env_raw = str(os.environ.get("PARAD0X_BROWSER_DEBUG_PORTS", "") or "").strip()
    if env_raw:
        for part in env_raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                ports.append(int(part))
            except ValueError:
                continue
    for port in (9222, 9223, 9224, 9333):
        if port not in ports:
            ports.append(port)
    process_ports = _browser_debug_ports_from_processes()
    for port in process_ports:
        if port not in ports:
            ports.insert(0, port)
    return ports


def _browser_debug_ports_from_processes() -> List[int]:
    ports: List[int] = []
    seen: Set[int] = set()
    system = platform.system()
    if system == "Windows":
        ps = _powershell_executable()
        rows = _normalize_json_rows(
            _load_json_cmd(
                [
                    ps,
                    "-NoProfile",
                    "-Command",
                    "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine } | "
                    "Select-Object Name,ProcessId,CommandLine | ConvertTo-Json -Compress",
                ],
                default=[],
            )
        )
        for row in rows:
            name = _browser_key_from_process_name(str(row.get("Name") or ""))
            if not name:
                continue
            cmdline = str(row.get("CommandLine") or "")
            for match in re.finditer(r"--remote-debugging-port(?:=|\s+)(\d+)", cmdline):
                port = int(match.group(1))
                if port not in seen:
                    seen.add(port)
                    ports.append(port)
    else:
        ps_out = _run_cmd(["ps", "-Ao", "args"])
        for line in ps_out.splitlines()[1:]:
            lower = line.lower()
            if not any(browser in lower for browser in ("chrome", "chromium", "brave", "msedge", "firefox")):
                continue
            for match in re.finditer(r"--remote-debugging-port(?:=|\s+)(\d+)", line):
                port = int(match.group(1))
                if port not in seen:
                    seen.add(port)
                    ports.append(port)
    return ports


def _clean_browser_window_title(title: str, browser_key: str) -> str:
    text = str(title or "").strip()
    suffixes = {
        "chrome": [" - Google Chrome", " - Chromium", " - Brave"],
        "edge": [" - Microsoft Edge", " - Edge"],
        "firefox": [" - Mozilla Firefox", " - Firefox"],
    }.get(browser_key, [])
    for suffix in suffixes:
        if text.endswith(suffix):
            text = text[: -len(suffix)].strip()
            break
    return text or str(title or "").strip()


def _lz4_decompress_block(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    length = len(data)
    while i < length:
        token = data[i]
        i += 1

        literal_len = token >> 4
        if literal_len == 15:
            while i < length:
                extra = data[i]
                i += 1
                literal_len += extra
                if extra != 255:
                    break
        if i + literal_len > length:
            raise ValueError("invalid lz4 literal length")
        out.extend(data[i : i + literal_len])
        i += literal_len
        if i >= length:
            break

        if i + 2 > length:
            raise ValueError("invalid lz4 offset")
        offset = data[i] | (data[i + 1] << 8)
        i += 2
        if offset <= 0 or offset > len(out):
            raise ValueError("invalid lz4 match offset")

        match_len = token & 0x0F
        if match_len == 15:
            while i < length:
                extra = data[i]
                i += 1
                match_len += extra
                if extra != 255:
                    break
        match_len += 4

        start = len(out) - offset
        for j in range(match_len):
            out.append(out[start + j])
    return bytes(out)


def _decode_mozlz4_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if not raw:
        return None
    try:
        if raw.startswith(b"mozLz40\0"):
            decoded = _lz4_decompress_block(raw[8:]).decode("utf-8")
        else:
            decoded = raw.decode("utf-8")
        payload = json.loads(decoded)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _firefox_profile_dirs() -> List[Path]:
    roots: List[Path] = []
    home = Path.home()
    system = platform.system()
    if system == "Linux":
        roots.extend(
            [
                home / ".mozilla" / "firefox",
                home / "snap" / "firefox" / "common" / ".mozilla" / "firefox",
                home / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox",
            ]
        )
    elif system == "Darwin":
        roots.append(home / "Library" / "Application Support" / "Firefox")
    elif system == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            roots.append(Path(appdata) / "Mozilla" / "Firefox")

    profiles: List[Tuple[int, Path]] = []
    seen: Set[Path] = set()
    for root in roots:
        ini_path = root / "profiles.ini"
        if not ini_path.exists():
            continue
        parser = configparser.ConfigParser()
        try:
            parser.read(ini_path, encoding="utf-8")
        except Exception:
            continue
        for section in parser.sections():
            if not section.lower().startswith("profile"):
                continue
            rel_path = parser.get(section, "Path", fallback="").strip()
            if not rel_path:
                continue
            is_relative = parser.getboolean(section, "IsRelative", fallback=True)
            profile_dir = (root / rel_path) if is_relative else Path(rel_path).expanduser()
            profile_dir = profile_dir.resolve()
            if not profile_dir.exists() or profile_dir in seen:
                continue
            seen.add(profile_dir)
            priority = 0 if parser.getboolean(section, "Default", fallback=False) else 1
            profiles.append((priority, profile_dir))
    profiles.sort(key=lambda item: (item[0], str(item[1])))
    return [path for _, path in profiles]


def _get_firefox_session_tabs() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    session_names = [
        ("sessionstore-backups", "recovery.jsonlz4"),
        ("sessionstore-backups", "recovery.baklz4"),
        ("sessionstore-backups", "previous.jsonlz4"),
        ("", "sessionstore.jsonlz4"),
    ]
    for profile_dir in _firefox_profile_dirs():
        session_data: Optional[Dict[str, Any]] = None
        for folder, name in session_names:
            candidate = profile_dir / folder / name if folder else profile_dir / name
            if not candidate.exists():
                continue
            session_data = _decode_mozlz4_json(candidate)
            if session_data:
                break
        if not session_data:
            continue
        for win_idx, window in enumerate(session_data.get("windows") or [], start=1):
            if not isinstance(window, dict):
                continue
            selected = int(window.get("selected") or 0)
            for tab_idx, tab in enumerate(window.get("tabs") or [], start=1):
                if not isinstance(tab, dict):
                    continue
                entries = [entry for entry in (tab.get("entries") or []) if isinstance(entry, dict)]
                if not entries:
                    continue
                current_idx = int(tab.get("index") or len(entries) or 1)
                current_idx = max(1, min(current_idx, len(entries)))
                entry = entries[current_idx - 1]
                url = str(entry.get("url") or "").strip()
                if not url:
                    continue
                try:
                    host = urllib.parse.urlparse(url).hostname or ""
                except Exception:
                    host = ""
                title = str(entry.get("title") or tab.get("title") or "").strip()
                tab_id = f"firefox_session_{profile_dir.name}_{win_idx}_{tab_idx}"
                if tab_id in seen:
                    continue
                seen.add(tab_id)
                rows.append(
                    {
                        "id": tab_id,
                        "browser": "firefox",
                        "window": win_idx,
                        "index": tab_idx,
                        "active": tab_idx == selected,
                        "title": title,
                        "url": url,
                        "host": host,
                        "label": title or host or f"tab {tab_idx}",
                        "sessionstore_tab": True,
                    }
                )
    return rows


def _browser_key_from_linux_window_class(window_class: str) -> str:
    lower = str(window_class or "").strip().lower()
    if not lower:
        return ""
    if any(token in lower for token in ("chrome", "chromium", "brave")):
        return "chrome"
    if any(token in lower for token in ("msedge", "edge")):
        return "edge"
    if "firefox" in lower or "navigator" in lower:
        return "firefox"
    return ""


def _linux_browser_tab_row(browser_key: str, title: str, idx: int, window_id: str = "") -> Optional[Dict[str, Any]]:
    clean_title = _clean_browser_window_title(title, browser_key)
    if not browser_key or not clean_title:
        return None
    row_id = f"{browser_key}_window_{window_id or idx}"
    return {
        "id": row_id,
        "browser": browser_key,
        "window": idx,
        "index": 1,
        "active": False,
        "title": clean_title,
        "url": "",
        "host": "",
        "label": clean_title,
        "fallback_window_title": True,
    }


def _get_linux_browser_window_tabs_from_wmctrl() -> List[Dict[str, Any]]:
    if shutil.which("wmctrl") is None:
        return []
    raw = _run_cmd(["wmctrl", "-lx"])
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for idx, line in enumerate(raw.splitlines(), start=1):
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        window_id = str(parts[0] or "").strip().lower()
        browser_key = _browser_key_from_linux_window_class(parts[3])
        row = _linux_browser_tab_row(browser_key, parts[4].strip(), idx, window_id=window_id)
        if not row or row["id"] in seen:
            continue
        seen.add(row["id"])
        out.append(row)
    return out


def _get_linux_browser_window_tabs_from_xprop() -> List[Dict[str, Any]]:
    if shutil.which("xprop") is None:
        return []
    root_raw = _run_cmd(["xprop", "-root", "_NET_CLIENT_LIST_STACKING"])
    if not root_raw:
        root_raw = _run_cmd(["xprop", "-root", "_NET_CLIENT_LIST"])
    window_ids = re.findall(r"0x[0-9a-fA-F]+", root_raw or "")
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for idx, window_id in enumerate(window_ids, start=1):
        props = _run_cmd(["xprop", "-id", window_id, "WM_CLASS", "_NET_WM_NAME", "WM_NAME"])
        if not props:
            continue
        window_class = ""
        title = ""
        for line in props.splitlines():
            if line.startswith("WM_CLASS"):
                window_class = line.split("=", 1)[-1].strip()
            elif line.startswith("_NET_WM_NAME") and "=" in line:
                title = line.split("=", 1)[-1].strip().strip('"')
            elif not title and line.startswith("WM_NAME") and "=" in line:
                title = line.split("=", 1)[-1].strip().strip('"')
        browser_key = _browser_key_from_linux_window_class(window_class)
        row = _linux_browser_tab_row(browser_key, title, idx, window_id=window_id.lower())
        if not row or row["id"] in seen:
            continue
        seen.add(row["id"])
        out.append(row)
    return out


def _get_windows_browser_window_tabs() -> List[Dict[str, Any]]:
    if platform.system() != "Windows":
        return []
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def add_row(browser_key: str, pid: int, title: str, idx: int) -> None:
        clean_title = _clean_browser_window_title(title, browser_key)
        if not clean_title:
            return
        tab_id = f"{browser_key}_window_{pid or idx}"
        if tab_id in seen:
            return
        seen.add(tab_id)
        out.append(
            {
                "id": tab_id,
                "browser": browser_key,
                "window": idx,
                "index": 1,
                "active": False,
                "title": clean_title,
                "url": "",
                "host": "",
                "label": clean_title,
                "fallback_window_title": True,
            }
        )

    tasklist_raw = _run_cmd(["tasklist", "/v", "/fo", "csv", "/nh"])
    for idx, row in enumerate(csv.reader(tasklist_raw.splitlines()), start=1):
        if len(row) < 9:
            continue
        browser_key = _browser_key_from_process_name(str(row[0] or "").strip())
        if not browser_key:
            continue
        title = str(row[-1] or "").strip()
        if not title or title.upper() == "N/A":
            continue
        try:
            pid = int(str(row[1] or "").strip())
        except Exception:
            pid = 0
        add_row(browser_key, pid, title, idx)

    if out:
        return out

    ps = _powershell_executable()
    rows = _normalize_json_rows(
        _load_json_cmd(
            [
                ps,
                "-NoProfile",
                "-Command",
                "Get-Process -Name chrome,msedge,firefox -ErrorAction SilentlyContinue | "
                "Where-Object { $_.MainWindowTitle -and $_.MainWindowTitle.Trim().Length -gt 0 } | "
                "Select-Object ProcessName,Id,MainWindowTitle | ConvertTo-Json -Compress",
            ],
            default=[],
        )
    )
    for idx, row in enumerate(rows, start=1):
        browser_key = _browser_key_from_process_name(str(row.get("ProcessName") or ""))
        if not browser_key:
            continue
        try:
            pid = int(row.get("Id") or 0)
        except Exception:
            pid = 0
        add_row(browser_key, pid, str(row.get("MainWindowTitle") or "").strip(), idx)
    return out


def _get_windows_browser_ui_tabs() -> List[Dict[str, Any]]:
    if platform.system() != "Windows":
        return []
    ps = _powershell_executable()
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName UIAutomationClient
$rows = @()
$procs = Get-Process -Name chrome,msedge,firefox -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 }
$windowCounter = 0
foreach ($proc in $procs) {
  try {
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($proc.MainWindowHandle)
    if (-not $root) { continue }
    $windowCounter++
    $cond = New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
      [System.Windows.Automation.ControlType]::TabItem
    )
    $tabs = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)
    if (-not $tabs -or $tabs.Count -eq 0) { continue }
    for ($i = 0; $i -lt $tabs.Count; $i++) {
      $tab = $tabs.Item($i)
      $name = $tab.Current.Name
      if ([string]::IsNullOrWhiteSpace($name)) { continue }
      $active = $false
      try {
        $pattern = $null
        if ($tab.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$pattern)) {
          $active = $pattern.Current.IsSelected
        }
      } catch {}
      $rows += [pscustomobject]@{
        ProcessName = $proc.ProcessName
        Id = $proc.Id
        Window = $windowCounter
        Index = ($i + 1)
        Title = $name
        Active = $active
      }
    }
  } catch {}
}
$rows | ConvertTo-Json -Compress
"""
    rows = _normalize_json_rows(
        _load_json_cmd([ps, "-NoProfile", "-Command", script], default=[])
    )
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for row in rows:
        browser_key = _browser_key_from_process_name(str(row.get("ProcessName") or ""))
        if not browser_key:
            continue
        try:
            pid = int(row.get("Id") or 0)
            window = int(row.get("Window") or 1)
            index = int(row.get("Index") or 1)
        except Exception:
            pid = 0
            window = 1
            index = 1
        title = _clean_browser_window_title(str(row.get("Title") or "").strip(), browser_key)
        if not title:
            continue
        tab_id = f"{browser_key}_uia_{pid}_{window}_{index}"
        if tab_id in seen:
            continue
        seen.add(tab_id)
        out.append(
            {
                "id": tab_id,
                "browser": browser_key,
                "window": window,
                "index": index,
                "active": bool(row.get("Active", False)),
                "title": title,
                "url": "",
                "host": "",
                "label": title,
                "fallback_window_title": True,
                "uia_tab_probe": True,
            }
        )
    return out


def _get_linux_browser_window_tabs() -> List[Dict[str, Any]]:
    if platform.system() != "Linux":
        return []
    wmctrl_rows = _get_linux_browser_window_tabs_from_wmctrl()
    xprop_rows = _get_linux_browser_window_tabs_from_xprop()
    if len(xprop_rows) > len(wmctrl_rows):
        return xprop_rows
    return wmctrl_rows


def _get_chromium_tabs() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for port in _debug_browser_ports():
        version = _load_json_url(f"http://127.0.0.1:{port}/json/version")
        browser_key = _browser_key_from_debug_version(version)
        if not browser_key:
            continue
        pages = _load_json_url(f"http://127.0.0.1:{port}/json/list")
        if not isinstance(pages, list):
            pages = _load_json_url(f"http://127.0.0.1:{port}/json")
        if not isinstance(pages, list):
            continue
        visible_idx = 0
        for page in pages:
            if not isinstance(page, dict):
                continue
            if str(page.get("type") or "page").lower() != "page":
                continue
            url = str(page.get("url") or "").strip()
            if not url or url.startswith("devtools://"):
                continue
            try:
                host = urllib.parse.urlparse(url).hostname or ""
            except Exception:
                host = ""
            title = str(page.get("title") or "").strip()
            visible_idx += 1
            tab_id = str(page.get("id") or f"{browser_key}_{port}_{visible_idx}")
            unique_id = f"{browser_key}_tab_{tab_id}"
            if unique_id in seen:
                continue
            seen.add(unique_id)
            rows.append(
                {
                    "id": unique_id,
                    "browser": browser_key,
                    "window": 1,
                    "index": visible_idx,
                    "active": bool(page.get("active", False)),
                    "title": title,
                    "url": url,
                    "host": host,
                    "label": title or host or f"tab {visible_idx}",
                }
            )
    return rows


def _get_safari_tabs() -> List[Dict[str, Any]]:
    if platform.system() != "Darwin":
        return []
    script = r'''
function run() {
  try {
    var safari = Application("Safari");
    if (!safari.running()) return "[]";
    var rows = [];
    safari.windows().forEach(function(w, wi) {
      var currentIndex = -1;
      try { currentIndex = w.currentTab().index(); } catch (e) {}
      w.tabs().forEach(function(t) {
        var title = "";
        var url = "";
        var index = 0;
        try { title = t.name() || ""; } catch (e) {}
        try { url = t.url() || ""; } catch (e) {}
        try { index = t.index() || 0; } catch (e) {}
        if (url) {
          rows.push({
            window: wi + 1,
            index: index,
            active: index === currentIndex,
            title: title,
            url: url
          });
        }
      });
    });
    return JSON.stringify(rows);
  } catch (e) {
    return "[]";
  }
}
'''
    raw = _run_cmd(["osascript", "-l", "JavaScript", "-e", script], default="[]")
    return _parse_safari_tabs_json(raw)


def _get_browser_tabs() -> List[Dict[str, Any]]:
    tabs: List[Dict[str, Any]] = []
    safari_tabs = _get_safari_tabs()
    tabs.extend(safari_tabs)

    chromium_tabs = _get_chromium_tabs()
    firefox_session_tabs = _get_firefox_session_tabs()
    browser_candidates: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    def add_source(source: str, rows: List[Dict[str, Any]]) -> None:
        for row in rows:
            key = str(row.get("browser") or "").lower()
            if not key:
                continue
            browser_candidates.setdefault(key, {}).setdefault(source, []).append(row)

    add_source("debug", chromium_tabs)
    add_source("session", firefox_session_tabs)
    if platform.system() == "Windows":
        add_source("uia", _get_windows_browser_ui_tabs())
        add_source("window", _get_windows_browser_window_tabs())
    elif platform.system() == "Linux":
        add_source("window", _get_linux_browser_window_tabs())

    source_priority = {"debug": 4, "session": 3, "uia": 2, "window": 1}
    for browser_key in sorted(browser_candidates.keys()):
        options = browser_candidates[browser_key]
        best_rows: List[Dict[str, Any]] = []
        best_score = (-1, -1, -1)
        for source, rows in options.items():
            url_count = sum(1 for row in rows if row.get("url"))
            score = (len(rows), url_count, source_priority.get(source, 0))
            if score > best_score:
                best_score = score
                best_rows = rows
        tabs.extend(best_rows)

    return tabs[:16]


def _get_cpu_info() -> Dict[str, Any]:
    cores = os.cpu_count() or 1
    info: Dict[str, Any] = {"cores": cores, "usage_pct": 0, "model": "Unknown CPU"}

    system = platform.system()
    if system == "Darwin":
        model = _run_cmd(["sysctl", "-n", "machdep.cpu.brand_string"])
        if model:
            info["model"] = model
        # Use ps to estimate aggregate CPU (much faster than `top -l 1`)
        ps_cpu = _run_cmd(["ps", "-eo", "pcpu"])
        total_cpu = 0.0
        for line in ps_cpu.splitlines()[1:]:
            try:
                total_cpu += float(line.strip())
            except ValueError:
                pass
        info["usage_pct"] = round(min(total_cpu / max(cores, 1), 100), 1)
    elif system == "Linux":
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if "model name" in line:
                        info["model"] = line.split(":")[1].strip()
                        break
        except OSError:
            pass
        try:
            with open("/proc/stat") as f:
                parts = f.readline().split()
            idle = int(parts[4])
            total = sum(int(x) for x in parts[1:])
            info["usage_pct"] = round(100.0 * (1 - idle / max(total, 1)), 1)
        except (OSError, IndexError, ValueError):
            pass
    elif system == "Windows":
        ps = _powershell_executable()
        model = _run_cmd(
            [
                ps,
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)",
            ]
        )
        if model:
            info["model"] = model.splitlines()[0].strip()
        load = _run_cmd(
            [
                ps,
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty LoadPercentage)",
            ]
        )
        try:
            info["usage_pct"] = round(min(max(float(str(load).strip() or "0"), 0.0), 100.0), 1)
        except ValueError:
            pass

    return info


def _get_memory_info() -> Dict[str, Any]:
    info: Dict[str, Any] = {"total_gb": 0, "used_gb": 0, "usage_pct": 0}
    system = platform.system()

    if system == "Darwin":
        mem_bytes = _run_cmd(["sysctl", "-n", "hw.memsize"])
        if mem_bytes:
            info["total_gb"] = round(int(mem_bytes) / (1024**3), 1)
        vm = _run_cmd(["vm_stat"])
        page_size = 16384
        m_ps = re.search(r"page size of (\d+)", vm)
        if m_ps:
            page_size = int(m_ps.group(1))
        free_pages = 0
        for line in vm.splitlines():
            if "Pages free" in line:
                m = re.search(r"(\d+)", line.split(":")[1])
                if m:
                    free_pages += int(m.group(1))
            elif "Pages inactive" in line:
                m = re.search(r"(\d+)", line.split(":")[1])
                if m:
                    free_pages += int(m.group(1))
        free_gb = (free_pages * page_size) / (1024**3)
        info["used_gb"] = round(info["total_gb"] - free_gb, 1)
        info["usage_pct"] = round(100 * info["used_gb"] / max(info["total_gb"], 0.1), 1)
    elif system == "Linux":
        try:
            with open("/proc/meminfo") as f:
                lines = f.readlines()
            kv = {}
            for line in lines:
                parts = line.split(":")
                if len(parts) == 2:
                    kv[parts[0].strip()] = int(re.sub(r"[^0-9]", "", parts[1].strip()) or "0")
            total_kb = kv.get("MemTotal", 0)
            avail_kb = kv.get("MemAvailable", total_kb)
            info["total_gb"] = round(total_kb / (1024**2), 1)
            info["used_gb"] = round((total_kb - avail_kb) / (1024**2), 1)
            info["usage_pct"] = round(100 * info["used_gb"] / max(info["total_gb"], 0.1), 1)
        except OSError:
            pass
    elif system == "Windows":
        ps = _powershell_executable()
        total_kb_raw = _run_cmd(
            [
                ps,
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_OperatingSystem | Select-Object -First 1 -ExpandProperty TotalVisibleMemorySize)",
            ]
        )
        free_kb_raw = _run_cmd(
            [
                ps,
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_OperatingSystem | Select-Object -First 1 -ExpandProperty FreePhysicalMemory)",
            ]
        )
        try:
            total_kb = int(re.sub(r"[^0-9]", "", total_kb_raw or "") or "0")
            free_kb = int(re.sub(r"[^0-9]", "", free_kb_raw or "") or "0")
        except ValueError:
            total_kb = 0
            free_kb = 0
        if total_kb > 0:
            used_kb = max(total_kb - free_kb, 0)
            info["total_gb"] = round(total_kb / (1024**2), 1)
            info["used_gb"] = round(used_kb / (1024**2), 1)
            info["usage_pct"] = round(100 * info["used_gb"] / max(info["total_gb"], 0.1), 1)

    if float(info.get("total_gb", 0) or 0) <= 0:
        try:
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
            total_pages = int(os.sysconf("SC_PHYS_PAGES"))
            avail_pages = int(os.sysconf("SC_AVPHYS_PAGES"))
            total_gb = (page_size * total_pages) / (1024**3)
            used_gb = (page_size * max(total_pages - avail_pages, 0)) / (1024**3)
            info["total_gb"] = round(total_gb, 1)
            info["used_gb"] = round(used_gb, 1)
            info["usage_pct"] = round(100 * used_gb / max(total_gb, 0.1), 1)
        except Exception:
            pass

    if float(info.get("total_gb", 0) or 0) <= 0:
        # Final fallback for constrained sandbox/CI environments where OS probes are blocked.
        info["total_gb"] = 1.0
        info["used_gb"] = max(0.0, float(info.get("used_gb", 0) or 0))
        info["usage_pct"] = round(100 * float(info["used_gb"]) / max(float(info["total_gb"]), 0.1), 1)

    return info


def _get_disk_info(path: Path) -> Dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
        return {
            "total_gb": round(usage.total / (1024**3), 1),
            "used_gb": round(usage.used / (1024**3), 1),
            "free_gb": round(usage.free / (1024**3), 1),
            "usage_pct": round(100 * usage.used / max(usage.total, 1), 1),
            "mount": str(path),
        }
    except OSError:
        return {"total_gb": 0, "used_gb": 0, "free_gb": 0, "usage_pct": 0, "mount": str(path)}


def _get_network_info() -> Dict[str, Any]:
    info: Dict[str, Any] = {"interface": "unknown", "type": "unknown", "ip": "0.0.0.0", "active": False}
    system = platform.system()

    if system == "Darwin":
        route = _run_cmd(["route", "-n", "get", "default"])
        for line in route.splitlines():
            if "interface:" in line:
                info["interface"] = line.split(":")[-1].strip()
                break
        if info["interface"].startswith("en"):
            info["type"] = "WiFi" if info["interface"] in ("en0", "en1") else "Ethernet"
        ifconfig = _run_cmd(["ifconfig", info["interface"]])
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ifconfig)
        if m:
            info["ip"] = m.group(1)
            info["active"] = True
    elif system == "Linux":
        route = _run_cmd(["ip", "route", "get", "1.1.1.1"])
        m = re.search(r"dev (\S+)", route)
        if m:
            info["interface"] = m.group(1)
        info["type"] = "WiFi" if "wl" in info["interface"] else "Ethernet"
        addr = _run_cmd(["hostname", "-I"])
        if addr:
            info["ip"] = addr.split()[0]
            info["active"] = True
    elif system == "Windows":
        netsh = _run_cmd(["netsh", "interface", "show", "interface"])
        for line in netsh.splitlines():
            stripped = line.strip()
            if not stripped or stripped.lower().startswith("admin") or set(stripped) == {"-"}:
                continue
            parts = re.split(r"\s{2,}", stripped)
            if len(parts) < 4:
                continue
            iface_state = _windows_network_interface_state(parts[3])
            if info["interface"] == "unknown" or iface_state.get("active"):
                info["interface"] = iface_state.get("interface", "unknown")
                info["active"] = bool(iface_state.get("active"))
                info["type"] = str(iface_state.get("type", "unknown"))
                if iface_state.get("active"):
                    break
        out = _run_cmd(["ipconfig"])
        current = ""
        for line in out.splitlines():
            if line.strip().endswith(":") and "adapter" in line.lower():
                current = line.split("adapter", 1)[-1].strip(" :")
            if "IPv4 Address" in line or "IPv4-adres" in line:
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    info["interface"] = current or "Ethernet"
                    info["ip"] = m.group(1)
                    info["active"] = True
                    break
        lower_iface = str(info["interface"]).lower()
        if lower_iface != "unknown":
            info["type"] = "WiFi" if ("wi-fi" in lower_iface or "wifi" in lower_iface or "wireless" in lower_iface or "wlan" in lower_iface) else "Ethernet"

    return info


def _macos_network_service_for_interface(interface: str) -> str:
    raw = _run_cmd(["networksetup", "-listallhardwareports"])
    current_port = ""
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("Hardware Port:"):
            current_port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:"):
            dev = line.split(":", 1)[1].strip()
            if dev == interface:
                return current_port
    return ""


def _run_checked_cmd(cmd: List[str], timeout: int = 8) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
        return True, (proc.stdout or proc.stderr or "").strip()
    except Exception as exc:
        return False, str(exc)


def _windows_network_interface_state(interface: str) -> Dict[str, Any]:
    iface = str(interface or "").strip()
    out = _run_cmd(["netsh", "interface", "show", "interface"])
    result: Dict[str, Any] = {
        "interface": iface or "unknown",
        "type": "unknown",
        "active": False,
        "admin_state": "unknown",
        "state": "unknown",
    }
    for line in out.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("admin") or set(stripped) == {"-"}:
            continue
        parts = re.split(r"\s{2,}", stripped)
        if len(parts) < 4:
            continue
        admin_state, state, _, iface_name = parts[0], parts[1], parts[2], parts[3]
        if iface and iface_name.lower() != iface.lower():
            continue
        lower_iface = iface_name.lower()
        result = {
            "interface": iface_name,
            "type": "WiFi" if ("wi-fi" in lower_iface or "wifi" in lower_iface or "wireless" in lower_iface or "wlan" in lower_iface) else "Ethernet",
            "active": state.lower() == "connected",
            "admin_state": admin_state,
            "state": state,
        }
        break
    return result


def _windows_elevated_network_cmd(interface: str, enable: bool) -> List[str]:
    ps = _powershell_executable()
    iface = str(interface or "").replace("'", "''")
    desired = "enabled" if enable else "disabled"
    cmd = (
        "$p = Start-Process -FilePath 'netsh' -Verb RunAs -WindowStyle Hidden "
        f"-ArgumentList @('interface','set','interface','name=\"{iface}\"','admin={desired}') "
        "-PassThru -Wait; "
        "exit $p.ExitCode"
    )
    return [ps, "-NoProfile", "-Command", cmd]


def _windows_wifi_profile_info(interface: str) -> Dict[str, str]:
    iface = str(interface or "").strip()
    out = _run_cmd(["netsh", "wlan", "show", "interfaces"])
    current: Dict[str, str] = {}
    for raw_line in out.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        key_lower = key.lower()
        if key_lower == "name":
            current["interface"] = value
        elif key_lower == "state":
            current["state"] = value
        elif key_lower == "ssid":
            current["ssid"] = value
        elif key_lower == "profile":
            current["profile"] = value
        if iface and current.get("interface", "").lower() == iface.lower() and key_lower == "profile":
            break
    if iface and current.get("interface", "").lower() != iface.lower():
        return {"interface": iface}
    return {
        "interface": current.get("interface", iface),
        "state": current.get("state", ""),
        "ssid": current.get("ssid", ""),
        "profile": current.get("profile", ""),
    }


def _network_action_result(action: str) -> Dict[str, Any]:
    global _NETWORK_PANIC_STATE
    net = _get_network_info()
    iface = str(net.get("interface") or "").strip()
    system = platform.system()
    if action not in {"off", "on"}:
        return {"ok": False, "error": f"Unsupported network action: {action}"}
    service = ""
    saved = _NETWORK_PANIC_STATE if _NETWORK_PANIC_STATE.get("system") == system else {}

    if action == "on" and saved:
        saved_iface = str(saved.get("interface") or "").strip()
        saved_type = str(saved.get("network_type") or net.get("type", "unknown"))
        current_active = bool(net.get("active"))
        current_type = str(net.get("type") or "").strip()
        should_restore_saved = (
            not iface
            or iface == "unknown"
            or not current_active
            or (saved_iface and iface.lower() != saved_iface.lower())
            or (saved_type and current_type and saved_type.lower() != current_type.lower())
        )
        if should_restore_saved and saved_iface:
            iface = saved_iface
            net = {
                **net,
                "interface": saved_iface,
                "type": saved_type,
            }
        service = str(saved.get("service") or "").strip()

    if not iface or iface == "unknown":
        return {"ok": False, "error": "No active network interface detected", "interface": iface, "network_type": net.get("type", "unknown")}

    enable = action == "on"
    cmds: List[List[str]] = []
    wifi_profile_name = str(saved.get("wifi_profile") or "").strip()

    if system == "Darwin":
        service = service or _macos_network_service_for_interface(iface)
        if str(net.get("type")) == "WiFi" and iface.startswith("en"):
            cmds.append(["networksetup", "-setairportpower", iface, "on" if enable else "off"])
        elif service:
            cmds.append(["networksetup", "-setnetworkserviceenabled", service, "on" if enable else "off"])
        cmds.append(["ifconfig", iface, "up" if enable else "down"])
    elif system == "Linux":
        if shutil.which("nmcli"):
            cmds.append(["nmcli", "networking", "on" if enable else "off"])
        cmds.append(["ip", "link", "set", "dev", iface, "up" if enable else "down"])
    elif system == "Windows":
        iface_quoted = iface.replace('"', '\\"')
        ps_iface = iface.replace("'", "''")
        wifi_profile = _windows_wifi_profile_info(iface) if str(net.get("type")) == "WiFi" else {}
        wifi_profile_name = str(wifi_profile_name or wifi_profile.get("profile") or "").strip()
        if str(net.get("type")) == "WiFi":
            if enable and wifi_profile_name:
                cmds.append(["netsh", "wlan", "connect", f'name="{wifi_profile_name}"', f'interface="{iface_quoted}"'])
            elif not enable:
                cmds.append(["netsh", "wlan", "disconnect", f'interface="{iface_quoted}"'])
        direct_cmds = [
            ["netsh", "interface", "set", "interface", f'name="{iface_quoted}"', f"admin={'enabled' if enable else 'disabled'}"],
            [
                _powershell_executable(),
                "-NoProfile",
                "-Command",
                f"{'Enable' if enable else 'Disable'}-NetAdapter -Name '{ps_iface}' -Confirm:$false",
            ],
        ]
        if _windows_is_admin():
            cmds.extend(direct_cmds)
        else:
            cmds.append(_windows_elevated_network_cmd(iface, enable))
            cmds.extend(direct_cmds)
    else:
        return {"ok": False, "error": f"Unsupported platform: {system}", "interface": iface, "network_type": net.get("type", "unknown")}

    last_error = ""
    used_cmd: List[str] = []
    for cmd in cmds:
        if not shutil.which(cmd[0]):
            last_error = f"Missing command: {cmd[0]}"
            continue
        ok, out = _run_checked_cmd(cmd)
        used_cmd = cmd
        if ok:
            if system == "Windows":
                time.sleep(0.5)
                state = _windows_network_interface_state(iface)
                if str(net.get("type")) == "WiFi" and cmd[:3] == ["netsh", "wlan", "disconnect"]:
                    wifi_state = _windows_wifi_profile_info(iface)
                    if str(wifi_state.get("state", "")).lower() == "connected":
                        last_error = f"wifi {iface} still connected after disconnect"
                        continue
                elif str(net.get("type")) == "WiFi" and enable and cmd[:3] == ["netsh", "wlan", "connect"]:
                    wifi_state = _windows_wifi_profile_info(iface)
                    if str(wifi_state.get("state", "")).lower() != "connected":
                        last_error = f"wifi {iface} still disconnected after reconnect"
                        continue
                elif action == "off":
                    disabled = str(state.get("admin_state", "")).lower().startswith("disabled")
                    if not disabled:
                        last_error = f"interface {iface} still enabled after command"
                        continue
                else:
                    disabled = str(state.get("admin_state", "")).lower().startswith("disabled")
                    if disabled:
                        last_error = f"interface {iface} still disabled after command"
                        continue
            if enable:
                _NETWORK_PANIC_STATE = {}
            else:
                _NETWORK_PANIC_STATE = {
                    "system": system,
                    "interface": iface,
                    "network_type": net.get("type", "unknown"),
                    "service": service,
                    "wifi_profile": wifi_profile_name,
                }
            return {
                "ok": True,
                "action": action,
                "interface": iface,
                "network_type": net.get("type", "unknown"),
                "service": service,
                "command": " ".join(cmd),
                "detail": out,
            }
        last_error = out or f"Command failed: {' '.join(cmd)}"

    return {
        "ok": False,
        "action": action,
        "interface": iface,
        "network_type": net.get("type", "unknown"),
        "service": service,
        "command": " ".join(used_cmd) if used_cmd else "",
        "error": last_error or "No usable network control command found",
    }


def _get_gpu_info() -> Dict[str, Any]:
    info: Dict[str, Any] = {"model": "Unknown GPU", "metal": "", "usage_pct": 0}
    system = platform.system()

    if system == "Darwin":
        out = _run_cmd(["system_profiler", "SPDisplaysDataType"])
        m = re.search(r"Chipset Model:\s*(.+)", out)
        if m:
            info["model"] = m.group(1).strip()
        m = re.search(r"Metal.*?:\s*(.+)", out)
        if m:
            info["metal"] = m.group(1).strip()
        gpu_procs = {"windowserver", "com.apple.webkit.gpu", "gpumemd"}
        ps_out = _run_cmd(["ps", "-eo", "pcpu,comm"])
        gpu_cpu = 0.0
        for line in ps_out.splitlines()[1:]:
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                name = os.path.basename(parts[1]).lower()
                if any(g in name for g in gpu_procs):
                    try:
                        gpu_cpu += float(parts[0])
                    except ValueError:
                        pass
        info["usage_pct"] = round(min(gpu_cpu, 100), 1)
    elif system == "Linux":
        nv = _run_cmd(["nvidia-smi", "--query-gpu=name,utilization.gpu",
                        "--format=csv,noheader,nounits"])
        if nv:
            parts = nv.split(",")
            if len(parts) >= 2:
                info["model"] = parts[0].strip()
                try:
                    info["usage_pct"] = round(float(parts[1].strip()), 1)
                except ValueError:
                    pass
    elif system == "Windows":
        ps = _powershell_executable()
        model = _run_cmd(
            [
                ps,
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_VideoController | Select-Object -First 1 -ExpandProperty Name)",
            ]
        )
        if not model:
            wmic = _run_cmd(["wmic", "path", "win32_VideoController", "get", "name"])
            lines = [line.strip() for line in wmic.splitlines() if line.strip() and line.strip().lower() != "name"]
            model = lines[0] if lines else ""
        if model:
            info["model"] = model.splitlines()[0].strip()

    return info


def _get_network_stats(interface: str) -> Dict[str, Any]:
    """Get bytes/packets in and out for the given interface."""
    stats: Dict[str, Any] = {
        "bytes_in": 0, "bytes_out": 0, "pkts_in": 0, "pkts_out": 0,
    }
    system = platform.system()

    if system == "Darwin":
        out = _run_cmd(["netstat", "-ib"])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 10 and parts[0] == interface and "<Link" in parts[2]:
                try:
                    stats["pkts_in"] = int(parts[4])
                    stats["bytes_in"] = int(parts[6])
                    stats["pkts_out"] = int(parts[7])
                    stats["bytes_out"] = int(parts[9])
                except (ValueError, IndexError):
                    pass
                break
    elif system == "Linux":
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    if interface in line:
                        parts = line.split(":")[1].split()
                        stats["bytes_in"] = int(parts[0])
                        stats["pkts_in"] = int(parts[1])
                        stats["bytes_out"] = int(parts[8])
                        stats["pkts_out"] = int(parts[9])
                        break
        except (OSError, IndexError, ValueError):
            pass

    return stats


def _canonical_process_group(name: str) -> Tuple[str, str]:
    raw = str(name or "unknown").strip()
    lower = raw.lower()
    if lower.endswith(".exe"):
        lower = lower[:-4]
    alias_map = {
        "visual studio code": "vscode",
        "code": "vscode",
        "code helper": "vscode",
        "code - insiders": "vscode",
        "iterm2": "iterm",
        "google chrome": "chrome",
        "google-chrome": "chrome",
        "google-chrome-stable": "chrome",
        "google chrome helper": "chrome",
        "chromium": "chrome",
        "chromium-browser": "chrome",
        "brave": "chrome",
        "brave-browser": "chrome",
        "msedge": "edge",
        "microsoft edge": "edge",
        "microsoft-edge": "edge",
        "microsoft-edge-stable": "edge",
        "microsoft edge webview2": "edge",
        "firefox-esr": "firefox",
        "spotify helper": "spotify",
        "spotify helper (renderer)": "spotify",
        "discord helper": "discord",
        "discord helper (renderer)": "discord",
        "telegram helper": "telegram",
        "telegram helper (renderer)": "telegram",
        "slack helper": "slack",
        "slack helper (renderer)": "slack",
        "cursor helper": "cursor",
        "codex helper": "codex",
        "safari web content": "safari",
        "safari networking": "safari",
        "com.apple.webkit.webcontent": "safari",
        "com.apple.webkit.gpu": "safari",
        "com.apple.webcontent": "safari",
        "windows explorer": "explorer",
    }
    lower = alias_map.get(lower, lower)
    for suffix in (
        " helper (renderer)",
        " helper (gpu)",
        " helper (plugin)",
        " helper",
        " (renderer)",
        " (gpu)",
        " (plugin)",
    ):
        if lower.endswith(suffix):
            lower = lower[: -len(suffix)].strip()
    lower = re.sub(r"\s+", " ", lower).strip() or "unknown"
    display_map = {
        "chrome": "Google Chrome",
        "safari": "Safari",
        "spotify": "Spotify",
        "discord": "Discord",
        "telegram": "Telegram",
        "slack": "Slack",
        "cursor": "Cursor",
        "codex": "Codex",
        "vscode": "VS Code",
        "iterm": "iTerm",
        "finder": "Finder",
        "explorer": "Explorer",
        "terminal": "Terminal",
        "whatsapp": "WhatsApp",
        "firefox": "Firefox",
        "xcode": "Xcode",
        "edge": "Edge",
    }
    display = display_map.get(lower, raw if raw and raw.lower() == lower else lower.title())
    return lower, display


def _is_helper_process_name(name: str) -> bool:
    lower = str(name or "").strip().lower()
    helper_markers = (
        "helper",
        "renderer",
        "plugin",
        "gpu",
        "web content",
        "networking",
        "webcontent",
    )
    return any(marker in lower for marker in helper_markers)


def _get_processes() -> List[Dict[str, Any]]:
    procs: List[Dict[str, Any]] = []
    seen_names: Dict[str, int] = {}
    system = platform.system()

    def _register_process(pid: int, cpu: float, mem: float, name: str) -> None:
        raw_lower = name.lower()
        name_lower, display_name = _canonical_process_group(name)

        if raw_lower in ("ps", "grep", "tail", "head", "cat", "kernel_task", "launchd", "syslogd"):
            return

        cat = "system"
        for category, keywords in PROCESS_CATEGORIES.items():
            if any((kw in name_lower) or (kw in raw_lower) for kw in keywords):
                cat = category
                break

        group_key = name_lower
        if group_key in seen_names:
            p = procs[seen_names[group_key]]
            p["cpu_pct"] = round(p["cpu_pct"] + cpu, 1)
            p["mem_pct"] = round(p["mem_pct"] + mem, 1)
            p["instance_count"] = p.get("instance_count", 1) + 1
            p.setdefault("_pids", []).append(pid)
            current_is_helper = _is_helper_process_name(name)
            existing_is_helper = _is_helper_process_name(p.get("raw_name", ""))
            if (existing_is_helper and not current_is_helper) or (
                existing_is_helper == current_is_helper and pid < int(p.get("pid", pid) or pid)
            ):
                p["pid"] = pid
                p["raw_name"] = name
                p["name"] = display_name
            return

        seen_names[group_key] = len(procs)
        procs.append({
            "pid": pid,
            "name": display_name,
            "raw_name": name,
            "cpu_pct": round(cpu, 1),
            "mem_pct": round(mem, 1),
            "category": cat,
            "instance_count": 1,
            "_pids": [pid],
            "_group": group_key,
        })

    if system == "Windows":
        tasklist_out = _run_cmd(["tasklist", "/fo", "csv", "/nh"])
        total_gb = float(_get_memory_info().get("total_gb", 0) or 0)
        for row in csv.reader(tasklist_out.splitlines()):
            if len(row) < 5:
                continue
            image_name = str(row[0] or "").strip()
            if not image_name or image_name.upper().startswith("INFO:"):
                continue
            try:
                pid = int(str(row[1] or "").strip())
            except ValueError:
                continue
            mem_kb = _parse_windows_mem_usage_kb(row[4])
            mem_pct = 0.0
            if total_gb > 0:
                mem_pct = round(100 * (mem_kb / (1024**2)) / max(total_gb, 0.1), 1)
            _register_process(pid, 0.0, mem_pct, os.path.basename(image_name))
    else:
        if system == "Darwin":
            ps_out = _run_cmd(["ps", "-eo", "pid,pcpu,pmem,comm"])
            lines = ps_out.splitlines()[1:]
        else:
            ps_out = _run_cmd(["ps", "-eo", "pid,pcpu,pmem,comm", "--no-headers"])
            lines = ps_out.splitlines()

        for line in lines:
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
            try:
                pid = int(parts[0])
                cpu = float(parts[1])
                mem = float(parts[2])
            except ValueError:
                continue
            cmd = parts[3].strip()
            name = os.path.basename(cmd) if cmd else "unknown"
            _register_process(pid, cpu, mem, name)

    procs.sort(key=lambda p: p["cpu_pct"] + p["mem_pct"], reverse=True)
    return procs[:40]


def _friendly_os_name() -> str:
    system = platform.system()
    if system == "Darwin":
        ver = platform.mac_ver()[0]
        if ver:
            major = int(ver.split(".")[0])
            _names = {
                11: "Big Sur", 12: "Monterey", 13: "Ventura", 14: "Sonoma",
                15: "Sequoia", 26: "Tahoe",
            }
            name = _names.get(major, f"macOS {major}")
            return f"macOS {name} {ver}"
        return f"macOS {platform.release()}"
    elif system == "Linux":
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return f"Linux {platform.release()}"
    return f"{system} {platform.release()}"


def _gather_system_snapshot(target: Path, workspace: Optional[Path] = None) -> Dict[str, Any]:
    cpu = _get_cpu_info()
    mem = _get_memory_info()
    disk = _get_disk_info(target)
    net = _get_network_info()
    gpu = _get_gpu_info()
    net_stats = _get_network_stats(net.get("interface", "en0"))
    procs = _get_processes()
    browser_tabs = _get_browser_tabs()
    monitor_rows = _build_monitor_rows(procs, net.get("type", "Disconnected"))
    ai_usage = _load_ai_usage_summary(workspace)

    hw_nodes = [
        {
            "id": "hw_cpu", "label": "CPU", "kind": "hardware", "category": "hardware",
            "detail": cpu["model"], "usage_pct": cpu["usage_pct"],
            "sub": f"{cpu['cores']} cores \u00b7 {cpu['usage_pct']}%",
        },
        {
            "id": "hw_gpu", "label": "GPU", "kind": "hardware", "category": "hardware",
            "detail": gpu["model"], "usage_pct": gpu["usage_pct"],
            "sub": f"{gpu['metal']} \u00b7 {gpu['usage_pct']}%" if gpu["metal"] else f"{gpu['usage_pct']}%",
        },
        {
            "id": "hw_ram", "label": "RAM", "kind": "hardware", "category": "hardware",
            "detail": f"{mem['used_gb']}/{mem['total_gb']} GB",
            "usage_pct": mem["usage_pct"],
            "sub": f"{mem['usage_pct']}% used",
        },
        {
            "id": "hw_disk", "label": "SSD", "kind": "hardware", "category": "hardware",
            "detail": f"{disk['used_gb']}/{disk['total_gb']} GB",
            "usage_pct": disk["usage_pct"],
            "sub": f"{disk['free_gb']} GB free",
        },
        {
            "id": "hw_net", "label": net["type"], "kind": "hardware", "category": "hardware",
            "detail": f"{net['interface']} \u00b7 {net['ip']}",
            "usage_pct": 50 if net["active"] else 0,
            "sub": f"{net['ip']}" if net["active"] else "Disconnected",
        },
    ]

    proc_nodes = []
    for p in procs:
        cpu_capped = min(p["cpu_pct"], 100.0)
        mem_capped = min(p["mem_pct"], 100.0)
        proc_nodes.append({
            "id": f"proc_{p['_group']}",
            "label": p["name"],
            "kind": "process",
            "category": p["category"],
            "cpu_pct": cpu_capped,
            "mem_pct": mem_capped,
            "pid": p["pid"],
            "instance_count": p.get("instance_count", 1),
            "sub": f"CPU {cpu_capped}% \u00b7 MEM {mem_capped}%",
            "_group": p["_group"],
            "_pids": list(p.get("_pids", [p["pid"]])),
            "raw_name": p.get("raw_name", p["name"]),
            "helper_process": _is_helper_process_name(p.get("raw_name", "")),
        })

    return {
        "timestamp": _utc_now(),
        "hostname": platform.node(),
        "os": _friendly_os_name(),
        "hardware": hw_nodes,
        "processes": proc_nodes,
        "browser_tabs": browser_tabs,
        "cpu": cpu,
        "memory": mem,
        "disk": disk,
        "network": net,
        "gpu": gpu,
        "net_stats": net_stats,
        "monitor_rows": monitor_rows,
        "ai_usage": ai_usage,
    }


def _render_live_html(system_data: Dict[str, Any], file_graph: Dict[str, Any], title: str, api_token: str = "") -> str:
    sys_json = json.dumps(system_data)
    file_json = json.dumps(file_graph)
    cat_colors_json = json.dumps(CATEGORY_COLORS)
    type_colors_json = json.dumps(TYPE_COLORS)
    api_token_json = json.dumps(api_token)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html, body {{ width: 100%; height: 100%; overflow: hidden; background: #020208; font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; color: #ccc; }}
  canvas {{ display: block; width: 100%; height: 100%; cursor: crosshair; }}
  canvas.dragging {{ cursor: grabbing; }}

  .panel-handle {{
    cursor: grab; user-select: none; display: flex; align-items: center;
    justify-content: space-between; margin: -4px -4px 6px -4px; padding: 2px 4px;
    border-radius: 4px;
  }}
  .panel-handle .panel-head {{
    display:flex; align-items:center; gap:6px; min-width:0;
  }}
  .panel-handle .panel-actions {{
    display:flex; align-items:center; gap:4px;
  }}
  .panel-handle:active {{ cursor: grabbing; }}
  .panel-handle .grip {{ color: #334455; font-size: 9px; letter-spacing: 2px; }}
  .panel-min-btn {{
    background: none; border: 1px solid rgba(100,220,255,0.15); color:#668899;
    border-radius: 5px; padding: 0 6px; height: 18px; cursor:pointer; font-size:10px;
    font-family: inherit;
  }}
  .panel-min-btn:hover {{ color:#dbeafe; border-color: rgba(100,220,255,0.3); }}
  .panel-collapsed {{ display: none !important; }}

  #hud {{
    position: fixed; top: 14px; left: 14px; z-index: 10;
    background: rgba(2,2,12,0.92); border: 1px solid rgba(100,220,255,0.12);
    border-radius: 10px; padding: 12px 16px; font-size: 11px; line-height: 1.55;
    backdrop-filter: blur(16px); max-width: 320px;
  }}
  #hud .title {{ color: #00ffcc; font-size: 14px; font-weight: 800; letter-spacing: 1px; }}
  #hud .stat {{ color: #556677; }}
  #hud .val {{ color: #aaccdd; font-weight: 600; }}
  #hud .bar-track {{ display: inline-block; width: 80px; height: 6px; background: rgba(255,255,255,0.06); border-radius: 3px; vertical-align: middle; margin-left: 6px; overflow: hidden; }}
  #hud .bar-fill {{ height: 100%; border-radius: 3px; transition: width 0.6s ease; }}
  #hud .private {{ filter: blur(5px); transition: filter 0.2s; user-select: none; }}
  #hud .private.revealed {{ filter: none; }}
  #hud .eye-btn {{
    background: none; border: none; color: #445566; cursor: pointer;
    font-size: 12px; padding: 0 4px; vertical-align: middle;
  }}
  #hud .eye-btn:hover {{ color: #88aacc; }}
  #hud .net-row {{ font-size: 9px; color: #445566; margin-top: 2px; }}
  #hud .net-row .val {{ font-size: 9px; }}

  #inspector-layer {{
    position: fixed; inset: 0; z-index: 20; pointer-events: none;
  }}
  #inspector, .inspector-card {{
    position: fixed;
    background: rgba(2,2,12,0.95); border: 1px solid rgba(100,220,255,0.2);
    border-radius: 12px; padding: 16px 20px; font-size: 11px; line-height: 1.6;
    backdrop-filter: blur(20px); max-width: 400px;
    box-shadow: 0 0 40px rgba(0,255,200,0.05), inset 0 0 30px rgba(0,0,0,0.3);
  }}
  #inspector {{
    bottom: 16px; right: 16px; display: none;
  }}
  .inspector-card {{
    pointer-events: auto;
    width: min(400px, calc(100vw - 32px));
    min-width: 300px;
    padding-top: 12px;
  }}
  .inspector-card .inspector-node-label {{
    color: #5f7994;
    font-size: 9px;
    margin: 2px 0 8px;
    text-transform: uppercase;
    letter-spacing: 0.7px;
  }}
  #inspector .holo-title, .inspector-card .holo-title {{
    color: #00ffcc; font-size: 15px; font-weight: 800; letter-spacing: 0.5px;
    text-shadow: 0 0 8px rgba(0,255,200,0.3);
  }}
  #inspector .holo-sub, .inspector-card .holo-sub {{ color: #668899; font-size: 10px; margin: 2px 0 8px; }}
  #inspector .holo-stat, .inspector-card .holo-stat {{ color: #8899aa; margin: 2px 0; }}
  #inspector .holo-val, .inspector-card .holo-val {{ color: #ddeeff; font-weight: 600; }}
  #inspector .holo-bar, .inspector-card .holo-bar {{ width: 100%; height: 8px; background: rgba(255,255,255,0.05); border-radius: 4px; margin: 4px 0 6px; overflow: hidden; }}
  #inspector .holo-bar-fill, .inspector-card .holo-bar-fill {{ height: 100%; border-radius: 4px; transition: width 0.4s ease; }}
  #inspector .tag, .inspector-card .tag {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 9px; margin: 2px 3px; font-weight: 700; letter-spacing: 0.3px;
  }}
  #inspector .close, .inspector-card .close {{
    position: absolute; top: 8px; right: 12px; color: #556677; cursor: pointer;
    font-size: 14px; line-height: 1;
  }}
  #inspector .close:hover, .inspector-card .close:hover {{ color: #aabbcc; }}
  .inspector-card .close-btn {{
    background: none;
    border: none;
    color: #556677;
    cursor: pointer;
    font-size: 14px;
    line-height: 1;
    padding: 0;
  }}
  .inspector-card .close-btn:hover {{ color: #aabbcc; }}

  #legend {{
    position: fixed; bottom: 16px; left: 14px; z-index: 10;
    background: rgba(2,2,12,0.88); border: 1px solid rgba(100,220,255,0.08);
    border-radius: 8px; padding: 8px 12px; font-size: 9px; line-height: 1.6;
    backdrop-filter: blur(12px);
  }}
  #legend .row {{ display: flex; align-items: center; gap: 6px; margin: 1px 0; }}
  #legend .dot {{ width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }}
  #legend .hex {{ width: 8px; height: 7px; clip-path: polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%); flex-shrink: 0; }}

  #controls {{
    position: fixed; top: 14px; right: 14px; z-index: 10;
    background: rgba(2,2,12,0.88); border: 1px solid rgba(100,220,255,0.08);
    border-radius: 8px; padding: 8px 10px;
    display: flex; flex-direction: column; gap: 5px;
  }}
  #controls button {{
    background: rgba(10,10,30,0.92); border: 1px solid rgba(100,220,255,0.15);
    color: #8899aa; padding: 5px 11px; border-radius: 5px; cursor: pointer;
    font-size: 9px; font-family: inherit; letter-spacing: 0.3px;
    transition: all 0.15s;
  }}
  #controls button:hover {{ background: rgba(30,50,80,0.9); color: #ccddee; border-color: rgba(100,220,255,0.3); }}
  #controls button.active {{ color: #00ffcc; border-color: rgba(0,255,200,0.4); }}

  #top-center {{
    position: fixed; top: 14px; left: 50%; transform: translateX(-50%); z-index: 11;
    display: flex; align-items: center; gap: 10px; max-width: min(92vw, 980px);
  }}
  #search {{
    position: relative; flex: 0 0 auto;
  }}
  #search input {{
    background: rgba(5,5,18,0.92); border: 1px solid rgba(100,220,255,0.15);
    color: #ddeeff; padding: 7px 16px; border-radius: 18px; width: 300px;
    font-size: 11px; font-family: inherit; outline: none;
    transition: border-color 0.2s;
  }}
  #search input:focus {{ border-color: rgba(0,255,200,0.4); box-shadow: 0 0 12px rgba(0,255,200,0.08); }}
  #search input::placeholder {{ color: #334455; }}
  #panel-dock {{
    display: flex; align-items: center; gap: 6px; flex-wrap: wrap; justify-content: flex-start;
    max-width: min(58vw, 620px);
  }}
  #panel-dock:empty {{ display: none; }}
  .dock-pill {{
    background: rgba(5,5,18,0.92); border: 1px solid rgba(100,220,255,0.15);
    color: #9eb3c8; padding: 4px 8px; border-radius: 12px; font-size: 9px;
    cursor: pointer; backdrop-filter: blur(14px); white-space: nowrap;
  }}
  .dock-pill:hover {{ color:#dbeafe; border-color: rgba(0,255,200,0.3); }}
  #btn-restore-panels {{ display:none; }}

  .surface-card {{
    position: fixed; z-index: 12;
    background: rgba(2,2,12,0.9);
    border: 1px solid rgba(100,220,255,0.12);
    border-radius: 10px;
    padding: 8px 10px;
    backdrop-filter: blur(14px);
    box-shadow: 0 0 24px rgba(0,180,255,0.04);
    color: #9eb3c8;
    font-size: 10px;
    line-height: 1.45;
  }}
  .surface-card .card-title {{ color: #00ffcc; font-weight: 800; letter-spacing: 0.5px; }}
  .surface-card .mini-tabs {{ display:flex; gap:4px; flex-wrap:wrap; margin: 6px 0 8px; }}
  .surface-card .mini-tabs button, .surface-card .card-actions button {{
    background: rgba(10,10,30,0.92);
    border: 1px solid rgba(100,220,255,0.15);
    color: #89a4bf;
    padding: 3px 7px;
    border-radius: 5px;
    cursor: pointer;
    font-size: 9px;
    font-family: inherit;
  }}
  .surface-card .mini-tabs button.active, .surface-card .card-actions button.active {{
    color: #00ffcc; border-color: rgba(0,255,200,0.35);
  }}
  .surface-card .card-actions button.action-pending,
  #node-menu button.action-pending {{
    color: #ffe39a;
    border-color: rgba(255,210,122,0.34);
    background: rgba(54,34,6,0.95);
    cursor: wait;
    opacity: 0.9;
  }}
  .surface-card .card-actions button:disabled,
  #node-menu button:disabled {{
    cursor: wait;
    opacity: 0.72;
  }}
  .surface-card .card-actions select {{
    background: rgba(10,10,30,0.92);
    border: 1px solid rgba(100,220,255,0.15);
    color: #89a4bf;
    padding: 3px 7px;
    border-radius: 5px;
    font-size: 9px;
    font-family: inherit;
    outline: none;
  }}
  .surface-card .usage-row {{
    display:flex; justify-content:space-between; gap:8px;
    padding: 4px 0; border-top: 1px solid rgba(100,220,255,0.06);
    cursor: pointer;
  }}
  .surface-card .usage-row:first-child {{ border-top: none; }}
  .surface-card .usage-row:hover {{ color: #dbeafe; }}
  .surface-card .muted {{ color: #556677; }}
  .surface-card .alert {{ color:#ffb4b4; margin-top: 4px; }}
  .surface-card .good {{ color:#68e2be; }}
  .surface-card details {{ margin: 6px 0; border-top: 1px solid rgba(0,255,204,0.10); padding-top: 6px; }}
  .surface-card details:first-child {{ border-top: none; padding-top: 0; }}
  .surface-card summary {{ cursor: pointer; color:#9eeaf7; font-weight:700; outline:none; }}
  .surface-card .guide-copy {{ color:#9fb4c8; margin-top: 6px; line-height: 1.45; }}
  .surface-card .guide-copy strong {{ color:#d7f8ff; font-weight:700; }}
  #usage-panel {{ top: 210px; right: 14px; width: 280px; }}
  #ai-panel {{ bottom: 150px; right: 14px; width: 280px; }}
  #threat-panel {{ bottom: 14px; right: 14px; width: 320px; }}
  #agent-ops-panel {{ top: 210px; left: 14px; width: 280px; }}
  #task-panel {{ top: 210px; left: 308px; width: 280px; }}
  #activity-panel {{ bottom: 186px; left: 14px; width: 360px; max-height: 240px; overflow: auto; }}
  #alarm-overlay {{
    position: fixed;
    inset: 0;
    pointer-events: none;
    opacity: 0;
    z-index: 6;
    transition: opacity 0.25s ease;
    background:
      radial-gradient(circle at center, rgba(255,80,80,0.08) 0%, rgba(255,80,80,0.03) 35%, rgba(0,0,0,0) 68%),
      linear-gradient(180deg, rgba(255,60,60,0.06), rgba(255,60,60,0));
  }}
  #alarm-overlay.active {{ opacity: 1; }}
  #alarm-overlay.amber {{
    background:
      radial-gradient(circle at center, rgba(255,191,36,0.08) 0%, rgba(255,191,36,0.03) 35%, rgba(0,0,0,0) 68%),
      linear-gradient(180deg, rgba(255,191,36,0.05), rgba(255,191,36,0));
    animation: threatPulseAmber 1.35s ease-in-out infinite;
  }}
  #alarm-overlay.red {{
    background:
      radial-gradient(circle at center, rgba(255,80,80,0.12) 0%, rgba(255,80,80,0.04) 35%, rgba(0,0,0,0) 68%),
      linear-gradient(180deg, rgba(255,80,80,0.07), rgba(255,80,80,0));
    animation: threatPulseRed 1.05s ease-in-out infinite;
  }}
  @keyframes threatPulseAmber {{
    0%, 100% {{ opacity: 0.3; }}
    50% {{ opacity: 0.9; }}
  }}
  @keyframes threatPulseRed {{
    0%, 100% {{ opacity: 0.45; }}
    50% {{ opacity: 1; }}
  }}
  #threat-panel.alarm-live {{
    box-shadow: 0 0 28px rgba(255,84,84,0.18), 0 0 60px rgba(255,84,84,0.08);
    border-color: rgba(255,108,108,0.34);
  }}
  #threat-panel.alarm-live.amber {{
    box-shadow: 0 0 24px rgba(251,191,36,0.18), 0 0 52px rgba(251,191,36,0.08);
    border-color: rgba(251,191,36,0.34);
  }}
  #node-menu {{
    position: fixed; display: none; z-index: 50;
    background: rgba(2,2,12,0.96);
    border: 1px solid rgba(100,220,255,0.16);
    border-radius: 8px; padding: 6px;
    backdrop-filter: blur(16px);
    min-width: 130px;
    box-shadow: 0 0 30px rgba(0,180,255,0.06);
  }}
  #node-menu button {{
    width: 100%; text-align: left; margin: 2px 0;
    background: rgba(10,10,30,0.92); border: 1px solid rgba(100,220,255,0.12);
    color: #9eb3c8; padding: 5px 8px; border-radius: 5px;
    cursor: pointer; font-size: 10px; font-family: inherit;
  }}
  #node-menu button:hover {{ color: #dbeafe; border-color: rgba(0,255,200,0.25); }}
</style>
</head>
<body>

<div id="hud" data-panel="hud">
  <div class="panel-handle" data-drag="hud"><span class="panel-head"><span class="title">PARAD0X COMMAND</span></span> <span class="panel-actions"><span class="grip">&equiv;</span></span></div>
  <div><button class="eye-btn" id="privacy-toggle" onclick="togglePrivacy()" title="Toggle private info">&#x1F441;</button>
    <span class="stat">Host:</span> <span class="val private" id="hud-host">-</span>
    &middot; <span class="stat">OS:</span> <span class="val private" id="hud-os">-</span>
  </div>
  <div>
    <span class="stat">CPU:</span> <span class="val" id="hud-cpu">-</span>
    <span class="bar-track"><span class="bar-fill" id="hud-cpu-bar" style="width:0%;background:#00ffcc"></span></span>
  </div>
  <div>
    <span class="stat">GPU:</span> <span class="val" id="hud-gpu">-</span>
    <span class="bar-track"><span class="bar-fill" id="hud-gpu-bar" style="width:0%;background:#a855f7"></span></span>
  </div>
  <div>
    <span class="stat">RAM:</span> <span class="val" id="hud-ram">-</span>
    <span class="bar-track"><span class="bar-fill" id="hud-ram-bar" style="width:0%;background:#818cf8"></span></span>
  </div>
  <div>
    <span class="stat">SSD:</span> <span class="val" id="hud-disk">-</span>
    <span class="bar-track"><span class="bar-fill" id="hud-disk-bar" style="width:0%;background:#fbbf24"></span></span>
  </div>
  <div><span class="stat">Net:</span> <span class="val private" id="hud-net">-</span></div>
  <div class="net-row">
    <span class="stat">&darr;</span> <span class="val" id="hud-net-in">-</span>
    <span class="stat">&uarr;</span> <span class="val" id="hud-net-out">-</span>
    <span class="stat">speed:</span> <span class="val" id="hud-net-speed">-</span>
  </div>
  <div class="net-row">
    <span class="stat">pkts&darr;</span> <span class="val" id="hud-net-pkts-in">-</span>
    <span class="stat">pkts&uarr;</span> <span class="val" id="hud-net-pkts-out">-</span>
  </div>
  <div><span class="stat">Procs:</span> <span class="val" id="hud-procs">-</span> &middot; <span class="stat">Files:</span> <span class="val" id="hud-files">-</span></div>
  <div style="margin-top:5px;color:#334455;font-size:8px;">Click = inspect &middot; Empty = reset &middot; Scroll = zoom &middot; Drag panels</div>
</div>

<div id="inspector-layer"></div>

<div id="legend" data-panel="legend">
  <div class="panel-handle" data-drag="legend"><span class="panel-head"><span style="color:#556677;font-weight:700;">CORE</span></span> <span class="panel-actions"><span class="grip">&equiv;</span></span></div>
  <div class="row"><div class="hex" style="background:#fbbf24"></div><span>Hardware</span></div>
  <div style="color:#556677;font-weight:700;margin:4px 0 2px;">APPS</div>
  <div class="row"><div class="dot" style="background:#7B68EE;box-shadow:0 0 5px #7B68EE"></div><span>Cursor</span></div>
  <div class="row"><div class="dot" style="background:#00D4AA;box-shadow:0 0 5px #00D4AA"></div><span>Codex</span></div>
  <div class="row"><div class="dot" style="background:#0088FF;box-shadow:0 0 5px #0088FF"></div><span>Safari</span></div>
  <div class="row"><div class="dot" style="background:#25D366;box-shadow:0 0 5px #25D366"></div><span>WhatsApp</span></div>
  <div class="row"><div class="dot" style="background:#0088cc;box-shadow:0 0 5px #0088cc"></div><span>Telegram</span></div>
  <div class="row"><div class="dot" style="background:#5865F2;box-shadow:0 0 5px #5865F2"></div><span>Discord</span></div>
  <div style="color:#556677;font-weight:700;margin:4px 0 2px;">PROCESSES</div>
  <div class="row"><div class="dot" style="background:#00ffcc;box-shadow:0 0 4px #00ffcc"></div><span>Agent</span></div>
  <div class="row"><div class="dot" style="background:#a855f7"></div><span>IDE</span></div>
  <div class="row"><div class="dot" style="background:#4285f4"></div><span>Browser</span></div>
  <div class="row"><div class="dot" style="background:#22c55e"></div><span>Terminal</span></div>
  <div class="row"><div class="dot" style="background:#e38c00"></div><span>Database</span></div>
  <div class="row"><div class="dot" style="background:#6b7280"></div><span>System</span></div>
  <div style="color:#556677;font-weight:700;margin:4px 0 2px;">FILES</div>
  <div class="row"><div class="dot" style="background:#ff4444;box-shadow:0 0 4px #ff4444"></div><span>Sensitive</span></div>
  <div class="row"><div class="dot" style="background:#00ff88;box-shadow:0 0 4px #00ff88"></div><span>Vault</span></div>
  <div class="row"><div class="dot" style="background:#3572A5"></div><span>Code</span></div>
  <div class="row"><div class="dot" style="background:#aaaaaa"></div><span>Docs</span></div>
</div>

<div id="top-center">
  <div id="search"><input type="text" placeholder="Search system..." id="search-input"></div>
  <div id="panel-dock"></div>
</div>


<div id="controls" data-panel="controls">
  <div class="panel-handle" data-drag="controls"><span class="panel-head"><span style="color:#556677;font-size:9px;">CONTROLS</span></span> <span class="panel-actions"><span class="grip">&equiv;</span></span></div>
  <button onclick="resetView()">Reset View</button>
  <button onclick="toggleLayer('apps')" id="btn-apps" class="active">Apps</button>
  <button onclick="toggleLayer('files')" id="btn-files" class="active">Files</button>
  <button onclick="toggleLayer('procs')" id="btn-procs" class="active">Processes</button>
  <button onclick="toggleLayer('hw')" id="btn-hw" class="active">Hardware</button>
  <button onclick="highlightAgents()">Agents Only</button>
  <button onclick="reLayout()">Re-Layout</button>
  <button id="btn-restore-panels" onclick="restoreAllPanels()">Restore Panels</button>
</div>

<div id="usage-panel" class="surface-card" data-panel="usage">
  <div class="panel-handle" data-drag="usage"><span class="panel-head"><span class="card-title">USAGE SURFACE</span></span><span class="panel-actions"><button class="panel-min-btn" onclick="togglePanelCollapsed('usage');event.stopPropagation();" title="Minimize">_</button><span class="grip">&equiv;</span></span></div>
  <div class="mini-tabs">
    <button id="usage-sort-cpu" class="active" onclick="setUsageSort('cpu')">CPU</button>
    <button id="usage-sort-ram" onclick="setUsageSort('ram')">RAM</button>
    <button id="usage-sort-gpu" onclick="setUsageSort('gpu')">GPU</button>
    <button id="usage-sort-ssd" onclick="setUsageSort('ssd')">SSD</button>
    <button id="usage-sort-net" onclick="setUsageSort('net')">NET</button>
  </div>
  <div id="usage-content" class="muted">Waiting for live stats...</div>
</div>

<div id="agent-ops-panel" class="surface-card" data-panel="agent-ops">
  <div class="panel-handle" data-drag="agent-ops"><span class="panel-head"><span class="card-title">AGENT OPS</span></span><span class="panel-actions"><button class="panel-min-btn" onclick="togglePanelCollapsed('agent-ops');event.stopPropagation();" title="Minimize">_</button><span class="grip">&equiv;</span></span></div>
  <div id="agent-ops-content" class="muted">Waiting for agent state...</div>
</div>

<div id="task-panel" class="surface-card" data-panel="task">
  <div class="panel-handle" data-drag="task"><span class="panel-head"><span class="card-title">TASK PROGRESS</span></span><span class="panel-actions"><button class="panel-min-btn" onclick="togglePanelCollapsed('task');event.stopPropagation();" title="Minimize">_</button><span class="grip">&equiv;</span></span></div>
  <div id="task-content" class="muted">Waiting for task state...</div>
</div>

<div id="activity-panel" class="surface-card" data-panel="activity">
  <div class="panel-handle" data-drag="activity"><span class="panel-head"><span class="card-title">RECENT ACTIVITY</span></span><span class="panel-actions"><button class="panel-min-btn" onclick="togglePanelCollapsed('activity');event.stopPropagation();" title="Minimize">_</button><span class="grip">&equiv;</span></span></div>
  <div id="activity-content" class="muted">Waiting for recent activity...</div>
</div>

<div id="ai-panel" class="surface-card" data-panel="ai">
  <div class="panel-handle" data-drag="ai"><span class="panel-head"><span class="card-title">AI LEDGER</span></span><span class="panel-actions"><button class="panel-min-btn" onclick="togglePanelCollapsed('ai');event.stopPropagation();" title="Minimize">_</button><span class="grip">&equiv;</span></span></div>
  <div id="ai-content" class="muted">Waiting for token data...</div>
</div>

<div id="threat-panel" class="surface-card" data-panel="threat">
  <div class="panel-handle" data-drag="threat"><span class="panel-head"><span class="card-title">THREAT MONITOR</span></span><span class="panel-actions"><button class="panel-min-btn" onclick="togglePanelCollapsed('threat');event.stopPropagation();" title="Minimize">_</button><span class="grip">&equiv;</span></span></div>
  <div class="card-actions" style="display:flex;gap:6px; margin: 4px 0 8px;">
    <button onclick="panicAction('write')" id="panic-halt-btn">WRITE HALT</button>
    <button onclick="panicAction('verify')" id="panic-verify-btn">VERIFY HALT</button>
    <button onclick="panicAction('term-agents')" id="panic-term-agents-btn">HALT AGENTS</button>
    <button onclick="panicAction('kill-agents')" id="panic-kill-agents-btn">KILL AGENTS HARD</button>
  </div>
  <div class="card-actions" style="display:flex;gap:6px; margin: 0 0 8px; align-items:center; flex-wrap:wrap;">
    <button onclick="panicAction('network-off')" id="panic-network-off-btn">CUT NETWORK</button>
    <button onclick="panicAction('network-on')" id="panic-network-on-btn">RESTORE NETWORK</button>
  </div>
  <div class="card-actions" style="display:flex;gap:6px; margin: 0 0 8px; align-items:center; flex-wrap:wrap;">
    <button onclick="toggleAlarmSound()" id="alarm-sound-toggle">SOUND ON</button>
    <select id="alarm-sound-select" onchange="setAlarmTone(this.value)">
      <option value="beacon">Beacon</option>
      <option value="siren">Siren</option>
      <option value="chime">Chime</option>
    </select>
    <button onclick="acknowledgeAlarm()" id="alarm-ack-btn">ACK / RESET</button>
  </div>
  <div id="threat-content" class="muted">Waiting for threat status...</div>
</div>

<div id="ops-panel" class="surface-card" data-panel="ops">
  <div class="panel-handle" data-drag="ops"><span class="panel-head"><span class="card-title">OPS LOG</span></span><span class="panel-actions"><button class="panel-min-btn" onclick="togglePanelCollapsed('ops');event.stopPropagation();" title="Minimize">_</button><span class="grip">&equiv;</span></span></div>
  <div id="ops-content" class="muted">No operator actions yet.</div>
</div>

<div id="guide-panel" class="surface-card" data-panel="guide">
  <div class="panel-handle" data-drag="guide"><span class="panel-head"><span class="card-title">COMMAND GUIDE</span></span><span class="panel-actions"><button class="panel-min-btn" onclick="togglePanelCollapsed('guide');event.stopPropagation();" title="Minimize">_</button><span class="grip">&equiv;</span></span></div>
  <div class="guide-copy">
    Quick legend for what this shell actually does. Short explanation first, deeper operator note if you expand it.
  </div>
  <details open>
    <summary>Threat controls</summary>
    <div class="guide-copy">
      <strong>WRITE HALT</strong> writes the guarded halt signal into the workspace so attached safety tooling can stop new work.<br>
      <strong>VERIFY HALT</strong> checks whether that halt signal is present and valid.<br>
      <strong>HALT AGENTS</strong> asks detected agent families to stop cleanly.<br>
      <strong>KILL AGENTS HARD</strong> kills the visible agent process tree and then does a survivor pass.<br>
      <strong>CUT NETWORK</strong> disables the active network interface.<br>
      <strong>RESTORE NETWORK</strong> brings that interface back.
    </div>
  </details>
  <details>
    <summary>System cards</summary>
    <div class="guide-copy">
      <strong>Usage Surface</strong> shows the hottest local workloads by CPU, RAM, GPU, SSD, or network.<br>
      <strong>AI Ledger</strong> separates local telemetry, billing interpretation, and provider-plan truth so estimates do not masquerade as bills.<br>
      <strong>Threat Monitor</strong> collects halt state, risky actions, sensitive files, heartbeat state, and spend signals into one alarm surface.
    </div>
  </details>
  <details>
    <summary>Nodes and actions</summary>
    <div class="guide-copy">
      Click a node to inspect it. Right-click process or app nodes for operator actions.<br>
      App nodes are larger than normal processes so they are easier to spot.<br>
      Browser tab nodes inherit from their parent browser and show estimated per-tab resource share.
    </div>
  </details>
  <details>
    <summary>Privacy and telemetry</summary>
    <div class="guide-copy">
      Privacy mode masks local home paths, localhost URLs, and internal machine details in visible cards.<br>
      Local telemetry is exact for what the shell can see. Provider billing is only exact when a real provider adapter or workspace ledger is available.
    </div>
  </details>
</div>

<div id="node-menu"></div>
<div id="alarm-overlay"></div>

<canvas id="galaxy"></canvas>

<script>
const API_TOKEN = {api_token_json};
const sysData = {sys_json};
const fileGraph = {file_json};
const CAT_COLORS = {cat_colors_json};
const TYPE_COLORS = {type_colors_json};
const canvas = document.getElementById("galaxy");
const ctx = canvas.getContext("2d");
const inspectorLayer = document.getElementById("inspector-layer");
const usageContent = document.getElementById("usage-content");
const agentOpsContent = document.getElementById("agent-ops-content");
const taskContent = document.getElementById("task-content");
const activityContent = document.getElementById("activity-content");
const aiContent = document.getElementById("ai-content");
const threatContent = document.getElementById("threat-content");
const opsContent = document.getElementById("ops-content");
const nodeMenu = document.getElementById("node-menu");
const alarmOverlay = document.getElementById("alarm-overlay");
const threatPanelEl = document.getElementById("threat-panel");
const pendingActionKeys = new Set();
const pendingPanicActions = new Set();

// --- Build unified node/edge model ---
const allNodes = [];
const allEdges = [];
const nodeMap = {{}};
const edgeStrengthMap = {{}};
const MAX_SUBPROCESS_SATELLITES = 6;
const layers = {{ hw: true, apps: true, procs: true, files: true }};
let selectedNode = null;
let highlightMode = null;
let camX = 0, camY = 0, camZoom = 0.8;
let frameTime = 0;
const openInspectors = new Map();
let inspectorPanelZ = 24;

function W() {{ return canvas.clientWidth || 1200; }}
function H() {{ return canvas.clientHeight || 720; }}
function edgeKey(e) {{ return e.source + ">" + e.target; }}

function followerNodeIds(nodeId) {{
  return allNodes
    .filter(n => n && (n.parentProcessId === nodeId || n.parentId === nodeId))
    .map(n => n.id);
}}

function removeNodeState(nodeId) {{
  if (!nodeId || !nodeMap[nodeId]) return;
  followerNodeIds(nodeId).forEach((childId) => {{
    if (childId !== nodeId) removeNodeState(childId);
  }});
  for (let i = allEdges.length - 1; i >= 0; i--) {{
    const edge = allEdges[i];
    if (!edge) continue;
    if (edge.source === nodeId || edge.target === nodeId) {{
      delete edgeStrengthMap[edgeKey(edge)];
      allEdges.splice(i, 1);
    }}
  }}
  const idx = allNodes.findIndex(n => n && n.id === nodeId);
  if (idx >= 0) allNodes.splice(idx, 1);
  closeInspector(nodeId);
  delete nodeMap[nodeId];
}}

function followerCountForNode(nodeId) {{
  return allNodes.filter(n => n && !n.hidden && n.parentProcessId === nodeId).length;
}}

function setAttachedFixed(nodeId, fixed) {{
  allNodes.forEach((n) => {{
    if (n && n.parentProcessId === nodeId && n.isSubprocess) {{
      n.fixed = fixed;
    }}
  }});
}}

function moveAttachedNodes(nodeId, worldDx, worldDy) {{
  allNodes.forEach((n) => {{
    if (!n || (n.parentProcessId !== nodeId && n.parentId !== nodeId)) return;
    n.x += worldDx;
    n.y += worldDy;
    if (typeof n.homeX === "number") n.homeX += worldDx;
    if (typeof n.homeY === "number") n.homeY += worldDy;
    if (typeof n.groupX === "number") n.groupX += worldDx;
    if (typeof n.groupY === "number") n.groupY += worldDy;
  }});
}}

function ensureChildLink(sourceId, targetId, strength) {{
  const existing = allEdges.find((e) => e && e.kind === "child-link" && e.source === sourceId && e.target === targetId);
  if (existing) {{
    existing.strength = strength;
    edgeStrengthMap[edgeKey(existing)] = strength;
    return existing;
  }}
  const edge = {{ source: sourceId, target: targetId, kind: "child-link", strength }};
  allEdges.push(edge);
  edgeStrengthMap[edgeKey(edge)] = strength;
  return edge;
}}

function subprocessSatelliteSpecs(proc) {{
  const rootId = proc.id || ("proc_" + proc._group);
  const rootPid = Number(proc.pid || 0);
  const allPids = Array.isArray(proc._pids) ? proc._pids.map(v => Number(v || 0)).filter(Boolean) : [];
  const childPids = allPids.filter((pid) => pid !== rootPid);
  const targetCount = Math.max(0, Math.min(MAX_SUBPROCESS_SATELLITES, Number(proc.instance_count || allPids.length || 1) - 1));
  const specs = childPids.slice(0, targetCount).map((pid, idx) => ({{
    id: `subproc_${{rootId}}_${{pid}}`,
    pid,
    label: `${{proc.label || proc.name || "process"}} child ${{idx + 1}}`,
  }}));
  while (specs.length < targetCount) {{
    const idx = specs.length + 1;
    specs.push({{
      id: `subproc_${{rootId}}_ghost_${{idx}}`,
      pid: null,
      label: `${{proc.label || proc.name || "process"}} child ${{idx}}`,
    }});
  }}
  return specs;
}}

function syncSubprocessNodes(processRows) {{
  const rows = Array.isArray(processRows) ? processRows : [];
  const liveChildIds = new Set();
  rows.forEach((proc) => {{
    const parentId = proc.id || ("proc_" + proc._group);
    const parent = nodeMap[parentId];
    if (!parent) return;
    const specs = subprocessSatelliteSpecs(proc);
    const total = specs.length;
    specs.forEach((spec, idx) => {{
      liveChildIds.add(spec.id);
      let node = nodeMap[spec.id];
      const orbitAngle = ((idx / Math.max(total, 1)) * Math.PI * 2) + (((Number(proc.pid || 0) % 13) || 0) * 0.11);
      const orbitRadius = Math.max(16, (parent.nodeRadius || 8) + 12 + (idx % 3) * 4 + total * 0.8);
      const orbitTilt = 0.74 + (idx % 2) * 0.1;
      const shareDivisor = Math.max(2, Number(proc.instance_count || total + 1));
      const cpuShare = Number((Math.max(0, Number(proc.cpu_pct || 0)) / shareDivisor).toFixed(1));
      const memShare = Number((Math.max(0, Number(proc.mem_pct || 0)) / shareDivisor).toFixed(1));
      const targetX = parent.x + Math.cos(orbitAngle) * orbitRadius;
      const targetY = parent.y + Math.sin(orbitAngle) * orbitRadius * orbitTilt;
      if (!node) {{
        node = {{
          id: spec.id,
          label: spec.label,
          kind: "process",
          category: proc.category || parent.category || "process",
          layer: "procs",
          ring: parent.ring,
          parentProcessId: parentId,
          isSubprocess: true,
          appColor: parent.appColor || null,
          x: targetX,
          y: targetY,
          vx: 0,
          vy: 0,
          fixed: false,
          hidden: false,
          highlight: false,
          searchMatch: false,
          nodeRadius: Math.max(2.4, (parent.nodeRadius || 5) * 0.42),
        }};
        allNodes.push(node);
        nodeMap[spec.id] = node;
        ensureChildLink(parentId, spec.id, Math.max(0.6, cpuShare + memShare));
      }}
      node.hidden = false;
      node.pid = spec.pid;
      node.label = spec.label;
      node.parentProcessId = parentId;
      node.category = proc.category || parent.category || node.category;
      node.appColor = parent.appColor || node.appColor || null;
      node.cpu_pct = cpuShare;
      node.mem_pct = memShare;
      node.instance_count = 1;
      node.orbitAngle = orbitAngle;
      node.orbitRadius = orbitRadius;
      node.orbitTilt = orbitTilt;
      node.orbitSpeed = 0.35 + (idx % 4) * 0.04;
      node.nodeRadius = Math.max(2.4, (parent.nodeRadius || 5) * 0.42);
      node.sub = `Orbiting ${{parent.label || parent.id}} · est CPU ${{cpuShare}}% · est MEM ${{memShare}}%`;

      ensureChildLink(parentId, spec.id, Math.max(0.6, cpuShare + memShare));
    }});
  }});

  const staleIds = [];
  allNodes.forEach((n) => {{
    if (n && n.isSubprocess && (!liveChildIds.has(n.id) || !nodeMap[n.parentProcessId])) {{
      staleIds.push(n.id);
    }}
  }});
  staleIds.forEach(removeNodeState);
}}

function clusterAppFollowers() {{
  const appNodes = allNodes.filter((n) => n && n.isApp && !n.hidden);
  const byKey = {{}};
  appNodes.forEach((n) => {{
    const key = String(n.appKey || "").trim();
    if (!key) return;
    if (!byKey[key]) byKey[key] = [];
    byKey[key].push(n);
  }});

  appNodes.forEach((n) => {{
    n.isAppFollower = false;
    n.parentProcessId = null;
  }});

  Object.values(byKey).forEach((group) => {{
    if (!Array.isArray(group) || group.length <= 1) return;
    group.sort((a, b) => {{
      const helperDelta = Number(Boolean(a.helper_process)) - Number(Boolean(b.helper_process));
      if (helperDelta !== 0) return helperDelta;
      const rawA = String(a.raw_name || a.label || "").toLowerCase();
      const rawB = String(b.raw_name || b.label || "").toLowerCase();
      const exactA = rawA === String(a.label || "").toLowerCase() ? 1 : 0;
      const exactB = rawB === String(b.label || "").toLowerCase() ? 1 : 0;
      if (exactA !== exactB) return exactB - exactA;
      return appPriorityScore(b) - appPriorityScore(a);
    }});
    const root = group[0];
    group.slice(1).forEach((node, idx) => {{
      const orbitAngle = (-Math.PI / 2) + (idx / Math.max(group.length - 1, 1)) * Math.PI * 2;
      const orbitRadius = Math.max(20, (root.nodeRadius || 8) + 16 + idx * 7);
      const orbitTilt = 0.74 + (idx % 2) * 0.08;
      node.parentProcessId = root.id;
      node.isAppFollower = true;
      node.orbitAngle = orbitAngle;
      node.orbitRadius = orbitRadius;
      node.orbitTilt = orbitTilt;
      node.orbitSpeed = 0.22 + (idx % 4) * 0.03;
      node.nodeRadius = Math.max(4.2, Math.min((root.nodeRadius || 7) * 0.72, 8.4));
      node.x = root.x + Math.cos(orbitAngle) * orbitRadius;
      node.y = root.y + Math.sin(orbitAngle) * orbitRadius * orbitTilt;
      ensureChildLink(root.id, node.id, Math.max(0.8, (node.cpu_pct || 0) + (node.mem_pct || 0)));
    }});
  }});

  for (let i = allEdges.length - 1; i >= 0; i--) {{
    const edge = allEdges[i];
    if (!edge || edge.kind !== "child-link") continue;
    const target = nodeMap[edge.target];
    if (!target || target.parentProcessId !== edge.source) {{
      delete edgeStrengthMap[edgeKey(edge)];
      allEdges.splice(i, 1);
    }}
  }}
}}

// --- Known Apps — branded colors, dedicated ring ---
const APP_REGISTRY = {{
  "cursor":    {{ color: "#7B68EE", glow: "rgba(123,104,238,0.4)", icon: "\u25C8" }},
  "codex":     {{ color: "#00D4AA", glow: "rgba(0,212,170,0.4)",  icon: "\u25C6" }},
  "safari":    {{ color: "#0088FF", glow: "rgba(0,136,255,0.4)",  icon: "\u25CE" }},
  "whatsapp":  {{ color: "#25D366", glow: "rgba(37,211,102,0.4)", icon: "\u25CF" }},
  "telegram":  {{ color: "#0088CC", glow: "rgba(0,136,204,0.4)",  icon: "\u25B6" }},
  "discord":   {{ color: "#5865F2", glow: "rgba(88,101,242,0.4)", icon: "\u25C9" }},
  "chrome":    {{ color: "#4285F4", glow: "rgba(66,133,244,0.4)", icon: "\u25CB" }},
  "edge":      {{ color: "#0EA5E9", glow: "rgba(14,165,233,0.4)", icon: "\u25D0" }},
  "firefox":   {{ color: "#FF7139", glow: "rgba(255,113,57,0.4)", icon: "\u25CB" }},
  "slack":     {{ color: "#4A154B", glow: "rgba(74,21,75,0.4)",   icon: "\u25A0" }},
  "spotify":   {{ color: "#1DB954", glow: "rgba(29,185,84,0.4)",  icon: "\u266B" }},
  "vscode":    {{ color: "#007ACC", glow: "rgba(0,122,204,0.4)",  icon: "\u25C8" }},
  "xcode":     {{ color: "#147EFB", glow: "rgba(20,126,251,0.4)", icon: "\u2699" }},
  "iterm":     {{ color: "#22c55e", glow: "rgba(34,197,94,0.4)",  icon: "\u25A4" }},
  "terminal":  {{ color: "#22c55e", glow: "rgba(34,197,94,0.4)",  icon: "\u25A4" }},
  "finder":    {{ color: "#3B99FC", glow: "rgba(59,153,252,0.4)", icon: "\u25A3" }},
  "explorer":  {{ color: "#60A5FA", glow: "rgba(96,165,250,0.4)", icon: "\u25A3" }},
}};

function matchApp(label) {{
  const l = (label || "").toLowerCase();
  for (const [key, val] of Object.entries(APP_REGISTRY)) {{
    if (l.includes(key)) return {{ key, ...val }};
  }}
  return null;
}}

function appFamily(key) {{
  if (["codex", "cursor", "vscode", "xcode", "terminal", "iterm"].includes(key)) return "build";
  if (["safari", "chrome", "firefox", "edge"].includes(key)) return "browse";
  if (["telegram", "whatsapp", "discord", "slack"].includes(key)) return "comms";
  if (["spotify"].includes(key)) return "media";
  if (["finder", "explorer"].includes(key)) return "system";
  return "other";
}}

function browserTabNodeId(tab) {{
  return String((tab && tab.id) || ("browser_tab_" + (tab && tab.window || 0) + "_" + (tab && tab.index || 0)));
}}

function browserDisplayName(key) {{
  const k = String(key || "").toLowerCase();
  return {{
    safari: "Safari",
    chrome: "Google Chrome",
    edge: "Edge",
    firefox: "Firefox",
  }}[k] || (k ? (k.charAt(0).toUpperCase() + k.slice(1)) : "Browser");
}}

function browserTabLayout(parent, idx, count, active) {{
  const safeCount = Math.max(count, 1);
  const angle = safeCount <= 1
    ? (-Math.PI / 2)
    : (-Math.PI / 2) + (idx / safeCount) * Math.PI * 2;
  const radius = 84 + Math.min(48, safeCount * 9);
  return {{
    x: parent.x + Math.cos(angle) * radius,
    y: parent.y + Math.sin(angle) * radius,
    angle,
  }};
}}

function syncBrowserTabs(browserTabs) {{
  const tabs = Array.isArray(browserTabs) ? browserTabs : [];
  for (let i = allEdges.length - 1; i >= 0; i--) {{
    if (allEdges[i] && allEdges[i].kind === "tab-link") {{
      delete edgeStrengthMap[edgeKey(allEdges[i])];
      allEdges.splice(i, 1);
    }}
  }}
  const existingTabs = allNodes.filter(n => n.kind === "browser_tab");
  if (!tabs.length) {{
    existingTabs.forEach(n => {{ removeNodeState(n.id); }});
    return;
  }}

  const sortedTabs = tabs.slice().sort((a, b) => Number(Boolean(b.active)) - Number(Boolean(a.active)));
  const visibleTabs = sortedTabs.slice(0, 12);
  const visibleMap = new Set(visibleTabs.map(t => browserTabNodeId(t)));
  const tabWeights = visibleTabs.map(tab => Boolean(tab.active) ? 1.9 : 1.0);
  const totalWeight = tabWeights.reduce((acc, n) => acc + n, 0) || 1;
  visibleTabs.forEach((tab, idx) => {{
    const browserKey = String(tab.browser || "safari").toLowerCase();
    const browserNode = allNodes.find(n => n.isApp && n.appKey === browserKey && !n.hidden);
    if (!browserNode) return;
    const id = browserTabNodeId(tab);
    const active = Boolean(tab.active);
    const host = String(tab.host || "").trim();
    const title = String(tab.title || "").trim();
    const displayHost = host.replace(/^www\./, "");
    const fallbackLabel = displayHost || title || ("tab " + (idx + 1));
    const label = String(fallbackLabel).trim().slice(0, 18);
    const traffic = Math.max(0.35, active ? 1.0 : 0.55);
    const share = tabWeights[idx] / totalWeight;
    const pos = browserTabLayout(browserNode, idx, visibleTabs.length, active);
    let node = nodeMap[id];
    if (!node) {{
      node = {{
        id,
        label,
        kind: "browser_tab",
        category: "browser_tab",
        layer: "apps",
        ring: 0.55,
        fixed: true,
        hidden: false,
        highlight: false,
        searchMatch: false,
        x: pos.x,
        y: pos.y,
        vx: 0,
        vy: 0,
        nodeRadius: active ? 7.4 : 5.8,
        browser: browserKey,
        appKey: browserKey,
      }};
      allNodes.push(node);
      nodeMap[id] = node;
    }}
    node.hidden = false;
    node.label = label;
    node.title = title || label;
    node.host = host;
    node.url = String(tab.url || "");
    node.tabActive = active;
    node.browser = browserKey;
    node.trafficScore = traffic;
    node.cpu_pct = Number(((browserNode.cpu_pct || 0) * share).toFixed(1));
    node.mem_pct = Number(((browserNode.mem_pct || 0) * share).toFixed(1));
    node.usageShare = share;
    node.parentId = browserNode.id;
    node.window = tab.window;
    node.index = tab.index;
    node.fixed = true;
    node.nodeRadius = active ? 8.2 : 6.4;
    node.x = pos.x;
    node.y = pos.y;
    node.vx = 0;
    node.vy = 0;
    node.sub = (host || node.url || "") + " · CPU " + node.cpu_pct.toFixed(1) + "% · MEM " + node.mem_pct.toFixed(1) + "%";
    allEdges.push({{ source: browserNode.id, target: id, kind: "tab-link", strength: 8 * traffic }});
  }});

  existingTabs.forEach(node => {{
    if (!visibleMap.has(node.id)) removeNodeState(node.id);
  }});
}}

// Hardware nodes — center hexagons
const hwIcons = {{ CPU: "\u2699", GPU: "\u25B2", RAM: "\u25A6", SSD: "\u25C9", WiFi: "\u25CE", Ethernet: "\u25CE" }};
sysData.hardware.forEach((hw, i) => {{
  const angle = (i / sysData.hardware.length) * Math.PI * 2 - Math.PI / 2;
  const r = 50;
  const n = {{
    ...hw, x: Math.cos(angle) * r, y: Math.sin(angle) * r,
    vx: 0, vy: 0, fixed: true, hidden: false, highlight: false, searchMatch: false,
    ring: 0, nodeRadius: 18, layer: "hw",
    icon: hwIcons[hw.label] || "\u25CB",
  }};
  allNodes.push(n);
  nodeMap[n.id] = n;
}});

// App + Process nodes — apps orbit an app core when grouped and explode into a shaped cluster when expanded
const APP_HUB_ID = "app_core";
const APP_HUB_HOME = {{ x: 315, y: 268 }};
const appSlotById = {{}};
const appRows = sysData.processes
  .filter(p => matchApp(p.label || p._group))
  .slice()
  .sort((a, b) => {{
    function score(proc) {{
      const app = matchApp(proc.label || proc._group);
      const cpu = Math.min(proc.cpu_pct || 0, 100);
      const mem = Math.min(proc.mem_pct || 0, 100);
      const key = app ? app.key : "";
      const bonus = {{
        codex: 18, cursor: 16, safari: 12, chrome: 12, finder: 10,
        terminal: 9, iterm: 9, telegram: 8, whatsapp: 8, discord: 8,
        spotify: 6, slack: 6, xcode: 10, vscode: 10, firefox: 7,
      }}[key] || 0;
      return cpu * 0.9 + mem * 6 + bonus;
    }}
    return score(b) - score(a);
  }});
const idleAppSlotById = {{}};
const activeAppIds = [];
appRows.forEach((p, idx) => {{
  const cpu = Math.min(p.cpu_pct || 0, 100);
  const mem = Math.min(p.mem_pct || 0, 100);
  const activeSignal = cpu >= 2 || mem >= 2.2 || (cpu + mem * 8) >= 14;
  if (activeSignal || (activeAppIds.length < Math.min(5, appRows.length) && (cpu + mem * 5) >= 1.5)) {{
    activeAppIds.push(p.id);
  }}
}});
const activeAppSet = new Set(activeAppIds.slice(0, 8));
appRows.forEach((p, idx) => {{
  if (activeAppSet.has(p.id)) appSlotById[p.id] = Object.keys(appSlotById).length;
}});
const appCount = Object.keys(appSlotById).length || 1;
let _idleCounter = 0;
appRows.forEach((p) => {{
  if (!activeAppSet.has(p.id)) {{
    idleAppSlotById[p.id] = _idleCounter++;
  }}
}});
const APP_FAMILY_ORDER = ["build", "browse", "comms", "media", "system", "other"];
const APP_FAMILY_CENTER = {{
  build: Math.PI * 1.18,
  browse: Math.PI * 1.56,
  comms: Math.PI * 1.88,
  media: Math.PI * 0.18,
  system: Math.PI * 0.58,
  other: Math.PI * 0.92,
}};
const appFamilyCounts = {{}};
const appFamilyIndexById = {{}};
appRows
  .filter(p => activeAppSet.has(p.id))
  .forEach((p) => {{
    const app = matchApp(p.label || p._group);
    const family = appFamily(app ? app.key : "");
    const idx = appFamilyCounts[family] || 0;
    appFamilyIndexById[p.id] = idx;
    appFamilyCounts[family] = idx + 1;
  }});
let appHubNode = null;
if (Object.keys(appSlotById).length > 0) {{
  appHubNode = {{
    id: APP_HUB_ID,
    label: "APPS",
    kind: "app_hub",
    category: "apps",
    x: APP_HUB_HOME.x,
    y: APP_HUB_HOME.y,
    vx: 0,
    vy: 0,
    fixed: true,
    hidden: true,
    highlight: false,
    searchMatch: false,
    ring: 0.5,
    nodeRadius: 22,
    layer: "apps",
    isAppHub: true,
    appColor: "#2dd4ff",
    appGlow: "rgba(45,212,255,0.4)",
    homeX: APP_HUB_HOME.x,
    homeY: APP_HUB_HOME.y,
  }};
  allNodes.push(appHubNode);
  nodeMap[appHubNode.id] = appHubNode;
}}

sysData.processes.forEach((p, i) => {{
  const app = matchApp(p.label || p._group);
  const cpuN = Math.min(p.cpu_pct || 0, 100);
  const memN = Math.min(p.mem_pct || 0, 100);

  if (app) {{
    const inOrbit = activeAppSet.has(p.id);
    const slot = appSlotById[p.id] || 0;
    const family = appFamily(app.key);
    const familyIndex = inOrbit ? (appFamilyIndexById[p.id] || 0) : 0;
    const familyCount = inOrbit ? (appFamilyCounts[family] || 1) : 1;
    const band = slot === 0 ? 0 : (slot < 6 ? 1 : (slot < 14 ? 2 : 3));
    const offset = band === 1 ? Math.max(0, slot - 1) : (band === 2 ? Math.max(0, slot - 6) : Math.max(0, slot - 14));
    const idleSlot = idleAppSlotById[p.id] || 0;
    let expandedX = 360, expandedY = 300;
    if (inOrbit && slot > 0) {{
      const spread = familyCount <= 1 ? 0 : Math.min(0.9, 0.26 + familyCount * 0.065);
      const t = familyCount <= 1 ? 0.5 : (familyIndex / (familyCount - 1));
      const radius = band === 1 ? 112 : (band === 2 ? 166 : 224);
      const angle = (APP_FAMILY_CENTER[family] || APP_FAMILY_CENTER.other) - spread / 2 + t * spread;
      expandedX = APP_HUB_HOME.x + Math.cos(angle) * radius;
      expandedY = APP_HUB_HOME.y + Math.sin(angle) * radius * 0.88 + ((offset % 2 === 0) ? 12 : -12);
    }} else if (!inOrbit) {{
      const idleBand = idleSlot < 6 ? 0 : (idleSlot < 14 ? 1 : 2);
      const idleOffset = idleBand === 0 ? idleSlot : (idleBand === 1 ? idleSlot - 6 : idleSlot - 14);
      const idlePerBand = idleBand === 0 ? 6 : (idleBand === 1 ? 8 : Math.max(6, _idleCounter - 14));
      const idleT = idlePerBand <= 1 ? 0.5 : (idleOffset / (idlePerBand - 1));
      const idleRadius = idleBand === 0 ? 162 : (idleBand === 1 ? 214 : 268);
      const idleAngle = 0.42 + idleT * 1.55 + idleBand * 0.08;
      expandedX = APP_HUB_HOME.x + Math.cos(idleAngle) * idleRadius;
      expandedY = APP_HUB_HOME.y + Math.sin(idleAngle) * idleRadius * 0.8;
    }}
    const orbitRadius = slot < 6 ? 68 : (slot < 12 ? 94 : 122);
    const orbitTilt = slot < 6 ? 0.48 : (slot < 12 ? 0.58 : 0.68);
    const spread = familyCount <= 1 ? 0 : Math.min(1.2, 0.42 + familyCount * 0.08);
    const orbitAngle = (APP_FAMILY_CENTER[family] || APP_FAMILY_CENTER.other) - spread / 2 + (familyCount <= 1 ? 0 : (familyIndex / Math.max(familyCount - 1, 1)) * spread) + (band * 0.03);
    const groupedX = inOrbit
      ? (APP_HUB_HOME.x + Math.cos(orbitAngle) * orbitRadius)
      : (APP_HUB_HOME.x + 74 + Math.cos(1.2 + idleSlot * 0.7) * (18 + (idleSlot % 3) * 10));
    const groupedY = inOrbit
      ? (APP_HUB_HOME.y + Math.sin(orbitAngle) * orbitRadius * orbitTilt)
      : (APP_HUB_HOME.y - 30 + Math.sin(1.2 + idleSlot * 0.7) * (16 + (idleSlot % 4) * 8));
    const prominence = Math.min(1, (cpuN + memN * 4) / 90);
    const n = {{
      ...p, cpu_pct: cpuN, mem_pct: memN,
      x: expandedX, y: expandedY,
      vx: 0, vy: 0, fixed: false, hidden: false, highlight: false, searchMatch: false,
      ring: 0.5, nodeRadius: 8.4 + prominence * 3.8, layer: "apps",
      isApp: true, appKey: app.key, appColor: app.color, appGlow: app.glow, appIcon: app.icon,
      appFamily: family,
      inOrbit: false,
      homeX: expandedX, homeY: expandedY,
      groupX: expandedX, groupY: expandedY,
      orbitAngle, orbitRadius, orbitTilt,
      orbitSpeed: 0,
    }};
    allNodes.push(n);
    nodeMap[n.id] = n;
    allEdges.push({{ source: "hw_cpu", target: n.id, kind: "uses", strength: cpuN }});
    allEdges.push({{ source: "hw_ram", target: n.id, kind: "uses", strength: memN }});
    if (app.key === "safari" || app.key === "chrome" || app.key === "firefox" || app.key === "discord" || app.key === "telegram" || app.key === "whatsapp" || app.key === "slack")
      allEdges.push({{ source: "hw_net", target: n.id, kind: "uses", strength: 8 }});
    if (app.key === "cursor" || app.key === "codex" || app.key === "vscode" || app.key === "xcode")
      allEdges.push({{ source: "hw_disk", target: n.id, kind: "uses", strength: 6 }});
    allEdges.push({{ source: "hw_gpu", target: n.id, kind: "uses", strength: Math.max(cpuN * 0.3, 2) }});
  }} else {{
    const angle = (i / Math.max(sysData.processes.length, 1)) * Math.PI * 2 + Math.random() * 0.3;
    const r = 220 + Math.random() * 80;
    const n = {{
      ...p, cpu_pct: cpuN, mem_pct: memN,
      x: Math.cos(angle) * r, y: Math.sin(angle) * r,
      vx: 0, vy: 0, fixed: false, hidden: false, highlight: false, searchMatch: false,
      ring: 1, nodeRadius: 4 + Math.min(cpuN + memN, 40) * 0.3, layer: "procs",
    }};
    allNodes.push(n);
    nodeMap[n.id] = n;
    if (cpuN > 1) allEdges.push({{ source: "hw_cpu", target: n.id, kind: "uses", strength: cpuN }});
    if (memN > 0.5) allEdges.push({{ source: "hw_ram", target: n.id, kind: "uses", strength: memN }});
    if (p.category === "browser" || p.category === "comms") allEdges.push({{ source: "hw_net", target: n.id, kind: "uses", strength: 3 }});
    if (p.category === "database") allEdges.push({{ source: "hw_disk", target: n.id, kind: "uses", strength: 5 }});
  }}
}});

// App nodes behave like first-class nodes now; no hub/orbit links.
clusterAppFollowers();
syncSubprocessNodes(sysData.processes || []);
syncBrowserTabs(sysData.browser_tabs || []);

// File nodes — outer ring (only top-importance files to avoid clutter)
const fileNodes = (fileGraph.nodes || [])
  .filter(n => n.kind === "file")
  .sort((a, b) => (b.importance || 0) - (a.importance || 0))
  .slice(0, 120);

fileNodes.forEach((fn, i) => {{
  const angle = (i / Math.max(fileNodes.length, 1)) * Math.PI * 2;
  const r = 400 + (fn.depth || 0) * 30 + Math.random() * 60;
  const n = {{
    ...fn, x: Math.cos(angle) * r, y: Math.sin(angle) * r,
    vx: 0, vy: 0, fixed: false, hidden: false, highlight: false, searchMatch: false,
    ring: 2, nodeRadius: 2 + (fn.importance || 10) / 100 * 3, layer: "files",
    category: fn.sensitive ? "sensitive" : (fn.agent_related ? "agent" : fn.file_type),
  }};
  allNodes.push(n);
  nodeMap[n.id] = n;

  // Connect agent files to agent processes
  if (fn.agent_related) {{
    const agentProc = sysData.processes.find(p => p.category === "agent");
    if (agentProc) allEdges.push({{ source: `proc_${{agentProc._group}}`, target: n.id, kind: "reads", strength: 2 }});
  }}
  allEdges.push({{ source: "hw_disk", target: n.id, kind: "stores", strength: 0.5 }});
}});

// File folder nodes as mini-constellations
const folderNodes = (fileGraph.nodes || [])
  .filter(n => n.kind === "folder" && n.id !== "root" && (n.agent_related || n.sensitive || (n.children_count || 0) > 3))
  .slice(0, 30);
folderNodes.forEach((fn, i) => {{
  const angle = (i / Math.max(folderNodes.length, 1)) * Math.PI * 2 + 0.5;
  const r = 350 + Math.random() * 40;
  const n = {{
    ...fn, x: Math.cos(angle) * r, y: Math.sin(angle) * r,
    vx: 0, vy: 0, fixed: false, hidden: false, highlight: false, searchMatch: false,
    ring: 2, nodeRadius: 4, layer: "files",
    category: fn.sensitive ? "sensitive" : (fn.agent_related ? "agent" : "folder"),
  }};
  allNodes.push(n);
  nodeMap[n.id] = n;
}});

// Reconnect file edges
(fileGraph.edges || []).forEach(e => {{
  if (nodeMap[e.source] && nodeMap[e.target]) {{
    allEdges.push({{ source: e.source, target: e.target, kind: "contains", strength: 1 }});
  }}
}});

// Update HUD
function barColor(pct) {{
  if (pct > 85) return "#ff4444";
  if (pct > 60) return "#fbbf24";
  return "#00ffcc";
}}
function formatBytes(b) {{
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b/1024).toFixed(1) + " KB";
  if (b < 1073741824) return (b/1048576).toFixed(1) + " MB";
  return (b/1073741824).toFixed(2) + " GB";
}}
function formatSpeed(bps) {{
  if (bps < 1024) return bps.toFixed(0) + " B/s";
  if (bps < 1048576) return (bps/1024).toFixed(1) + " KB/s";
  if (bps < 1073741824) return (bps/1048576).toFixed(1) + " MB/s";
  return (bps/1073741824).toFixed(2) + " GB/s";
}}
function formatPkts(n) {{
  if (n < 1000) return n + "";
  if (n < 1000000) return (n/1000).toFixed(1) + "K";
  return (n/1000000).toFixed(1) + "M";
}}
function cpuCoreEquivFromPct(pct) {{
  return Math.max(0, Number(pct || 0) / 100);
}}
function formatCoreEquiv(pct) {{
  const used = cpuCoreEquivFromPct(pct);
  const total = Number((sysData.cpu && sysData.cpu.cores) || 0);
  if (total > 0) return `${{used.toFixed(2)}} / ${{total}} core-equiv`;
  return `${{used.toFixed(2)}} core-equiv`;
}}
function ramBytesFromPct(pct) {{
  const totalGb = Number((sysData.memory && sysData.memory.total_gb) || 0);
  return totalGb * 1073741824 * (Number(pct || 0) / 100);
}}
function formatRamFromPct(pct) {{
  return formatBytes(ramBytesFromPct(pct));
}}

let prevNetIn = sysData.net_stats ? sysData.net_stats.bytes_in : 0;
let prevNetOut = sysData.net_stats ? sysData.net_stats.bytes_out : 0;
let prevNetTime = Date.now();

document.getElementById("hud-host").textContent = sysData.hostname || "-";
document.getElementById("hud-os").textContent = sysData.os || "-";
document.getElementById("hud-cpu").textContent = sysData.cpu.usage_pct + "%";
document.getElementById("hud-cpu-bar").style.width = sysData.cpu.usage_pct + "%";
document.getElementById("hud-cpu-bar").style.background = barColor(sysData.cpu.usage_pct);
const gpuData = sysData.gpu || {{}};
document.getElementById("hud-gpu").textContent = (gpuData.model || "N/A") + " " + (gpuData.usage_pct || 0) + "%";
document.getElementById("hud-gpu-bar").style.width = (gpuData.usage_pct || 0) + "%";
document.getElementById("hud-gpu-bar").style.background = barColor(gpuData.usage_pct || 0);
document.getElementById("hud-ram").textContent = sysData.memory.used_gb + "/" + sysData.memory.total_gb + " GB";
document.getElementById("hud-ram-bar").style.width = sysData.memory.usage_pct + "%";
document.getElementById("hud-ram-bar").style.background = barColor(sysData.memory.usage_pct);
document.getElementById("hud-disk").textContent = sysData.disk.used_gb + "/" + sysData.disk.total_gb + " GB";
document.getElementById("hud-disk-bar").style.width = sysData.disk.usage_pct + "%";
document.getElementById("hud-disk-bar").style.background = barColor(sysData.disk.usage_pct);
document.getElementById("hud-net").textContent = (sysData.network.active ? sysData.network.type + " " + sysData.network.ip : "Disconnected");
if (sysData.net_stats) {{
  document.getElementById("hud-net-in").textContent = formatBytes(sysData.net_stats.bytes_in);
  document.getElementById("hud-net-out").textContent = formatBytes(sysData.net_stats.bytes_out);
  document.getElementById("hud-net-pkts-in").textContent = formatPkts(sysData.net_stats.pkts_in);
  document.getElementById("hud-net-pkts-out").textContent = formatPkts(sysData.net_stats.pkts_out);
  document.getElementById("hud-net-speed").textContent = "calc...";
}}
document.getElementById("hud-procs").textContent = sysData.processes.length;
document.getElementById("hud-files").textContent = (fileGraph.stats || {{}}).total_files || 0;

let usageSort = "cpu";
let contextNode = null;
const opsLog = [];
const ALARM_PREF_KEY = "parad0x_alarm_prefs";
let alarmSoundEnabled = true;
let alarmSoundTone = "beacon";
let alarmAckKey = "";
let currentAlarmKey = "";
let alarmLoop = null;
let alarmAudioCtx = null;

function esc(s) {{
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}}

function maskHomePath(raw) {{
  let out = String(raw || "");
  out = out.replace(/\/Users\/[^/]+/g, "/Users/••••••");
  out = out.replace(/\/home\/[^/]+/g, "/home/••••••");
  return out;
}}

function privacyText(raw, kind="text") {{
  let out = String(raw || "");
  if (privacyHidden) {{
    if (kind === "path") out = maskHomePath(out);
  }}
  return esc(out);
}}

function money(v) {{
  const n = Number(v || 0);
  return "$" + n.toFixed(n >= 10 ? 2 : 4);
}}

function loadAlarmPrefs() {{
  try {{
    const raw = localStorage.getItem(ALARM_PREF_KEY);
    if (!raw) return;
    const prefs = JSON.parse(raw);
    if (typeof prefs.enabled === "boolean") alarmSoundEnabled = prefs.enabled;
    if (typeof prefs.tone === "string" && prefs.tone) alarmSoundTone = prefs.tone;
    if (typeof prefs.ackKey === "string") alarmAckKey = prefs.ackKey;
  }} catch (e) {{}}
}}

function saveAlarmPrefs() {{
  try {{
    localStorage.setItem(ALARM_PREF_KEY, JSON.stringify({{
      enabled: alarmSoundEnabled,
      tone: alarmSoundTone,
      ackKey: alarmAckKey,
    }}));
  }} catch (e) {{}}
}}

function ensureAlarmAudio() {{
  if (!alarmAudioCtx) {{
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return null;
    alarmAudioCtx = new Ctx();
  }}
  if (alarmAudioCtx && alarmAudioCtx.state === "suspended") {{
    alarmAudioCtx.resume().catch(() => {{}});
  }}
  return alarmAudioCtx;
}}

function playAlarmTone(kind) {{
  const ac = ensureAlarmAudio();
  if (!ac) return;
  const now = ac.currentTime;
  const master = ac.createGain();
  master.connect(ac.destination);
  master.gain.setValueAtTime(0.0001, now);
  const steps = kind === "siren"
    ? [{{f: 620, t: 0.00, d: 0.12}}, {{f: 760, t: 0.16, d: 0.12}}, {{f: 620, t: 0.34, d: 0.12}}]
    : kind === "chime"
      ? [{{f: 660, t: 0.00, d: 0.10}}, {{f: 880, t: 0.18, d: 0.14}}]
      : [{{f: 740, t: 0.00, d: 0.11}}, {{f: 520, t: 0.18, d: 0.11}}];
  steps.forEach((step, idx) => {{
    const osc = ac.createOscillator();
    const gain = ac.createGain();
    osc.type = idx % 2 === 0 ? "sine" : "triangle";
    osc.frequency.setValueAtTime(step.f, now + step.t);
    gain.gain.setValueAtTime(0.0001, now + step.t);
    gain.gain.exponentialRampToValueAtTime(0.055, now + step.t + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + step.t + step.d);
    osc.connect(gain);
    gain.connect(master);
    osc.start(now + step.t);
    osc.stop(now + step.t + step.d + 0.03);
  }});
}}

function stopAlarmLoop() {{
  if (alarmLoop) {{
    clearInterval(alarmLoop);
    alarmLoop = null;
  }}
}}

function startAlarmLoop(level) {{
  if (!alarmSoundEnabled) return;
  if (alarmLoop) return;
  playAlarmTone(level === "red" ? alarmSoundTone : (alarmSoundTone === "siren" ? "beacon" : alarmSoundTone));
  alarmLoop = setInterval(() => {{
    playAlarmTone(level === "red" ? alarmSoundTone : (alarmSoundTone === "siren" ? "beacon" : alarmSoundTone));
  }}, level === "red" ? 1500 : 2200);
}}

function alarmStateKey(threat) {{
  if (!threat || !threat.status || threat.status === "CLEAR") return "";
  return JSON.stringify({{
    status: threat.status,
    level: threat.level || "amber",
    halt: !!threat.halt_present,
    providers: Number(threat.provider_failures || 0),
    risky: Number(threat.risky_actions_24h || 0),
    alerts: Array.isArray(threat.alerts) ? threat.alerts.slice(0, 6) : [],
    heartbeat: threat.heartbeat && threat.heartbeat.present ? [threat.heartbeat.fresh, threat.heartbeat.age_s] : [],
  }});
}}

function setAlarmVisual(active, level) {{
  alarmOverlay.classList.toggle("active", !!active);
  alarmOverlay.classList.toggle("amber", !!active && level === "amber");
  alarmOverlay.classList.toggle("red", !!active && level === "red");
  threatPanelEl.classList.toggle("alarm-live", !!active);
  threatPanelEl.classList.toggle("amber", !!active && level === "amber");
}}

function applyAlarmState(threat) {{
  currentAlarmKey = alarmStateKey(threat);
  const active = !!currentAlarmKey && currentAlarmKey !== alarmAckKey;
  const level = threat && threat.level === "red" ? "red" : "amber";
  setAlarmVisual(active, level);
  if (active) startAlarmLoop(level);
  else stopAlarmLoop();
  const ackBtn = document.getElementById("alarm-ack-btn");
  const soundBtn = document.getElementById("alarm-sound-toggle");
  const soundSelect = document.getElementById("alarm-sound-select");
  if (ackBtn) ackBtn.textContent = active ? "ACK / RESET" : "RESET";
  if (soundBtn) {{
    soundBtn.textContent = alarmSoundEnabled ? "SOUND ON" : "SOUND OFF";
    soundBtn.classList.toggle("active", alarmSoundEnabled);
  }}
  if (soundSelect) soundSelect.value = alarmSoundTone;
}}

function acknowledgeAlarm() {{
  alarmAckKey = currentAlarmKey || "";
  saveAlarmPrefs();
  applyAlarmState(sysData.threat || {{}});
  pushOpsLog("alarm acknowledged", "info");
}}

function toggleAlarmSound() {{
  alarmSoundEnabled = !alarmSoundEnabled;
  saveAlarmPrefs();
  if (!alarmSoundEnabled) stopAlarmLoop();
  else applyAlarmState(sysData.threat || {{}});
}}

function setAlarmTone(value) {{
  alarmSoundTone = value || "beacon";
  saveAlarmPrefs();
  if (alarmSoundEnabled && currentAlarmKey && currentAlarmKey !== alarmAckKey) {{
    stopAlarmLoop();
    applyAlarmState(sysData.threat || {{}});
  }}
}}

function shortWhen(ts) {{
  if (!ts) return "now";
  try {{
    const d = new Date(ts);
    if (!Number.isNaN(d.getTime())) return d.toLocaleTimeString();
  }} catch (e) {{}}
  return String(ts);
}}

function usageMetricValue(row) {{
  return Number(row && row[usageSort] || 0);
}}

function setUsageSort(kind) {{
  usageSort = kind;
  ["cpu","ram","gpu","ssd","net"].forEach(k => {{
    const el = document.getElementById("usage-sort-" + k);
    if (el) el.classList.toggle("active", k === kind);
  }});
  renderUsageSurface(sysData.monitor_rows || []);
}}

function renderUsageSurface(rows) {{
  const sorted = [...(rows || [])].sort((a, b) => usageMetricValue(b) - usageMetricValue(a)).slice(0, 8);
  if (!sorted.length) {{
    usageContent.innerHTML = '<div class="muted">No process usage data.</div>';
    return;
  }}
  usageContent.innerHTML = sorted.map(row => `
    <div class="usage-row" onclick="selectNode(nodeMap['${{row.id}}'])">
      <div>
        <div>${{esc(row.name)}}</div>
        <div class="muted">${{esc(row.category)}} · PID ${{row.pid}}</div>
      </div>
      <div style="text-align:right">
        <div>${{usageMetricValue(row).toFixed(1)}}%</div>
        <div class="muted">CPU ${{row.cpu}} · RAM ${{row.ram}}</div>
      </div>
    </div>
  `).join("");
}}

function renderAgentOps(agentOps) {{
  if (!agentOps) {{
    agentOpsContent.innerHTML = '<div class="muted">No agent state.</div>';
    return;
  }}
  const color = agentOps.status === "ALARM" ? "#ff6666" : (agentOps.status === "WATCH" ? "#fbbf24" : "#68e2be");
  const hot = agentOps.hot_agents || [];
  agentOpsContent.innerHTML = `
    <div style="color:${{color}};font-weight:800">${{esc(agentOps.status || 'CLEAR')}}</div>
    <div><span class="muted">Running agents</span> <b>${{agentOps.agent_count || 0}}</b></div>
    <div><span class="muted">Providers</span> <b>${{agentOps.providers_healthy || 0}} / ${{agentOps.providers_enabled || 0}}</b></div>
    <div><span class="muted">Active provider</span> <b>${{esc(agentOps.active_provider || 'n/a')}}</b></div>
    <div><span class="muted">Halt</span> <b>${{agentOps.halt_present ? 'present' : 'clear'}}</b></div>
    <div class="muted" style="margin-top:6px">Hot agents</div>
    ${{hot.length ? hot.map(row => `
      <div class="usage-row">
        <div>
          <div>${{esc(row.name)}}</div>
          <div class="muted">PID ${{row.pid}}</div>
        </div>
        <div style="text-align:right">
          <div>CPU ${{Number(row.cpu_pct || 0).toFixed(1)}}%</div>
          <div class="muted">RAM ${{Number(row.mem_pct || 0).toFixed(1)}}%</div>
        </div>
      </div>`).join('') : '<div class="muted">No agent-tagged processes detected.</div>'}}
  `;
}}

function renderTaskProgress(task) {{
  if (!task) {{
    taskContent.innerHTML = '<div class="muted">No task state.</div>';
    return;
  }}
  const lastAction = task.last_action || null;
  taskContent.innerHTML = `
    <div><span class="muted">Phase</span> <b>${{esc(task.phase || 'idle')}}</b></div>
    <div><span class="muted">Provider sync</span> <b>${{Number(task.sync_pct || 0).toFixed(1)}}%</b></div>
    <div><span class="muted">Healthy</span> <b>${{task.providers_healthy || 0}} / ${{task.providers_enabled || 0}}</b></div>
    <div><span class="muted">Active provider</span> <b>${{esc(task.active_provider || 'n/a')}}</b></div>
    <div class="muted" style="margin-top:6px">Last action</div>
    ${{lastAction ? `
      <div><b>${{esc(lastAction.type || 'action')}}</b></div>
      <div class="muted">${{esc((lastAction.command || '').slice(0, 120) || 'n/a')}}</div>
      <div class="muted">${{shortWhen(lastAction.ts)}}</div>
    ` : '<div class="muted">No recent action in history guard state.</div>'}}
  `;
}}

function renderActivityFeed(items) {{
  const rows = items || [];
  if (!rows.length) {{
    activityContent.innerHTML = '<div class="muted">No recent activity.</div>';
    return;
  }}
  activityContent.innerHTML = rows.map(item => `
    <div class="usage-row">
      <div>
        <div>${{esc(item.label || item.kind || 'event')}}</div>
        <div class="muted">${{esc(item.detail || '')}}</div>
      </div>
      <div class="muted" style="text-align:right;min-width:74px">${{esc(shortWhen(item.ts))}}</div>
    </div>
  `).join("");
}}

function renderAiLedger(ai) {{
  if (!ai || !ai.enabled) {{
    aiContent.innerHTML = `
      <div class="muted">No token ledger data.</div>
      <div class="muted" style="margin-top:4px">${{esc(ai && ai.reason || 'No usage source found.')}}</div>
    `;
    return;
  }}
  const mode = String(ai.billing_mode || 'usage_only');
  const costMode = ai.cost_confidence === 'exact' ? 'exact' : (ai.cost_confidence === 'estimated' ? 'estimated' : 'unknown');
  const telemetryTitle = ai.telemetry_label || 'Model requests logged today';
  const avgTokensLabel = ai.avg_tokens_label || 'Avg tokens / request';
  const telemetrySource = ai.telemetry_source_label || ai.source || 'unknown';
  const providerName = String(ai.provider || 'unknown');
  const providerApiStatus = String(ai.provider_api_status || 'unknown');
  const providerSource = String(ai.provider_source || ai.billing_profile_source || ai.source || 'unknown');
  let providerBlock = `
    <div class="muted" style="margin-top:8px">Provider adapter</div>
    <div><span class="muted">Provider</span> <b>${{esc(providerName)}}</b></div>
    <div><span class="muted">Status</span> <b>${{esc(providerApiStatus)}}</b></div>
    <div><span class="muted">Source</span> <b>${{esc(providerSource)}}</b></div>
    <div class="muted" style="margin-top:4px">${{esc(ai.provider_api_note || ai.provider_plan_note || '')}}</div>
  `;
  if (ai.provider_exact_usage || ai.provider_exact_billing) {{
    providerBlock = `
      <div class="muted" style="margin-top:8px">Provider adapter</div>
      <div><span class="muted">Provider</span> <b>${{esc(providerName)}}</b></div>
      <div><span class="muted">Status</span> <b>${{esc(providerApiStatus)}}</b></div>
      <div><span class="muted">Source</span> <b>${{esc(providerSource)}}</b></div>
      <div><span class="muted">Exact provider requests today</span> <b>${{Number(ai.provider_requests_today || 0).toLocaleString()}}</b></div>
      <div><span class="muted">Exact provider input tokens</span> <b>${{Number(ai.provider_input_tokens_today || 0).toLocaleString()}}</b></div>
      <div><span class="muted">Exact provider output tokens</span> <b>${{Number(ai.provider_output_tokens_today || 0).toLocaleString()}}</b></div>
      <div><span class="muted">Exact provider cost today</span> <b>${{money(ai.provider_cost_usd_today || 0)}}</b></div>
      <div><span class="muted">Exact provider 30d cost</span> <b>${{money(ai.provider_month_cost_usd || 0)}}</b></div>
      <div class="muted" style="margin-top:4px">${{esc(ai.provider_api_note || '')}}</div>
    `;
  }}
  let planBlock = '';
  let billingBlock = '';
  if (mode === 'quota') {{
    const quotaUsed = ai.quota_used == null ? 'n/a' : Number(ai.quota_used).toLocaleString();
    const quotaLimit = ai.quota_limit == null ? 'n/a' : Number(ai.quota_limit).toLocaleString();
    const quotaRemaining = ai.quota_remaining == null ? 'n/a' : Number(ai.quota_remaining).toLocaleString();
    planBlock = `
      <div class="muted" style="margin-top:8px">Provider plan status</div>
      <div><span class="muted">Plan</span> <b>${{esc(ai.billing_label || 'quota')}}</b></div>
      <div><span class="muted">Quota used</span> <b>${{quotaUsed}} / ${{quotaLimit}}</b></div>
      <div><span class="muted">Remaining</span> <b>${{quotaRemaining}}</b></div>
      <div><span class="muted">Quota %</span> <b>${{ai.quota_pct == null ? 'n/a' : (Number(ai.quota_pct).toFixed(1) + '%')}}</b></div>
      <div><span class="muted">Reset</span> <b>${{esc(ai.reset_at || 'n/a')}}</b></div>
      <div class="muted" style="margin-top:4px">${{esc(ai.provider_plan_note || '')}}</div>
    `;
  }} else if (mode === 'subscription') {{
    billingBlock = `
      <div class="muted" style="margin-top:8px">Billing interpretation</div>
      <div><span class="muted">${{esc(ai.today_cost_label || 'Estimated API-equiv today')}}</span> <b>${{money(ai.estimated_cost_usd_today)}}</b></div>
      <div><span class="muted">${{esc(ai.month_cost_label || 'Estimated API-equiv 30d')}}</span> <b>${{money(ai.month_cost_usd)}}</b></div>
      <div class="muted" style="margin-top:4px">${{costMode}} pricing benchmark only · not provider billing</div>
    `;
    planBlock = `
      <div class="muted" style="margin-top:8px">Provider plan status</div>
      <div><span class="muted">Plan</span> <b>${{esc(ai.billing_label || 'subscription')}}</b></div>
      <div><span class="muted">Remaining quota</span> <b>${{ai.quota_remaining == null ? 'unknown' : Number(ai.quota_remaining).toLocaleString()}}</b></div>
      <div><span class="muted">Reset</span> <b>${{esc(ai.reset_at || 'unknown')}}</b></div>
      <div class="muted" style="margin-top:4px">${{esc(ai.provider_plan_note || '')}}</div>
    `;
  }} else if (mode === 'metered') {{
    billingBlock = `
      <div class="muted" style="margin-top:8px">Billing interpretation</div>
      <div><span class="muted">${{esc(ai.today_cost_label || 'Provider spend today')}}</span> <b>${{money(ai.estimated_cost_usd_today)}}</b></div>
      <div><span class="muted">${{esc(ai.month_cost_label || 'Provider 30d spend')}}</span> <b>${{money(ai.month_cost_usd)}}</b></div>
      <div><span class="muted">Limit</span> <b>${{ai.spend_limit_usd == null ? 'n/a' : money(ai.spend_limit_usd)}}</b></div>
      <div class="muted" style="margin-top:4px">${{costMode}} billing source · ${{esc(ai.billing_profile_source || ai.source || 'unknown')}}</div>
    `;
    planBlock = `
      <div class="muted" style="margin-top:8px">Provider plan status</div>
      <div><span class="muted">Plan</span> <b>${{esc(ai.billing_label || 'metered')}}</b></div>
      <div><span class="muted">Source</span> <b>${{esc(ai.billing_profile_source || ai.source || 'unknown')}}</b></div>
      <div><span class="muted">Reset</span> <b>${{esc(ai.reset_at || 'n/a')}}</b></div>
      <div class="muted" style="margin-top:4px">${{esc(ai.provider_plan_note || '')}}</div>
    `;
  }} else {{
    billingBlock = `
      <div class="muted" style="margin-top:8px">Billing interpretation</div>
      <div><span class="muted">${{esc(ai.today_cost_label || 'Estimated API-equiv today')}}</span> <b>${{money(ai.estimated_cost_usd_today)}}</b></div>
      <div><span class="muted">${{esc(ai.month_cost_label || 'Estimated API-equiv 30d')}}</span> <b>${{money(ai.month_cost_usd)}}</b></div>
      <div class="muted" style="margin-top:4px">${{costMode}} pricing benchmark only · not provider billing</div>
    `;
    planBlock = `
      <div class="muted" style="margin-top:8px">Provider plan status</div>
      <div><span class="muted">Plan</span> <b>${{esc(ai.billing_label || 'unknown')}}</b></div>
      <div><span class="muted">Availability</span> <b>${{ai.provider_plan_available ? 'configured' : 'not available'}}</b></div>
      <div class="muted" style="margin-top:4px">${{esc(ai.provider_plan_note || '')}}</div>
    `;
  }}
  aiContent.innerHTML = `
    <div class="muted">Local telemetry</div>
    <div><span class="muted">${{esc(telemetryTitle)}}</span> <b>${{ai.requests_logged_today || ai.calls_today || 0}}</b></div>
    <div><span class="muted">Input tokens logged</span> <b>${{(ai.input_tokens_today || 0).toLocaleString()}}</b></div>
    <div><span class="muted">Output tokens logged</span> <b>${{(ai.output_tokens_today || 0).toLocaleString()}}</b></div>
    <div><span class="muted">Total tokens logged</span> <b>${{(ai.total_tokens_today || 0).toLocaleString()}}</b></div>
    <div><span class="muted">${{esc(avgTokensLabel)}}</span> <b>${{Number(ai.avg_tokens_per_call || 0).toLocaleString()}}</b></div>
    <div class="muted" style="margin-top:4px">Source: ${{esc(telemetrySource)}} · ${{esc(ai.source || 'unknown')}}</div>
    ${{billingBlock}}
    ${{providerBlock}}
    ${{planBlock}}
    <div class="muted" style="margin-top:8px">Top models (30d request count): ${{(ai.top_models || []).map(m => esc(m[0]) + ' x' + Number(m[1] || 0).toLocaleString()).join(', ') || 'n/a'}}</div>
  `;
}}

function renderThreatCard(threat) {{
  if (!threat) {{
    threatContent.innerHTML = '<div class="muted">No threat data.</div>';
    applyAlarmState({{}});
    return;
  }}
  const color = threat.level === "red" ? "#ff6666" : (threat.level === "amber" ? "#fbbf24" : "#68e2be");
  const hb = threat.heartbeat || {{}};
  const alarmActive = !!alarmStateKey(threat) && alarmStateKey(threat) !== alarmAckKey;
  threatContent.innerHTML = `
    <div style="color:${{color}};font-weight:800">${{esc(threat.status || 'CLEAR')}}</div>
    <div><span class="muted">Provider failures</span> <b>${{threat.provider_failures || 0}}</b></div>
    <div><span class="muted">Risky 24h</span> <b>${{threat.risky_actions_24h || 0}}</b></div>
    <div><span class="muted">Sensitive files</span> <b>${{threat.sensitive_count || 0}}</b></div>
    <div><span class="muted">Agent-linked</span> <b>${{threat.agent_related_count || 0}}</b></div>
    <div><span class="muted">Heartbeat</span> <b>${{hb.armed ? (hb.fresh ? 'fresh' : ('stale ' + hb.age_s + 's')) : 'not armed'}}</b></div>
    <div><span class="muted">AI spend</span> <b>${{money(threat.ai_spend_today)}}</b></div>
    <div><span class="muted">Alarm state</span> <b>${{alarmActive ? 'ACTIVE' : 'acknowledged / clear'}}</b></div>
    <div style="margin-top:6px">${{(threat.alerts || []).map(a => `<div class="alert">${{esc(a)}}</div>`).join('') || '<div class="good">No active operator alarms.</div>'}}</div>
  `;
  applyAlarmState(threat);
}}

function pushOpsLog(message, level="info") {{
  opsLog.unshift({{ ts: new Date().toLocaleTimeString(), level, message }});
  while (opsLog.length > 8) opsLog.pop();
  renderOpsLog();
}}

function renderOpsLog() {{
  if (!opsLog.length) {{
    opsContent.innerHTML = '<div class="muted">No operator actions yet.</div>';
    return;
  }}
  opsContent.innerHTML = opsLog.map(item => {{
    const color = item.level === "error" ? "#ff8f8f" : (item.level === "warn" ? "#ffd27a" : "#9deccf");
    return `<div style="margin-bottom:6px"><span class="muted">${{esc(item.ts)}}</span> <span style="color:${{color}}">${{esc(item.message)}}</span></div>`;
  }}).join("");
}}

function processActionKey(action, n) {{
  const label = String((n && (n._group || n.id || n.pid || n.label || n.name)) || "process");
  return `proc:${{action}}:${{label}}`;
}}

function panicActionKey(action) {{
  return `panic:${{String(action || '')}}`;
}}

function processActionLabel(action) {{
  return action === "kill" ? "Killing..." : "Closing...";
}}

function panicActionLabel(action) {{
  if (action === "write") return "WRITING HALT...";
  if (action === "verify") return "VERIFYING...";
  if (action === "term-agents") return "HALTING AGENTS...";
  if (action === "kill-agents") return "KILLING AGENTS...";
  if (action === "network-off") return "CUTTING NETWORK...";
  if (action === "network-on") return "RESTORING NETWORK...";
  return "PROCESSING...";
}}

function syncThreatButtonState() {{
  const map = {{
    "write": ["panic-halt-btn", "WRITE HALT"],
    "verify": ["panic-verify-btn", "VERIFY HALT"],
    "term-agents": ["panic-term-agents-btn", "HALT AGENTS"],
    "kill-agents": ["panic-kill-agents-btn", "KILL AGENTS HARD"],
    "network-off": ["panic-network-off-btn", "CUT NETWORK"],
    "network-on": ["panic-network-on-btn", "RESTORE NETWORK"],
  }};
  Object.entries(map).forEach(([action, pair]) => {{
    const [id, baseLabel] = pair;
    const btn = document.getElementById(id);
    if (!btn) return;
    const pending = pendingPanicActions.has(panicActionKey(action));
    btn.disabled = pending;
    btn.classList.toggle("action-pending", pending);
    btn.textContent = pending ? panicActionLabel(action) : baseLabel;
  }});
}}

function markProcessPending(n, action, pending) {{
  if (!n) return;
  n.pendingAction = pending ? action : "";
  refreshInspectorForNode(n.id);
}}

function describeProcessActionResult(action, label, res) {{
  const verb = action === "kill" ? "Kill hard" : "Force close";
  const target = Number(res && res.count || 0);
  const survivors = Number(res && res.survivor_count || 0);
  const ok = !!(res && res.ok);
  let msg = `${{verb}} ${{label || "process"}}`;
  if (target > 0) msg += ` · targeted ${{target}} pid${{target === 1 ? "" : "s"}}`;
  if (survivors > 0) msg += ` · survivors ${{survivors}}`;
  else if (ok) msg += ` · cleared`;
  if (!ok && res && res.error) msg += ` · ${{res.error}}`;
  return msg;
}}

function describePanicActionResult(action, res) {{
  const base = {{
    "write": "panic halt written",
    "verify": "halt verified",
    "term-agents": "agent halt issued",
    "kill-agents": "agent hard kill issued",
    "network-off": "network panic issued",
    "network-on": "network restore issued",
  }}[action] || action;
  const target = Number(res && res.count || 0);
  const survivors = Number(res && res.survivor_count || 0);
  let msg = base;
  if (res && res.interface) {{
    msg += ` · ${{
      res.network_type ? `${{res.network_type}} ` : ""
    }}${{res.interface}}`;
  }}
  if (target > 0) msg += ` · targeted ${{target}} pid${{target === 1 ? "" : "s"}}`;
  if (survivors > 0) msg += ` · survivors ${{survivors}}`;
  else if (res && res.ok && target > 0) msg += ` · cleared`;
  if (res && !res.ok && res.error) msg += ` · ${{res.error}}`;
  return msg;
}}

function fetchJsonWithTimeout(url, timeoutMs = 12000, options = {{}}) {{
  const mergedHeaders = Object.assign({{ "X-Parad0x-Token": API_TOKEN }}, options.headers || {{}});
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const fetchOptions = Object.assign({{}}, options, {{ signal: controller.signal, cache: "no-store", headers: mergedHeaders }});
  return fetch(url, fetchOptions)
    .then(async r => {{
      const data = await r.json().catch(() => ({{ ok: false, error: `HTTP ${{r.status}}` }}));
      if (!r.ok) {{
        const err = new Error(String((data && data.error) || `HTTP ${{r.status}}`));
        err.response = data;
        throw err;
      }}
      return data;
    }})
    .finally(() => clearTimeout(timer));
}}

function postJsonWithTimeout(url, payload, timeoutMs = 12000) {{
  return fetchJsonWithTimeout(url, timeoutMs, {{
    method: "POST",
    headers: {{
      "Content-Type": "application/json",
      "X-Parad0x-Token": API_TOKEN,
    }},
    body: JSON.stringify(payload || {{}}),
  }});
}}

function processAction(action, n) {{
  const pid = n && n.pid ? n.pid : 0;
  const group = n && n._group ? n._group : "";
  if (!pid && !group) return;
  const actionKey = processActionKey(action, n);
  if (pendingActionKeys.has(actionKey)) return;
  pendingActionKeys.add(actionKey);
  markProcessPending(n, action, true);
  pushOpsLog(`${{action === "kill" ? "Kill hard" : "Force close"}} ${{n.label || n.name || "process"}} · processing...`, "warn");
  postJsonWithTimeout(`/api/process-action`, group ? {{ action, group }} : {{ action, pid }})
    .then(res => {{
      pushOpsLog(describeProcessActionResult(action, n.label || n.name || "process", res), res.ok ? (action === "kill" ? "warn" : "info") : "error");
      n.lastAction = res;
      refreshInspectorForNode(n.id);
      hideNodeMenu();
      setTimeout(pollStats, 250);
    }})
    .catch(() => pushOpsLog(`Action ${{action}} failed for ${{n.label || n.name || "process"}}`, "error"))
    .finally(() => {{
      pendingActionKeys.delete(actionKey);
      markProcessPending(n, action, false);
    }});
}}

function panicAction(action) {{
  const actionKey = panicActionKey(action);
  if (pendingPanicActions.has(actionKey)) return;
  pendingPanicActions.add(actionKey);
  syncThreatButtonState();
  pushOpsLog(`${{panicActionLabel(action)}}`, "warn");
  let route = `/api/halt`;
  let payload = {{ action }};
  if (action === "term-agents" || action === "kill-agents") {{
    route = `/api/process-action`;
  }} else if (action === "network-off") {{
    route = `/api/network`;
    payload = {{ action: "off" }};
  }} else if (action === "network-on") {{
    route = `/api/network`;
    payload = {{ action: "on" }};
  }}
  postJsonWithTimeout(route, payload, action === "network-off" ? 3000 : 12000)
    .then(res => {{
      pushOpsLog(describePanicActionResult(action, res), res.ok ? (action === "kill-agents" ? "warn" : "info") : "error");
      setTimeout(pollStats, 150);
    }})
    .catch((err) => {{
      const timedOut = !!(err && err.name === "AbortError");
      if (action === "network-off" && timedOut) {{
        pushOpsLog("network panic issued · request timed out waiting for local response", "warn");
      }} else {{
        pushOpsLog(`panic action failed: ${{action}}`, "error");
      }}
    }})
    .finally(() => {{
      pendingPanicActions.delete(actionKey);
      syncThreatButtonState();
    }});
}}

function closestNodeAtClient(clientX, clientY) {{
  const w = screenToWorld(clientX, clientY);
  let closest = null, closestDist = Infinity;
  allNodes.forEach(n => {{
    if (n.hidden || !layers[n.layer]) return;
    const dx = n.x - w.wx, dy = n.y - w.wy;
    const d = Math.sqrt(dx*dx + dy*dy);
    const pickR = n.nodeRadius / camZoom + 12 / camZoom;
    if (d < pickR && d < closestDist) {{ closest = n; closestDist = d; }}
  }});
  return closest;
}}

function showNodeMenu(clientX, clientY, n) {{
  contextNode = n;
  const actions = [
    `<button onclick="selectNode(contextNode); hideNodeMenu()">Inspect</button>`
  ];
  if (n && (n.kind === "process" || n.isApp) && n.pid) {{
    actions.push(`<button onclick="processAction('term', contextNode)">Force Close</button>`);
    actions.push(`<button onclick="processAction('kill', contextNode)">Kill Hard</button>`);
  }}
  nodeMenu.innerHTML = actions.join("");
  nodeMenu.style.display = "block";
  nodeMenu.style.left = Math.min(window.innerWidth - 160, clientX) + "px";
  nodeMenu.style.top = Math.min(window.innerHeight - 120, clientY) + "px";
}}

function hideNodeMenu() {{
  nodeMenu.style.display = "none";
  contextNode = null;
}}

renderUsageSurface(sysData.monitor_rows || []);
renderAgentOps(sysData.agent_ops || {{}});
renderTaskProgress(sysData.task_progress || {{}});
renderActivityFeed(sysData.activity_feed || []);
renderAiLedger(sysData.ai_usage || {{}});
renderThreatCard(sysData.threat || {{}});
renderOpsLog();
syncThreatButtonState();

function appPriorityScore(n) {{
  const cpu = Math.min(n.cpu_pct || 0, 100);
  const mem = Math.min(n.mem_pct || 0, 100);
  const bonus = {{
    codex: 18, cursor: 16, safari: 12, chrome: 12, finder: 10,
    terminal: 9, iterm: 9, telegram: 8, whatsapp: 8, discord: 8,
    spotify: 6, slack: 6, xcode: 10, vscode: 10, firefox: 7,
  }}[n.appKey || ""] || 0;
  return cpu * 0.9 + mem * 6 + bonus;
}}

function recomputeAppOrbit(processRows) {{
  const appNodes = getAppNodes();
  if (!appNodes.length) return;
  const processById = {{}};
  (processRows || []).forEach(p => {{
    const id = p.id || ("proc_" + p._group);
    processById[id] = p;
  }});
  appNodes.forEach(n => {{
    const p = processById[n.id];
    const cpu = Math.min((p ? p.cpu_pct : n.cpu_pct) || 0, 100);
    const mem = Math.min((p ? p.mem_pct : n.mem_pct) || 0, 100);
    n.cpu_pct = cpu;
    n.mem_pct = mem;
    const prominence = Math.min(1, (cpu + mem * 4) / 90);
    n.nodeRadius = 6.6 + prominence * 3.2;
    n.inOrbit = false;
  }});
}}

function addUsageEdgesForProcessNode(node, proc, appMeta) {{
  const cpuN = Math.min(proc.cpu_pct || 0, 100);
  const memN = Math.min(proc.mem_pct || 0, 100);
  allEdges.push({{ source: "hw_cpu", target: node.id, kind: "uses", strength: cpuN }});
  allEdges.push({{ source: "hw_ram", target: node.id, kind: "uses", strength: memN }});
  if (appMeta) {{
    if (["safari","chrome","firefox","discord","telegram","whatsapp","slack"].includes(appMeta.key))
      allEdges.push({{ source: "hw_net", target: node.id, kind: "uses", strength: 8 }});
    if (["cursor","codex","vscode","xcode"].includes(appMeta.key))
      allEdges.push({{ source: "hw_disk", target: node.id, kind: "uses", strength: 6 }});
    allEdges.push({{ source: "hw_gpu", target: node.id, kind: "uses", strength: Math.max(cpuN * 0.3, 2) }});
  }} else {{
    if (proc.category === "browser" || proc.category === "comms") allEdges.push({{ source: "hw_net", target: node.id, kind: "uses", strength: 3 }});
    if (proc.category === "database") allEdges.push({{ source: "hw_disk", target: node.id, kind: "uses", strength: 5 }});
  }}
}}

function addLiveProcessNode(proc) {{
  const app = matchApp(proc.label || proc._group);
  const cpuN = Math.min(proc.cpu_pct || 0, 100);
  const memN = Math.min(proc.mem_pct || 0, 100);
  if (app) {{
    const existingApps = getAppNodes().length;
    const angle = 0.45 + existingApps * 0.52;
    const radius = 132 + (existingApps % 4) * 18;
    const x = APP_HUB_HOME.x + Math.cos(angle) * radius;
    const y = APP_HUB_HOME.y + Math.sin(angle) * radius * 0.8;
    const prominence = Math.min(1, (cpuN + memN * 4) / 90);
    const node = {{
      ...proc,
      cpu_pct: cpuN,
      mem_pct: memN,
      x, y,
      vx: 0, vy: 0,
      fixed: false, hidden: false, highlight: false, searchMatch: false,
      ring: 0.5, nodeRadius: 6.6 + prominence * 3.2, layer: "apps",
      isApp: true, appKey: app.key, appColor: app.color, appGlow: app.glow, appIcon: app.icon,
      appFamily: appFamily(app.key),
      inOrbit: false,
      homeX: x, homeY: y,
      groupX: x, groupY: y,
      orbitAngle: 0, orbitRadius: 0, orbitTilt: 0, orbitSpeed: 0,
      sub: "CPU " + cpuN + "% · MEM " + memN + "%",
    }};
    allNodes.push(node);
    nodeMap[node.id] = node;
    addUsageEdgesForProcessNode(node, proc, app);
    return;
  }}

  const existingProcs = allNodes.filter(n => n.layer === "procs" && !n.hidden).length;
  const angle = 0.2 + existingProcs * 0.41;
  const radius = 235 + (existingProcs % 5) * 22;
  const node = {{
    ...proc,
    cpu_pct: cpuN,
    mem_pct: memN,
    x: Math.cos(angle) * radius,
    y: Math.sin(angle) * radius,
    vx: 0, vy: 0,
    fixed: false, hidden: false, highlight: false, searchMatch: false,
    ring: 1, nodeRadius: 4 + Math.min(cpuN + memN, 40) * 0.3, layer: "procs",
    sub: "CPU " + cpuN + "% · MEM " + memN + "%",
  }};
  allNodes.push(node);
  nodeMap[node.id] = node;
  addUsageEdgesForProcessNode(node, proc, null);
}}

function syncProcessNodes(processRows) {{
  const liveIds = new Set();
  (processRows || []).forEach(proc => {{
    const nid = proc.id || ("proc_" + proc._group);
    liveIds.add(nid);
    const existing = nodeMap[nid];
    if (!existing) {{
      addLiveProcessNode(proc);
      return;
    }}
    existing.hidden = false;
    existing.pid = proc.pid;
    existing.instance_count = proc.instance_count || 1;
    existing.cpu_pct = Math.min(proc.cpu_pct || 0, 100);
    existing.mem_pct = Math.min(proc.mem_pct || 0, 100);
    existing.category = proc.category || existing.category;
    existing.sub = "CPU " + existing.cpu_pct + "% · MEM " + existing.mem_pct + "%";
  }});
  const staleIds = [];
  allNodes.forEach(n => {{
    if ((n.isApp || n.layer === "procs") && n.kind !== "browser_tab" && String(n.id || "").startsWith("proc_")) {{
      if (!liveIds.has(n.id)) staleIds.push(n.id);
    }}
  }});
  staleIds.forEach(removeNodeState);
}}

// --- Physics ---
// Zoom-adaptive: when zoomed in, labels show, so we increase min-distance
// between same-ring nodes so text doesn't overlap. Clamped so nodes
// don't "run away" at extreme zoom levels.
function simulate() {{
  const zoomBoost = Math.min(Math.max(camZoom, 0.8), 4);
  const baseRepulsion = 600;
  const repulsion = baseRepulsion * (0.7 + zoomBoost * 0.5);
  const damping = 0.82;
  const minSep = 25 * zoomBoost;

  function syncAttachedNodeOrbits() {{
    allNodes.forEach((n) => {{
      if (!n || n.hidden || !n.parentProcessId) return;
      const parent = nodeMap[n.parentProcessId];
      if (!parent || parent.hidden) return;
      const angle = (n.orbitAngle || 0) + frameTime * (n.orbitSpeed || 0.35);
      const targetX = parent.x + Math.cos(angle) * (n.orbitRadius || 18);
      const targetY = parent.y + Math.sin(angle) * (n.orbitRadius || 18) * (n.orbitTilt || 0.78);
      n.x = targetX;
      n.y = targetY;
      n.vx = 0;
      n.vy = 0;
    }});
  }}

  for (let i = 0; i < allNodes.length; i++) {{
    const ni = allNodes[i];
    if (ni.hidden || ni.fixed || ni.parentProcessId) continue;
    let fx = 0, fy = 0;
    for (let j = 0; j < allNodes.length; j++) {{
      const nj = allNodes[j];
      if (i === j || nj.hidden || nj.parentProcessId) continue;
      const dx = ni.x - nj.x, dy = ni.y - nj.y;
      const dist = Math.sqrt(dx*dx + dy*dy) + 1;
      const sameRing = ni.ring === nj.ring;
      const rep = sameRing ? repulsion * 0.7 : repulsion * 0.25;
      let f = rep / (dist * dist);
      if (sameRing && dist < minSep) f += (minSep - dist) * 0.15;
      fx += (dx/dist) * f; fy += (dy/dist) * f;
    }}
    if (ni.isAppHub) {{
      fx += ((ni.homeX || APP_HUB_HOME.x) - ni.x) * 0.02;
      fy += ((ni.homeY || APP_HUB_HOME.y) - ni.y) * 0.02;
    }} else if (ni.isApp && appsGrouped && typeof ni.groupX === "number") {{
      const hub = nodeMap[APP_HUB_ID] || {{ x: APP_HUB_HOME.x, y: APP_HUB_HOME.y }};
      if (ni.inOrbit) {{
        const angle = (ni.orbitAngle || 0) + frameTime * (ni.orbitSpeed || 0.18);
        const targetX = hub.x + Math.cos(angle) * (ni.orbitRadius || 42);
        const targetY = hub.y + Math.sin(angle) * (ni.orbitRadius || 42) * (ni.orbitTilt || 0.42);
        fx += (targetX - ni.x) * 0.07;
        fy += (targetY - ni.y) * 0.07;
        const tangentAngle = angle + Math.PI / 2;
        fx += Math.cos(tangentAngle) * 0.018;
        fy += Math.sin(tangentAngle) * 0.018;
      }} else {{
        fx += (ni.groupX - ni.x) * 0.06;
        fy += (ni.groupY - ni.y) * 0.06;
      }}
    }} else if (ni.isApp && typeof ni.homeX === "number") {{
      fx += (ni.homeX - ni.x) * 0.015;
      fy += (ni.homeY - ni.y) * 0.015;
    }} else {{
      const targetR = ni.ring === 0.5 ? (120 + zoomBoost * 10) : (ni.ring === 1 ? (240 + zoomBoost * 20) : (ni.ring === 2 ? (450 + zoomBoost * 30) : 50));
      const curR = Math.sqrt(ni.x*ni.x + ni.y*ni.y) + 0.1;
      const ringF = (curR - targetR) * 0.003;
      fx -= (ni.x / curR) * ringF;
      fy -= (ni.y / curR) * ringF;
    }}
    ni.vx = (ni.vx + fx) * damping; ni.vy = (ni.vy + fy) * damping;
  }}

  allEdges.forEach(e => {{
    const s = nodeMap[e.source], t = nodeMap[e.target];
    if (!s || !t || s.hidden || t.hidden) return;
    if (e.kind === "child-link") return;
    const dx = t.x - s.x, dy = t.y - s.y;
    const dist = Math.sqrt(dx*dx + dy*dy) + 1;
    const ideal = s.ring === t.ring ? (40 + zoomBoost * 8) : (Math.abs(s.ring - t.ring) * 120);
    const groupedAppEdge = appsGrouped && ((s.isApp && s.inOrbit) || (t.isApp && t.inOrbit) || s.isAppHub || t.isAppHub);
    const springMult = e.kind === "app-link" ? 0.018 : (groupedAppEdge ? 0.0012 : 0.008);
    const f = (dist - ideal) * springMult;
    const fx = (dx/dist)*f, fy = (dy/dist)*f;
    if (!s.fixed) {{ s.vx += fx; s.vy += fy; }}
    if (!t.fixed) {{ t.vx -= fx; t.vy -= fy; }}
  }});

  allNodes.forEach(n => {{
    if (n.hidden || n.fixed) return;
    n.x += n.vx; n.y += n.vy;
  }});
  syncAttachedNodeOrbits();
}}

// --- Drawing ---
function worldToScreen(wx, wy) {{ return {{ sx: (wx-camX)*camZoom+W()/2, sy: (wy-camY)*camZoom+H()/2 }}; }}
function screenToWorld(sx, sy) {{ return {{ wx: (sx-W()/2)/camZoom+camX, wy: (sy-H()/2)/camZoom+camY }}; }}

function nodeColor(n) {{
  if (n.kind === "hardware") return "#fbbf24";
  if (n.isAppHub) return n.appColor || "#2dd4ff";
  if (n.isApp && n.appColor) return n.appColor;
  if (n.kind === "browser_tab") return n.tabActive ? "#7ed8ff" : "#2aa6ff";
  if (n.isSubprocess && n.appColor) return n.appColor;
  if (n.sensitive) return "#ff4444";
  if (n.file_type === "vault") return "#00ff88";
  if (n.agent_related || n.category === "agent") return "#00ffcc";
  if (n.kind === "process") return CAT_COLORS[n.category] || "#6b7280";
  return TYPE_COLORS[n.file_type] || TYPE_COLORS[n.category] || "#555555";
}}

// Nebula background cache
let nebulaBg = null;
function drawNebula() {{
  if (!nebulaBg || nebulaBg.w !== Math.floor(W()) || nebulaBg.h !== Math.floor(H())) {{
    const w = Math.floor(W()), h = Math.floor(H());
    const offCanvas = document.createElement("canvas");
    offCanvas.width = w; offCanvas.height = h;
    const oc = offCanvas.getContext("2d");
    oc.fillStyle = "#020208"; oc.fillRect(0,0,w,h);

    // Nebula clouds
    const nebulae = [
      {{ x: w*0.2, y: h*0.3, r: 300, c: "rgba(60,20,80,0.04)" }},
      {{ x: w*0.7, y: h*0.6, r: 250, c: "rgba(20,40,80,0.05)" }},
      {{ x: w*0.5, y: h*0.2, r: 350, c: "rgba(0,60,60,0.03)" }},
    ];
    nebulae.forEach(nb => {{
      const g = oc.createRadialGradient(nb.x, nb.y, 0, nb.x, nb.y, nb.r);
      g.addColorStop(0, nb.c); g.addColorStop(1, "transparent");
      oc.fillStyle = g; oc.fillRect(0,0,w,h);
    }});

    // Stars
    for (let i = 0; i < 350; i++) {{
      const sx = Math.random()*w, sy = Math.random()*h;
      const sz = Math.random()*1.2+0.2;
      oc.globalAlpha = Math.random()*0.3+0.1;
      oc.fillStyle = Math.random()>0.8 ? "#aaddff" : "#ffffff";
      oc.fillRect(sx, sy, sz, sz);
    }}
    oc.globalAlpha = 1;
    nebulaBg = {{ img: offCanvas, w: w, h: h }};
  }}
  ctx.drawImage(nebulaBg.img, 0, 0);
}}

// Concentric ring guides
function drawRings() {{
  ctx.save();
  const center = worldToScreen(0, 0);
  [80, 135, 280, 450].forEach((r, i) => {{
    const sr = r * camZoom;
    ctx.globalAlpha = i === 1 ? 0.06 : 0.04;
    ctx.strokeStyle = i === 1 ? "#6644aa" : "#4488aa";
    ctx.lineWidth = 0.5;
    ctx.beginPath(); ctx.arc(center.sx, center.sy, sr, 0, Math.PI*2); ctx.stroke();
  }});
  ctx.restore();
}}

function drawHexagon(cx, cy, r) {{
  ctx.beginPath();
  for (let i = 0; i < 6; i++) {{
    const angle = Math.PI/3 * i - Math.PI/6;
    const px = cx + r * Math.cos(angle), py = cy + r * Math.sin(angle);
    if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
  }}
  ctx.closePath();
}}

function drawDiamond(cx, cy, r) {{
  ctx.beginPath();
  ctx.moveTo(cx, cy-r); ctx.lineTo(cx+r*0.7, cy);
  ctx.lineTo(cx, cy+r); ctx.lineTo(cx-r*0.7, cy);
  ctx.closePath();
}}

function draw() {{
  frameTime = performance.now() / 1000;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.floor(canvas.clientWidth * dpr);
  canvas.height = Math.floor(canvas.clientHeight * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  drawNebula();
  drawRings();

  const dimAll = highlightMode !== null;

  // Edges
  allEdges.forEach(e => {{
    const s = nodeMap[e.source], t = nodeMap[e.target];
    if (!s || !t || s.hidden || t.hidden) return;
    if (!layers[s.layer] || !layers[t.layer]) return;
    const sp = worldToScreen(s.x, s.y), tp = worldToScreen(t.x, t.y);
    const edgeDim = dimAll && !(selectedNode && (s.id === selectedNode.id || t.id === selectedNode.id));

    const isHwEdge = s.kind === "hardware" || t.kind === "hardware";
    const isAppLink = e.kind === "app-link";
    const isTabLink = e.kind === "tab-link";
    const isChildLink = e.kind === "child-link";
    const liveStr = edgeStrengthMap[edgeKey(e)] || 0;

    const groupedAppEdge = appsGrouped && (s.isApp || t.isApp || s.isAppHub || t.isAppHub);
    if (isTabLink) {{
      const pulse = 0.18 + 0.1 * Math.sin(frameTime * 2.4);
      ctx.globalAlpha = edgeDim ? 0.02 : pulse;
      ctx.strokeStyle = "rgba(80,190,255,0.85)";
      ctx.lineWidth = 0.9;
      ctx.setLineDash([5, 4]);
      ctx.beginPath(); ctx.moveTo(sp.sx, sp.sy); ctx.lineTo(tp.sx, tp.sy); ctx.stroke();
      ctx.setLineDash([]);
    }} else if (isAppLink) {{
      const pulse = 0.08 + 0.06 * Math.sin(frameTime * 1.5);
      ctx.globalAlpha = edgeDim ? 0.01 : pulse;
      ctx.strokeStyle = "#7766bb";
      ctx.lineWidth = 0.6;
      ctx.setLineDash([3, 5]);
      ctx.beginPath(); ctx.moveTo(sp.sx, sp.sy); ctx.lineTo(tp.sx, tp.sy); ctx.stroke();
      ctx.setLineDash([]);
    }} else if (isChildLink) {{
      const pulse = 0.08 + 0.05 * Math.sin(frameTime * 2.1 + liveStr);
      ctx.globalAlpha = edgeDim ? 0.01 : pulse;
      ctx.strokeStyle = s.appColor || t.appColor || nodeColor(s);
      ctx.lineWidth = 0.45;
      ctx.setLineDash([2, 4]);
      ctx.beginPath(); ctx.moveTo(sp.sx, sp.sy); ctx.lineTo(tp.sx, tp.sy); ctx.stroke();
      ctx.setLineDash([]);
    }} else {{
      const baseAlpha = groupedAppEdge ? 0.008 : (isHwEdge ? 0.04 + Math.min(liveStr, 30) * 0.004 : 0.035);
      ctx.globalAlpha = edgeDim ? 0.01 : baseAlpha;
      ctx.strokeStyle = groupedAppEdge ? "rgba(90,140,210,0.35)" : (isHwEdge ? nodeColor(s.kind === "hardware" ? t : s) : "#223344");
      ctx.lineWidth = groupedAppEdge ? 0.25 : (isHwEdge ? 0.4 + Math.min(liveStr, 20) * 0.06 : 0.35);
      ctx.beginPath(); ctx.moveTo(sp.sx, sp.sy); ctx.lineTo(tp.sx, tp.sy); ctx.stroke();
    }}

    // Flow dots — count and speed driven by live strength
    if (!edgeDim && !groupedAppEdge && !isChildLink && liveStr > 0.5) {{
      const dotCount = Math.min(Math.ceil(liveStr / 5), 6);
      const speed = (isTabLink ? 0.11 : 0.05) + liveStr * (isTabLink ? 0.012 : 0.008);
      const dotColor = isTabLink ? "#86dbff" : nodeColor(t.kind === "hardware" ? s : t);
      const dotR = (0.8 + Math.min(liveStr, 15) * 0.06) * camZoom;
      const seed = e.source.length * 7 + e.target.length * 13;
      for (let di = 0; di < dotCount; di++) {{
        const phase = (di / dotCount) + (seed * 0.01);
        const flowT = (frameTime * speed + phase) % 1;
        const fx = sp.sx + (tp.sx - sp.sx) * flowT;
        const fy = sp.sy + (tp.sy - sp.sy) * flowT;
        const dotAlpha = 0.25 + 0.35 * Math.sin(flowT * Math.PI);
        ctx.globalAlpha = dotAlpha;
        ctx.fillStyle = dotColor;
        ctx.beginPath(); ctx.arc(fx, fy, dotR, 0, Math.PI*2); ctx.fill();
      }}
    }}
  }});
  ctx.globalAlpha = 1;

  // Nodes
  allNodes.forEach(n => {{
    if (n.hidden) return;
    if (!layers[n.layer]) return;
    const p = worldToScreen(n.x, n.y);
    const r = n.nodeRadius * camZoom;
    const color = nodeColor(n);
    const dimThis = dimAll && !n.highlight && !n.searchMatch && n !== selectedNode;

    // Aura for hardware
    if (n.kind === "hardware" && !dimThis) {{
      const usage = (n.usage_pct || 0) / 100;
      const pulse = 0.2 + 0.15 * Math.sin(frameTime * 1.5 + n.x * 0.1);
      const auraR = r + (15 + usage * 10) * camZoom;
      const hue = usage > 0.7 ? "255,100,60" : (usage > 0.4 ? "251,191,36" : "0,255,200");
      const grad = ctx.createRadialGradient(p.sx, p.sy, r*0.8, p.sx, p.sy, auraR);
      grad.addColorStop(0, `rgba(${{hue}},${{(pulse + usage*0.2).toFixed(2)}})`);
      grad.addColorStop(1, `rgba(${{hue}},0)`);
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, auraR, 0, Math.PI*2); ctx.fill();
    }}

    // Aura for App Core + Apps
    if (n.isAppHub && !dimThis) {{
      const pulse = 0.24 + 0.18 * Math.sin(frameTime * 1.9);
      const auraR = r + 18 * camZoom;
      const grad = ctx.createRadialGradient(p.sx, p.sy, r*0.7, p.sx, p.sy, auraR);
      grad.addColorStop(0, `rgba(45,212,255,${{(pulse + 0.18).toFixed(2)}})`);
      grad.addColorStop(0.55, `rgba(88,28,255,${{(pulse * 0.42).toFixed(2)}})`);
      grad.addColorStop(1, "rgba(88,28,255,0)");
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, auraR, 0, Math.PI*2); ctx.fill();
      ctx.save();
      ctx.translate(p.sx, p.sy);
      ctx.rotate(-0.36);
      ctx.globalAlpha = 0.72;
      ctx.strokeStyle = "rgba(100,210,255,0.92)";
      ctx.lineWidth = Math.max(1.6, 2.6 * camZoom);
      ctx.beginPath();
      ctx.ellipse(0, 0, r * 2.2, r * 0.82, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.globalAlpha = 0.28;
      ctx.strokeStyle = "rgba(120,110,255,0.88)";
      ctx.lineWidth = Math.max(2.8, 4.8 * camZoom);
      ctx.beginPath();
      ctx.ellipse(0, 0, r * 2.45, r * 0.96, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.restore();
    }}

    // Aura for Apps — branded glow with breathing pulse
    if (n.isApp && n.appGlow && !dimThis) {{
      const usage = ((n.cpu_pct || 0) + (n.mem_pct || 0)) / 200;
      const pulse = (n.inOrbit ? 0.25 : 0.08) + (n.inOrbit ? 0.2 : 0.08) * Math.sin(frameTime * 2.2 + n.x * 0.05);
      const auraR = r + ((n.inOrbit ? 12 : 5) + usage * (n.inOrbit ? 15 : 5)) * camZoom;
      const grad = ctx.createRadialGradient(p.sx, p.sy, r*0.5, p.sx, p.sy, auraR);
      grad.addColorStop(0, n.appGlow.replace("0.4", ((pulse + usage * (n.inOrbit ? 0.3 : 0.1)).toFixed(2))));
      grad.addColorStop(0.6, n.appGlow.replace("0.4", ((pulse * (n.inOrbit ? 0.3 : 0.16)).toFixed(2))));
      grad.addColorStop(1, n.appGlow.replace("0.4", "0"));
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, auraR, 0, Math.PI*2); ctx.fill();
    }}

    if (n.kind === "browser_tab" && !dimThis) {{
      const base = n.tabActive ? 0.22 : 0.1;
      const pulse = base + (n.tabActive ? 0.18 : 0.06) * Math.sin(frameTime * 2.8 + (n.index || 0) * 0.4);
      const auraR = r + (n.tabActive ? 10 : 5) * camZoom;
      const grad = ctx.createRadialGradient(p.sx, p.sy, r * 0.6, p.sx, p.sy, auraR);
      grad.addColorStop(0, `rgba(120,220,255,${{pulse.toFixed(2)}})`);
      grad.addColorStop(1, "rgba(120,220,255,0)");
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, auraR, 0, Math.PI*2); ctx.fill();
    }}

    // Aura for agent processes/files
    if ((n.category === "agent" || n.agent_related) && !dimThis) {{
      const pulse = 0.15 + 0.2 * Math.sin(frameTime * 3 + n.y * 0.05);
      const auraR = r + 8 * camZoom;
      const grad = ctx.createRadialGradient(p.sx, p.sy, r, p.sx, p.sy, auraR);
      grad.addColorStop(0, `rgba(0,255,200,${{pulse.toFixed(2)}})`);
      grad.addColorStop(1, "rgba(0,255,200,0)");
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, auraR, 0, Math.PI*2); ctx.fill();
    }}

    // Aura for sensitive
    if (n.sensitive && !dimThis) {{
      const pulse = 0.2 + 0.25 * Math.sin(frameTime * 2.5 + n.x * 0.02);
      const auraR = r + 7 * camZoom;
      const grad = ctx.createRadialGradient(p.sx, p.sy, r, p.sx, p.sy, auraR);
      grad.addColorStop(0, `rgba(255,60,60,${{pulse.toFixed(2)}})`);
      grad.addColorStop(1, "rgba(255,60,60,0)");
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, auraR, 0, Math.PI*2); ctx.fill();
    }}

    // Vault glow
    if (n.file_type === "vault" && !dimThis) {{
      const pulse = 0.2 + 0.2 * Math.sin(frameTime * 1.8);
      const auraR = r + 9 * camZoom;
      const grad = ctx.createRadialGradient(p.sx, p.sy, r, p.sx, p.sy, auraR);
      grad.addColorStop(0, `rgba(0,255,136,${{pulse.toFixed(2)}})`);
      grad.addColorStop(1, "rgba(0,255,136,0)");
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, auraR, 0, Math.PI*2); ctx.fill();
    }}

    // Process heartbeat (CPU-active processes pulse)
    if (n.kind === "process" && (n.cpu_pct || 0) > 5 && !dimThis) {{
      const beat = 0.3 + 0.3 * Math.abs(Math.sin(frameTime * 4 + n.pid * 0.1));
      const auraR = r + 5 * camZoom;
      const grad = ctx.createRadialGradient(p.sx, p.sy, r, p.sx, p.sy, auraR);
      grad.addColorStop(0, `rgba(100,200,255,${{beat.toFixed(2)}})`);
      grad.addColorStop(1, "rgba(100,200,255,0)");
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, auraR, 0, Math.PI*2); ctx.fill();
    }}

    // Search glow
    if (n.searchMatch) {{
      const pulse = 0.5 + 0.5 * Math.sin(frameTime * 5);
      ctx.globalAlpha = pulse;
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, r + 5*camZoom, 0, Math.PI*2); ctx.stroke();
      ctx.globalAlpha = 1;
    }}

    // Node body
    ctx.globalAlpha = dimThis ? 0.06 : 1;
    const brightness = n.kind === "hardware" ? 1 : (0.45 + (n.importance || n.cpu_pct || 30) / 100 * 0.55);
    ctx.fillStyle = color;
    ctx.globalAlpha *= brightness;

    if (n.kind === "hardware") {{
      drawHexagon(p.sx, p.sy, r);
      ctx.fill();
      ctx.strokeStyle = "rgba(255,255,255,0.2)"; ctx.lineWidth = 1; ctx.stroke();
      if (n.usage_pct > 0) {{
        ctx.save(); ctx.clip();
        const fillH = r * 2 * (n.usage_pct / 100);
        const fillColor = n.usage_pct > 85 ? "rgba(255,80,60,0.4)" : (n.usage_pct > 60 ? "rgba(251,191,36,0.3)" : "rgba(0,255,200,0.25)");
        ctx.fillStyle = fillColor;
        ctx.fillRect(p.sx - r, p.sy + r - fillH, r*2, fillH);
        ctx.restore();
      }}
      ctx.fillStyle = "#111";
      ctx.font = `bold ${{Math.max(8, r*0.55)}}px monospace`;
      ctx.textAlign = "center"; ctx.textBaseline = "middle";
      ctx.fillText(n.label, p.sx, p.sy);
    }} else if (n.isAppHub) {{
      ctx.beginPath();
      ctx.arc(p.sx, p.sy, r, 0, Math.PI*2);
      ctx.fill();
      ctx.strokeStyle = "rgba(255,255,255,0.28)";
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.save();
      ctx.translate(p.sx, p.sy);
      ctx.rotate(-0.35);
      ctx.globalAlpha = dimThis ? 0.05 : 0.82;
      ctx.strokeStyle = "rgba(130,200,255,0.9)";
      ctx.lineWidth = Math.max(1.3, 2 * camZoom);
      ctx.beginPath();
      ctx.ellipse(0, 0, r * 1.75, r * 0.62, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.globalAlpha = dimThis ? 0.03 : 0.22;
      ctx.strokeStyle = "rgba(140,110,255,0.8)";
      ctx.lineWidth = Math.max(2.4, 3.8 * camZoom);
      ctx.beginPath();
      ctx.ellipse(0, 0, r * 1.95, r * 0.72, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.restore();
      ctx.fillStyle = "#021019";
      ctx.font = `bold ${{Math.max(7, r*0.42)}}px monospace`;
      ctx.textAlign = "center"; ctx.textBaseline = "middle";
      ctx.fillText("APPS", p.sx, p.sy);
    }} else if (n.isApp) {{
      if (appsGrouped) {{
        ctx.beginPath();
        ctx.arc(p.sx, p.sy, r, 0, Math.PI*2);
        ctx.fill();
        ctx.strokeStyle = "rgba(255,255,255,0.18)";
        ctx.lineWidth = 0.8;
        ctx.stroke();
        if (n.inOrbit && (n.cpu_pct || n.mem_pct || 0) > 0) {{
          ctx.globalAlpha = dimThis ? 0.05 : 0.72;
          ctx.strokeStyle = "rgba(255,255,255,0.28)";
          ctx.lineWidth = Math.max(0.8, 1.1 * camZoom);
          ctx.beginPath();
          ctx.arc(p.sx, p.sy, r + 3.5 * camZoom, 0, Math.PI * 2);
          ctx.stroke();
        }}
      }} else {{
      // Apps — branded shell with icon badge and stronger outline so they read apart from raw processes
        const rr = r * 1.34;
        const shellColor = n.appColor || color;
        const shellAlpha = dimThis ? 0.18 : 0.92;
        ctx.globalAlpha = shellAlpha;
        ctx.fillStyle = shellColor;
        ctx.beginPath();
        ctx.moveTo(p.sx - rr + 4, p.sy - rr*0.8);
        ctx.arcTo(p.sx + rr, p.sy - rr*0.8, p.sx + rr, p.sy + rr*0.8, 5);
        ctx.arcTo(p.sx + rr, p.sy + rr*0.8, p.sx - rr, p.sy + rr*0.8, 5);
        ctx.arcTo(p.sx - rr, p.sy + rr*0.8, p.sx - rr, p.sy - rr*0.8, 5);
        ctx.arcTo(p.sx - rr, p.sy - rr*0.8, p.sx + rr, p.sy - rr*0.8, 5);
        ctx.closePath();
        ctx.fill();
        ctx.globalAlpha = dimThis ? 0.1 : 0.24;
        ctx.fillStyle = "#020814";
        ctx.fillRect(p.sx - rr * 0.88, p.sy - rr * 0.52, rr * 1.76, rr * 1.02);
        ctx.globalAlpha = dimThis ? 0.08 : 0.95;
        ctx.strokeStyle = "rgba(255,255,255,0.34)"; ctx.lineWidth = 1.15; ctx.stroke();
        ctx.globalAlpha = dimThis ? 0.06 : 0.65;
        ctx.strokeStyle = shellColor;
        ctx.lineWidth = Math.max(1.4, 1.9 * camZoom);
        ctx.beginPath();
        ctx.moveTo(p.sx - rr + 4, p.sy - rr*0.8);
        ctx.arcTo(p.sx + rr, p.sy - rr*0.8, p.sx + rr, p.sy + rr*0.8, 5);
        ctx.arcTo(p.sx + rr, p.sy + rr*0.8, p.sx - rr, p.sy + rr*0.8, 5);
        ctx.arcTo(p.sx - rr, p.sy + rr*0.8, p.sx - rr, p.sy - rr*0.8, 5);
        ctx.arcTo(p.sx - rr, p.sy - rr*0.8, p.sx + rr, p.sy - rr*0.8, 5);
        ctx.closePath();
        ctx.stroke();
        if ((n.cpu_pct || 0) > 0) {{
          const barW = rr * 1.6 * (Math.min(n.cpu_pct, 100) / 100);
          ctx.fillStyle = shellColor;
          ctx.globalAlpha = dimThis ? 0.08 : 0.55;
          ctx.fillRect(p.sx - rr*0.8, p.sy + rr*0.55, barW, 2.4 * camZoom);
        }}
        ctx.globalAlpha = dimThis ? 0.1 : 1;
        ctx.fillStyle = shellColor;
        ctx.beginPath();
        ctx.arc(p.sx - rr * 0.58, p.sy, Math.max(5, r * 0.34), 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = "#031018";
        ctx.font = `bold ${{Math.max(6, r*0.44)}}px monospace`;
        ctx.fillText(n.appIcon || "•", p.sx - rr * 0.58, p.sy + 0.2);
        ctx.fillStyle = "#f8fbff";
        let appFontPx = Math.max(6.2, r * 0.44);
        const minAppFontPx = Math.max(5.1, r * 0.34);
        const maxLabelW = rr * 1.14;
        let appLbl = String(n.label || "");
        ctx.textAlign = "left"; ctx.textBaseline = "middle";
        ctx.font = `bold ${{appFontPx}}px monospace`;
        while (ctx.measureText(appLbl).width > maxLabelW && appFontPx > minAppFontPx) {{
          appFontPx = Math.max(minAppFontPx, appFontPx - 0.45);
          ctx.font = `bold ${{appFontPx}}px monospace`;
        }}
        while (ctx.measureText(appLbl).width > maxLabelW && appLbl.length > 4) {{
          appLbl = appLbl.slice(0, -2) + "\u2026";
        }}
        ctx.fillText(appLbl, p.sx - rr * 0.14, p.sy);
      }}
    }} else if (n.kind === "browser_tab") {{
      const w = Math.max(18, r * 2.7);
      const h = Math.max(10, r * 1.55);
      const rr = 5;
      ctx.beginPath();
      ctx.moveTo(p.sx - w/2 + rr, p.sy - h/2);
      ctx.arcTo(p.sx + w/2, p.sy - h/2, p.sx + w/2, p.sy + h/2, rr);
      ctx.arcTo(p.sx + w/2, p.sy + h/2, p.sx - w/2, p.sy + h/2, rr);
      ctx.arcTo(p.sx - w/2, p.sy + h/2, p.sx - w/2, p.sy - h/2, rr);
      ctx.arcTo(p.sx - w/2, p.sy - h/2, p.sx + w/2, p.sy - h/2, rr);
      ctx.closePath();
      ctx.fill();
      ctx.strokeStyle = "rgba(255,255,255,0.2)";
      ctx.lineWidth = 0.8;
      ctx.stroke();
      if (n.tabActive) {{
        ctx.fillStyle = "rgba(255,255,255,0.26)";
        ctx.fillRect(p.sx - w/2 + 2, p.sy - h/2 + 2, 4, h - 4);
      }}
      ctx.fillStyle = "#e7f4ff";
      ctx.font = `bold ${{Math.max(6, r*0.42)}}px monospace`;
      ctx.textAlign = "center"; ctx.textBaseline = "middle";
      const tabLbl = n.label.length > 14 ? n.label.slice(0,13) + "\u2026" : n.label;
      ctx.fillText(tabLbl, p.sx, p.sy);
    }} else if (n.isSubprocess) {{
      ctx.beginPath();
      ctx.arc(p.sx, p.sy, r * 0.82, 0, Math.PI*2);
      ctx.fill();
      ctx.strokeStyle = "rgba(255,255,255,0.18)";
      ctx.lineWidth = 0.6;
      ctx.stroke();
    }} else if (n.kind === "folder") {{
      ctx.rect(p.sx - r, p.sy - r*0.6, r*2, r*1.2);
      ctx.fill();
    }} else if (n.category === "agent" || n.agent_related) {{
      drawDiamond(p.sx, p.sy, r * 1.3);
      ctx.fill();
    }} else {{
      ctx.beginPath(); ctx.arc(p.sx, p.sy, r, 0, Math.PI*2); ctx.fill();
    }}

    // Outer glow
    if (!dimThis && r > 2) {{
      ctx.globalAlpha = 0.1 * brightness;
      ctx.fillStyle = color;
      ctx.beginPath(); ctx.arc(p.sx, p.sy, r * 2, 0, Math.PI*2); ctx.fill();
    }}

    // Selected ring
    if (n === selectedNode) {{
      ctx.globalAlpha = 1;
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 1.5;
      ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.arc(p.sx, p.sy, r + 4*camZoom, 0, Math.PI*2); ctx.stroke();
      ctx.setLineDash([]);
    }}

    // Labels with background pill for readability
    if (!dimThis) {{
      const showLabel = n.isSubprocess ? false : (n.kind === "hardware" ? false : (n.kind === "browser_tab" ? camZoom > 0.42 : (n.isAppHub ? true : (n.isApp ? ((appsGrouped && n.inOrbit && camZoom > 1.05) || (!appsGrouped && camZoom > 0.62)) : (camZoom > (n.ring < 2 ? 0.9 : 1.8))))));
      if (showLabel) {{
        const fontSize = (n.isApp || n.isAppHub) ? Math.max(8, Math.min(10 * camZoom, 13)) : Math.max(7, Math.min(9 * camZoom, 14));
        ctx.font = `${{fontSize}}px monospace`;
        const maxChars = (n.isApp || n.isAppHub) ? 12 : Math.max(8, Math.floor(28 / camZoom));
        const lbl = n.label.length > maxChars ? n.label.slice(0, maxChars - 1) + "\u2026" : n.label;
        const tw = ctx.measureText(lbl).width;
        const lx = p.sx, ly = p.sy + r + 9 * camZoom;
        const labelAlpha = (n.isApp || n.isAppHub) ? Math.min(1, 0.65 + camZoom * 0.22) : Math.min(1, n.kind === "process" ? (camZoom - 0.8) : (camZoom - 1.5) * 2);
        ctx.globalAlpha = labelAlpha * ((n.isApp || n.isAppHub) ? 0.78 : 0.6);
        ctx.fillStyle = (n.isApp || n.isAppHub) ? "rgba(4,8,18,0.94)" : "#020208";
        ctx.fillRect(lx - tw/2 - 3, ly - fontSize + 1, tw + 6, fontSize + 2);
        ctx.globalAlpha = labelAlpha;
        ctx.fillStyle = (n.isApp || n.isAppHub) ? "#d8e7ff" : "#8899aa";
        ctx.textAlign = "center";
        ctx.fillText(lbl, lx, ly);
        ctx.globalAlpha = 1;
      }}
    }}
    ctx.globalAlpha = 1;
  }});

  requestAnimationFrame(() => {{ simulate(); draw(); }});
}}

// --- Interaction ---
let dragMode = null, dragStart = null, draggedNode = null;
let pointerDown = false, pointerTravel = 0;
let appsGrouped = false;
let lastClickTime = 0, lastClickNode = null;

function getAppNodes() {{
  return allNodes.filter(n => n.isApp && !n.hidden);
}}

function getAppHubNode() {{
  return null;
}}

function appGroupCenter() {{
  const hub = getAppHubNode();
  if (hub) return {{ x: hub.x, y: hub.y }};
  const apps = getAppNodes();
  if (!apps.length) return {{ x: 0, y: 0 }};
  let sx = 0, sy = 0;
  apps.forEach(a => {{ sx += a.x; sy += a.y; }});
  return {{ x: sx / apps.length, y: sy / apps.length }};
}}

canvas.addEventListener("mousedown", e => {{
  pointerDown = true; pointerTravel = 0;
  dragStart = {{ x: e.clientX, y: e.clientY }};
  hideNodeMenu();
  const closest = closestNodeAtClient(e.clientX, e.clientY);

  if (closest) {{
    dragMode = "node"; draggedNode = closest; draggedNode.fixed = true;
    if (draggedNode.id) setAttachedFixed(draggedNode.id, true);
    if ((closest.isApp || closest.isAppHub) && appsGrouped) {{
      getAppNodes().forEach(a => {{ a.fixed = true; }});
      getAppNodes().forEach(a => {{ setAttachedFixed(a.id, true); }});
      const hub = getAppHubNode();
      if (hub) hub.fixed = true;
    }}
    canvas.classList.add("dragging");
  }} else {{
    dragMode = "pan";
  }}
}});

canvas.addEventListener("contextmenu", e => {{
  e.preventDefault();
  const closest = closestNodeAtClient(e.clientX, e.clientY);
  if (closest && (closest.kind === "process" || closest.isApp) && closest.pid) {{
    showNodeMenu(e.clientX, e.clientY, closest);
  }} else {{
    hideNodeMenu();
  }}
}});

canvas.addEventListener("mousemove", e => {{
  if (!pointerDown) return;
  const dx = e.clientX - dragStart.x, dy = e.clientY - dragStart.y;
  pointerTravel += Math.abs(dx) + Math.abs(dy);
  dragStart = {{ x: e.clientX, y: e.clientY }};
  if (dragMode === "node" && draggedNode) {{
    const worldDx = dx / camZoom, worldDy = dy / camZoom;
    if ((draggedNode.isApp || draggedNode.isAppHub) && appsGrouped) {{
      const hub = getAppHubNode();
      if (hub) {{
        hub.x += worldDx;
        hub.y += worldDy;
        hub.homeX = hub.x;
        hub.homeY = hub.y;
      }}
      getAppNodes().forEach(a => {{
        a.x += worldDx;
        a.y += worldDy;
        if (typeof a.groupX === "number") a.groupX += worldDx;
        if (typeof a.groupY === "number") a.groupY += worldDy;
        if (!appsGrouped && typeof a.homeX === "number") {{
          a.homeX += worldDx;
          a.homeY += worldDy;
        }}
        moveAttachedNodes(a.id, worldDx, worldDy);
      }});
    }} else if (draggedNode.isApp && !appsGrouped && typeof draggedNode.homeX === "number") {{
      draggedNode.x += worldDx; draggedNode.y += worldDy;
      draggedNode.homeX = draggedNode.x;
      draggedNode.homeY = draggedNode.y;
      moveAttachedNodes(draggedNode.id, worldDx, worldDy);
    }} else {{
      draggedNode.x += worldDx; draggedNode.y += worldDy;
      moveAttachedNodes(draggedNode.id, worldDx, worldDy);
    }}
  }} else if (dragMode === "pan") {{
    camX -= dx / camZoom; camY -= dy / camZoom;
  }}
}});

canvas.addEventListener("mouseup", e => {{
  if (pointerDown && pointerTravel < 5) {{
    const now = Date.now();
    if (dragMode === "node" && draggedNode) {{
      if (draggedNode.isAppHub) {{
        if (lastClickNode === draggedNode && (now - lastClickTime) < 400) {{
          toggleAppGroup();
          lastClickTime = 0; lastClickNode = null;
        }} else {{
          selectNode(draggedNode);
          lastClickTime = now; lastClickNode = draggedNode;
        }}
      }} else if (draggedNode.kind === "browser_tab" && lastClickNode === draggedNode && (now - lastClickTime) < 400) {{
        openUrlNode(draggedNode);
        lastClickTime = 0; lastClickNode = null;
      }} else if (draggedNode.isApp && lastClickNode === draggedNode && (now - lastClickTime) < 400) {{
        openApp(draggedNode);
        lastClickTime = 0; lastClickNode = null;
      }} else {{
        selectNode(draggedNode);
        lastClickTime = now; lastClickNode = draggedNode;
      }}
    }}
    // empty-space click does NOT close inspector — only X button does
  }}
  if (dragMode === "node" && draggedNode) {{
    draggedNode.fixed = true;
    if (draggedNode.id) setAttachedFixed(draggedNode.id, false);
    if ((draggedNode.isApp || draggedNode.isAppHub) && appsGrouped) {{
      getAppNodes().forEach(a => {{ a.fixed = true; }});
      getAppNodes().forEach(a => {{ setAttachedFixed(a.id, false); }});
      const hub = getAppHubNode();
      if (hub) hub.fixed = true;
    }}
    saveLayout();
  }}
  pointerDown = false; dragMode = null; draggedNode = null;
  canvas.classList.remove("dragging");
}});

canvas.addEventListener("wheel", e => {{
  e.preventDefault();
  const factor = e.deltaY > 0 ? 0.92 : 1.08;
  camZoom = Math.max(0.15, Math.min(25, camZoom * factor));
}}, {{ passive: false }});

function openApp(n) {{
  if (!n.isApp) return;
  const appMap = {{
    cursor: "Cursor", codex: "Codex", safari: "Safari", whatsapp: "WhatsApp",
    telegram: "Telegram", discord: "Discord", chrome: "Google Chrome",
    edge: "Microsoft Edge", spotify: "Spotify", slack: "Slack", xcode: "Xcode", vscode: "Visual Studio Code",
    iterm: "iTerm", firefox: "Firefox", finder: "Finder", explorer: "Explorer", terminal: "Terminal",
  }};
  const appName = appMap[n.appKey] || n.label;
  postJsonWithTimeout("/api/open-app", {{ name: appName }}, 5000).catch(() => {{}});
}}

function openUrlNode(n) {{
  if (!n || !n.url) return;
  postJsonWithTimeout("/api/open-url", {{ url: n.url }}, 5000).catch(() => {{}});
}}

function estimatedSummary(n) {{
  const path = String(n.path || '').toLowerCase();
  const fileType = String(n.file_type || n.kind || '').toLowerCase();
  const bits = [];
  if (n.isApp) {{
    bits.push(`Likely the main local app node for ${{n.label}}.`);
    bits.push(`Tracks runtime pressure from grouped subprocesses and foreground activity.`);
    if ((n.cpu_pct || 0) > 20 || (n.mem_pct || 0) > 5) bits.push(`Currently active enough to matter operationally.`);
  }} else if (n.kind === 'process') {{
    bits.push(`Likely a live operating-system process or grouped subprocess family.`);
    if (String(n.category || '') === 'agent') bits.push(`This process is categorized as agent-related, so it is operationally important.`);
    if ((n.cpu_pct || 0) > 20 || (n.mem_pct || 0) > 5) bits.push(`Resource usage is elevated right now.`);
  }} else if (n.kind === 'browser_tab') {{
    const browserName = browserDisplayName(n.browser || n.appKey);
    if (n.url) bits.push(`Likely an active ${{browserName}} tab mapped from the current browser session.`);
    else bits.push(`Likely a ${{browserName}} window-title fallback because no live tab endpoint was available.`);
    if (n.host) bits.push(`Host: ${{n.host}}.`);
    if (n.tabActive) bits.push(`This is the currently active tab and gets the strongest traffic and resource weighting.`);
    else bits.push(`Resource values are estimated as a share of the parent ${{browserName}} process.`);
  }} else if (n.kind === 'folder') {{
    bits.push(`Likely a container folder grouping related files or artifacts.`);
    if (n.sensitive) bits.push(`Marked sensitive because of path/location or sensitive children.`);
    if (n.agent_related) bits.push(`Likely tied to agent outputs, logs, or runtime state.`);
  }} else if (n.kind === 'hardware') {{
    bits.push(`Live local telemetry node representing a machine resource.`);
  }} else {{
    if (fileType === 'javascript') bits.push(`Likely a JavaScript source or built extension bundle.`);
    else if (fileType === 'python') bits.push(`Likely a Python source, script, or automation entrypoint.`);
    else if (fileType === 'json' || fileType === 'jsonl') bits.push(`Likely structured data, config, logs, or trace output.`);
    else if (fileType === 'vault') bits.push(`Likely a Liquefy vault artifact or archive surface.`);
    else if (fileType) bits.push(`Likely a ${{fileType}} file used by the current workspace.`);
    else bits.push(`Likely a workspace file or generated artifact.`);

    if (path.includes('extension') || path.includes('plugin')) bits.push(`Looks extension/plugin-related, so it can influence tooling behavior.`);
    if (path.includes('config') || path.endsWith('.env')) bits.push(`Looks configuration-related.`);
    if (n.sensitive) bits.push(`Marked sensitive because its type/path could expose credentials, logic, or private data.`);
    if (n.agent_related) bits.push(`Likely connected to agent activity, logs, or outputs.`);
    if ((n.importance || 0) >= 70) bits.push(`Importance is high because the node sits on a critical or high-signal path.`);
  }}
  return bits.slice(0, 3).join(' ');
}}

function renderEstimatedSummary(n) {{
  const text = estimatedSummary(n);
  if (!text) return '';
  return `
    <div style="margin-top:8px">
      <div class="holo-stat">Estimated summary</div>
      <div class="holo-sub" style="line-height:1.45;color:#c7d7ec">${{text}}</div>
    </div>
  `;
}}

function processActionByNodeId(action, nodeId) {{
  const node = nodeMap[String(nodeId || "")];
  if (node) processAction(action, node);
}}

function openUrlNodeById(nodeId) {{
  const node = nodeMap[String(nodeId || "")];
  if (node) openUrlNode(node);
}}

function inspectorPanelId(nodeId) {{
  return "inspector-node-" + String(nodeId || "node").replace(/[^a-zA-Z0-9_-]+/g, "_").slice(0, 72);
}}

function inspectorPanelTitle(n) {{
  const raw = String((n && (n.title || n.label || n.host || n.id)) || "Inspector").trim() || "Inspector";
  return raw.length > 24 ? raw.slice(0, 23) + "…" : raw;
}}

function inspectorStartPosition(index) {{
  const lane = index % 6;
  const column = Math.floor(index / 6) % 2;
  return {{
    top: 88 + lane * 34,
    right: 16 + column * 34,
  }};
}}

function bringPanelToFront(panel) {{
  if (!panel) return;
  inspectorPanelZ += 1;
  panel.style.zIndex = String(inspectorPanelZ);
}}

function ensureInspectorPanel(n) {{
  const nodeId = String(n.id || "");
  let entry = openInspectors.get(nodeId);
  if (entry) return entry;
  const panelId = inspectorPanelId(nodeId);
  const nodeIdJson = JSON.stringify(nodeId);
  const panel = document.createElement("div");
  const pos = inspectorStartPosition(openInspectors.size);
  panel.id = panelId;
  panel.className = "surface-card inspector-card";
  panel.setAttribute("data-panel", panelId);
  panel.setAttribute("data-node-id", nodeId);
  panel.style.top = pos.top + "px";
  panel.style.right = pos.right + "px";
  panel.style.left = "auto";
  panel.style.bottom = "auto";
  panel.innerHTML = `
    <div class="panel-handle" data-drag="${{panelId}}">
      <span class="panel-head"><span class="card-title">INSPECTOR</span></span>
      <span class="panel-actions"><button class="panel-min-btn" onclick="togglePanelCollapsed('${{panelId}}');event.stopPropagation();" title="Minimize">_</button><button class="close-btn" onclick='closeInspector(${{nodeIdJson}});event.stopPropagation();' title="Close">&times;</button><span class="grip">&equiv;</span></span>
    </div>
    <div class="inspector-node-label"></div>
    <div class="inspector-content"></div>
  `;
  inspectorLayer.appendChild(panel);
  entry = {{
    nodeId,
    panelId,
    panel,
    titleEl: panel.querySelector(".inspector-node-label"),
    contentEl: panel.querySelector(".inspector-content"),
  }};
  openInspectors.set(nodeId, entry);
  panelTitles[panelId] = inspectorPanelTitle(n);
  bringPanelToFront(panel);
  return entry;
}}

function renderInspectorPanel(n, options) {{
  if (!n || !n.id) return;
  const opts = options || {{}};
  const entry = ensureInspectorPanel(n);
  entry.panel.setAttribute("data-node-id", String(n.id));
  entry.titleEl.textContent = inspectorPanelTitle(n);
  panelTitles[entry.panelId] = inspectorPanelTitle(n);
  entry.contentEl.innerHTML = inspectorHtml(n);
  if (!opts.preserveCollapsed) {{
    collapsedPanels.delete(entry.panelId);
    entry.panel.classList.remove("panel-collapsed");
    entry.panel.style.display = "";
    entry.panel.style.pointerEvents = "";
  }}
  if (opts.focus !== false) bringPanelToFront(entry.panel);
  renderPanelDock();
  updateRestoreBtn();
}}

function refreshInspectorForNode(nodeId) {{
  const entry = openInspectors.get(String(nodeId || ""));
  if (!entry) return;
  const liveNode = nodeMap[String(nodeId || "")];
  if (!liveNode) {{
    closeInspector(nodeId);
    return;
  }}
  renderInspectorPanel(liveNode, {{
    focus: false,
    preserveCollapsed: collapsedPanels.has(entry.panelId),
  }});
}}

function refreshOpenInspectors() {{
  Array.from(openInspectors.keys()).forEach((nodeId) => refreshInspectorForNode(nodeId));
}}

function inspectorHtml(n) {{
  const nodeIdJson = JSON.stringify(String(n.id || ""));
  let html = "";

  if (n.kind === "hardware") {{
    html = `
      <div class="holo-title">${{n.label}}</div>
      <div class="holo-sub">${{n.detail || ''}}</div>
      <div class="holo-stat">Utilization: <span class="holo-val">${{n.usage_pct || 0}}%</span></div>
      <div class="holo-bar"><div class="holo-bar-fill" style="width:${{n.usage_pct||0}}%;background:${{barColor(n.usage_pct||0)}}"></div></div>
      <div class="holo-stat">${{n.sub || ''}}</div>
      ${{renderEstimatedSummary(n)}}
    `;
  }} else if (n.isAppHub) {{
    const appNodes = getAppNodes();
    const activeApps = appNodes.filter(a => a.inOrbit);
    const idleApps = appNodes.filter(a => !a.inOrbit);
    const hotApps = appNodes
      .slice()
      .sort((a, b) => ((b.cpu_pct || 0) + (b.mem_pct || 0) * 4) - ((a.cpu_pct || 0) + (a.mem_pct || 0) * 4))
      .slice(0, 5)
      .map(a => `<span class="tag" style="background:${{a.appColor || '#334455'}};color:#031018">${{a.label}}</span>`)
      .join(" ");
    html = `
      <div class="holo-title" style="color:#7be7ff">APPS</div>
      <div class="holo-sub">${{appsGrouped ? 'saturn ring view' : 'expanded cluster view'}} &middot; ${{appNodes.length}} tracked apps</div>
      <div class="holo-stat">Orbiting now: <span class="holo-val">${{activeApps.length}}</span> &middot; Swarm: <span class="holo-val">${{idleApps.length}}</span></div>
      <div class="holo-stat">Single-click selects this card. Double-click the hub toggles expand/collapse.</div>
      <div class="holo-stat">Double-click a satellite to launch/focus its app.</div>
      <div style="margin:8px 0;display:flex;gap:6px;flex-wrap:wrap">${{hotApps || '<span class="tag" style="background:#223344;color:#aaccdd">no apps</span>'}}</div>
      <div style="margin-top:8px;display:grid;grid-template-columns:1fr auto auto;gap:6px;font-size:10px;color:#b8cbe4;">
        ${{appNodes.slice().sort((a,b)=>((b.cpu_pct||0)+(b.mem_pct||0)*4)-((a.cpu_pct||0)+(a.mem_pct||0)*4)).map(a => `
          <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${{a.label}}</div>
          <div style="text-align:right;">CPU ${{(a.cpu_pct||0).toFixed(1)}}%</div>
          <div style="text-align:right;">RAM ${{(a.mem_pct||0).toFixed(1)}}%</div>
        `).join('')}}
      </div>
      ${{renderEstimatedSummary(n)}}
    `;
  }} else if (n.isApp) {{
    const isClosing = n.pendingAction === 'term';
    const isKilling = n.pendingAction === 'kill';
    const followerCount = followerCountForNode(n.id);
    const linkedTabCount = ["safari", "chrome", "edge", "firefox"].includes(String(n.appKey || "")) ? allNodes.filter(x => x.kind === 'browser_tab' && !x.hidden && x.parentId === n.id).length : 0;
    const browserName = browserDisplayName(n.appKey);
    html = `
      <div class="holo-title" style="color:${{n.appColor || '#00ffcc'}}">${{n.label}}</div>
      <div class="holo-sub">APP &middot; PID ${{n.pid || '?'}} &middot; ${{n.instance_count > 1 ? n.instance_count + ' instances' : 'single'}}</div>
      <div><span class="tag" style="background:${{n.appColor}};color:#000">${{n.appKey}}</span><span class="tag" style="background:${{CAT_COLORS[n.category]||'#6b7280'}};color:#000">${{n.category}}</span></div>
      <div class="holo-stat">CPU: <span class="holo-val">${{n.cpu_pct || 0}}%</span></div>
      <div class="holo-bar"><div class="holo-bar-fill" style="width:${{Math.min(n.cpu_pct||0, 100)}}%;background:${{n.appColor}}"></div></div>
      <div class="holo-stat">Approx CPU load: <span class="holo-val">${{formatCoreEquiv(n.cpu_pct || 0)}}</span></div>
      <div class="holo-stat">Memory: <span class="holo-val">${{n.mem_pct || 0}}%</span></div>
      <div class="holo-bar"><div class="holo-bar-fill" style="width:${{Math.min(n.mem_pct||0, 100)}}%;background:${{n.appColor}}88"></div></div>
      <div class="holo-stat">Approx RAM: <span class="holo-val">${{formatRamFromPct(n.mem_pct || 0)}}</span></div>
      ${{followerCount ? `<div class="holo-stat">Sticky subprocess orbitals: <span class="holo-val">${{followerCount}}</span></div>` : ''}}
      ${{linkedTabCount ? `<div class="holo-stat">${{browserName}}-linked tabs: <span class="holo-val">${{linkedTabCount}}</span></div>` : ''}}
      <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap"><button onclick='processActionByNodeId("term", ${{nodeIdJson}})' ${{isClosing || isKilling ? 'disabled' : ''}} class="${{isClosing ? 'action-pending' : ''}}" style="background:rgba(30,10,10,0.9);border:1px solid rgba(255,80,80,0.25);color:#ffb4b4;padding:5px 8px;border-radius:6px;cursor:pointer;font-family:inherit;font-size:10px;">${{isClosing ? 'Closing...' : 'Force Close'}}</button><button onclick='processActionByNodeId("kill", ${{nodeIdJson}})' ${{isClosing || isKilling ? 'disabled' : ''}} class="${{isKilling ? 'action-pending' : ''}}" style="background:rgba(30,8,8,0.95);border:1px solid rgba(255,60,60,0.35);color:#ffd0d0;padding:5px 8px;border-radius:6px;cursor:pointer;font-family:inherit;font-size:10px;">${{isKilling ? 'Killing...' : 'Kill Hard'}}</button></div>
      ${{renderEstimatedSummary(n)}}
    `;
  }} else if (n.kind === "browser_tab") {{
    const browserName = browserDisplayName(n.browser || n.appKey);
    html = `
      <div class="holo-title" style="color:${{n.tabActive ? '#7ed8ff' : '#2aa6ff'}}">${{n.title || n.label}}</div>
      <div class="holo-sub">${{browserName}} tab &middot; ${{esc(n.host || 'unknown host')}}</div>
      <div><span class="tag" style="background:${{n.tabActive ? '#7ed8ff' : '#2aa6ff'}};color:#031018">${{n.tabActive ? 'ACTIVE TAB' : 'tab'}}</span><span class="tag" style="background:#22374d;color:#d2ebff">window ${{n.window || '?'}} / tab ${{n.index || '?'}}</span></div>
      <div class="holo-stat">Traffic pulse: <span class="holo-val">${{((n.trafficScore || 0) * 100).toFixed(0)}}%</span></div>
      <div class="holo-bar"><div class="holo-bar-fill" style="width:${{Math.min(100, (n.trafficScore || 0) * 100)}}%;background:#55cfff"></div></div>
      <div class="holo-stat">${{browserName}} CPU share: <span class="holo-val">${{(n.cpu_pct || 0).toFixed(1)}}%</span></div>
      <div class="holo-bar"><div class="holo-bar-fill" style="width:${{Math.min(n.cpu_pct||0, 100)}}%;background:#38e0c4"></div></div>
      <div class="holo-stat">Approx CPU load: <span class="holo-val">${{formatCoreEquiv(n.cpu_pct || 0)}}</span></div>
      <div class="holo-stat">${{browserName}} memory share: <span class="holo-val">${{(n.mem_pct || 0).toFixed(1)}}%</span></div>
      <div class="holo-bar"><div class="holo-bar-fill" style="width:${{Math.min(n.mem_pct||0, 100)}}%;background:#74a7ff"></div></div>
      <div class="holo-stat">Approx ${{browserName}} RAM: <span class="holo-val">${{formatRamFromPct(n.mem_pct || 0)}}</span></div>
      <div class="holo-sub">Share values are estimated from the current ${{browserName}} family load, not total machine usage.</div>
      ${{n.url ? '' : `<div class="holo-sub">This tab node is a browser-window fallback title because no live browser debug endpoint was detected.</div>`}}
      <div class="holo-stat" style="font-size:9px;word-break:break-all;color:#4d6d89;margin-top:4px">${{privacyText(n.url || '')}}</div>
      ${{n.url ? `<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap"><button onclick='openUrlNodeById(${{nodeIdJson}})' style="background:rgba(9,22,38,0.94);border:1px solid rgba(80,180,255,0.28);color:#d7eeff;padding:5px 8px;border-radius:6px;cursor:pointer;font-family:inherit;font-size:10px;">Open URL</button></div>` : ''}}
      ${{renderEstimatedSummary(n)}}
    `;
  }} else if (n.kind === "process" && n.isSubprocess) {{
    const catColor = n.appColor || CAT_COLORS[n.category] || "#6b7280";
    const parent = nodeMap[n.parentProcessId] || null;
    html = `
      <div class="holo-title">${{n.label}}</div>
      <div class="holo-sub">SUBPROCESS &middot; PID ${{n.pid || 'grouped'}} &middot; sticky orbital follower</div>
      <div><span class="tag" style="background:${{catColor}};color:#000">${{n.category}}</span><span class="tag" style="background:#22374d;color:#d2ebff">subprocess</span></div>
      <div class="holo-stat">Parent: <span class="holo-val">${{parent ? parent.label : 'detached'}}</span></div>
      <div class="holo-stat">Estimated CPU share: <span class="holo-val">${{n.cpu_pct || 0}}%</span></div>
      <div class="holo-stat">Estimated RAM share: <span class="holo-val">${{n.mem_pct || 0}}%</span></div>
      <div class="holo-sub">This node stays sticky to its root process when the root is moved.</div>
      ${{renderEstimatedSummary(n)}}
    `;
  }} else if (n.kind === "process") {{
    const catColor = CAT_COLORS[n.category] || "#6b7280";
    const isClosing = n.pendingAction === 'term';
    const isKilling = n.pendingAction === 'kill';
    const followerCount = followerCountForNode(n.id);
    html = `
      <div class="holo-title">${{n.label}}</div>
      <div class="holo-sub">PID ${{n.pid || '?'}} &middot; ${{n.instance_count > 1 ? n.instance_count + ' instances' : 'single'}}</div>
      <div><span class="tag" style="background:${{catColor}};color:#000">${{n.category}}</span></div>
      <div class="holo-stat">CPU: <span class="holo-val">${{n.cpu_pct || 0}}%</span></div>
      <div class="holo-bar"><div class="holo-bar-fill" style="width:${{Math.min(n.cpu_pct||0, 100)}}%;background:#00ffcc"></div></div>
      <div class="holo-stat">Approx CPU load: <span class="holo-val">${{formatCoreEquiv(n.cpu_pct || 0)}}</span></div>
      <div class="holo-stat">Memory: <span class="holo-val">${{n.mem_pct || 0}}%</span></div>
      <div class="holo-bar"><div class="holo-bar-fill" style="width:${{Math.min(n.mem_pct||0, 100)}}%;background:#818cf8"></div></div>
      <div class="holo-stat">Approx RAM: <span class="holo-val">${{formatRamFromPct(n.mem_pct || 0)}}</span></div>
      ${{followerCount ? `<div class="holo-stat">Sticky subprocess orbitals: <span class="holo-val">${{followerCount}}</span></div>` : ''}}
      <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap"><button onclick='processActionByNodeId("term", ${{nodeIdJson}})' ${{isClosing || isKilling ? 'disabled' : ''}} class="${{isClosing ? 'action-pending' : ''}}" style="background:rgba(30,10,10,0.9);border:1px solid rgba(255,80,80,0.25);color:#ffb4b4;padding:5px 8px;border-radius:6px;cursor:pointer;font-family:inherit;font-size:10px;">${{isClosing ? 'Closing...' : 'Force Close'}}</button><button onclick='processActionByNodeId("kill", ${{nodeIdJson}})' ${{isClosing || isKilling ? 'disabled' : ''}} class="${{isKilling ? 'action-pending' : ''}}" style="background:rgba(30,8,8,0.95);border:1px solid rgba(255,60,60,0.35);color:#ffd0d0;padding:5px 8px;border-radius:6px;cursor:pointer;font-family:inherit;font-size:10px;">${{isKilling ? 'Killing...' : 'Kill Hard'}}</button></div>
      ${{renderEstimatedSummary(n)}}
    `;
  }} else {{
    const color = nodeColor(n);
    let tags = `<span class="tag" style="background:${{color}};color:#000">${{n.file_type || n.kind}}</span>`;
    if (n.sensitive) tags += `<span class="tag" style="background:#ff4444;color:#fff">SENSITIVE</span>`;
    if (n.agent_related) tags += `<span class="tag" style="background:#00ffcc;color:#000">AGENT</span>`;
    if (n.is_log) tags += `<span class="tag" style="background:#6b7280;color:#fff">LOG</span>`;
    if (n.file_type === "vault") tags += `<span class="tag" style="background:#00ff88;color:#000">VAULT</span>`;
    html = `
      <div class="holo-title">${{n.label}}</div>
      <div class="holo-sub">${{n.kind}} &middot; ${{formatBytes(n.size||0)}} &middot; importance ${{n.importance||0}}/100</div>
      <div style="margin:4px 0">${{tags}}</div>
      ${{n.importance > 50 ? '<div class="holo-stat">Importance:</div><div class="holo-bar"><div class="holo-bar-fill" style="width:'+(n.importance||0)+'%;background:#fbbf24"></div></div>' : ''}}
      <div class="holo-stat" style="font-size:9px;word-break:break-all;color:#445566;margin-top:4px">${{privacyText(n.path || '', 'path')}}</div>
      ${{renderEstimatedSummary(n)}}
    `;
  }}

  // Folder inspector — show child count, types, path
  if (n.kind === "folder") {{
    const childFiles = (fileGraph.nodes || []).filter(c => c.parent === n.id);
    const typeSet = {{}};
    childFiles.forEach(c => {{ typeSet[c.file_type || "unknown"] = (typeSet[c.file_type || "unknown"] || 0) + 1; }});
    const typeList = Object.entries(typeSet).sort((a,b) => b[1]-a[1]).map(([t,c]) => `<span class="tag" style="background:#334455;color:#aabbcc">${{t}} (${{c}})</span>`).join(" ");
    html = `
      <div class="holo-title">${{n.label}}</div>
      <div class="holo-sub">folder &middot; ${{childFiles.length}} items &middot; depth ${{n.depth || 0}}</div>
      <div style="margin:6px 0">${{typeList || '<span style="color:#556677">empty</span>'}}</div>
      ${{n.sensitive ? '<div><span class="tag" style="background:#ff4444;color:#fff">SENSITIVE</span></div>' : ''}}
      ${{n.agent_related ? '<div><span class="tag" style="background:#00ffcc;color:#000">AGENT</span></div>' : ''}}
      <div class="holo-stat" style="font-size:9px;word-break:break-all;color:#445566;margin-top:4px">${{n.path || ''}}</div>
      ${{renderEstimatedSummary(n)}}
    `;
  }}

  return html;
}}

// --- Hologram Inspector ---
function selectNode(n) {{
  if (!n || !n.id) return;
  selectedNode = n;
  renderInspectorPanel(n);
}}

function closeInspector(nodeId) {{
  const targetId = String(nodeId || (selectedNode && selectedNode.id) || "");
  if (!targetId) return;
  const entry = openInspectors.get(targetId);
  if (!entry) {{
    if (selectedNode && selectedNode.id === targetId) selectedNode = null;
    return;
  }}
  collapsedPanels.delete(entry.panelId);
  delete panelTitles[entry.panelId];
  entry.panel.remove();
  openInspectors.delete(targetId);
  if (selectedNode && selectedNode.id === targetId) selectedNode = null;
  renderPanelDock();
  updateRestoreBtn();
  saveLayout();
}}

// --- Controls ---
function resetView() {{
  camX = 0; camY = 0; camZoom = 0.8;
  highlightMode = null;
  allNodes.forEach(n => {{ n.highlight = false; n.searchMatch = false; }});
  // Keep inspector open if user has one selected
}}

function toggleLayer(layer) {{
  layers[layer] = !layers[layer];
  const btn = document.getElementById("btn-" + layer);
  if (btn) btn.classList.toggle("active");
  allNodes.forEach(n => {{ if (n.layer === layer) n.hidden = !layers[layer]; }});
}}

function highlightAgents() {{
  if (highlightMode === "agent") {{
    highlightMode = null;
    allNodes.forEach(n => {{ n.highlight = false; }});
  }} else {{
    highlightMode = "agent";
    allNodes.forEach(n => {{
      n.highlight = n.category === "agent" || n.agent_related || false;
    }});
  }}
}}

function toggleAppGroup() {{
  return;
}}

function reLayout() {{
  allNodes.forEach(n => {{
    if (n.kind !== "hardware") {{
      n.fixed = false;
      if (n.isAppHub) {{
        n.x = (n.homeX || APP_HUB_HOME.x) + (Math.random() - 0.5) * 8;
        n.y = (n.homeY || APP_HUB_HOME.y) + (Math.random() - 0.5) * 8;
      }} else if (n.isApp && appsGrouped && typeof n.groupX === "number") {{
        n.x = n.groupX + (Math.random() - 0.5) * 6;
        n.y = n.groupY + (Math.random() - 0.5) * 6;
      }} else if (n.isApp && typeof n.homeX === "number") {{
        n.x = n.homeX + (Math.random() - 0.5) * 8;
        n.y = n.homeY + (Math.random() - 0.5) * 8;
      }} else {{
        const angle = Math.random() * Math.PI * 2;
        const ring = n.ring || 0;
        const r = ring === 0.5 ? 115 + Math.random()*20 : (ring === 1 ? 240 + Math.random()*60 : (ring === 2 ? 450 + Math.random()*80 : 50));
        n.x = Math.cos(angle) * r; n.y = Math.sin(angle) * r;
      }}
    }}
  }});
  saveLayout();
}}

document.getElementById("search-input").addEventListener("input", e => {{
  const q = e.target.value.toLowerCase().trim();
  allNodes.forEach(n => {{
    n.searchMatch = q.length > 0 && ((n.label||'').toLowerCase().includes(q) || (n.path||'').toLowerCase().includes(q) || (n.detail||'').toLowerCase().includes(q) || (n.category||'').toLowerCase().includes(q));
  }});
  if (q.length > 0) {{
    highlightMode = "search";
    allNodes.forEach(n => {{ n.highlight = n.searchMatch; }});
  }} else {{
    highlightMode = null;
    allNodes.forEach(n => {{ n.highlight = false; n.searchMatch = false; }});
  }}
}});

// --- Privacy toggle ---
let privacyHidden = true;
loadAlarmPrefs();
function togglePrivacy() {{
  privacyHidden = !privacyHidden;
  document.querySelectorAll("#hud .private").forEach(el => {{
    el.classList.toggle("revealed", !privacyHidden);
  }});
  document.getElementById("privacy-toggle").style.opacity = privacyHidden ? 0.4 : 1;
}}

// --- Edge strength cache (dynamic, keyed by edge source+target) ---
allEdges.forEach(e => {{ edgeStrengthMap[edgeKey(e)] = e.strength || 0; }});
let pollInFlight = false;

function updateEdgeStrengths() {{
  allEdges.forEach(e => {{
    const s = nodeMap[e.source], t = nodeMap[e.target];
    if (!s || !t) return;
    let str = 0;
    if (e.kind === "uses") {{
      const proc = s.kind === "process" ? s : (t.kind === "process" ? t : null);
      if (proc) {{
        if (e.source === "hw_cpu" || e.target === "hw_cpu") str = proc.cpu_pct || 0;
        else if (e.source === "hw_ram" || e.target === "hw_ram") str = proc.mem_pct || 0;
        else str = (proc.cpu_pct || 0) + (proc.mem_pct || 0);
      }}
    }} else {{
      str = e.strength || 0.5;
    }}
    edgeStrengthMap[edgeKey(e)] = str;
  }});
}}

// --- Live polling ---
function pollStats() {{
  if (pollInFlight || pendingActionKeys.size > 0 || pendingPanicActions.size > 0) return;
  pollInFlight = true;
  fetchJsonWithTimeout("/api/stats").then(data => {{
    sysData.monitor_rows = data.monitor_rows || [];
    sysData.ai_usage = data.ai_usage || {{}};
    sysData.threat = data.threat || {{}};
    sysData.browser_tabs = data.browser_tabs || [];
    // CPU
    document.getElementById("hud-cpu").textContent = data.cpu.usage_pct + "%";
    document.getElementById("hud-cpu-bar").style.width = data.cpu.usage_pct + "%";
    document.getElementById("hud-cpu-bar").style.background = barColor(data.cpu.usage_pct);
    // GPU
    if (data.gpu) {{
      document.getElementById("hud-gpu").textContent = (data.gpu.model || "N/A") + " " + (data.gpu.usage_pct || 0) + "%";
      document.getElementById("hud-gpu-bar").style.width = (data.gpu.usage_pct || 0) + "%";
      document.getElementById("hud-gpu-bar").style.background = barColor(data.gpu.usage_pct || 0);
      const gpuNode = nodeMap["hw_gpu"];
      if (gpuNode) {{ gpuNode.usage_pct = data.gpu.usage_pct; gpuNode.sub = (data.gpu.metal || "") + " \\u00b7 " + data.gpu.usage_pct + "%"; }}
    }}
    // RAM
    document.getElementById("hud-ram").textContent = data.memory.used_gb + "/" + data.memory.total_gb + " GB";
    document.getElementById("hud-ram-bar").style.width = data.memory.usage_pct + "%";
    document.getElementById("hud-ram-bar").style.background = barColor(data.memory.usage_pct);
    // Network stats + speed
    if (data.net_stats) {{
      const now = Date.now();
      const dt = (now - prevNetTime) / 1000;
      if (dt > 0.5) {{
        const inSpeed = (data.net_stats.bytes_in - prevNetIn) / dt;
        const outSpeed = (data.net_stats.bytes_out - prevNetOut) / dt;
        document.getElementById("hud-net-speed").textContent = formatSpeed(inSpeed + outSpeed);
        prevNetIn = data.net_stats.bytes_in;
        prevNetOut = data.net_stats.bytes_out;
        prevNetTime = now;
      }}
      document.getElementById("hud-net-in").textContent = formatBytes(data.net_stats.bytes_in);
      document.getElementById("hud-net-out").textContent = formatBytes(data.net_stats.bytes_out);
      document.getElementById("hud-net-pkts-in").textContent = formatPkts(data.net_stats.pkts_in);
      document.getElementById("hud-net-pkts-out").textContent = formatPkts(data.net_stats.pkts_out);
      // Update net node activity based on speed
      const netNode = nodeMap["hw_net"];
      if (netNode) {{
        const totalSpeed = ((data.net_stats.bytes_in - prevNetIn) + (data.net_stats.bytes_out - prevNetOut));
        const activity = Math.min(totalSpeed / 5000000, 100);
        netNode.usage_pct = Math.max(activity, data.network && data.network.active ? 10 : 0);
      }}
    }}

    const cpuNode = nodeMap["hw_cpu"];
    if (cpuNode) {{ cpuNode.usage_pct = data.cpu.usage_pct; cpuNode.sub = data.cpu.cores + " cores \\u00b7 " + data.cpu.usage_pct + "%"; }}
    const ramNode = nodeMap["hw_ram"];
    if (ramNode) {{ ramNode.usage_pct = data.memory.usage_pct; ramNode.detail = data.memory.used_gb + "/" + data.memory.total_gb + " GB"; }}

    syncProcessNodes(data.processes || []);
    clusterAppFollowers();
    syncSubprocessNodes(data.processes || []);

    (data.processes || []).forEach(p => {{
      const nid = p.id || ("proc_" + p._group);
      const existing = nodeMap[nid];
      if (existing) {{
        const cpuNorm = Math.min(p.cpu_pct || 0, 100);
        const memNorm = Math.min(p.mem_pct || 0, 100);
        existing.cpu_pct = cpuNorm;
        existing.mem_pct = memNorm;
        existing.instance_count = p.instance_count || 1;
        existing.sub = "CPU " + cpuNorm + "% \\u00b7 MEM " + memNorm + "%";
        if (existing.isApp) {{
          existing.nodeRadius = 12 + Math.min(cpuNorm + memNorm, 60) * 0.08;
        }} else {{
          existing.nodeRadius = 4 + Math.min(cpuNorm + memNorm, 40) * 0.3;
        }}
      }}
    }});

    recomputeAppOrbit(data.processes || []);
    syncBrowserTabs(data.browser_tabs || []);
    updateEdgeStrengths();
    renderUsageSurface(data.monitor_rows || []);
    renderAgentOps(data.agent_ops || {{}});
    renderTaskProgress(data.task_progress || {{}});
    renderActivityFeed(data.activity_feed || []);
    renderAiLedger(data.ai_usage || {{}});
    renderThreatCard(data.threat || {{}});
    refreshOpenInspectors();
  }}).catch(() => {{}}).finally(() => {{
    pollInFlight = false;
  }});
}}
setInterval(pollStats, 2500);

// --- Draggable panels + localStorage persistence ---
const PERSIST_KEY = "galactic_command_layout";
const collapsedPanels = new Set();
const panelTitles = {{
  "usage": "Usage",
  "agent-ops": "Agents",
  "task": "Tasks",
  "activity": "Activity",
  "ai": "AI",
  "threat": "Threat",
  "ops": "Ops",
  "guide": "Guide",
}};

function renderPanelDock() {{
  const dock = document.getElementById("panel-dock");
  if (!dock) return;
  dock.innerHTML = "";
  Array.from(collapsedPanels).forEach((panelId) => {{
    const pill = document.createElement("button");
    pill.className = "dock-pill";
    pill.textContent = panelTitles[panelId] || panelId;
    pill.onclick = () => togglePanelCollapsed(panelId, false);
    dock.appendChild(pill);
  }});
}}

function updateRestoreBtn() {{
  const btn = document.getElementById("btn-restore-panels");
  if (btn) btn.style.display = collapsedPanels.size > 0 ? "" : "none";
}}

function restoreAllPanels() {{
  Array.from(collapsedPanels).forEach((panelId) => togglePanelCollapsed(panelId, false));
}}

function togglePanelCollapsed(panelId, forceState) {{
  const panel = document.querySelector('[data-panel="' + panelId + '"]');
  if (!panel) return;
  const shouldCollapse = forceState === undefined ? !collapsedPanels.has(panelId) : !!forceState;
  if (shouldCollapse) {{
    collapsedPanels.add(panelId);
    panel.classList.add("panel-collapsed");
  }} else {{
    collapsedPanels.delete(panelId);
    panel.classList.remove("panel-collapsed");
  }}
  panel.style.display = shouldCollapse ? "none" : "";
  panel.style.pointerEvents = shouldCollapse ? "none" : "";
  renderPanelDock();
  updateRestoreBtn();
  saveLayout();
}}

function loadLayout() {{
  try {{
    const saved = localStorage.getItem(PERSIST_KEY);
    if (!saved) return;
    const layout = JSON.parse(saved);
    Object.entries(layout).forEach(([panelId, pos]) => {{
      if (panelId.startsWith("_")) return;
      const el = document.querySelector('[data-panel="' + panelId + '"]');
      if (el && pos && pos.left !== undefined) {{
        el.style.left = pos.left + "px"; el.style.top = pos.top + "px";
        el.style.right = "auto"; el.style.bottom = "auto";
      }}
    }});
    if (layout._camX !== undefined) {{ camX = layout._camX; camY = layout._camY; camZoom = layout._camZoom || 0.8; }}
    if (layout._privacy === false) {{ privacyHidden = true; togglePrivacy(); }}
    if (layout._layers) {{
      Object.entries(layout._layers).forEach(([k, v]) => {{
        if (layers[k] !== v) toggleLayer(k);
      }});
    }}
    collapsedPanels.clear();
    (layout._collapsed || []).forEach((panelId) => {{
      const panel = document.querySelector('[data-panel="' + panelId + '"]');
      if (panel) {{
        collapsedPanels.add(panelId);
        panel.classList.add("panel-collapsed");
        panel.style.display = "none";
        panel.style.pointerEvents = "none";
      }}
    }});
    renderPanelDock();
    updateRestoreBtn();
    appsGrouped = false;
    if (layout._nodes) {{
      Object.entries(layout._nodes).forEach(([nodeId, pos]) => {{
        const n = nodeMap[nodeId];
        if (!n || !pos) return;
        if (typeof pos.x === "number" && typeof pos.y === "number") {{
          if (n.isAppHub) {{
            n.x = pos.x;
            n.y = pos.y;
            n.homeX = pos.x;
            n.homeY = pos.y;
          }} else if (n.isApp) {{
            n.homeX = pos.x;
            n.homeY = pos.y;
          }} else {{
            n.x = pos.x;
            n.y = pos.y;
          }}
        }}
        if (!n.isApp && typeof pos.fixed === "boolean") n.fixed = pos.fixed;
      }});
    }}
  }} catch(e) {{}}
}}

function saveLayout() {{
  try {{
    const layout = {{
      _camX: camX,
      _camY: camY,
      _camZoom: camZoom,
      _privacy: privacyHidden,
      _layers: {{...layers}},
      _collapsed: Array.from(collapsedPanels),
      _appsGrouped: appsGrouped,
      _nodes: {{}},
    }};
    document.querySelectorAll("[data-panel]").forEach(el => {{
      const id = el.getAttribute("data-panel");
      const rect = el.getBoundingClientRect();
      layout[id] = {{ left: Math.round(rect.left), top: Math.round(rect.top) }};
    }});
    allNodes.forEach(n => {{
      if (n.isApp || n.isAppHub || n.fixed) {{
        layout._nodes[n.id] = {{
          x: Math.round(n.x * 100) / 100,
          y: Math.round(n.y * 100) / 100,
          fixed: !!n.fixed,
        }};
      }}
    }});
    localStorage.setItem(PERSIST_KEY, JSON.stringify(layout));
  }} catch(e) {{}}
}}

let _dragPanel = null, _dragPanelStart = null;

document.addEventListener("mousedown", e => {{
  if (nodeMenu.style.display === "block" && !e.target.closest("#node-menu")) hideNodeMenu();
  const handle = e.target.closest("[data-drag]");
  if (!handle) return;
  e.preventDefault(); e.stopPropagation();
  const panelId = handle.getAttribute("data-drag");
  const panel = document.querySelector('[data-panel="' + panelId + '"]');
  if (!panel) return;
  const rect = panel.getBoundingClientRect();
  panel.style.left = rect.left + "px"; panel.style.top = rect.top + "px";
  panel.style.right = "auto"; panel.style.bottom = "auto";
  _dragPanel = panel;
  _dragPanelStart = {{ x: e.clientX - rect.left, y: e.clientY - rect.top }};
}}, true);

document.addEventListener("mousemove", e => {{
  if (!_dragPanel) return;
  e.preventDefault();
  const nx = Math.max(0, Math.min(window.innerWidth - 60, e.clientX - _dragPanelStart.x));
  const ny = Math.max(0, Math.min(window.innerHeight - 30, e.clientY - _dragPanelStart.y));
  _dragPanel.style.left = nx + "px"; _dragPanel.style.top = ny + "px";
}}, true);

document.addEventListener("mouseup", e => {{
  if (_dragPanel) {{ _dragPanel = null; saveLayout(); }}
}}, true);

setInterval(saveLayout, 15000);
window.addEventListener("beforeunload", saveLayout);
loadLayout();
recomputeAppOrbit(sysData.processes || []);

simulate();
draw();
</script>
</body>
</html>"""


def _merge_graphs(graphs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge multiple scan graphs into one, deduplicating by node id."""
    merged_nodes = []
    merged_edges = []
    seen_ids: set = set()
    total_files = 0
    total_folders = 0
    total_bytes = 0
    type_counts: Dict[str, int] = {}
    sensitive = 0
    agent_related = 0

    for g in graphs:
        for n in g.get("nodes", []):
            if n["id"] not in seen_ids:
                seen_ids.add(n["id"])
                merged_nodes.append(n)
        for e in g.get("edges", []):
            merged_edges.append(e)
        s = g.get("stats", {})
        total_files += s.get("total_files", 0)
        total_folders += s.get("total_folders", 0)
        total_bytes += s.get("total_bytes", 0)
        sensitive += s.get("sensitive_count", 0)
        agent_related += s.get("agent_related_count", 0)
        for t, c in s.get("type_breakdown", {}).items():
            type_counts[t] = type_counts.get(t, 0) + c

    return {
        "root": graphs[0]["root"] if graphs else "",
        "root_name": graphs[0].get("root_name", "") if graphs else "",
        "generated_at_utc": _utc_now(),
        "nodes": merged_nodes,
        "edges": merged_edges,
        "stats": {
            "total_files": total_files,
            "total_folders": total_folders,
            "total_bytes": total_bytes,
            "type_breakdown": dict(sorted(type_counts.items(), key=lambda x: -x[1])),
            "sensitive_count": sensitive,
            "agent_related_count": agent_related,
        },
    }


def cmd_live(args: argparse.Namespace) -> int:
    target = Path(args.path).expanduser().resolve()
    if not target.is_dir():
        print(f"ERROR: not a directory: {target}", file=sys.stderr)
        return 1
    workspace = None
    if getattr(args, "workspace", None):
        ws = Path(args.workspace).expanduser().resolve()
        if ws.is_dir():
            workspace = ws

    scan_dirs = [target]
    extra = getattr(args, "also", None)
    if extra:
        for p in extra:
            ep = Path(p).expanduser().resolve()
            if ep.is_dir() and ep != target:
                scan_dirs.append(ep)

    desktop = Path.home() / "Desktop"
    if getattr(args, "desktop", False) and desktop.is_dir() and desktop.resolve() != target:
        scan_dirs.append(desktop.resolve())

    per_dir_budget = max(50, args.max_files // len(scan_dirs))
    graphs = []
    print("Scanning filesystem...")
    for d in scan_dirs:
        g = _scan_directory(d, max_files=per_dir_budget, max_depth=args.max_depth)
        print(f"  {d.name}: {g['stats']['total_files']} files, {g['stats']['total_folders']} folders")
        graphs.append(g)

    file_graph = _merge_graphs(graphs) if len(graphs) > 1 else graphs[0]
    print(f"  Total: {file_graph['stats']['total_files']} files")

    print("Gathering system info...")
    history_summary = _load_history_guard_summary(workspace)
    sys_snapshot = _gather_system_snapshot(target, workspace)
    sys_snapshot["threat"] = _build_threat_summary(history_summary, file_graph, sys_snapshot.get("ai_usage", {}), workspace)
    sys_snapshot["agent_ops"] = _build_agent_ops_summary(sys_snapshot.get("processes", []), history_summary, sys_snapshot["threat"])
    sys_snapshot["task_progress"] = _build_task_progress_summary(history_summary)
    sys_snapshot["activity_feed"] = _build_activity_feed(history_summary, sys_snapshot.get("monitor_rows", []), sys_snapshot["threat"])
    print(f"  {len(sys_snapshot['processes'])} processes, {sys_snapshot['cpu']['cores']} CPU cores")

    title = "Parad0x Command"
    api_token = secrets.token_urlsafe(24)
    html_content = _render_live_html(sys_snapshot, file_graph, title, api_token=api_token)

    port = args.port

    class Handler(http.server.BaseHTTPRequestHandler):
        def _require_api_auth(self) -> bool:
            error = _validate_local_api_request(self.headers, port, api_token)
            if error:
                _send_json_response(self, 403, {"ok": False, "error": error})
                return False
            return True

        def do_GET(self):
            req = urllib.parse.urlparse(self.path)
            req_path = req.path
            if req_path == "/api/stats":
                if not self._require_api_auth():
                    return
                data = _gather_system_snapshot(target, workspace)
                history = _load_history_guard_summary(workspace)
                data["threat"] = _build_threat_summary(history, file_graph, data.get("ai_usage", {}), workspace)
                data["agent_ops"] = _build_agent_ops_summary(data.get("processes", []), history, data["threat"])
                data["task_progress"] = _build_task_progress_summary(history)
                data["activity_feed"] = _build_activity_feed(history, data.get("monitor_rows", []), data["threat"])
                _send_json_response(self, 200, data)
            elif req_path.startswith("/api/"):
                _send_json_response(self, 405, {"ok": False, "error": "POST required"})
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(html_content.encode("utf-8"))

        def do_POST(self):
            req = urllib.parse.urlparse(self.path)
            req_path = req.path
            if not req_path.startswith("/api/"):
                _send_json_response(self, 404, {"ok": False, "error": "Not found"})
                return
            if not self._require_api_auth():
                return

            payload = _read_json_request_body(self)

            if req_path == "/api/process-action":
                action = str(payload.get("action", "term") or "term")
                if action in {"term-agents", "kill-agents"}:
                    result = _agent_process_action_result("kill" if action == "kill-agents" else "term")
                else:
                    group = str(payload.get("group", "") or "").strip()
                    if group:
                        result = _group_process_action_result(group, action)
                    else:
                        pid = int(payload.get("pid", 0) or 0)
                        result = _process_action_result(pid, action)
                _send_json_response(self, 200, result)
            elif req_path == "/api/halt":
                action = str(payload.get("action", "verify") or "verify")
                if action == "write":
                    result = _halt_action(workspace, _load_history_guard_summary(workspace))
                else:
                    result = _verify_halt_action(workspace)
                _send_json_response(self, 200, result)
            elif req_path == "/api/network":
                action = str(payload.get("action", "off") or "off")
                if action == "off":
                    net = _get_network_info()
                    if net.get("interface") and str(net.get("interface")) != "unknown":
                        wifi_profile = _windows_wifi_profile_info(str(net.get("interface") or "")) if platform.system() == "Windows" and str(net.get("type")) == "WiFi" else {}
                        _NETWORK_PANIC_STATE = {
                            "system": platform.system(),
                            "interface": str(net.get("interface") or ""),
                            "network_type": str(net.get("type") or "unknown"),
                            "service": _macos_network_service_for_interface(str(net.get("interface") or "")) if platform.system() == "Darwin" else "",
                            "wifi_profile": str(wifi_profile.get("profile") or ""),
                        }
                    result = {
                        "ok": True,
                        "action": action,
                        "scheduled": True,
                        "interface": net.get("interface", "unknown"),
                        "network_type": net.get("type", "unknown"),
                        "detail": "network cut scheduled",
                    }

                    def _deferred_network_cut() -> None:
                        try:
                            time.sleep(0.25)
                            _network_action_result("off")
                        except Exception:
                            pass

                    _send_json_response(self, 200, result)
                    try:
                        self.wfile.flush()
                    except Exception:
                        pass
                    threading.Thread(target=_deferred_network_cut, daemon=True).start()
                    return

                result = _network_action_result(action)
                _send_json_response(self, 200, result)
            elif req_path == "/api/open-app":
                app_name = str(payload.get("name", "") or "")
                if app_name:
                    if platform.system() == "Darwin":
                        subprocess.Popen(["open", "-a", app_name])
                    elif platform.system() == "Linux":
                        subprocess.Popen(["xdg-open", app_name])
                _send_json_response(self, 200, {"ok": True})
            elif req_path == "/api/open-url":
                url = str(payload.get("url", "") or "")
                result = _open_url_result(url)
                _send_json_response(self, 200, result)
            else:
                _send_json_response(self, 404, {"ok": False, "error": "Not found"})

        def log_message(self, fmt, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"\n  PARAD0X COMMAND live at {url}")
    print(f"  System organism: {sys_snapshot['hostname']} ({sys_snapshot['os']})")
    print(f"  Ctrl+C to stop\n")

    wallpaper_mode = getattr(args, "wallpaper", False)

    def _launch_browser():
        if wallpaper_mode:
            _launch_wallpaper(url, port)
        else:
            webbrowser.open(url)

    threading.Timer(0.5, _launch_browser).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_native(args: argparse.Namespace) -> int:
    # Compatibility alias: restored safepoint renderer is the live graph-first shell.
    return cmd_live(args)


def _launch_wallpaper(url: str, port: int) -> None:
    """Launch galactic command as a desktop wallpaper / kiosk."""
    system = platform.system()

    if system == "Darwin":
        plash = Path("/Applications/Plash.app")
        if plash.exists():
            print("  Plash detected — setting as desktop wallpaper...")
            subprocess.Popen(["open", "-a", "Plash", url])
            return

        chrome = Path("/Applications/Google Chrome.app")
        if chrome.exists():
            print("  Launching Chrome kiosk (fullscreen, no UI)...")
            subprocess.Popen([
                str(chrome / "Contents/MacOS/Google Chrome"),
                f"--app={url}",
                "--start-fullscreen",
                "--disable-session-crashed-bubble",
                "--disable-infobars",
                f"--user-data-dir=/tmp/galactic-kiosk-{port}",
            ])
            return

        print("  Launching Safari fullscreen...")
        script = f'''
            tell application "Safari"
                activate
                open location "{url}"
                delay 1
                tell application "System Events"
                    keystroke "f" using {{command down, control down}}
                end tell
            end tell
        '''
        subprocess.Popen(["osascript", "-e", script])

    elif system == "Linux":
        for browser in ["google-chrome", "google-chrome-stable", "chromium-browser", "chromium"]:
            if shutil.which(browser):
                print(f"  Launching {browser} kiosk (fullscreen, no UI)...")
                subprocess.Popen([
                    browser,
                    f"--app={url}",
                    "--start-fullscreen",
                    "--disable-session-crashed-bubble",
                    "--disable-infobars",
                    f"--user-data-dir=/tmp/galactic-kiosk-{port}",
                ])
                return

        xwinwrap = shutil.which("xwinwrap")
        if xwinwrap:
            print("  xwinwrap detected — embedding as desktop wallpaper...")
            subprocess.Popen([
                xwinwrap, "-ov", "-fs", "-st", "-sp", "-b", "-nf",
                "--", "midori", "-e", "Fullscreen", "-a", url,
            ])
            return

        print("  Falling back to default browser fullscreen...")
        webbrowser.open(url)
    else:
        webbrowser.open(url)


# ---------------------------------------------------------------------------
# Desktop Replica — 1:1 battle station
# ---------------------------------------------------------------------------

def _get_screen_resolution() -> Tuple[int, int]:
    """Get logical screen resolution. Returns (width, height)."""
    system = platform.system()
    if system == "Darwin":
        out = _run_cmd(["system_profiler", "SPDisplaysDataType"])
        m = re.search(r"Resolution:\s+(\d+)\s*x\s*(\d+)", out)
        if m:
            return int(m.group(1)) // 2, int(m.group(2)) // 2
    elif system == "Linux":
        out = _run_cmd(["xrandr"])
        m = re.search(r"(\d+)x(\d+)\s+\d+\.\d+\*", out)
        if m:
            return int(m.group(1)), int(m.group(2))
    return 1920, 1080


def _get_desktop_items(desktop_dir: Path) -> List[Dict[str, Any]]:
    """List items on the desktop with file metadata."""
    items = []
    try:
        for entry in sorted(desktop_dir.iterdir()):
            if entry.name.startswith("."):
                continue
            try:
                stat = entry.stat()
                ftype = "folder" if entry.is_dir() else _classify_file(entry)
                items.append({
                    "name": entry.name,
                    "path": str(entry),
                    "is_dir": entry.is_dir(),
                    "file_type": ftype,
                    "size": stat.st_size if not entry.is_dir() else 0,
                    "mtime": stat.st_mtime,
                    "sensitive": _is_sensitive(entry),
                    "agent_related": _is_agent_related(entry),
                    "importance": _importance_score(entry, stat.st_size if not entry.is_dir() else 0, ftype),
                })
            except OSError:
                continue
    except OSError:
        pass
    return items


def _build_desktop_grid(
    items: List[Dict[str, Any]],
    screen_w: int,
    screen_h: int,
) -> List[Dict[str, Any]]:
    """Arrange items in macOS-style desktop grid (right-to-left, top-to-bottom)."""
    icon_spacing_x = 100
    icon_spacing_y = 100
    margin = 20
    menu_h = 25
    dock_h = 70

    usable_w = screen_w - margin * 2
    usable_h = screen_h - menu_h - dock_h - margin * 2
    rows = max(1, usable_h // icon_spacing_y)
    cols = max(1, usable_w // icon_spacing_x)

    positioned = []
    for idx, item in enumerate(items):
        col = cols - 1 - (idx // rows)
        row = idx % rows
        x = margin + col * icon_spacing_x + icon_spacing_x // 2
        y = menu_h + margin + row * icon_spacing_y + icon_spacing_y // 2
        item["grid_x"] = x
        item["grid_y"] = y
        positioned.append(item)

    return positioned


def _render_battlestation_html(
    desktop_items: List[Dict[str, Any]],
    system_data: Dict[str, Any],
    screen_w: int,
    screen_h: int,
    title: str,
    file_graph: Optional[Dict[str, Any]] = None,
    history_data: Optional[Dict[str, Any]] = None,
    background_path: Optional[str] = None,
    api_token: str = "",
) -> str:
    items_json = json.dumps(desktop_items)
    sys_json = json.dumps(system_data)
    file_json = json.dumps(file_graph or {"nodes": [], "edges": [], "stats": {}})
    history_json = json.dumps(history_data or {"enabled": False, "providers": [], "alerts": []})
    background_json = json.dumps(background_path or "")
    cat_colors_json = json.dumps(CATEGORY_COLORS)
    type_colors_json = json.dumps(TYPE_COLORS)
    api_token_json = json.dumps(api_token)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html, body {{
    width: 100%; height: 100%; overflow: hidden;
    background: #020208;
    font-family: 'SF Mono', 'Fira Code', monospace; color: #ccc;
    background-image: var(--deck-bg-image);
    background-size: cover;
    background-position: center center;
    background-repeat: no-repeat;
  }}
  canvas {{ display: block; width: 100%; height: 100%; cursor: default; }}
  canvas.dragging {{ cursor: grabbing; }}

  #hud {{
    position: fixed; top: 0; left: 0; right: 0; height: 26px; z-index: 20;
    background: rgba(2,2,12,0.85); border-bottom: 1px solid rgba(100,220,255,0.08);
    display: flex; align-items: center; padding: 0 14px; font-size: 10px;
    backdrop-filter: blur(16px); gap: 16px;
  }}
  #hud .title {{ color: #00ffcc; font-weight: 800; letter-spacing: 1px; }}
  #hud .stat {{ color: #445566; }}
  #hud .val {{ color: #8899aa; }}
  #hud .bar-track {{ display: inline-block; width: 50px; height: 4px; background: rgba(255,255,255,0.06); border-radius: 2px; vertical-align: middle; margin-left: 4px; overflow: hidden; }}
  #hud .bar-fill {{ height: 100%; border-radius: 2px; transition: width 0.6s; }}
  #hud .private {{ filter: blur(4px); transition: filter 0.2s; user-select: none; }}
  #hud .private.revealed {{ filter: none; }}
  #hud .eye-btn {{ background: none; border: none; color: #334455; cursor: pointer; font-size: 11px; padding: 0 3px; }}
  #hud .eye-btn:hover {{ color: #88aacc; }}

  #dock {{
    position: fixed; bottom: 0; left: 50%; transform: translateX(-50%); z-index: 20;
    background: rgba(2,2,12,0.8); border: 1px solid rgba(100,220,255,0.08);
    border-bottom: none; border-radius: 12px 12px 0 0;
    display: flex; align-items: center; padding: 6px 16px; gap: 8px;
    backdrop-filter: blur(16px); font-size: 9px;
  }}
  .dock-item {{
    display: flex; flex-direction: column; align-items: center; gap: 2px;
    padding: 4px 8px; border-radius: 6px; cursor: pointer; transition: all 0.15s;
  }}
  .dock-item:hover {{ background: rgba(100,220,255,0.08); }}
  .dock-dot {{ width: 16px; height: 16px; border-radius: 3px; }}
  .dock-label {{ color: #556677; font-size: 8px; max-width: 50px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

  #inspector {{
    position: fixed; top: 40px; right: 16px; z-index: 20;
    background: rgba(2,2,12,0.95); border: 1px solid rgba(100,220,255,0.2);
    border-radius: 12px; padding: 16px 20px; font-size: 11px; line-height: 1.6;
    backdrop-filter: blur(20px); max-width: 350px; display: none;
    box-shadow: 0 0 40px rgba(0,255,200,0.05), inset 0 0 30px rgba(0,0,0,0.3);
  }}
  #inspector .holo-title {{ color: #00ffcc; font-size: 14px; font-weight: 800; text-shadow: 0 0 8px rgba(0,255,200,0.3); }}
  #inspector .holo-sub {{ color: #556677; font-size: 10px; margin: 2px 0 6px; }}
  #inspector .holo-stat {{ color: #8899aa; margin: 2px 0; }}
  #inspector .holo-val {{ color: #ddeeff; font-weight: 600; }}
  #inspector .holo-bar {{ width: 100%; height: 8px; background: rgba(255,255,255,0.05); border-radius: 4px; margin: 3px 0 5px; overflow: hidden; }}
  #inspector .holo-bar-fill {{ height: 100%; border-radius: 4px; transition: width 0.4s; }}
  #inspector .tag {{ display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 9px; margin: 1px 2px; font-weight: 700; }}
  #inspector .close {{ position: absolute; top: 8px; right: 12px; color: #445566; cursor: pointer; font-size: 14px; }}
  #inspector .close:hover {{ color: #aabbcc; }}

  #search {{
    position: fixed; top: 34px; left: 50%; transform: translateX(-50%); z-index: 15;
  }}
  #search input {{
    background: rgba(5,5,18,0.92); border: 1px solid rgba(100,220,255,0.12);
    color: #ddeeff; padding: 5px 14px; border-radius: 14px; width: 240px;
    font-size: 10px; font-family: inherit; outline: none;
  }}
  #search input:focus {{ border-color: rgba(0,255,200,0.4); }}
  #search input::placeholder {{ color: #334455; }}

  #agent-panel {{
    position: fixed; top: 38px; left: 14px; z-index: 20;
    width: 360px; max-width: calc(100vw - 28px);
    background: rgba(2,2,12,0.92);
    border: 1px solid rgba(100,220,255,0.18);
    border-radius: 12px;
    padding: 10px 12px;
    font-size: 10px;
    line-height: 1.45;
    color: #a7bbcf;
    backdrop-filter: blur(14px);
    box-shadow: 0 0 30px rgba(0, 180, 255, 0.08);
  }}
  #agent-panel .row {{ display: flex; justify-content: space-between; gap: 8px; margin-bottom: 6px; }}
  #agent-panel .k {{ color: #4f6a84; }}
  #agent-panel .v {{ color: #d5e6f5; font-weight: 600; }}
  #agent-panel .warn {{ color: #ff9d9d; }}
  #agent-panel .ok {{ color: #68e2be; }}
  #agent-panel .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
  #agent-panel .sep {{ border-top: 1px dashed rgba(120,160,200,0.2); margin: 7px 0; }}
  #agent-panel .alert {{
    border-left: 2px solid rgba(255,100,100,0.7);
    padding-left: 6px; margin: 4px 0; color: #ffb4b4;
  }}
  #agent-panel .hint {{ color: #7391ae; font-size: 9px; }}
</style>
</head>
<body>

<div id="hud">
  <span class="title">BATTLE STATION</span>
  <span class="stat">CPU</span><span class="val" id="hud-cpu">-</span>
  <span class="bar-track"><span class="bar-fill" id="hud-cpu-bar" style="width:0%;background:#00ffcc"></span></span>
  <span class="stat">RAM</span><span class="val" id="hud-ram">-</span>
  <span class="bar-track"><span class="bar-fill" id="hud-ram-bar" style="width:0%;background:#818cf8"></span></span>
  <span class="stat">SSD</span><span class="val" id="hud-disk">-</span>
  <span class="bar-track"><span class="bar-fill" id="hud-disk-bar" style="width:0%;background:#fbbf24"></span></span>
  <span class="stat">Net</span><span class="val private" id="hud-net">-</span>
  <button class="eye-btn" id="privacy-toggle" onclick="togglePrivacy()">&#x1F441;</button>
</div>

<div id="dock"></div>
<div id="inspector"><span class="close" onclick="closeInspector()">&times;</span><div id="inspector-content"></div></div>
<div id="agent-panel"></div>
<div id="search"><input type="text" placeholder="Search..." id="search-input"></div>

<canvas id="station"></canvas>

<script>
const API_TOKEN = {api_token_json};
const desktopItems = {items_json};
const sysData = {sys_json};
const fileGraph = {file_json};
let historyData = {history_json};
const desktopBgPath = {background_json};
const CAT_COLORS = {cat_colors_json};
const TYPE_COLORS = {type_colors_json};
const SCREEN_W = {screen_w}, SCREEN_H = {screen_h};
const canvas = document.getElementById("station");
const ctx = canvas.getContext("2d");
const agentPanel = document.getElementById("agent-panel");
const hasDesktopBg = Boolean(desktopBgPath);

if (desktopBgPath) {{
  document.documentElement.style.setProperty("--deck-bg-image", `url("${{desktopBgPath}}")`);
}} else {{
  document.documentElement.style.setProperty("--deck-bg-image", "none");
}}

function formatBytes(b) {{
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b/1024).toFixed(1) + " KB";
  if (b < 1073741824) return (b/1048576).toFixed(1) + " MB";
  return (b/1073741824).toFixed(2) + " GB";
}}
function barColor(p) {{ return p > 85 ? "#ff4444" : p > 60 ? "#fbbf24" : "#00ffcc"; }}

function escHtml(s) {{
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}}

function fetchJsonWithToken(url, timeoutMs = 12000) {{
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, {{
    signal: controller.signal,
    cache: "no-store",
    headers: {{ "X-Parad0x-Token": API_TOKEN }},
  }})
    .then(async r => {{
      const data = await r.json().catch(() => ({{ ok: false, error: `HTTP ${{r.status}}` }}));
      if (!r.ok) {{
        const err = new Error(String((data && data.error) || `HTTP ${{r.status}}`));
        err.response = data;
        throw err;
      }}
      return data;
    }})
    .finally(() => clearTimeout(timer));
}}

function renderHistoryPanel() {{
  if (!agentPanel) return;
  if (!historyData || !historyData.enabled) {{
    agentPanel.innerHTML = `
      <div class="row"><span class="k">COMMAND DECK</span><span class="v">standalone</span></div>
      <div class="hint">Pass --workspace to bind history-guard telemetry and activity map.</div>
    `;
    return;
  }}
  const providers = Array.isArray(historyData.providers) ? historyData.providers : [];
  const enabled = providers.filter(p => p && p.enabled);
  const failing = providers.filter(p => p && p.last_ok === false);
  const active = providers.find(p => p && p.id === historyData.active_provider) || null;
  const last = historyData.last_action || null;
  const alerts = Array.isArray(historyData.alerts) ? historyData.alerts.slice(0, 4) : [];
  const statusClass = failing.length > 0 ? "warn" : "ok";
  const statusLabel = failing.length > 0 ? `degraded (${{failing.length}} fail)` : "green";
  const risky24 = Number(historyData.risky_actions_24h || 0);
  const riskyClass = risky24 > 0 ? "warn" : "ok";
  const command = last ? escHtml(String(last.command || "").slice(0, 120)) : "n/a";
  agentPanel.innerHTML = `
    <div class="row"><span class="k">COMMAND DECK</span><span class="v ${{statusClass}}">${{statusLabel}}</span></div>
    <div class="row"><span class="k">Workspace</span><span class="v mono">${{escHtml(historyData.workspace || "n/a")}}</span></div>
    <div class="row"><span class="k">Providers</span><span class="v">${{enabled.length}}/${{providers.length}}</span></div>
    <div class="row"><span class="k">Active Provider</span><span class="v">${{escHtml(active ? active.id : "none")}}</span></div>
    <div class="row"><span class="k">Risky (24h)</span><span class="v ${{riskyClass}}">${{risky24}}</span></div>
    <div class="sep"></div>
    <div class="k">Last Action</div>
    <div class="v mono">${{last ? escHtml(last.type || "action") : "none"}}</div>
    <div class="hint mono">${{command}}</div>
    ${{alerts.length ? `<div class="sep"></div>${{alerts.map(a => `<div class="alert">${{escHtml(a)}}</div>`).join("")}}` : ""}}
  `;
}}

// HUD init
document.getElementById("hud-cpu").textContent = sysData.cpu.usage_pct + "%";
document.getElementById("hud-cpu-bar").style.width = sysData.cpu.usage_pct + "%";
document.getElementById("hud-cpu-bar").style.background = barColor(sysData.cpu.usage_pct);
document.getElementById("hud-ram").textContent = sysData.memory.used_gb + "/" + sysData.memory.total_gb + "G";
document.getElementById("hud-ram-bar").style.width = sysData.memory.usage_pct + "%";
document.getElementById("hud-ram-bar").style.background = barColor(sysData.memory.usage_pct);
document.getElementById("hud-disk").textContent = sysData.disk.free_gb + "G free";
document.getElementById("hud-disk-bar").style.width = sysData.disk.usage_pct + "%";
document.getElementById("hud-disk-bar").style.background = barColor(sysData.disk.usage_pct);
document.getElementById("hud-net").textContent = sysData.network.active ? sysData.network.type + " " + sysData.network.ip : "Off";

let privacyHidden = true;
function togglePrivacy() {{
  privacyHidden = !privacyHidden;
  document.querySelectorAll(".private").forEach(el => el.classList.toggle("revealed", !privacyHidden));
  document.getElementById("privacy-toggle").style.opacity = privacyHidden ? 0.4 : 1;
}}

// Build dock from top processes
const dockEl = document.getElementById("dock");
const topProcs = sysData.processes.filter(p => p.cpu_pct > 1 || p.category === "agent" || p.category === "ide").slice(0, 12);
topProcs.forEach(p => {{
  const col = CAT_COLORS[p.category] || "#6b7280";
  const d = document.createElement("div");
  d.className = "dock-item";
  d.innerHTML = `<div class="dock-dot" style="background:${{col}};box-shadow:0 0 6px ${{col}}"></div><div class="dock-label">${{p.name}}</div>`;
  d.onclick = () => selectProc(p);
  dockEl.appendChild(d);
}});

// Map desktop items to canvas space
// Canvas covers the viewport; we scale desktop coords to fit
const nodes = [];
const scaleX = () => canvas.clientWidth / SCREEN_W;
const scaleY = () => canvas.clientHeight / SCREEN_H;

desktopItems.forEach((item, i) => {{
  nodes.push({{
    ...item,
    id: "desk_" + i,
    cx: item.grid_x,
    cy: item.grid_y,
    selected: false,
    searchMatch: false,
    hover: false,
    activity: false,
  }});
}});

function applyHistoryActivity() {{
  const activeProvider = String((historyData && historyData.active_provider) || "").toLowerCase();
  const last = (historyData && historyData.last_action) || null;
  const risky = Boolean(last && last.risky);
  nodes.forEach(n => {{
    const path = String(n.path || "").toLowerCase();
    const name = String(n.name || "").toLowerCase();
    const providerMatch = activeProvider && (path.includes(`/${{activeProvider}}/`) || name.includes(activeProvider));
    const actionMatch = last && String(last.type || "").toLowerCase().includes("gate") && (n.sensitive || n.agent_related);
    n.activity = Boolean(providerMatch || actionMatch);
    n.risky_hot = Boolean(risky && (n.sensitive || n.agent_related));
  }});
}}
renderHistoryPanel();
applyHistoryActivity();

// Nebula bg
let nebulaBg = null;
function drawNebula(w, h) {{
  if (!nebulaBg || nebulaBg.w !== w || nebulaBg.h !== h) {{
    const off = document.createElement("canvas");
    off.width = w; off.height = h;
    const oc = off.getContext("2d");
    oc.fillStyle = hasDesktopBg ? "rgba(2,2,8,0.22)" : "#020208";
    oc.fillRect(0,0,w,h);
    const nbs = [
      {{ x:w*0.15, y:h*0.25, r:400, c:"rgba(40,15,60,0.03)" }},
      {{ x:w*0.75, y:h*0.65, r:350, c:"rgba(15,30,60,0.04)" }},
      {{ x:w*0.5, y:h*0.15, r:300, c:"rgba(0,40,50,0.025)" }},
      {{ x:w*0.3, y:h*0.8, r:200, c:"rgba(50,20,40,0.03)" }},
    ];
    nbs.forEach(nb => {{
      const g = oc.createRadialGradient(nb.x,nb.y,0,nb.x,nb.y,nb.r);
      g.addColorStop(0, hasDesktopBg ? nb.c.replace("0.03", "0.018").replace("0.04", "0.022").replace("0.025", "0.015") : nb.c);
      g.addColorStop(1,"transparent");
      oc.fillStyle = g; oc.fillRect(0,0,w,h);
    }});
    for (let i = 0; i < 500; i++) {{
      oc.globalAlpha = Math.random()*0.25+0.05;
      oc.fillStyle = Math.random()>0.85 ? "#aaddff" : "#ffffff";
      oc.fillRect(Math.random()*w, Math.random()*h, Math.random()*1.2+0.2, Math.random()*1.2+0.2);
    }}
    oc.globalAlpha = 1;
    nebulaBg = {{ img: off, w, h }};
  }}
  ctx.drawImage(nebulaBg.img, 0, 0);
}}

function nodeColor(n) {{
  if (n.sensitive) return "#ff4444";
  if (n.file_type === "vault") return "#00ff88";
  if (n.agent_related) return "#00ffcc";
  if (n.is_dir) return "#fbbf24";
  return TYPE_COLORS[n.file_type] || "#667788";
}}

// === GALACTIC BALL — background organism ===
const ballNodes = [];
const ballEdges = [];
const ballMap = {{}};
const BALL_CX = () => canvas.clientWidth * 0.45;
const BALL_CY = () => canvas.clientHeight * 0.5;
const BALL_SCALE = () => Math.min(canvas.clientWidth, canvas.clientHeight) * 0.0018;

// Hardware nodes at center
const hwIcons = {{ CPU: "\u2699", RAM: "\u25A6", SSD: "\u25C9", WiFi: "\u25CE", Ethernet: "\u25CE" }};
sysData.hardware.forEach((hw, i) => {{
  const angle = (i / sysData.hardware.length) * Math.PI * 2 - Math.PI / 2;
  const n = {{
    ...hw, x: Math.cos(angle) * 40, y: Math.sin(angle) * 40,
    vx: 0, vy: 0, fixed: true, hidden: false, ring: 0, nodeRadius: 14,
  }};
  ballNodes.push(n); ballMap[n.id] = n;
}});

// Process nodes — middle ring
sysData.processes.forEach((p, i) => {{
  const angle = (i / Math.max(sysData.processes.length, 1)) * Math.PI * 2 + Math.random() * 0.3;
  const r = 130 + Math.random() * 50;
  const n = {{
    ...p, id: "proc_" + p._group,
    x: Math.cos(angle) * r, y: Math.sin(angle) * r,
    vx: 0, vy: 0, fixed: false, hidden: false, ring: 1,
    nodeRadius: 3 + Math.min(p.cpu_pct + p.mem_pct, 20) * 0.3,
  }};
  ballNodes.push(n); ballMap[n.id] = n;
  if (p.cpu_pct > 1) ballEdges.push({{ source: "hw_cpu", target: n.id, kind: "uses", strength: p.cpu_pct }});
  if (p.mem_pct > 0.5) ballEdges.push({{ source: "hw_ram", target: n.id, kind: "uses", strength: p.mem_pct }});
}});

// File nodes — outer ring (top by importance)
const bgFiles = (fileGraph.nodes || []).filter(n => n.kind === "file")
  .sort((a, b) => (b.importance || 0) - (a.importance || 0)).slice(0, 60);
bgFiles.forEach((fn, i) => {{
  const angle = (i / Math.max(bgFiles.length, 1)) * Math.PI * 2;
  const r = 260 + Math.random() * 50;
  const n = {{
    ...fn, x: Math.cos(angle) * r, y: Math.sin(angle) * r,
    vx: 0, vy: 0, fixed: false, hidden: false, ring: 2,
    nodeRadius: 1.5 + (fn.importance || 10) / 100 * 2,
    category: fn.sensitive ? "sensitive" : (fn.agent_related ? "agent" : fn.file_type),
  }};
  ballNodes.push(n); ballMap[n.id] = n;
  ballEdges.push({{ source: "hw_disk", target: n.id, kind: "stores", strength: 0.3 }});
}});

function simulateBall() {{
  const rep = 300, damp = 0.8;
  for (let i = 0; i < ballNodes.length; i++) {{
    const ni = ballNodes[i];
    if (ni.fixed) continue;
    let fx = 0, fy = 0;
    for (let j = 0; j < ballNodes.length; j++) {{
      if (i === j) continue;
      const dx = ni.x - ballNodes[j].x, dy = ni.y - ballNodes[j].y;
      const d = Math.sqrt(dx*dx + dy*dy) + 1;
      const same = ni.ring === ballNodes[j].ring;
      const f = (same ? rep * 0.5 : rep * 0.2) / (d * d);
      fx += (dx/d) * f; fy += (dy/d) * f;
    }}
    const tR = ni.ring === 1 ? 140 : (ni.ring === 2 ? 270 : 40);
    const cR = Math.sqrt(ni.x*ni.x + ni.y*ni.y) + 0.1;
    const rF = (cR - tR) * 0.003;
    fx -= (ni.x / cR) * rF; fy -= (ni.y / cR) * rF;
    ni.vx = (ni.vx + fx) * damp; ni.vy = (ni.vy + fy) * damp;
    ni.x += ni.vx; ni.y += ni.vy;
  }}
  ballEdges.forEach(e => {{
    const s = ballMap[e.source], t = ballMap[e.target];
    if (!s || !t) return;
    const dx = t.x - s.x, dy = t.y - s.y;
    const d = Math.sqrt(dx*dx + dy*dy) + 1;
    const ideal = Math.abs(s.ring - t.ring) * 100;
    const f = (d - ideal) * 0.005;
    if (!s.fixed) {{ s.vx += (dx/d)*f; s.vy += (dy/d)*f; }}
    if (!t.fixed) {{ t.vx -= (dx/d)*f; t.vy -= (dy/d)*f; }}
  }});
}}

function ballColor(n) {{
  if (n.kind === "hardware") return "#fbbf24";
  if (n.sensitive) return "#ff4444";
  if (n.file_type === "vault") return "#00ff88";
  if (n.agent_related || n.category === "agent") return "#00ffcc";
  if (n.kind === "process") return CAT_COLORS[n.category] || "#6b7280";
  return TYPE_COLORS[n.file_type] || "#555555";
}}

function drawGalacticBall(cw, ch) {{
  simulateBall();
  const bcx = BALL_CX(), bcy = BALL_CY(), bs = BALL_SCALE();
  const ft = performance.now() / 1000;

  // Ring guides
  ctx.save();
  [60, 150, 270].forEach(r => {{
    ctx.globalAlpha = 0.025;
    ctx.strokeStyle = "#3366aa";
    ctx.lineWidth = 0.5;
    ctx.beginPath(); ctx.arc(bcx, bcy, r * bs, 0, Math.PI*2); ctx.stroke();
  }});

  // Edges
  ballEdges.forEach(e => {{
    const s = ballMap[e.source], t = ballMap[e.target];
    if (!s || !t) return;
    const sx = bcx + s.x * bs, sy = bcy + s.y * bs;
    const tx = bcx + t.x * bs, ty = bcy + t.y * bs;
    const str = e.strength || 0;
    ctx.globalAlpha = 0.03 + Math.min(str, 15) * 0.002;
    ctx.strokeStyle = ballColor(t.kind === "hardware" ? s : t);
    ctx.lineWidth = 0.3 + Math.min(str, 10) * 0.03;
    ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(tx, ty); ctx.stroke();
    if (str > 1) {{
      const speed = 0.05 + str * 0.006;
      const dotCount = Math.min(Math.ceil(str / 6), 4);
      for (let di = 0; di < dotCount; di++) {{
        const phase = di / dotCount;
        const flowT = (ft * speed + phase + e.source.length * 0.03) % 1;
        const fx = sx + (tx - sx) * flowT, fy = sy + (ty - sy) * flowT;
        ctx.globalAlpha = 0.2 + 0.15 * Math.sin(flowT * Math.PI);
        ctx.fillStyle = ballColor(t.kind === "hardware" ? s : t);
        ctx.beginPath(); ctx.arc(fx, fy, (0.6 + str * 0.03) * bs * 2, 0, Math.PI*2); ctx.fill();
      }}
    }}
  }});

  // Nodes
  ballNodes.forEach(n => {{
    const px = bcx + n.x * bs, py = bcy + n.y * bs;
    const r = n.nodeRadius * bs;
    const color = ballColor(n);

    // Auras
    if (n.kind === "hardware") {{
      const usage = (n.usage_pct || 0) / 100;
      const pulse = 0.12 + 0.1 * Math.sin(ft * 1.5 + n.x * 0.1);
      const aR = r + (10 + usage * 8) * bs;
      const hue = usage > 0.7 ? "255,100,60" : (usage > 0.4 ? "251,191,36" : "0,255,200");
      const g = ctx.createRadialGradient(px, py, r * 0.8, px, py, aR);
      g.addColorStop(0, `rgba(${{hue}},${{(pulse + usage * 0.15).toFixed(2)}})`);
      g.addColorStop(1, `rgba(${{hue}},0)`);
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(px, py, aR, 0, Math.PI*2); ctx.fill();
    }}
    if ((n.category === "agent" || n.agent_related) && n.kind !== "hardware") {{
      const pulse = 0.08 + 0.1 * Math.sin(ft * 3 + n.y * 0.05);
      const aR = r + 5 * bs;
      const g = ctx.createRadialGradient(px, py, r, px, py, aR);
      g.addColorStop(0, `rgba(0,255,200,${{pulse.toFixed(2)}})`);
      g.addColorStop(1, "rgba(0,255,200,0)");
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(px, py, aR, 0, Math.PI*2); ctx.fill();
    }}

    // Body
    ctx.globalAlpha = n.kind === "hardware" ? 0.7 : 0.4;
    ctx.fillStyle = color;
    if (n.kind === "hardware") {{
      // Hexagon
      ctx.beginPath();
      for (let hi = 0; hi < 6; hi++) {{
        const a = Math.PI/3 * hi - Math.PI/6;
        const hx = px + r * Math.cos(a), hy = py + r * Math.sin(a);
        hi === 0 ? ctx.moveTo(hx, hy) : ctx.lineTo(hx, hy);
      }}
      ctx.closePath(); ctx.fill();
      ctx.strokeStyle = "rgba(255,255,255,0.15)"; ctx.lineWidth = 0.5; ctx.stroke();
      // Usage fill
      if (n.usage_pct > 0) {{
        ctx.save(); ctx.clip();
        const fH = r * 2 * (n.usage_pct / 100);
        ctx.fillStyle = n.usage_pct > 85 ? "rgba(255,80,60,0.3)" : (n.usage_pct > 60 ? "rgba(251,191,36,0.25)" : "rgba(0,255,200,0.2)");
        ctx.fillRect(px - r, py + r - fH, r * 2, fH);
        ctx.restore();
      }}
      // Label
      ctx.globalAlpha = 0.6;
      ctx.fillStyle = "#ccc";
      ctx.font = `bold ${{Math.max(6, r * 0.5)}}px monospace`;
      ctx.textAlign = "center"; ctx.textBaseline = "middle";
      ctx.fillText(n.label, px, py);
    }} else {{
      ctx.beginPath(); ctx.arc(px, py, r, 0, Math.PI*2); ctx.fill();
      ctx.globalAlpha = 0.06;
      ctx.beginPath(); ctx.arc(px, py, r * 2, 0, Math.PI*2); ctx.fill();
    }}

    // Heartbeat for active processes
    if (n.kind === "process" && (n.cpu_pct || 0) > 5) {{
      const beat = 0.15 + 0.15 * Math.abs(Math.sin(ft * 4 + (n.pid || 0) * 0.1));
      ctx.globalAlpha = beat;
      ctx.fillStyle = color;
      ctx.beginPath(); ctx.arc(px, py, r + 3 * bs, 0, Math.PI*2); ctx.fill();
    }}
  }});
  ctx.restore();
  ctx.globalAlpha = 1;
}}

// === DESKTOP FOREGROUND LAYER ===
// Icon shape constants
const ICON_SIZE = 36;
const LABEL_GAP = 8;

let selectedNode = null;
let frameTime = 0;

function draw() {{
  frameTime = performance.now() / 1000;
  const dpr = window.devicePixelRatio || 1;
  const cw = canvas.clientWidth, ch = canvas.clientHeight;
  canvas.width = Math.floor(cw * dpr);
  canvas.height = Math.floor(ch * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  drawNebula(Math.floor(cw), Math.floor(ch));

  // === GALACTIC BALL BACKGROUND LAYER ===
  drawGalacticBall(cw, ch);

  const sx = scaleX(), sy = scaleY();

  // Connection lines from selected to hardware (subtle)
  if (selectedNode) {{
    const nx = selectedNode.cx * sx, ny = selectedNode.cy * sy;
    // Draw lines to dock items
    topProcs.forEach((p, i) => {{
      if (p.category === "agent" || selectedNode.agent_related) {{
        const dx = 60 + i * 55, dy = ch - 18;
        ctx.globalAlpha = 0.06;
        ctx.strokeStyle = "#00ffcc";
        ctx.lineWidth = 0.5;
        ctx.beginPath(); ctx.moveTo(nx, ny); ctx.lineTo(dx, dy); ctx.stroke();
      }}
    }});
    ctx.globalAlpha = 1;
  }}

  // Draw nodes (desktop items)
  nodes.forEach(n => {{
    const px = n.cx * sx;
    const py = n.cy * sy;
    const color = nodeColor(n);
    const r = ICON_SIZE / 2;
    const isSelected = n === selectedNode;
    const dimThis = selectedNode && !isSelected && !n.searchMatch;

    // Auras
    if (!dimThis) {{
      if (n.activity) {{
        const pulse = 0.18 + 0.25 * Math.sin(frameTime * 3.4 + n.cx * 0.01);
        const g = ctx.createRadialGradient(px, py, r, px, py, r + 22);
        g.addColorStop(0, `rgba(64,201,255,${{pulse.toFixed(2)}})`);
        g.addColorStop(1, "rgba(64,201,255,0)");
        ctx.fillStyle = g; ctx.beginPath(); ctx.arc(px, py, r + 22, 0, Math.PI*2); ctx.fill();
      }}
      if (n.sensitive) {{
        const pulse = 0.2 + 0.2 * Math.sin(frameTime * 2.5 + n.cx * 0.01);
        const g = ctx.createRadialGradient(px, py, r, px, py, r + 20);
        g.addColorStop(0, `rgba(255,60,60,${{pulse.toFixed(2)}})`);
        g.addColorStop(1, "rgba(255,60,60,0)");
        ctx.fillStyle = g; ctx.beginPath(); ctx.arc(px, py, r+20, 0, Math.PI*2); ctx.fill();
      }}
      if (n.risky_hot) {{
        const pulse = 0.15 + 0.18 * Math.sin(frameTime * 4.2 + n.cy * 0.01);
        const g = ctx.createRadialGradient(px, py, r, px, py, r + 28);
        g.addColorStop(0, `rgba(255,130,80,${{pulse.toFixed(2)}})`);
        g.addColorStop(1, "rgba(255,130,80,0)");
        ctx.fillStyle = g; ctx.beginPath(); ctx.arc(px, py, r + 28, 0, Math.PI*2); ctx.fill();
      }}
      if (n.agent_related && !n.sensitive) {{
        const pulse = 0.15 + 0.2 * Math.sin(frameTime * 3 + n.cy * 0.01);
        const g = ctx.createRadialGradient(px, py, r, px, py, r + 15);
        g.addColorStop(0, `rgba(0,255,200,${{pulse.toFixed(2)}})`);
        g.addColorStop(1, "rgba(0,255,200,0)");
        ctx.fillStyle = g; ctx.beginPath(); ctx.arc(px, py, r+15, 0, Math.PI*2); ctx.fill();
      }}
      if (n.file_type === "vault") {{
        const pulse = 0.2 + 0.15 * Math.sin(frameTime * 1.8);
        const g = ctx.createRadialGradient(px, py, r, px, py, r + 18);
        g.addColorStop(0, `rgba(0,255,136,${{pulse.toFixed(2)}})`);
        g.addColorStop(1, "rgba(0,255,136,0)");
        ctx.fillStyle = g; ctx.beginPath(); ctx.arc(px, py, r+18, 0, Math.PI*2); ctx.fill();
      }}
    }}

    ctx.globalAlpha = dimThis ? 0.15 : 1;

    // Icon body — rounded rect for folders, circle for files
    if (n.is_dir) {{
      const rr = 6;
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.moveTo(px-r+rr, py-r); ctx.lineTo(px+r-rr, py-r);
      ctx.quadraticCurveTo(px+r, py-r, px+r, py-r+rr);
      ctx.lineTo(px+r, py+r-rr);
      ctx.quadraticCurveTo(px+r, py+r, px+r-rr, py+r);
      ctx.lineTo(px-r+rr, py+r);
      ctx.quadraticCurveTo(px-r, py+r, px-r, py+r-rr);
      ctx.lineTo(px-r, py-r+rr);
      ctx.quadraticCurveTo(px-r, py-r, px-r+rr, py-r);
      ctx.fill();
      // Folder tab
      ctx.fillStyle = color;
      ctx.globalAlpha *= 0.7;
      ctx.fillRect(px - r, py - r - 4, r * 0.8, 5);
      ctx.globalAlpha = dimThis ? 0.15 : 1;
    }} else {{
      // Circle with glow
      ctx.fillStyle = color;
      ctx.beginPath(); ctx.arc(px, py, r * 0.7, 0, Math.PI*2); ctx.fill();
      // Outer glow
      ctx.globalAlpha *= 0.12;
      ctx.fillStyle = color;
      ctx.beginPath(); ctx.arc(px, py, r, 0, Math.PI*2); ctx.fill();
      ctx.globalAlpha = dimThis ? 0.15 : 1;
    }}

    // Selected ring
    if (isSelected) {{
      ctx.globalAlpha = 1;
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 1.5;
      ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.arc(px, py, r + 4, 0, Math.PI*2); ctx.stroke();
      ctx.setLineDash([]);
    }}

    // Search highlight
    if (n.searchMatch && !isSelected) {{
      const sp = 0.5 + 0.5 * Math.sin(frameTime * 5);
      ctx.globalAlpha = sp;
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(px, py, r + 5, 0, Math.PI*2); ctx.stroke();
      ctx.globalAlpha = dimThis ? 0.15 : 1;
    }}

    // Label
    ctx.globalAlpha = dimThis ? 0.12 : 0.9;
    ctx.fillStyle = "#aabbcc";
    ctx.font = "10px monospace";
    ctx.textAlign = "center";
    const maxLabelW = 90;
    let label = n.name;
    while (ctx.measureText(label).width > maxLabelW && label.length > 4) {{
      label = label.slice(0, -2) + "\u2026";
    }}
    // Label bg
    const tw = ctx.measureText(label).width;
    ctx.globalAlpha *= 0.5;
    ctx.fillStyle = "#020208";
    ctx.fillRect(px - tw/2 - 3, py + r + LABEL_GAP - 10, tw + 6, 13);
    ctx.globalAlpha = dimThis ? 0.12 : 0.85;
    ctx.fillStyle = isSelected ? "#ddeeff" : "#8899aa";
    ctx.fillText(label, px, py + r + LABEL_GAP);

    ctx.globalAlpha = 1;
  }});

  // Ambient particles drifting across screen
  if (!draw._particles) {{
    draw._particles = [];
    for (let i = 0; i < 30; i++) {{
      draw._particles.push({{
        x: Math.random() * cw, y: Math.random() * ch,
        vx: (Math.random() - 0.5) * 0.3, vy: (Math.random() - 0.5) * 0.15,
        s: Math.random() * 1.5 + 0.5, life: Math.random(),
      }});
    }}
  }}
  draw._particles.forEach(p => {{
    p.x += p.vx; p.y += p.vy;
    if (p.x < 0) p.x = cw; if (p.x > cw) p.x = 0;
    if (p.y < 0) p.y = ch; if (p.y > ch) p.y = 0;
    const a = 0.08 + 0.06 * Math.sin(frameTime * 2 + p.life * 10);
    ctx.globalAlpha = a;
    ctx.fillStyle = "#4488aa";
    ctx.beginPath(); ctx.arc(p.x, p.y, p.s, 0, Math.PI*2); ctx.fill();
  }});
  ctx.globalAlpha = 1;

  requestAnimationFrame(draw);
}}

// Interaction
let hoverNode = null;
canvas.addEventListener("click", e => {{
  const sx = scaleX(), sy = scaleY();
  const mx = e.clientX, my = e.clientY;
  let hit = null;
  nodes.forEach(n => {{
    const dx = n.cx * sx - mx, dy = n.cy * sy - my;
    if (Math.sqrt(dx*dx + dy*dy) < ICON_SIZE/2 + 8) hit = n;
  }});
  if (hit) {{
    selectedNode = hit;
    showInspector(hit);
  }} else {{
    selectedNode = null;
    document.getElementById("inspector").style.display = "none";
  }}
}});

canvas.addEventListener("dblclick", e => {{
  if (selectedNode && selectedNode.is_dir) {{
    // Could open in Finder — for now just show path
    showInspector(selectedNode);
  }}
}});

function showInspector(n) {{
  const color = nodeColor(n);
  let tags = `<span class="tag" style="background:${{color}};color:#000">${{n.file_type}}</span>`;
  if (n.is_dir) tags += `<span class="tag" style="background:#fbbf24;color:#000">FOLDER</span>`;
  if (n.sensitive) tags += `<span class="tag" style="background:#ff4444;color:#fff">SENSITIVE</span>`;
  if (n.agent_related) tags += `<span class="tag" style="background:#00ffcc;color:#000">AGENT</span>`;
  if (n.activity) tags += `<span class="tag" style="background:#40c9ff;color:#001622">ACTIVE</span>`;
  if (n.risky_hot) tags += `<span class="tag" style="background:#ff7f50;color:#1f0800">RISK FLOW</span>`;

  document.getElementById("inspector-content").innerHTML = `
    <div class="holo-title">${{n.name}}</div>
    <div class="holo-sub">${{n.is_dir ? "Folder" : n.file_type}} &middot; ${{formatBytes(n.size || 0)}}</div>
    <div style="margin:4px 0">${{tags}}</div>
    ${{n.importance > 30 ? '<div class="holo-stat">Importance: <span class="holo-val">' + n.importance + '/100</span></div><div class="holo-bar"><div class="holo-bar-fill" style="width:'+n.importance+'%;background:#fbbf24"></div></div>' : ''}}
    <div class="holo-stat" style="font-size:9px;word-break:break-all;color:#445566;margin-top:4px">${{n.path}}</div>
  `;
  document.getElementById("inspector").style.display = "block";
}}

function selectProc(p) {{
  const color = CAT_COLORS[p.category] || "#6b7280";
  document.getElementById("inspector-content").innerHTML = `
    <div class="holo-title">${{p.name}}</div>
    <div class="holo-sub">PID ${{p.pid}} &middot; ${{p.instance_count > 1 ? p.instance_count + " instances" : "single"}}</div>
    <div><span class="tag" style="background:${{color}};color:#000">${{p.category}}</span></div>
    <div class="holo-stat">CPU: <span class="holo-val">${{p.cpu_pct}}%</span></div>
    <div class="holo-bar"><div class="holo-bar-fill" style="width:${{Math.min(p.cpu_pct,100)}}%;background:#00ffcc"></div></div>
    <div class="holo-stat">MEM: <span class="holo-val">${{p.mem_pct}}%</span></div>
    <div class="holo-bar"><div class="holo-bar-fill" style="width:${{Math.min(p.mem_pct,100)}}%;background:#818cf8"></div></div>
  `;
  document.getElementById("inspector").style.display = "block";
}}

function closeInspector() {{
  selectedNode = null;
  document.getElementById("inspector").style.display = "none";
}}

document.getElementById("search-input").addEventListener("input", e => {{
  const q = e.target.value.toLowerCase().trim();
  nodes.forEach(n => {{
    n.searchMatch = q.length > 0 && n.name.toLowerCase().includes(q);
  }});
}});

// Live polling — updates HUD + galactic ball nodes
function pollStats() {{
  fetchJsonWithToken("/api/stats").then(data => {{
    document.getElementById("hud-cpu").textContent = data.cpu.usage_pct + "%";
    document.getElementById("hud-cpu-bar").style.width = data.cpu.usage_pct + "%";
    document.getElementById("hud-cpu-bar").style.background = barColor(data.cpu.usage_pct);
    document.getElementById("hud-ram").textContent = data.memory.used_gb + "/" + data.memory.total_gb + "G";
    document.getElementById("hud-ram-bar").style.width = data.memory.usage_pct + "%";
    document.getElementById("hud-ram-bar").style.background = barColor(data.memory.usage_pct);

    // Update galactic ball hardware nodes
    const cpuN = ballMap["hw_cpu"];
    if (cpuN) cpuN.usage_pct = data.cpu.usage_pct;
    const ramN = ballMap["hw_ram"];
    if (ramN) ramN.usage_pct = data.memory.usage_pct;

    // Update ball process nodes
    (data.processes || []).forEach(p => {{
      const bn = ballMap["proc_" + p._group];
      if (bn) {{
        bn.cpu_pct = p.cpu_pct;
        bn.mem_pct = p.mem_pct;
        bn.nodeRadius = 3 + Math.min(p.cpu_pct + p.mem_pct, 20) * 0.3;
      }}
    }});

    // Update edge strengths
    ballEdges.forEach(e => {{
      const t = ballMap[e.target];
      if (t && e.kind === "uses") {{
        if (e.source === "hw_cpu") e.strength = t.cpu_pct || 0;
        else if (e.source === "hw_ram") e.strength = t.mem_pct || 0;
      }}
    }});
  }}).catch(() => {{}});

  fetchJsonWithToken("/api/history").then(data => {{
    historyData = data || historyData;
    renderHistoryPanel();
    applyHistoryActivity();
  }}).catch(() => {{}});
}}
setInterval(pollStats, 2500);

draw();
</script>
</body>
</html>"""


def cmd_battlestation(args: argparse.Namespace) -> int:
    desktop_dir = Path(args.path).expanduser().resolve() if args.path else Path.home() / "Desktop"
    if not desktop_dir.is_dir():
        print(f"ERROR: not a directory: {desktop_dir}", file=sys.stderr)
        return 1

    workspace_path: Optional[Path] = None
    if getattr(args, "workspace", None):
        workspace_path = Path(str(args.workspace)).expanduser().resolve()
        if not workspace_path.exists() or not workspace_path.is_dir():
            print(f"ERROR: workspace not found: {workspace_path}", file=sys.stderr)
            return 1

    print("Reading screen layout...")
    screen_w, screen_h = _get_screen_resolution()
    print(f"  Screen: {screen_w}x{screen_h} (logical)")

    print("Scanning desktop items...")
    items = _get_desktop_items(desktop_dir)
    print(f"  {len(items)} items")

    positioned = _build_desktop_grid(items, screen_w, screen_h)

    print("Scanning filesystem for galactic ball...")
    file_graph = _scan_directory(desktop_dir, max_files=200, max_depth=4)
    print(f"  {file_graph['stats']['total_files']} files for background")

    print("Gathering system info...")
    sys_snapshot = _gather_system_snapshot(desktop_dir)
    print(f"  {len(sys_snapshot['processes'])} processes, {sys_snapshot['cpu']['cores']} cores")

    history_summary = _load_history_guard_summary(workspace_path)
    if history_summary.get("enabled"):
        print(f"  History guard linked: {history_summary.get('workspace')}")
    else:
        print("  History guard: not linked (use --workspace)")

    api_token = secrets.token_urlsafe(24)
    bg_img = _resolve_background_image(desktop_dir, str(getattr(args, "desktop_bg", "none")), workspace_path)
    bg_url = f"/deck-bg?token={urllib.parse.quote(api_token)}" if bg_img is not None else None
    if bg_img is not None:
        print(f"  Desktop background: {bg_img}")

    title = "BATTLE STATION"
    html_content = _render_battlestation_html(
        positioned,
        sys_snapshot,
        screen_w,
        screen_h,
        title,
        file_graph=file_graph,
        history_data=history_summary,
        background_path=bg_url,
        api_token=api_token,
    )

    port = args.port

    class Handler(http.server.BaseHTTPRequestHandler):
        def _require_api_auth(self) -> bool:
            error = _validate_local_api_request(self.headers, port, api_token)
            if error:
                _send_json_response(self, 403, {"ok": False, "error": error})
                return False
            return True

        def do_GET(self):
            req = urllib.parse.urlparse(self.path)
            req_path = req.path
            if req_path == "/api/stats":
                if not self._require_api_auth():
                    return
                data = _gather_system_snapshot(desktop_dir)
                _send_json_response(self, 200, data)
            elif req_path == "/api/history":
                if not self._require_api_auth():
                    return
                data = _load_history_guard_summary(workspace_path)
                _send_json_response(self, 200, data)
            elif req_path == "/deck-bg" and bg_img is not None and bg_img.exists():
                qs = urllib.parse.parse_qs(req.query)
                if str(qs.get("token", [""])[0] or "") != api_token:
                    self.send_response(403)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(b"forbidden")
                    return
                mime, _ = mimetypes.guess_type(str(bg_img))
                self.send_response(200)
                self.send_header("Content-Type", mime or "image/png")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(bg_img.read_bytes())
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(html_content.encode("utf-8"))

        def log_message(self, fmt, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"\n  BATTLE STATION live at {url}")
    print(f"  {len(items)} desktop items | {screen_w}x{screen_h}")
    print(f"  Ctrl+C to stop\n")

    threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_commanddeck(args: argparse.Namespace) -> int:
    desktop_path = args.path if args.path else str(Path.home() / "Desktop")
    bg_mode = args.desktop_bg if args.desktop_bg else "screenshot"
    class _DeckArgs:
        pass
    bridge = _DeckArgs()
    bridge.path = desktop_path
    bridge.port = int(args.port)
    bridge.workspace = args.workspace
    bridge.desktop_bg = bg_mode
    return cmd_battlestation(bridge)


def cmd_billing_doctor(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else None
    result = _billing_doctor_result(workspace)
    if args.json:
        _emit("billing-doctor", True, result)
        return 0
    print("[billing-doctor]")
    print(f"  status={result.get('status')}")
    if result.get("workspace"):
        print(f"  workspace={result.get('workspace')}")
    print(f"  telemetry_source={result.get('telemetry_source')}")
    if result.get("telemetry_source_label"):
        print(f"  telemetry_label={result.get('telemetry_source_label')}")
    if result.get("billing_mode"):
        print(f"  billing_mode={result.get('billing_mode')}")
    if result.get("billing_exactness"):
        print(f"  billing_exactness={result.get('billing_exactness')}")
    if result.get("provider"):
        print(f"  provider={result.get('provider')}")
    if result.get("provider_api_status"):
        print(f"  provider_api_status={result.get('provider_api_status')}")
    if result.get("provider_api_note"):
        print(f"  note={result.get('provider_api_note')}")
    if result.get("quota_limit") is not None:
        print(
            f"  quota={result.get('quota_used')} / {result.get('quota_limit')} "
            f"(remaining {result.get('quota_remaining')})"
        )
    if result.get("reset_at"):
        print(f"  reset_at={result.get('reset_at')}")
    if result.get("requests_logged_today") is not None:
        print(f"  requests_logged_today={result.get('requests_logged_today')}")
    if result.get("estimated_cost_usd_today") is not None:
        print(f"  estimated_cost_usd_today={result.get('estimated_cost_usd_today')}")
    if result.get("provider_cost_usd_today") is not None:
        print(f"  provider_cost_usd_today={result.get('provider_cost_usd_today')}")
    print("  supported_adapters=")
    for item in result.get("supported_adapters", []):
        print(f"    - {item['provider']}: {item['mode']} ({item['activation']})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="liquefy-desktop-viz",
        description="Galactic Desktop — live filesystem visualization",
    )
    sub = ap.add_subparsers(dest="subcmd", required=True)

    p_scan = sub.add_parser("scan", help="Scan directory, output graph JSON")
    p_scan.add_argument("path", help="Directory to scan")
    p_scan.add_argument("--out", help="Output JSON path")
    p_scan.add_argument("--max-files", type=int, default=MAX_FILES)
    p_scan.add_argument("--max-depth", type=int, default=MAX_DEPTH)
    p_scan.add_argument("--json", action="store_true")
    p_scan.set_defaults(fn=cmd_scan)

    p_render = sub.add_parser("render", help="Scan + generate HTML visualization")
    p_render.add_argument("path")
    p_render.add_argument("--out", help="Output HTML path")
    p_render.add_argument("--max-files", type=int, default=MAX_FILES)
    p_render.add_argument("--max-depth", type=int, default=MAX_DEPTH)
    p_render.add_argument("--json", action="store_true")
    p_render.set_defaults(fn=cmd_render)

    p_serve = sub.add_parser("serve", help="Scan + render + launch browser")
    p_serve.add_argument("path")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.add_argument("--max-files", type=int, default=MAX_FILES)
    p_serve.add_argument("--max-depth", type=int, default=MAX_DEPTH)
    p_serve.set_defaults(fn=cmd_serve)

    p_live = sub.add_parser("live", help="Full system organism — hardware + processes + files, live updating")
    p_live.add_argument("path", help="Root directory to visualize")
    p_live.add_argument("--port", type=int, default=8765)
    p_live.add_argument("--max-files", type=int, default=MAX_FILES)
    p_live.add_argument("--max-depth", type=int, default=MAX_DEPTH)
    p_live.add_argument("--desktop", action="store_true", help="Also include ~/Desktop")
    p_live.add_argument("--also", nargs="*", metavar="DIR", help="Extra directories to include")
    p_live.add_argument("--workspace", default=None, help="Accepted for compatibility; ignored in restored safepoint mode")
    p_live.add_argument("--wallpaper", action="store_true",
                        help="Launch as desktop wallpaper (Plash/kiosk/xwinwrap)")
    p_live.set_defaults(fn=cmd_live)

    p_native = sub.add_parser("native", help="Compatibility alias for the restored graph-first shell")
    p_native.add_argument("path", help="Root directory to visualize")
    p_native.add_argument("--port", type=int, default=8765)
    p_native.add_argument("--max-files", type=int, default=MAX_FILES)
    p_native.add_argument("--max-depth", type=int, default=MAX_DEPTH)
    p_native.add_argument("--desktop", action="store_true", help="Also include ~/Desktop")
    p_native.add_argument("--also", nargs="*", metavar="DIR", help="Extra directories to include")
    p_native.add_argument("--workspace", default=None, help="Accepted for compatibility; ignored in restored safepoint mode")
    p_native.set_defaults(fn=cmd_native)

    p_bs = sub.add_parser("battlestation", help="1:1 desktop replica — your actual desktop as a battle station")
    p_bs.add_argument("path", nargs="?", default=None, help="Desktop directory (default: ~/Desktop)")
    p_bs.add_argument("--port", type=int, default=8765)
    p_bs.add_argument("--workspace", default=None, help="History-guard workspace for live agent telemetry")
    p_bs.add_argument(
        "--desktop-bg",
        default="none",
        help="Desktop background mode: none | screenshot | /path/to/image",
    )
    p_bs.set_defaults(fn=cmd_battlestation)

    p_cd = sub.add_parser("commanddeck", help="Browser-native sovereign cockpit (desktop clone + telemetry)")
    p_cd.add_argument("path", nargs="?", default=None, help="Desktop directory (default: ~/Desktop)")
    p_cd.add_argument("--port", type=int, default=8765)
    p_cd.add_argument("--workspace", default=None, help="History-guard workspace for live agent telemetry")
    p_cd.add_argument(
        "--desktop-bg",
        default="screenshot",
        help="Desktop background mode: screenshot | none | /path/to/image",
    )
    p_cd.set_defaults(fn=cmd_commanddeck)

    p_bd = sub.add_parser("billing-doctor", help="Inspect which billing/usage source is active and how exact it is")
    p_bd.add_argument("--workspace", default=None, help="Workspace path for billing.json / ledger lookup")
    p_bd.add_argument("--json", action="store_true")
    p_bd.set_defaults(fn=cmd_billing_doctor)

    return ap


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
