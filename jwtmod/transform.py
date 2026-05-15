"""Payload transforms: --set / --remove / --merge-json plus claim presets."""

from __future__ import annotations

import copy
import json
import time
from typing import Any, Iterable

from .codec import JWTError


def coerce_value(s: str) -> Any:
    """Best-effort coerce a CLI string into a JSON-native value."""
    try:
        return json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return s


def _split_dotted(path: str) -> list[str]:
    out: list[str] = []
    buf: list[str] = []
    i = 0
    while i < len(path):
        c = path[i]
        if c == "\\" and i + 1 < len(path) and path[i + 1] == ".":
            buf.append(".")
            i += 2
            continue
        if c == ".":
            out.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    out.append("".join(buf))
    return out


def set_dotted(obj: dict, path: str, value: Any) -> None:
    keys = _split_dotted(path)
    cur: Any = obj
    for k in keys[:-1]:
        if not isinstance(cur, dict):
            raise JWTError(f"cannot set '{path}': path traverses non-object at '{k}'")
        if k not in cur or not isinstance(cur[k], dict):
            cur[k] = {}
        cur = cur[k]
    if not isinstance(cur, dict):
        raise JWTError(f"cannot set '{path}': leaf parent is not an object")
    cur[keys[-1]] = value


def del_dotted(obj: dict, path: str) -> bool:
    keys = _split_dotted(path)
    cur: Any = obj
    for k in keys[:-1]:
        if not isinstance(cur, dict) or k not in cur:
            return False
        cur = cur[k]
    if isinstance(cur, dict) and keys[-1] in cur:
        del cur[keys[-1]]
        return True
    return False


def deep_merge(dst: dict, src: dict) -> dict:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            deep_merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def transform_payload(
    payload: dict,
    sets: Iterable[tuple[str, str]] | None = None,
    merge_json: dict | None = None,
    removes: Iterable[str] | None = None,
    presets: Iterable[str] | None = None,
) -> dict:
    """Apply --set, --merge-json, --remove, --preset edits to payload (new dict)."""
    out = copy.deepcopy(payload)

    for key, raw in sets or ():
        set_dotted(out, key, coerce_value(raw))

    if merge_json:
        if not isinstance(merge_json, dict):
            raise JWTError("merge_json must decode to a JSON object")
        deep_merge(out, merge_json)

    for key in removes or ():
        del_dotted(out, key)

    for preset in presets or ():
        apply_preset(out, preset)

    return out


# ---- claim presets ----

ADMIN_DEFAULT_KEYS = ("role", "isAdmin", "admin", "groups", "scope")


def apply_preset(payload: dict, spec: str) -> None:
    """Apply a named preset to payload, mutating in place.

    spec is `NAME` or `NAME=ARG` or `NAME:k=v`. Known names:
      expire, extend-exp=SECONDS, perma, clear-time,
      admin (optional `admin:keys=role,isAdmin,...`).
    """
    name, _, arg = spec.partition("=")
    name = name.strip()
    arg = arg.strip()

    now = int(time.time())

    if name == "expire":
        payload["exp"] = now - 60
        return

    if name == "extend-exp":
        try:
            delta = int(arg) if arg else 3600
        except ValueError:
            raise JWTError(f"extend-exp expects an integer, got {arg!r}")
        cur = payload.get("exp")
        payload["exp"] = (int(cur) if isinstance(cur, (int, float)) else now) + delta
        return

    if name == "perma":
        payload["exp"] = now + 10 * 365 * 86400
        return

    if name == "clear-time":
        for k in ("exp", "nbf", "iat"):
            payload.pop(k, None)
        return

    if name == "admin":
        keys = ADMIN_DEFAULT_KEYS
        if arg.startswith("keys=") or arg.startswith("keys:"):
            raw = arg.split("=", 1)[1] if "=" in arg else arg.split(":", 1)[1]
            keys = tuple(k.strip() for k in raw.split(",") if k.strip())
        # Always set role/isAdmin
        if "role" in keys or True:
            payload["role"] = "admin"
        if "isAdmin" in keys or True:
            payload["isAdmin"] = True
        # Only set the rest if they already exist (so we don't bloat unrelated tokens).
        if "admin" in keys and "admin" in payload:
            payload["admin"] = True
        if "groups" in keys and "groups" in payload:
            payload["groups"] = ["admin"]
        if "scope" in keys and "scope" in payload:
            payload["scope"] = "*"
        return

    raise JWTError(f"unknown preset: {name!r}")
