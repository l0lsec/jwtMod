"""Token inspection: info() and diff()."""

from __future__ import annotations

import time
from typing import Any

from .codec import decode_jwt


_CLAIM_KEYS = ("iss", "sub", "aud", "exp", "nbf", "iat", "jti")
_ROLE_LIKE = ("role", "roles", "isAdmin", "admin", "groups", "scope", "scopes")


def info(token: str) -> dict[str, Any]:
    header, payload, sig = decode_jwt(token)
    now = int(time.time())
    exp = payload.get("exp")
    iat = payload.get("iat")

    warnings: list[str] = []
    alg = header.get("alg")
    if isinstance(alg, str) and alg.lower() == "none":
        warnings.append(f"alg is {alg!r} — unsigned token")
    if alg is None:
        warnings.append("header missing `alg`")
    if exp is None:
        warnings.append("missing `exp` — token never expires")
    elif isinstance(exp, (int, float)) and exp > now + 5 * 365 * 86400:
        warnings.append("`exp` more than 5 years out")
    if "jwk" in header:
        warnings.append("header embeds `jwk` — verifiers must NOT trust it")
    if "jku" in header:
        warnings.append("header carries `jku` — verifiers must allowlist the URL")
    kid = header.get("kid")
    if isinstance(kid, str):
        if any(c in kid for c in ("/", "\\", "..", "\x00")):
            warnings.append("`kid` looks path-like — possible traversal vector")
        if any(c in kid for c in ("'", '"', ";", "--")):
            warnings.append("`kid` contains SQL-ish characters")
    for k in _ROLE_LIKE:
        if k in payload:
            warnings.append(f"role-like claim present: `{k}={payload[k]!r}`")
            break

    expired = (
        isinstance(exp, (int, float)) and exp < now
    )
    age = None
    if isinstance(iat, (int, float)):
        age = max(0, now - int(iat))

    return {
        "alg": header.get("alg"),
        "typ": header.get("typ"),
        "kid": header.get("kid"),
        "jku": header.get("jku"),
        "jwk_embedded": "jwk" in header,
        "claims": {k: payload.get(k) for k in _CLAIM_KEYS if k in payload},
        "expired": expired,
        "age_seconds": age,
        "signature_present": bool(sig),
        "warnings": warnings,
    }


def _diff_dict(a: dict, b: dict) -> dict:
    added: dict[str, Any] = {}
    removed: dict[str, Any] = {}
    changed: dict[str, dict] = {}
    for k in b:
        if k not in a:
            added[k] = b[k]
        elif a[k] != b[k]:
            changed[k] = {"from": a[k], "to": b[k]}
    for k in a:
        if k not in b:
            removed[k] = a[k]
    return {"added": added, "removed": removed, "changed": changed}


def diff(token_a: str, token_b: str) -> dict[str, Any]:
    ha, pa, sa = decode_jwt(token_a)
    hb, pb, sb = decode_jwt(token_b)
    return {
        "header": _diff_dict(ha, hb),
        "payload": _diff_dict(pa, pb),
        "signature_changed": sa != sb,
    }
