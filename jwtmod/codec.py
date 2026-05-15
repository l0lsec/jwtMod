"""Base64url + JSON codec for JWTs.

Intentionally dependency-free so it can be vendored anywhere.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any


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


def json_encode(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Split and decode a JWT into (header, payload, raw_signature)."""
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


def encode_segments(header: dict, payload: dict) -> tuple[str, str]:
    """Return (header_b64, payload_b64) for signing."""
    return b64url_encode(json_encode(header)), b64url_encode(json_encode(payload))


def signing_input(header: dict, payload: dict) -> bytes:
    h, p = encode_segments(header, payload)
    return f"{h}.{p}".encode("ascii")
