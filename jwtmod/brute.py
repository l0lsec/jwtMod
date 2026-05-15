"""HS* secret brute force against a wordlist."""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Iterable, Iterator

from .codec import JWTError, b64url_decode, decode_jwt


_HS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def default_wordlist_path() -> str:
    return os.path.join(os.path.dirname(__file__), "wordlists", "jwt-secrets-top.txt")


def iter_wordlist(path: str) -> Iterator[bytes]:
    with open(path, "rb") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith(b"#"):
                continue
            yield line


def detect_alg(token: str) -> str:
    header, _payload, _sig = decode_jwt(token)
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in _HS:
        raise JWTError(f"token alg is not HS* (got {alg!r})")
    return alg


def try_secrets(
    token: str,
    secrets: Iterable[bytes | str],
    alg: str | None = None,
    *,
    max_tries: int | None = None,
    progress_every: int = 5000,
    on_progress=None,
) -> bytes | None:
    """Return the first secret that verifies the token, else None."""
    if alg is None:
        alg = detect_alg(token)
    if alg not in _HS:
        raise JWTError(f"unsupported alg for brute: {alg}")
    digest = _HS[alg]

    parts = token.strip().split(".")
    if len(parts) != 3:
        raise JWTError("token must have 3 segments")
    si = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        target = b64url_decode(parts[2])
    except JWTError:
        return None

    tried = 0
    for s in secrets:
        if isinstance(s, str):
            s = s.encode("utf-8")
        if hmac.compare_digest(hmac.new(s, si, digest).digest(), target):
            return s
        tried += 1
        if max_tries is not None and tried >= max_tries:
            return None
        if on_progress and tried % progress_every == 0:
            on_progress(tried)
    return None
