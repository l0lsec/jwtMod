"""JWS signing + verification for HS / RS / PS / ES / none."""

from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .codec import JWTError, b64url_decode, b64url_encode, signing_input

ALGS = {
    "none",
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
}

_HASH = {
    "256": hashes.SHA256(),
    "384": hashes.SHA384(),
    "512": hashes.SHA512(),
}

_HASHLIB = {
    "256": hashlib.sha256,
    "384": hashlib.sha384,
    "512": hashlib.sha512,
}

# JWS ES* signatures are fixed-width r||s. Sizes per RFC 7518.
_ES_COORD_LEN = {"ES256": 32, "ES384": 48, "ES512": 66}


def _as_bytes(key) -> bytes:
    if isinstance(key, str):
        return key.encode("utf-8")
    if isinstance(key, (bytes, bytearray)):
        return bytes(key)
    raise JWTError(f"HS* key must be bytes/str, got {type(key).__name__}")


def sign(header: dict, payload: dict, alg: str, key=None, *, alg_literal: str | None = None) -> str:
    """Build a complete JWT for the given alg.

    alg_literal: override the `alg` header value while still using `alg` to pick the
    signature algorithm. Used for the alg:none case-bypass variants (None, NONE, nOnE).
    """
    if alg not in ALGS:
        raise JWTError(f"unsupported alg: {alg}")

    h = dict(header)
    h["alg"] = alg_literal if alg_literal is not None else alg
    h.setdefault("typ", "JWT")
    si = signing_input(h, payload)
    header_b, payload_b = si.decode("ascii").split(".")

    if alg == "none":
        return f"{header_b}.{payload_b}."

    if alg.startswith("HS"):
        digest = _HASHLIB[alg[2:]]
        mac = hmac.new(_as_bytes(key), si, digest).digest()
        return f"{header_b}.{payload_b}.{b64url_encode(mac)}"

    if alg.startswith("RS"):
        if not isinstance(key, RSAPrivateKey):
            raise JWTError("RS* requires an RSA private key")
        sig = key.sign(si, padding.PKCS1v15(), _HASH[alg[2:]])
        return f"{header_b}.{payload_b}.{b64url_encode(sig)}"

    if alg.startswith("PS"):
        if not isinstance(key, RSAPrivateKey):
            raise JWTError("PS* requires an RSA private key")
        h_alg = _HASH[alg[2:]]
        sig = key.sign(
            si,
            padding.PSS(mgf=padding.MGF1(h_alg), salt_length=h_alg.digest_size),
            h_alg,
        )
        return f"{header_b}.{payload_b}.{b64url_encode(sig)}"

    if alg.startswith("ES"):
        if not isinstance(key, EllipticCurvePrivateKey):
            raise JWTError("ES* requires an EC private key")
        h_alg = _HASH[alg[2:]]
        der = key.sign(si, ec.ECDSA(h_alg))
        r, s = decode_dss_signature(der)
        n = _ES_COORD_LEN[alg]
        sig = r.to_bytes(n, "big") + s.to_bytes(n, "big")
        return f"{header_b}.{payload_b}.{b64url_encode(sig)}"

    raise JWTError(f"alg not implemented: {alg}")


def verify(token: str, alg: str, key) -> bool:
    """Verify a JWT's signature. Returns True/False (no exception on bad sig)."""
    if alg not in ALGS:
        raise JWTError(f"unsupported alg: {alg}")
    parts = token.strip().split(".")
    if len(parts) == 2:
        parts.append("")
    if len(parts) != 3:
        raise JWTError("token must have 2 or 3 segments")
    header_b, payload_b, sig_b = parts
    si = f"{header_b}.{payload_b}".encode("ascii")

    if alg == "none":
        return sig_b == ""

    if not sig_b:
        return False
    try:
        sig = b64url_decode(sig_b)
    except JWTError:
        return False

    if alg.startswith("HS"):
        digest = _HASHLIB[alg[2:]]
        expected = hmac.new(_as_bytes(key), si, digest).digest()
        return hmac.compare_digest(expected, sig)

    if alg.startswith("RS"):
        pub = _ensure_rsa_public(key)
        try:
            pub.verify(sig, si, padding.PKCS1v15(), _HASH[alg[2:]])
            return True
        except InvalidSignature:
            return False

    if alg.startswith("PS"):
        pub = _ensure_rsa_public(key)
        h_alg = _HASH[alg[2:]]
        try:
            pub.verify(
                sig,
                si,
                padding.PSS(mgf=padding.MGF1(h_alg), salt_length=h_alg.digest_size),
                h_alg,
            )
            return True
        except InvalidSignature:
            return False

    if alg.startswith("ES"):
        pub = _ensure_ec_public(key)
        n = _ES_COORD_LEN[alg]
        if len(sig) != 2 * n:
            return False
        r = int.from_bytes(sig[:n], "big")
        s = int.from_bytes(sig[n:], "big")
        der = encode_dss_signature(r, s)
        try:
            pub.verify(der, si, ec.ECDSA(_HASH[alg[2:]]))
            return True
        except InvalidSignature:
            return False

    return False


def _ensure_rsa_public(key) -> RSAPublicKey:
    if isinstance(key, RSAPublicKey):
        return key
    if isinstance(key, RSAPrivateKey):
        return key.public_key()
    raise JWTError("RSA verify requires an RSA public or private key")


def _ensure_ec_public(key) -> EllipticCurvePublicKey:
    if isinstance(key, EllipticCurvePublicKey):
        return key
    if isinstance(key, EllipticCurvePrivateKey):
        return key.public_key()
    raise JWTError("EC verify requires an EC public or private key")
