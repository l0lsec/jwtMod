"""Key utilities: PEM load, RSA/EC generation, JWK + RFC 7638 thumbprint."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from .codec import JWTError, b64url_encode


def load_pem(data: str | bytes, password: bytes | None = None):
    """Load a PEM-encoded key (private or public). Returns the cryptography object."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    data = data.strip()
    if b"PRIVATE KEY" in data:
        try:
            return serialization.load_pem_private_key(data, password=password)
        except Exception as e:
            raise JWTError(f"invalid private PEM: {e}") from e
    if b"PUBLIC KEY" in data or b"BEGIN CERTIFICATE" in data:
        try:
            return serialization.load_pem_public_key(data)
        except Exception as e:
            raise JWTError(f"invalid public PEM: {e}") from e
    raise JWTError("PEM block not recognized (need PRIVATE KEY or PUBLIC KEY)")


def gen_rsa(bits: int = 2048) -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


_CURVE_BY_ALG = {
    "ES256": ec.SECP256R1(),
    "ES384": ec.SECP384R1(),
    "ES512": ec.SECP521R1(),
}


def gen_ec(alg: str = "ES256") -> EllipticCurvePrivateKey:
    curve = _CURVE_BY_ALG.get(alg)
    if curve is None:
        raise JWTError(f"unsupported EC alg for keygen: {alg}")
    return ec.generate_private_key(curve)


def private_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_pem(key) -> bytes:
    if hasattr(key, "public_key"):
        pub = key.public_key()
    else:
        pub = key
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _int_to_b64url(n: int, length: int | None = None) -> str:
    if length is None:
        length = (n.bit_length() + 7) // 8 or 1
    return b64url_encode(n.to_bytes(length, "big"))


_EC_CRV_NAME = {
    "secp256r1": ("P-256", 32),
    "secp384r1": ("P-384", 48),
    "secp521r1": ("P-521", 66),
}


def pub_to_jwk(key) -> dict[str, Any]:
    """Build a public JWK (RFC 7517) for an RSA or EC key (private or public)."""
    if hasattr(key, "public_key"):
        pub = key.public_key()
    else:
        pub = key

    if isinstance(pub, RSAPublicKey):
        numbers = pub.public_numbers()
        jwk = {
            "kty": "RSA",
            "n": _int_to_b64url(numbers.n),
            "e": _int_to_b64url(numbers.e),
        }
    elif isinstance(pub, EllipticCurvePublicKey):
        numbers = pub.public_numbers()
        curve_name = pub.curve.name
        info = _EC_CRV_NAME.get(curve_name)
        if not info:
            raise JWTError(f"unsupported EC curve: {curve_name}")
        crv, size = info
        jwk = {
            "kty": "EC",
            "crv": crv,
            "x": _int_to_b64url(numbers.x, size),
            "y": _int_to_b64url(numbers.y, size),
        }
    else:
        raise JWTError(f"unsupported key type for JWK: {type(pub).__name__}")

    jwk["kid"] = rfc7638_thumbprint(jwk)
    return jwk


def rfc7638_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url) used as default kid."""
    if jwk.get("kty") == "RSA":
        canon = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif jwk.get("kty") == "EC":
        canon = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif jwk.get("kty") == "oct":
        canon = {"k": jwk["k"], "kty": "oct"}
    else:
        raise JWTError(f"thumbprint: unsupported kty {jwk.get('kty')!r}")
    data = json.dumps(canon, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b64url_encode(hashlib.sha256(data).digest())
