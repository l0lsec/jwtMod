"""jwtmod — JWT security testing toolkit.

Public re-exports keep the old `jwt_none` surface working.
"""

from .codec import (
    JWTError,
    b64url_decode,
    b64url_encode,
    decode_jwt,
    json_encode,
    signing_input,
)
from .transform import (
    apply_preset,
    coerce_value,
    deep_merge,
    del_dotted,
    set_dotted,
    transform_payload,
)
from .sign import ALGS, sign, verify
from .attacks import (
    KID_PAYLOADS,
    forge_duplicate_claim,
    forge_jku,
    forge_jwk_embed,
    forge_kid,
    forge_none,
    forge_psychic_es256,
    forge_rs_to_hs_confusion,
    forge_signed,
    forge_strip_signature,
)
from .inspect import diff, info
from .brute import default_wordlist_path, iter_wordlist, try_secrets
from .keys import gen_ec, gen_rsa, load_pem, private_pem, pub_to_jwk, public_pem, rfc7638_thumbprint

__all__ = [
    "JWTError",
    "ALGS",
    "b64url_decode",
    "b64url_encode",
    "decode_jwt",
    "json_encode",
    "signing_input",
    "apply_preset",
    "coerce_value",
    "deep_merge",
    "del_dotted",
    "set_dotted",
    "transform_payload",
    "sign",
    "verify",
    "KID_PAYLOADS",
    "forge_duplicate_claim",
    "forge_jku",
    "forge_jwk_embed",
    "forge_kid",
    "forge_none",
    "forge_psychic_es256",
    "forge_rs_to_hs_confusion",
    "forge_signed",
    "forge_strip_signature",
    "diff",
    "info",
    "default_wordlist_path",
    "iter_wordlist",
    "try_secrets",
    "gen_ec",
    "gen_rsa",
    "load_pem",
    "private_pem",
    "pub_to_jwk",
    "public_pem",
    "rfc7638_thumbprint",
]
