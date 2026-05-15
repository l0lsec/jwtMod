"""Local Flask UI for jwtmod.

Binds to 127.0.0.1 by default. Security testing helper — do not deploy.
"""

from __future__ import annotations

import argparse
import json

from flask import Flask, jsonify, render_template, request

from jwtmod import (
    JWTError,
    decode_jwt,
    diff as diff_tokens,
    info as info_token,
    forge_none,
    forge_signed,
    forge_jwk_embed,
    forge_jku,
    forge_kid,
    forge_rs_to_hs_confusion,
    forge_strip_signature,
    forge_psychic_es256,
    load_pem,
    sign as sign_jwt,
    verify as verify_jwt,
    default_wordlist_path,
    iter_wordlist,
    try_secrets,
)


app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/wordlist")
def bundled_wordlist():
    with open(default_wordlist_path(), "r", encoding="utf-8") as f:
        return f.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}


def _parse_sets(raw):
    out = []
    if not raw:
        return out
    if isinstance(raw, str):
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            k, _, v = line.partition("=")
            out.append((k.strip(), v))
        return out
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, list) and len(item) == 2:
                out.append((str(item[0]), str(item[1])))
            elif isinstance(item, str) and "=" in item:
                k, _, v = item.partition("=")
                out.append((k.strip(), v))
        return out
    return out


def _common_kw(data):
    return {
        "sets": _parse_sets(data.get("sets")),
        "removes": data.get("removes") or [],
        "merge_json": data.get("merge_json") if isinstance(data.get("merge_json"), dict) else None,
        "presets": data.get("presets") or [],
    }


def _err(msg, code=400):
    return jsonify(error=msg), code


def _need(data, *keys):
    for k in keys:
        if not data.get(k):
            return _err(f"{k} is required")
    return None


@app.post("/api/decode")
def api_decode():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return _err("token is required")
    try:
        header, payload, sig = decode_jwt(token)
    except JWTError as e:
        return _err(str(e))
    return jsonify(header=header, payload=payload, signature=sig)


@app.post("/api/forge")
def api_forge():
    """Backwards-compatible alg:none forge endpoint."""
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return _err("token is required")
    try:
        nh, np_, nt, extra = forge_none(
            token,
            **_common_kw(data),
            alg_literal=data.get("alg_literal", "none"),
            keep_header_extras=bool(data.get("keep_header_extras")),
            trailing_dot=bool(data.get("trailing_dot", True)),
        )
    except JWTError as e:
        return _err(str(e))
    return jsonify(header=nh, payload=np_, token=nt, extra=extra)


@app.post("/api/sign")
def api_sign():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    alg = data.get("alg") or ""
    if not token or not alg:
        return _err("token and alg required")
    try:
        if alg.startswith("HS"):
            secret = data.get("secret")
            if secret is None:
                return _err("secret required for HS*")
            key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        elif alg == "none":
            key = None
        else:
            pem = data.get("key_pem")
            if not pem:
                return _err("key_pem required for RS/PS/ES")
            key = load_pem(pem)
        nh, np_, nt, extra = forge_signed(
            token, alg=alg, key=key, kid=data.get("kid"),
            keep_header_extras=bool(data.get("keep_header_extras")),
            **_common_kw(data),
        )
    except JWTError as e:
        return _err(str(e))
    return jsonify(header=nh, payload=np_, token=nt, extra=extra)


@app.post("/api/verify")
def api_verify():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    alg = data.get("alg") or ""
    if not token or not alg:
        return _err("token and alg required")
    try:
        if alg.startswith("HS"):
            secret = data.get("secret") or ""
            key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        elif alg == "none":
            key = None
        else:
            pem = data.get("key_pem")
            if not pem:
                return _err("key_pem required")
            key = load_pem(pem)
        ok = verify_jwt(token, alg, key)
    except JWTError as e:
        return _err(str(e))
    return jsonify(valid=bool(ok))


@app.post("/api/info")
def api_info():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return _err("token required")
    try:
        return jsonify(info_token(token))
    except JWTError as e:
        return _err(str(e))


@app.post("/api/diff")
def api_diff():
    data = request.get_json(silent=True) or {}
    a = (data.get("token_a") or "").strip()
    b = (data.get("token_b") or "").strip()
    if not a or not b:
        return _err("token_a and token_b required")
    try:
        return jsonify(diff_tokens(a, b))
    except JWTError as e:
        return _err(str(e))


@app.post("/api/brute")
def api_brute():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return _err("token required")
    raw = data.get("wordlist")
    if raw:
        secrets = (line.strip() for line in raw.splitlines() if line.strip() and not line.startswith("#"))
    else:
        secrets = iter_wordlist(default_wordlist_path())
    try:
        found = try_secrets(token, secrets, alg=data.get("alg"),
                            max_tries=data.get("max_tries"))
    except JWTError as e:
        return _err(str(e))
    if found is None:
        return jsonify(found=False)
    try:
        return jsonify(found=True, secret=found.decode("utf-8"))
    except UnicodeDecodeError:
        return jsonify(found=True, secret_hex=found.hex())


@app.post("/api/attack/jwk-embed")
def api_attack_jwk_embed():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return _err("token required")
    try:
        nh, np_, nt, extra = forge_jwk_embed(token, alg=data.get("alg", "RS256"), **_common_kw(data))
    except JWTError as e:
        return _err(str(e))
    return jsonify(header=nh, payload=np_, token=nt, extra=extra)


@app.post("/api/attack/jku")
def api_attack_jku():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    url = data.get("url") or ""
    if not token or not url:
        return _err("token and url required")
    try:
        nh, np_, nt, extra = forge_jku(token, jku_url=url, alg=data.get("alg", "RS256"), **_common_kw(data))
    except JWTError as e:
        return _err(str(e))
    return jsonify(header=nh, payload=np_, token=nt, extra=extra)


@app.post("/api/attack/kid")
def api_attack_kid():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    value = data.get("value")
    if not token or value is None:
        return _err("token and value required")
    secret = data.get("secret") or ""
    key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    try:
        nh, np_, nt, extra = forge_kid(
            token, kid_value=value, secret=key, alg=data.get("alg", "HS256"), **_common_kw(data),
        )
    except JWTError as e:
        return _err(str(e))
    return jsonify(header=nh, payload=np_, token=nt, extra=extra)


@app.post("/api/attack/rs-to-hs")
def api_attack_rs_to_hs():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    pem = data.get("public_pem")
    if not token or not pem:
        return _err("token and public_pem required")
    try:
        nh, np_, nt, extra = forge_rs_to_hs_confusion(
            token, public_pem=pem, hs_alg=data.get("alg", "HS256"), **_common_kw(data),
        )
    except JWTError as e:
        return _err(str(e))
    return jsonify(header=nh, payload=np_, token=nt, extra=extra)


@app.post("/api/attack/strip-sig")
def api_attack_strip_sig():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return _err("token required")
    try:
        nh, np_, nt, extra = forge_strip_signature(
            token, alg_literal=data.get("alg_literal"),
            trailing_dot=bool(data.get("trailing_dot", False)),
            **_common_kw(data),
        )
    except JWTError as e:
        return _err(str(e))
    return jsonify(header=nh, payload=np_, token=nt, extra=extra)


@app.post("/api/attack/psychic-es256")
def api_attack_psychic_es256():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return _err("token required")
    try:
        nh, np_, nt, extra = forge_psychic_es256(token, **_common_kw(data))
    except JWTError as e:
        return _err(str(e))
    return jsonify(header=nh, payload=np_, token=nt, extra=extra)


def main() -> int:
    parser = argparse.ArgumentParser(description="jwtmod local web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
