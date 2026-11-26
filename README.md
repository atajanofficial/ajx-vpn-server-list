# AJX VPN Server List

Public, automatically refreshed VPN Gate relay list for the AJX VPN Android
client. This repository removes the need for a private VPS just to distribute a
server list.

- **Source:** <https://www.vpngate.net/api/iphone/> (the same public feed already
  used by the AJX VPN project)
- **Refresh schedule:** every 30 minutes, UTC (`*/30 * * * *`), plus manual
  `workflow_dispatch`
- **Published files:** `servers.txt` (primary, format v2), `servers.json`
  (compatibility mirror), `metadata.json` (counts and provenance)
- **No secrets:** the repository contains no credentials, tokens, private keys,
  or user data. GitHub Actions uses the automatically provided `GITHUB_TOKEN`
  with `contents: write` only.

## Files

| File | Purpose |
| --- | --- |
| `servers.txt` | Primary list, header-driven format v2, including inline OpenVPN profiles |
| `servers.json` | The same records in the Android-compatible schema v1 envelope |
| `metadata.json` | Source, timestamps, protocol/validation counts, content hash |
| `scripts/fetch_servers.py` | Downloads the official feed over verified HTTPS |
| `scripts/validate_servers.py` | Parses, normalizes, deduplicates and validates records |
| `scripts/generate_server_list.py` | Writes the three published files, only when content changed |
| `scripts/test_server_list.py` | Standard-library unit tests for the pipeline |
| `.github/workflows/update-servers.yml` | Scheduled/manual refresh workflow |
| `FIREBASE_HOSTING.md` | Account setup, deployment gate and live checks for the Firebase mirror |

## servers.txt format (format version 2)

`servers.txt` is the primary list. It is UTF-8, uses LF line endings, starts
with comment lines, and then writes one tab-separated record per line. Columns
are declared by name, so parsers must map them by name rather than position:

```
# AJX VPN server list
# format_version=2
# source=https://www.vpngate.net/api/iphone/
# last_updated=1794485699687
# columns=server_id	ip	country_code	country_name	hostname	port	protocol	score	ping	speed	sessions	uptime	total_users	total_traffic	log_type	operator	message	openvpn_config_base64	validation_state	source	last_updated
4a5e0f2d9c1b7e83	203.0.113.10	JP	Japan	public-vpn-203.0.113.10	443	TCP	2673244	30	273048039	119	1659351416	11368548	658827788456190	2weeks	Example operator		Y2xpZW50CmRldiB0dW4K...	DISCOVERED	vpngate	1794485699687
```

Format version 1 was a lossy summary with ten columns and no OpenVPN profile. It
is intentionally rejected as a primary source: without
`openvpn_config_base64` the Android engine has nothing to connect with.

Required columns are exactly the names shown above. Extra columns may be added
in a future version and are ignored by a header-driven parser. A row with the
wrong field count, a duplicate IP, an invalid public IPv4, a missing or invalid
base64 profile, or a profile whose `remote`/port/protocol does not match the row
rejects the whole list. An empty list is never published.

## servers.json format (schema v1)

This is the compatibility mirror of `servers.txt`. The Android client already
understands the schema; it is the same envelope used by the previous VPS API, so
no parser rewrite is required for older builds. New builds prefer
`servers.txt` and use this file only as a fallback.

```json
{
  "schema_version": 1,
  "last_successful_refresh": 1794485699687,
  "stale": false,
  "last_refresh_error": null,
  "servers": [
    {
      "id": "4a5e0f2d9c1b7e83",
      "ip": "203.0.113.10",
      "hostname": "public-vpn-203.0.113.10",
      "country": "Japan",
      "country_code": "JP",
      "score": 2673244,
      "ping": 30,
      "speed": 273048039,
      "sessions": 119,
      "uptime": "1659351416",
      "total_users": 11368548,
      "total_traffic": "658827788456190",
      "log_type": "2weeks",
      "operator": "Example operator",
      "message": "",
      "openvpn_config_base64": "Y2xpZW50CmRldiB0dW4K...",
      "protocol": "tcp",
      "port": 443,
      "verification": {
        "state": "UNKNOWN",
        "last_checked_at": null,
        "expires_at": null,
        "detail": "structurally validated by the refresh workflow; not probed"
      }
    }
  ]
}
```

### Field rules

| Field | Rule |
| --- | --- |
| `id` | Stable SHA-256 prefix of the IP; matches `[A-Za-z0-9_-]{1,96}` |
| `ip` | Public IPv4 only; private, loopback, link-local, CGNAT, documentation and multicast ranges are rejected |
| `hostname` | Non-empty, control characters removed, max 255 characters |
| `country` | Display name; `Unknown` when the source omits it |
| `country_code` | Two uppercase ASCII letters, otherwise `??` |
| `score`, `ping`, `speed`, `sessions`, `total_users` | Non-negative integers reported by the source |
| `uptime`, `total_traffic`, `log_type` | Source strings, control characters removed |
| `operator`, `message` | Source strings, length-limited |
| `openvpn_config_base64` | Canonical base64 of a decodable OpenVPN profile |
| `protocol` | `tcp` or `udp`, derived from the profile; `unknown` records are rejected |
| `port` | Explicit port from the profile, 1-65535 |
| `verification.state` | Always `UNKNOWN` in this repository: the workflow does **not** probe servers |

The workflow also enforces that the profile's `remote` host equals the record
IP and that the profile port/protocol match the record. This is the same
strictness the Android client applies, so a malformed row can never make the
whole downloaded list unusable.

## Validation states

The list uses the same conservative vocabulary as the Android app:

| State | Meaning here |
| --- | --- |
| `DISCOVERED` | The record passed structural validation and is publishable |
| `CHECKING` | Not produced by this workflow |
| `REACHABLE` | Not produced by this workflow |
| `PROTOCOL_VALID` | Not produced by this workflow; would require a real protocol handshake |
| `AUTH_REQUIRED` | Not produced by this workflow |
| `FAILED` | A record that failed validation is dropped, not published |
| `UNKNOWN` | Android's stored verification state for a record that was never probed |

TCP reachability is **not** proof of a working VPN tunnel. This repository never
claims that a server is OpenVPN-compatible beyond "the profile is structurally
valid"; actual connectivity is decided by the Android engine.

## Fail-safe behaviour

- A blank feed, a feed with no usable records, or fewer than 5 usable records
  aborts the run before any file is replaced.
- Validation and serialization complete before the first file is written.
- The generated `servers.txt` is parsed back and compared field-by-field with
  `servers.json` before either file is published.
- If the canonical server payload and the list format version are unchanged, no
  file is rewritten and the workflow makes no commit. A format upgrade rewrites
  the files once, even when the server payload is unchanged.
- If the fetch fails, the workflow fails and the previously published list stays
  in place.
- Concurrency protection prevents overlapping refreshes.

## Local usage

```bash
python -m unittest discover -s scripts -p "test_*.py" -v
python scripts/fetch_servers.py --output /tmp/vpngate.csv
python scripts/generate_server_list.py --root . --raw /tmp/vpngate.csv
# Rebuild servers.txt + metadata.json after a format change, without the feed:
python scripts/generate_server_list.py --root . --from-json
```

Python 3.11+ is required. The scripts use only the standard library.

## Android consumption

The Android client uses `servers.txt` as its primary endpoint and keeps
`servers.json` as a compatibility fallback:

```
https://raw.githubusercontent.com/atajanofficial/ajx-vpn-server-list/main/servers.txt
https://raw.githubusercontent.com/atajanofficial/ajx-vpn-server-list/main/servers.json
```

A jsDelivr mirror of the same committed files can be configured as a secondary
fallback:

```
https://cdn.jsdelivr.net/gh/atajanofficial/ajx-vpn-server-list@main/servers.txt
https://cdn.jsdelivr.net/gh/atajanofficial/ajx-vpn-server-list@main/servers.json
```

The Android build reads `github.servers.txt.url`, `github.servers.json.url` and
`github.servers.fallbackUrls` from `local.properties`. The client only accepts
HTTPS URLs on an explicit host allowlist, disables redirects, and keeps its Room
cache when every endpoint fails.

`raw.githubusercontent.com` caches responses for a few minutes after a refresh,
so a client may briefly see the previous list; the `ETag` changes when the
content does. Each endpoint is tracked with its own `ETag` / `Last-Modified`
validator, so a fallback success never destroys the primary endpoint's
conditional-request state.

## Security

- No personal access token is required; the workflow uses `GITHUB_TOKEN`.
- No token is stored in the Android app, Gradle files, this repository, or git
  history.
- The fetch validates HTTPS and stays on `vpngate.net` hosts.
- TLS certificate verification is never disabled.
- The workflow only writes `servers.txt`, `servers.json` and `metadata.json`.
