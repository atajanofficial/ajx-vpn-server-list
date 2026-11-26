"""Build the static Firebase Hosting deployment from validated local files.

Firebase Hosting is an additional source, not a replacement for the GitHub
publisher or the Cloudflare deployment. This script therefore publishes exactly
the dataset committed by the publisher workflow:

* ``servers.txt`` stays the primary format v2 file;
* ``servers.json`` remains the compatibility fallback;
* ``manifest.json`` carries the exact size and SHA-256 of both files;
* ``manifest.sig`` is included when the publisher signed the manifest.

Everything is validated by :mod:`published_dataset` before a single byte is
staged. The generated ``firebase.json`` is validated as well: it must serve the
same directory, must not rewrite missing files, must not publish its own
configuration, and must give the list files a revalidating cache policy.

The deployment directory is assembled in a temporary sibling and swapped into
place only after every check has passed. A rejected rebuild leaves the previous
good deployment untouched.

Usage::

    python scripts/build_firebase_hosting.py --root . --output firebase-hosting
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from typing import Dict, List, Optional

from generate_server_list import (
    MANIFEST_JSON,
    MANIFEST_SIG,
    METADATA_JSON,
    SERVERS_JSON,
    SERVERS_TXT,
)
from published_dataset import DatasetError, sha256_hex, validate_dataset

PROJECT_ID = "ajx-vpn-servers"
FIREBASE_HOST = f"{PROJECT_ID}.web.app"
FIREBASE_CONFIG = "firebase.json"
FIREBASERC = ".firebaserc"
INDEX_HTML = "index.html"

# Kept as a module-level name so tests and callers can catch one error type.
FirebaseBuildError = DatasetError

_REVALIDATE = "public, max-age=0, must-revalidate"
_PROJECT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


def _write_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _index_html(server_count: int, generated_at: int, manifest_sha: str) -> str:
    # Provider-neutral: this page is public and must not advertise hosting
    # infrastructure. It only documents the published files.
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AJX VPN server list</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 44rem;
      line-height: 1.5; color: #222; }}
    code {{ background: #f4f4f4; padding: .1rem .3rem; }}
  </style>
</head>
<body>
  <h1>AJX VPN server list</h1>
  <p>Static distribution files for the AJX VPN application.</p>
  <ul>
    <li><a href="/servers.txt">servers.txt</a> (primary)</li>
    <li><a href="/servers.json">servers.json</a> (compatibility fallback)</li>
    <li><a href="/manifest.json">manifest.json</a> (integrity metadata)</li>
  </ul>
  <p>
    Records: <strong>{server_count}</strong><br>
    Published: <code>{generated_at}</code><br>
    Manifest SHA-256: <code>{manifest_sha}</code>
  </p>
</body>
</html>
"""


def _header_rule(source: str, values: Dict[str, str]) -> Dict[str, object]:
    return {
        "source": source,
        "headers": [
            {"key": key, "value": value} for key, value in values.items()
        ],
    }


def _firebase_config() -> Dict[str, object]:
    return {
        "hosting": {
            # The validated files sit next to firebase.json. The ignore list
            # below keeps the deployment configuration itself off the public
            # origin.
            "public": ".",
            "ignore": [
                FIREBASE_CONFIG,
                FIREBASERC,
                "**/.*",
                "**/node_modules/**",
            ],
            "headers": [
                _header_rule(
                    "**",
                    {
                        "X-Content-Type-Options": "nosniff",
                        "Referrer-Policy": "no-referrer",
                        "Access-Control-Allow-Origin": "*",
                    },
                ),
                _header_rule(
                    "/servers.txt",
                    {
                        "Content-Type": "text/plain; charset=utf-8",
                        "Cache-Control": _REVALIDATE,
                    },
                ),
                _header_rule(
                    "/servers.json",
                    {
                        "Content-Type": "application/json; charset=utf-8",
                        "Cache-Control": _REVALIDATE,
                    },
                ),
                _header_rule(
                    "/manifest.json",
                    {
                        "Content-Type": "application/json; charset=utf-8",
                        "Cache-Control": _REVALIDATE,
                    },
                ),
                _header_rule(
                    "/manifest.sig",
                    {
                        "Content-Type": "application/json; charset=utf-8",
                        "Cache-Control": _REVALIDATE,
                    },
                ),
                _header_rule(
                    "/index.html",
                    {
                        "Content-Type": "text/html; charset=utf-8",
                        "Cache-Control": "public, max-age=300",
                    },
                ),
            ],
        }
    }


def _firebaserc(project_id: str) -> Dict[str, object]:
    if not _PROJECT_ID_PATTERN.fullmatch(project_id):
        raise FirebaseBuildError(f"invalid Firebase project id: {project_id!r}")
    return {"projects": {"default": project_id}}


def _json_bytes(document: Dict[str, object]) -> bytes:
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _validate_generated_config(
    config: Dict[str, object], firebaserc: Dict[str, object]
) -> None:
    hosting = config.get("hosting")
    if not isinstance(hosting, dict):
        raise FirebaseBuildError("firebase.json must contain a hosting object")
    if hosting.get("public") != ".":
        raise FirebaseBuildError("firebase.json must serve the deployment directory")
    if hosting.get("rewrites") or hosting.get("redirects"):
        raise FirebaseBuildError("firebase.json must not rewrite or redirect files")

    ignore = hosting.get("ignore")
    if not isinstance(ignore, list) or FIREBASE_CONFIG not in ignore:
        raise FirebaseBuildError("firebase.json must ignore its own configuration")
    if FIREBASERC not in ignore:
        raise FirebaseBuildError("firebase.json must ignore .firebaserc")

    rules = hosting.get("headers")
    if not isinstance(rules, list) or not rules:
        raise FirebaseBuildError("firebase.json must declare response headers")
    by_source: Dict[str, Dict[str, str]] = {}
    for rule in rules:
        if not isinstance(rule, dict):
            raise FirebaseBuildError("each header rule must be an object")
        source = rule.get("source")
        entries = rule.get("headers")
        if not isinstance(source, str) or not isinstance(entries, list):
            raise FirebaseBuildError("a header rule is malformed")
        values: Dict[str, str] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise FirebaseBuildError("a header entry is malformed")
            key = entry.get("key")
            value = entry.get("value")
            if not isinstance(key, str) or not isinstance(value, str):
                raise FirebaseBuildError("a header entry is malformed")
            values[key.lower()] = value
        by_source[source] = values

    global_headers = by_source.get("**", {})
    if global_headers.get("x-content-type-options") != "nosniff":
        raise FirebaseBuildError("missing nosniff header")
    if global_headers.get("access-control-allow-origin") != "*":
        raise FirebaseBuildError("missing CORS header")

    expected_types = {
        "/servers.txt": "text/plain",
        "/servers.json": "application/json",
        "/manifest.json": "application/json",
        "/manifest.sig": "application/json",
    }
    for source, media_type in expected_types.items():
        values = by_source.get(source)
        if values is None:
            raise FirebaseBuildError(f"missing header rule for {source}")
        if not values.get("content-type", "").startswith(media_type):
            raise FirebaseBuildError(f"wrong content type for {source}")
        if values.get("cache-control") != _REVALIDATE:
            raise FirebaseBuildError(f"unsafe cache policy for {source}")

    index = by_source.get("/index.html")
    if index is None or "max-age=300" not in index.get("cache-control", ""):
        raise FirebaseBuildError("index.html must have a short cache lifetime")

    projects = firebaserc.get("projects")
    if not isinstance(projects, dict):
        raise FirebaseBuildError(".firebaserc must contain projects")
    project_id = projects.get("default")
    if not isinstance(project_id, str) or not _PROJECT_ID_PATTERN.fullmatch(project_id):
        raise FirebaseBuildError(".firebaserc has an invalid project id")


def build(root: str, output: str) -> Dict[str, object]:
    """Validate the committed dataset, then publish it atomically."""
    dataset = validate_dataset(root)
    files = dataset["files"]  # type: ignore[index]
    manifest_bytes = files[MANIFEST_JSON]  # type: ignore[index]
    manifest_sha = sha256_hex(manifest_bytes)

    config = _firebase_config()
    firebaserc = _firebaserc(PROJECT_ID)
    _validate_generated_config(config, firebaserc)

    expected = {
        SERVERS_TXT,
        SERVERS_JSON,
        MANIFEST_JSON,
        INDEX_HTML,
        FIREBASE_CONFIG,
        FIREBASERC,
    }
    if dataset["signature"] is not None:
        expected.add(MANIFEST_SIG)

    output = os.path.abspath(output)
    parent = os.path.dirname(output) or "."
    os.makedirs(parent, exist_ok=True)
    staging = tempfile.mkdtemp(prefix=".firebase-stage-", dir=parent)
    backup: Optional[str] = None
    try:
        for name in (SERVERS_TXT, SERVERS_JSON):
            _write_bytes(os.path.join(staging, name), files[name])  # type: ignore[index]
        _write_bytes(os.path.join(staging, MANIFEST_JSON), manifest_bytes)
        if dataset["signature"] is not None:
            _write_bytes(os.path.join(staging, MANIFEST_SIG), dataset["signature"])  # type: ignore[arg-type]
        _write_bytes(
            os.path.join(staging, INDEX_HTML),
            _index_html(
                int(dataset["server_count"]),  # type: ignore[arg-type]
                int(dataset["generated_at"]),  # type: ignore[arg-type]
                manifest_sha,
            ).encode("utf-8"),
        )
        _write_bytes(os.path.join(staging, FIREBASE_CONFIG), _json_bytes(config))
        _write_bytes(os.path.join(staging, FIREBASERC), _json_bytes(firebaserc))

        # Never publish a stray file, a temporary file or a credential.
        actual = set(os.listdir(staging))
        if actual != expected:
            unexpected = sorted(actual - expected)
            missing = sorted(expected - actual)
            raise FirebaseBuildError(
                f"unexpected deployment contents: extra={unexpected} missing={missing}"
            )

        if os.path.isdir(output):
            backup = tempfile.mkdtemp(prefix=".firebase-old-", dir=parent)
            os.rmdir(backup)
            os.replace(output, backup)
        try:
            os.replace(staging, output)
        except BaseException:
            if backup is not None and os.path.isdir(backup) and not os.path.exists(output):
                os.replace(backup, output)
                backup = None
            raise
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)
            backup = None
    finally:
        if os.path.isdir(staging):
            shutil.rmtree(staging, ignore_errors=True)
        if backup is not None and os.path.isdir(backup):
            shutil.rmtree(backup, ignore_errors=True)

    return {
        "project": PROJECT_ID,
        "host": FIREBASE_HOST,
        "server_count": dataset["server_count"],
        "generated_at": dataset["generated_at"],
        "manifest_sha256": manifest_sha,
        "servers_txt_sha256": sha256_hex(files[SERVERS_TXT]),  # type: ignore[index]
        "servers_json_sha256": sha256_hex(files[SERVERS_JSON]),  # type: ignore[index]
        "firebase_config_sha256": sha256_hex(_json_bytes(config)),
        "output": output,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="directory containing the published list")
    parser.add_argument(
        "--output", default="firebase-hosting", help="static deployment directory"
    )
    args = parser.parse_args(argv)

    try:
        summary = build(args.root, args.output)
    except DatasetError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"Firebase project (candidate): {summary['project']}")
    print(f"Expected host: https://{summary['host']}/")
    print(f"Server count: {summary['server_count']}")
    print(f"Generated at: {summary['generated_at']}")
    print(f"manifest.json SHA-256: {summary['manifest_sha256']}")
    print(f"servers.txt SHA-256: {summary['servers_txt_sha256']}")
    print(f"servers.json SHA-256: {summary['servers_json_sha256']}")
    print(f"firebase.json SHA-256: {summary['firebase_config_sha256']}")
    print(f"Deployment directory: {summary['output']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
