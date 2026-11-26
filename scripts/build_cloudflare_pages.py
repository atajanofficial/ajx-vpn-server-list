"""Build the static Cloudflare Pages deployment from validated local files.

The publisher workflow in this repository commits ``servers.txt``,
``servers.json``, ``manifest.json`` and ``metadata.json`` together. This script
refuses to assemble a deployment unless those files describe exactly the same
dataset: the manifest hashes must match the bytes on disk, both list formats
must parse to the same canonical records, and their record counts must agree
with the metadata.

Files are staged in a temporary directory and swapped into place only after
every validation has passed. A failed run never leaves a partially generated
deployment directory behind.

Usage::

    python scripts/build_cloudflare_pages.py --root . --output cloudflare-pages
"""

from __future__ import annotations

import argparse
import os
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
from published_dataset import (
    PUBLISHED_FILES,
    DatasetError,
    sha256_hex,
    validate_dataset,
)

PROJECT_NAME = "ajx-vpn-servers"
PAGES_HOST = "ajx-vpn-servers.pages.dev"

# Kept as a module-level alias so existing callers and tests keep working.
CloudflareBuildError = DatasetError


def _sha256(data: bytes) -> str:
    return sha256_hex(data)


def _write_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _index_html(server_count: int, generated_at: int, manifest_sha: str) -> str:
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


def _headers() -> str:
    return """/*
  Access-Control-Allow-Origin: *
  X-Content-Type-Options: nosniff

/servers.txt
  Content-Type: text/plain; charset=UTF-8
  Cache-Control: public, max-age=0, must-revalidate

/servers.json
  Content-Type: application/json; charset=UTF-8
  Cache-Control: public, max-age=0, must-revalidate

/manifest.json
  Content-Type: application/json; charset=UTF-8
  Cache-Control: public, max-age=0, must-revalidate

/manifest.sig
  Content-Type: application/json; charset=UTF-8
  Cache-Control: public, max-age=0, must-revalidate

/index.html
  Content-Type: text/html; charset=UTF-8
  Cache-Control: public, max-age=300
"""


def build(root: str, output: str) -> Dict[str, object]:
    """Validate the committed dataset, then publish it atomically."""
    dataset = validate_dataset(root)
    files = dataset["files"]  # type: ignore[index]
    manifest_bytes = files[MANIFEST_JSON]  # type: ignore[index]
    manifest_sha = _sha256(manifest_bytes)

    output = os.path.abspath(output)
    parent = os.path.dirname(output) or "."
    os.makedirs(parent, exist_ok=True)
    staging = tempfile.mkdtemp(prefix=".pages-stage-", dir=parent)
    backup: Optional[str] = None
    try:
        for name in PUBLISHED_FILES:
            _write_bytes(os.path.join(staging, name), files[name])  # type: ignore[index]
        _write_bytes(os.path.join(staging, MANIFEST_JSON), manifest_bytes)
        if dataset["signature"] is not None:
            _write_bytes(os.path.join(staging, MANIFEST_SIG), dataset["signature"])  # type: ignore[arg-type]
        _write_bytes(
            os.path.join(staging, "index.html"),
            _index_html(
                int(dataset["server_count"]),  # type: ignore[arg-type]
                int(dataset["generated_at"]),  # type: ignore[arg-type]
                manifest_sha,
            ).encode("utf-8"),
        )
        _write_bytes(os.path.join(staging, "_headers"), _headers().encode("utf-8"))

        if os.path.isdir(output):
            backup = tempfile.mkdtemp(prefix=".pages-old-", dir=parent)
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
        "project": PROJECT_NAME,
        "host": PAGES_HOST,
        "server_count": dataset["server_count"],
        "generated_at": dataset["generated_at"],
        "manifest_sha256": manifest_sha,
        "servers_txt_sha256": _sha256(files[SERVERS_TXT]),  # type: ignore[index]
        "servers_json_sha256": _sha256(files[SERVERS_JSON]),  # type: ignore[index]
        "output": output,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="directory containing the published list")
    parser.add_argument(
        "--output", default="cloudflare-pages", help="static deployment directory"
    )
    args = parser.parse_args(argv)

    try:
        summary = build(args.root, args.output)
    except CloudflareBuildError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"Cloudflare Pages project: {summary['project']}")
    print(f"Expected host: https://{summary['host']}/")
    print(f"Server count: {summary['server_count']}")
    print(f"Generated at: {summary['generated_at']}")
    print(f"manifest.json SHA-256: {summary['manifest_sha256']}")
    print(f"servers.txt SHA-256: {summary['servers_txt_sha256']}")
    print(f"servers.json SHA-256: {summary['servers_json_sha256']}")
    print(f"Deployment directory: {summary['output']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
