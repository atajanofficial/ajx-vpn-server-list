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
import base64
import binascii
import hashlib
import json
import os
import shutil
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

from generate_server_list import (
    MANIFEST_JSON,
    MANIFEST_SIG,
    METADATA_JSON,
    SERVERS_JSON,
    SERVERS_TXT,
    canonical_payload,
    content_hash,
)
from validate_servers import (
    LIST_FORMAT_VERSION,
    MIN_EXPECTED_SERVERS,
    SERVER_JSON_SCHEMA_VERSION,
    ServerListError,
    parse_servers_json,
    parse_servers_txt,
)

PROJECT_NAME = "ajx-vpn-servers"
PAGES_HOST = "ajx-vpn-servers.pages.dev"
PUBLISHED_FILES = (SERVERS_TXT, SERVERS_JSON)
REQUIRED_FILES = (SERVERS_TXT, SERVERS_JSON, MANIFEST_JSON, METADATA_JSON)


class CloudflareBuildError(Exception):
    """Raised when the input dataset is unsafe to publish."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_required(path: str) -> bytes:
    if not os.path.isfile(path):
        raise CloudflareBuildError(f"missing required file: {os.path.basename(path)}")
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        raise CloudflareBuildError(
            f"cannot read {os.path.basename(path)}: {error}"
        ) from error
    if not data:
        raise CloudflareBuildError(f"{os.path.basename(path)} is empty")
    return data


def _decode_json(data: bytes, name: str) -> Dict[str, object]:
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise CloudflareBuildError(f"{name} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(document, dict):
        raise CloudflareBuildError(f"{name} must contain a JSON object")
    return document


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _validate_manifest(
    manifest: Dict[str, object], files: Dict[str, bytes], manifest_bytes: bytes
) -> None:
    if manifest.get("manifest_version") != 1:
        raise CloudflareBuildError("manifest_version must be 1")
    if manifest.get("list_format_version") != LIST_FORMAT_VERSION:
        raise CloudflareBuildError(
            f"manifest list_format_version must be {LIST_FORMAT_VERSION}"
        )
    if not _is_positive_int(manifest.get("generated_at")):
        raise CloudflareBuildError("manifest generated_at must be a positive integer")
    if not _is_positive_int(manifest.get("server_count")):
        raise CloudflareBuildError("manifest server_count must be a positive integer")

    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise CloudflareBuildError("manifest files must be a non-empty array")
    declared: Dict[str, Tuple[int, str]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise CloudflareBuildError("each manifest file entry must be an object")
        name = entry.get("name")
        size = entry.get("size")
        sha256 = entry.get("sha256")
        if not isinstance(name, str) or not name:
            raise CloudflareBuildError("a manifest file entry has no name")
        if not _is_positive_int(size):
            raise CloudflareBuildError(f"manifest size for {name} is invalid")
        if not isinstance(sha256, str) or len(sha256) != 64:
            raise CloudflareBuildError(f"manifest sha256 for {name} is invalid")
        if name in declared:
            raise CloudflareBuildError(f"manifest declares {name} twice")
        declared[name] = (int(size), sha256.lower())

    if set(declared) != set(PUBLISHED_FILES):
        raise CloudflareBuildError(
            "manifest must describe exactly servers.txt and servers.json"
        )
    for name, (size, sha256) in declared.items():
        actual = files[name]
        if len(actual) != size:
            raise CloudflareBuildError(
                f"{name} size mismatch: manifest={size} actual={len(actual)}"
            )
        actual_sha = _sha256(actual)
        if actual_sha != sha256:
            raise CloudflareBuildError(
                f"{name} SHA-256 mismatch: manifest={sha256} actual={actual_sha}"
            )

    # The manifest itself is described by metadata. This catches a stale
    # metadata document paired with a newer list and manifest.
    metadata = _decode_json(files[METADATA_JSON], METADATA_JSON)
    metadata_manifest = metadata.get("manifest")
    if not isinstance(metadata_manifest, dict):
        raise CloudflareBuildError("metadata has no manifest section")
    recorded_manifest_sha = metadata_manifest.get("sha256")
    if not isinstance(recorded_manifest_sha, str) or \
            recorded_manifest_sha.lower() != _sha256(manifest_bytes):
        raise CloudflareBuildError("metadata manifest SHA-256 does not match manifest.json")


def _validate_dataset(root: str) -> Dict[str, object]:
    paths = {name: os.path.join(root, name) for name in REQUIRED_FILES}
    files = {name: _read_required(path) for name, path in paths.items()}

    signature_path = os.path.join(root, MANIFEST_SIG)
    signature_bytes: Optional[bytes] = None
    if os.path.exists(signature_path):
        signature_bytes = _read_required(signature_path)
        signature = _decode_json(signature_bytes, MANIFEST_SIG)
        if signature.get("algorithm") != "ECDSA_P256_SHA256":
            raise CloudflareBuildError("manifest.sig has an unsupported algorithm")
        if not isinstance(signature.get("key_id"), str) or not signature["key_id"]:
            raise CloudflareBuildError("manifest.sig has no key_id")
        encoded = str(signature.get("signature_base64") or "")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise CloudflareBuildError("manifest.sig has invalid base64") from error
        if not 60 <= len(decoded) <= 72:
            raise CloudflareBuildError("manifest.sig has an invalid ECDSA signature length")

    manifest = _decode_json(files[MANIFEST_JSON], MANIFEST_JSON)
    _validate_manifest(manifest, files, files[MANIFEST_JSON])

    try:
        txt = parse_servers_txt(
            files[SERVERS_TXT].decode("utf-8"), min_servers=MIN_EXPECTED_SERVERS
        )
        parsed_json = parse_servers_json(
            files[SERVERS_JSON].decode("utf-8"), min_servers=MIN_EXPECTED_SERVERS
        )
    except UnicodeDecodeError as error:
        raise CloudflareBuildError(f"a list file is not valid UTF-8: {error}") from error
    except ServerListError as error:
        raise CloudflareBuildError(f"published list failed validation: {error}") from error

    if canonical_payload(txt.records) != canonical_payload(parsed_json.records):
        raise CloudflareBuildError("servers.txt and servers.json contain different records")
    if txt.refresh_ms != parsed_json.refresh_ms:
        raise CloudflareBuildError("the two list formats have different refresh times")

    expected_count = int(manifest["server_count"])
    if len(txt.records) != expected_count or len(parsed_json.records) != expected_count:
        raise CloudflareBuildError(
            f"record count mismatch: manifest={expected_count} "
            f"txt={len(txt.records)} json={len(parsed_json.records)}"
        )
    generated_at = int(manifest["generated_at"])
    if txt.refresh_ms != generated_at or parsed_json.refresh_ms != generated_at:
        raise CloudflareBuildError("manifest and list publication times differ")

    metadata = _decode_json(files[METADATA_JSON], METADATA_JSON)
    if metadata.get("schema_version") != SERVER_JSON_SCHEMA_VERSION:
        raise CloudflareBuildError("metadata schema_version is unsupported")
    if metadata.get("list_format_version") != LIST_FORMAT_VERSION:
        raise CloudflareBuildError("metadata list_format_version is unsupported")
    if metadata.get("server_count") != expected_count:
        raise CloudflareBuildError("metadata server_count does not match the manifest")
    if metadata.get("generated_at") != generated_at:
        raise CloudflareBuildError("metadata generated_at does not match the manifest")
    if metadata.get("content_hash") != content_hash(canonical_payload(txt.records)):
        raise CloudflareBuildError("metadata content_hash does not match the records")
    if metadata.get("published_files") != list(PUBLISHED_FILES):
        raise CloudflareBuildError("metadata published_files is incomplete")

    declared_hashes = {
        entry["name"]: (entry["size"], entry["sha256"])
        for entry in manifest.get("files", [])
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }
    if metadata.get("file_hashes") != {
        name: {"size": size, "sha256": sha256}
        for name, (size, sha256) in declared_hashes.items()
    }:
        raise CloudflareBuildError("metadata file hashes do not match the manifest")

    return {
        "files": files,
        "signature": signature_bytes,
        "manifest": manifest,
        "metadata": metadata,
        "server_count": expected_count,
        "generated_at": generated_at,
    }


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


def _write_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def build(root: str, output: str) -> Dict[str, object]:
    """Validate the committed dataset, then publish it atomically."""
    dataset = _validate_dataset(root)
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
