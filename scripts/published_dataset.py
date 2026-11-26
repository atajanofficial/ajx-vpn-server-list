"""Strict validation shared by the static deployment builders.

Every static host (Cloudflare Pages, Firebase Hosting) must publish exactly the
dataset that the publisher workflow committed. This module performs the checks
once so two builders cannot drift apart:

* ``servers.txt``, ``servers.json``, ``manifest.json`` and ``metadata.json``
  must all be present and non-empty;
* the manifest must describe exactly the two list files, with matching byte
  sizes and SHA-256 digests;
* both list formats must parse to the same canonical records and count;
* the publication timestamp and record count must agree everywhere;
* an optional detached signature must have the expected structure.

The builders stage their output separately; this module only reads and
validates, so a rejected dataset never reaches a deployment directory.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from typing import Dict, Optional, Tuple

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

PUBLISHED_FILES = (SERVERS_TXT, SERVERS_JSON)
REQUIRED_FILES = (SERVERS_TXT, SERVERS_JSON, MANIFEST_JSON, METADATA_JSON)


class DatasetError(Exception):
    """Raised when the input dataset is unsafe to publish."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_required(path: str) -> bytes:
    if not os.path.isfile(path):
        raise DatasetError(f"missing required file: {os.path.basename(path)}")
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        raise DatasetError(f"cannot read {os.path.basename(path)}: {error}") from error
    if not data:
        raise DatasetError(f"{os.path.basename(path)} is empty")
    return data


def decode_json(data: bytes, name: str) -> Dict[str, object]:
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise DatasetError(f"{name} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(document, dict):
        raise DatasetError(f"{name} must contain a JSON object")
    return document


def is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _validate_manifest(
    manifest: Dict[str, object], files: Dict[str, bytes], manifest_bytes: bytes
) -> None:
    if manifest.get("manifest_version") != 1:
        raise DatasetError("manifest_version must be 1")
    if manifest.get("list_format_version") != LIST_FORMAT_VERSION:
        raise DatasetError(
            f"manifest list_format_version must be {LIST_FORMAT_VERSION}"
        )
    if not is_positive_int(manifest.get("generated_at")):
        raise DatasetError("manifest generated_at must be a positive integer")
    if not is_positive_int(manifest.get("server_count")):
        raise DatasetError("manifest server_count must be a positive integer")

    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise DatasetError("manifest files must be a non-empty array")
    declared: Dict[str, Tuple[int, str]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise DatasetError("each manifest file entry must be an object")
        name = entry.get("name")
        size = entry.get("size")
        sha256 = entry.get("sha256")
        if not isinstance(name, str) or not name:
            raise DatasetError("a manifest file entry has no name")
        if not is_positive_int(size):
            raise DatasetError(f"manifest size for {name} is invalid")
        if not isinstance(sha256, str) or len(sha256) != 64:
            raise DatasetError(f"manifest sha256 for {name} is invalid")
        if name in declared:
            raise DatasetError(f"manifest declares {name} twice")
        declared[name] = (int(size), sha256.lower())

    if set(declared) != set(PUBLISHED_FILES):
        raise DatasetError(
            "manifest must describe exactly servers.txt and servers.json"
        )
    for name, (size, sha256) in declared.items():
        actual = files[name]
        if len(actual) != size:
            raise DatasetError(
                f"{name} size mismatch: manifest={size} actual={len(actual)}"
            )
        actual_sha = sha256_hex(actual)
        if actual_sha != sha256:
            raise DatasetError(
                f"{name} SHA-256 mismatch: manifest={sha256} actual={actual_sha}"
            )

    # The manifest itself is described by metadata. This catches a stale
    # metadata document paired with a newer list and manifest.
    metadata = decode_json(files[METADATA_JSON], METADATA_JSON)
    metadata_manifest = metadata.get("manifest")
    if not isinstance(metadata_manifest, dict):
        raise DatasetError("metadata has no manifest section")
    recorded_manifest_sha = metadata_manifest.get("sha256")
    if not isinstance(recorded_manifest_sha, str) or \
            recorded_manifest_sha.lower() != sha256_hex(manifest_bytes):
        raise DatasetError("metadata manifest SHA-256 does not match manifest.json")


def validate_dataset(root: str) -> Dict[str, object]:
    """Validate the committed dataset and return its bytes and summary values."""
    paths = {name: os.path.join(root, name) for name in REQUIRED_FILES}
    files = {name: read_required(path) for name, path in paths.items()}

    signature_path = os.path.join(root, MANIFEST_SIG)
    signature_bytes: Optional[bytes] = None
    if os.path.exists(signature_path):
        signature_bytes = read_required(signature_path)
        signature = decode_json(signature_bytes, MANIFEST_SIG)
        if signature.get("algorithm") != "ECDSA_P256_SHA256":
            raise DatasetError("manifest.sig has an unsupported algorithm")
        if not isinstance(signature.get("key_id"), str) or not signature["key_id"]:
            raise DatasetError("manifest.sig has no key_id")
        encoded = str(signature.get("signature_base64") or "")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise DatasetError("manifest.sig has invalid base64") from error
        if not 60 <= len(decoded) <= 72:
            raise DatasetError("manifest.sig has an invalid ECDSA signature length")

    manifest = decode_json(files[MANIFEST_JSON], MANIFEST_JSON)
    _validate_manifest(manifest, files, files[MANIFEST_JSON])

    try:
        txt = parse_servers_txt(
            files[SERVERS_TXT].decode("utf-8"), min_servers=MIN_EXPECTED_SERVERS
        )
        parsed_json = parse_servers_json(
            files[SERVERS_JSON].decode("utf-8"), min_servers=MIN_EXPECTED_SERVERS
        )
    except UnicodeDecodeError as error:
        raise DatasetError(f"a list file is not valid UTF-8: {error}") from error
    except ServerListError as error:
        raise DatasetError(f"published list failed validation: {error}") from error

    if canonical_payload(txt.records) != canonical_payload(parsed_json.records):
        raise DatasetError("servers.txt and servers.json contain different records")
    if txt.refresh_ms != parsed_json.refresh_ms:
        raise DatasetError("the two list formats have different refresh times")

    expected_count = int(manifest["server_count"])
    if len(txt.records) != expected_count or len(parsed_json.records) != expected_count:
        raise DatasetError(
            f"record count mismatch: manifest={expected_count} "
            f"txt={len(txt.records)} json={len(parsed_json.records)}"
        )
    generated_at = int(manifest["generated_at"])
    if txt.refresh_ms != generated_at or parsed_json.refresh_ms != generated_at:
        raise DatasetError("manifest and list publication times differ")

    metadata = decode_json(files[METADATA_JSON], METADATA_JSON)
    if metadata.get("schema_version") != SERVER_JSON_SCHEMA_VERSION:
        raise DatasetError("metadata schema_version is unsupported")
    if metadata.get("list_format_version") != LIST_FORMAT_VERSION:
        raise DatasetError("metadata list_format_version is unsupported")
    if metadata.get("server_count") != expected_count:
        raise DatasetError("metadata server_count does not match the manifest")
    if metadata.get("generated_at") != generated_at:
        raise DatasetError("metadata generated_at does not match the manifest")
    if metadata.get("content_hash") != content_hash(canonical_payload(txt.records)):
        raise DatasetError("metadata content_hash does not match the records")
    if metadata.get("published_files") != list(PUBLISHED_FILES):
        raise DatasetError("metadata published_files is incomplete")

    declared_hashes = {
        entry["name"]: (entry["size"], entry["sha256"])
        for entry in manifest.get("files", [])
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }
    if metadata.get("file_hashes") != {
        name: {"size": size, "sha256": sha256}
        for name, (size, sha256) in declared_hashes.items()
    }:
        raise DatasetError("metadata file hashes do not match the manifest")

    return {
        "files": files,
        "signature": signature_bytes,
        "manifest": manifest,
        "metadata": metadata,
        "server_count": expected_count,
        "generated_at": generated_at,
    }
