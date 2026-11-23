"""Generate the versioned AJX VPN server list files from a raw VPN Gate feed.

Outputs (all in the repository root):

* ``servers.txt`` - authoritative, header-driven format v2 list. It carries the
  full record set, including the inline OpenVPN profiles the engine needs.
* ``servers.json`` - the same records in the Android-compatible schema v1
  envelope, kept as a compatibility mirror.
* ``metadata.json`` - counts, source provenance, format versions and the
  content hash used for no-change detection.
* ``manifest.json`` - the exact byte size and SHA-256 of every published list
  file. The Android client verifies a downloaded payload against this document
  before parsing it.
* ``manifest.sig`` - optional detached ECDSA P-256 / SHA-256 signature over the
  exact bytes of ``manifest.json``. It is produced by ``sign_manifest.py`` from
  a private key held only in CI, and verified by the client against a public key
  pinned at build time.

The manifest is the only integrity metadata the client trusts, and it is never
downloaded from the same HTTP response as the payload it describes.

The generator is fail-safe:

* it validates every record before touching an existing file;
* it refuses to publish an empty or implausibly small list;
* it only rewrites the files when the canonical server payload changed, so a
  30-minute scheduled run does not create an empty commit every time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from validate_servers import (
    LIST_FORMAT_VERSION,
    MIN_EXPECTED_SERVERS,
    SERVER_JSON_SCHEMA_VERSION,
    SOURCE_NAME,
    SOURCE_URL,
    TXT_COLUMNS,
    EmptySourceError,
    ServerListError,
    ServerRecord,
    ValidationStats,
    parse_servers_json,
    parse_servers_txt,
    parse_source,
    protocol_counts,
    validation_counts,
)

SERVERS_JSON = "servers.json"
SERVERS_TXT = "servers.txt"
METADATA_JSON = "metadata.json"
MANIFEST_JSON = "manifest.json"
MANIFEST_SIG = "manifest.sig"
MANIFEST_VERSION = 1

VALIDATION_DETAIL = "structurally validated by the refresh workflow; not probed"
# Kept as an alias for callers that imported the old constant.
TXT_HEADER_COLUMNS = TXT_COLUMNS


@dataclass
class GenerationResult:
    changed: bool
    server_count: int
    content_hash: str
    refresh_ms: int
    stats: Optional[ValidationStats] = None
    protocol_counts: Optional[Dict[str, int]] = None
    validation_counts: Optional[Dict[str, int]] = None
    manifest_sha256: str = ""
    manifest_changed: bool = False


class GenerationError(ServerListError):
    """The generated list failed its own pre-publish check."""


def _record_payload(record: ServerRecord) -> Dict[str, object]:
    return {
        "id": record.server_id,
        "ip": record.ip,
        "hostname": record.hostname,
        "country": record.country,
        "country_code": record.country_code,
        "score": record.score,
        "ping": record.ping,
        "speed": record.speed,
        "sessions": record.sessions,
        "uptime": record.uptime,
        "total_users": record.total_users,
        "total_traffic": record.total_traffic,
        "log_type": record.log_type,
        "operator": record.operator,
        "message": record.message,
        "openvpn_config_base64": record.openvpn_config_base64,
        "protocol": record.protocol,
        "port": record.port,
        "verification": {
            "state": "UNKNOWN",
            "last_checked_at": None,
            "expires_at": None,
            "detail": VALIDATION_DETAIL,
        },
    }


def canonical_payload(records: List[ServerRecord]) -> List[Dict[str, object]]:
    """The timestamp-free payload used for hashing and change detection."""

    return [_record_payload(record) for record in records]


def content_hash(payload: List[Dict[str, object]]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest_files(servers_txt: str, servers_json: str) -> List[Dict[str, object]]:
    """Hashes of the exact UTF-8 bytes that are written to disk."""

    files = []
    for name, content in ((SERVERS_TXT, servers_txt), (SERVERS_JSON, servers_json)):
        encoded = content.encode("utf-8")
        files.append(
            {
                "name": name,
                "size": len(encoded),
                "sha256": _sha256_hex(encoded),
            }
        )
    return files


def build_manifest(
    servers_txt: str,
    servers_json: str,
    refresh_ms: int,
    server_count: int,
) -> str:
    """Deterministic integrity manifest for the two published list files.

    The document deliberately contains no signature field: ``manifest.sig``
    signs these exact bytes, so adding the signature inside the document would
    be circular.
    """

    document = {
        "manifest_version": MANIFEST_VERSION,
        "list_format_version": LIST_FORMAT_VERSION,
        "generated_at": refresh_ms,
        "server_count": server_count,
        "primary_format": SERVERS_TXT,
        "files": _manifest_files(servers_txt, servers_json),
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _verify_manifest(
    manifest: str,
    servers_txt: str,
    servers_json: str,
    expected_count: int,
) -> None:
    try:
        parsed = json.loads(manifest)
    except ValueError as error:
        raise GenerationError(f"generated manifest.json is not valid JSON: {error}") from error

    if parsed.get("manifest_version") != MANIFEST_VERSION:
        raise GenerationError("generated manifest.json has the wrong manifest version")
    if parsed.get("list_format_version") != LIST_FORMAT_VERSION:
        raise GenerationError("generated manifest.json has the wrong list format version")
    if parsed.get("server_count") != expected_count or expected_count <= 0:
        raise GenerationError("generated manifest.json has the wrong server count")
    if not isinstance(parsed.get("generated_at"), int) or parsed["generated_at"] <= 0:
        raise GenerationError("generated manifest.json has an invalid timestamp")

    entries = parsed.get("files")
    if not isinstance(entries, list) or len(entries) != 2:
        raise GenerationError("generated manifest.json must describe exactly two files")

    expected = {
        entry["name"]: (entry["size"], entry["sha256"])
        for entry in _manifest_files(servers_txt, servers_json)
    }
    for entry in entries:
        name = entry.get("name")
        if name not in expected:
            raise GenerationError(f"generated manifest.json lists an unexpected file: {name}")
        size, digest = expected[name]
        if entry.get("size") != size or entry.get("sha256") != digest:
            raise GenerationError(f"generated manifest.json hash mismatch for {name}")


def _write_if_changed(path: str, content: str) -> bool:
    data = content.encode("utf-8")
    try:
        with open(path, "rb") as handle:
            if handle.read() == data:
                return False
    except OSError:
        pass
    _write_atomic(path, content)
    return True


def _remove_if_exists(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def build_servers_json(records: List[ServerRecord], refresh_ms: int) -> str:
    document = {
        "schema_version": SERVER_JSON_SCHEMA_VERSION,
        "last_successful_refresh": refresh_ms,
        "stale": False,
        "last_refresh_error": None,
        "servers": canonical_payload(records),
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _txt_field(value: object) -> str:
    text = str(value)
    return text.replace("\t", " ").replace("\r", " ").replace("\n", " ").strip()


def build_servers_txt(records: List[ServerRecord], refresh_ms: int) -> str:
    lines = [
        "# AJX VPN server list",
        f"# format_version={LIST_FORMAT_VERSION}",
        f"# source={SOURCE_URL}",
        f"# last_updated={refresh_ms}",
        "# columns=" + "\t".join(TXT_COLUMNS),
    ]
    for record in records:
        lines.append(
            "\t".join(
                [
                    _txt_field(record.server_id),
                    _txt_field(record.ip),
                    _txt_field(record.country_code),
                    _txt_field(record.country),
                    _txt_field(record.hostname),
                    _txt_field(record.port),
                    _txt_field(record.protocol.upper()),
                    _txt_field(record.score),
                    _txt_field(record.ping),
                    _txt_field(record.speed),
                    _txt_field(record.sessions),
                    _txt_field(record.uptime),
                    _txt_field(record.total_users),
                    _txt_field(record.total_traffic),
                    _txt_field(record.log_type),
                    _txt_field(record.operator),
                    _txt_field(record.message),
                    _txt_field(record.openvpn_config_base64),
                    _txt_field(record.validation_state),
                    _txt_field(record.source),
                    _txt_field(refresh_ms),
                ]
            )
        )
    return "\n".join(lines) + "\n"


def build_metadata(
    records: List[ServerRecord],
    refresh_ms: int,
    digest: str,
    stats: ValidationStats,
    manifest_text: str,
    source_url: str = SOURCE_URL,
) -> str:
    document = {
        "schema_version": SERVER_JSON_SCHEMA_VERSION,
        "list_format_version": LIST_FORMAT_VERSION,
        "source": {
            "name": SOURCE_NAME,
            "url": source_url,
            "retrieved_at": refresh_ms,
        },
        "generated_at": refresh_ms,
        "last_changed_at": refresh_ms,
        "server_count": len(records),
        "protocol_counts": protocol_counts(records),
        "validation_counts": validation_counts(records),
        "content_hash": digest,
        "published_files": [SERVERS_TXT, SERVERS_JSON],
        "primary_format": SERVERS_TXT,
        "compatibility_format": SERVERS_JSON,
        "file_hashes": {
            entry["name"]: {
                "size": entry["size"],
                "sha256": entry["sha256"],
            }
            for entry in _manifest_files(
                build_servers_txt(records, refresh_ms),
                build_servers_json(records, refresh_ms),
            )
        },
        "manifest": {
            "file": MANIFEST_JSON,
            "signature_file": MANIFEST_SIG,
            "sha256": _sha256_hex(manifest_text.encode("utf-8")),
        },
        "parse_stats": {
            "source_rows": stats.source_rows,
            "accepted": stats.accepted,
            "skipped_invalid": stats.skipped_invalid,
            "skipped_duplicate": stats.skipped_duplicate,
            "rejection_reasons": dict(sorted(stats.rejection_reasons.items())),
        },
        "notes": [
            "DISCOVERED means the record passed structural validation.",
            "No server is probed by this workflow; reachability is not claimed.",
            "servers.txt is the primary list consumed by the Android app.",
            "servers.json carries the same records in the compatible schema v1 envelope.",
            "manifest.json lists the exact byte size and SHA-256 of both files.",
            "manifest.sig, when present, is a detached ECDSA P-256 signature over manifest.json.",
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _write_atomic(path: str, content: str) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        dir=directory,
        prefix=".tmp-",
        delete=False,
    )
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def _read_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def _verify_output(servers_json: str, servers_txt: str, expected_count: int) -> None:
    try:
        parsed = json.loads(servers_json)
    except ValueError as error:
        raise GenerationError(f"generated servers.json is not valid JSON: {error}") from error

    if parsed.get("schema_version") != SERVER_JSON_SCHEMA_VERSION:
        raise GenerationError("generated servers.json has the wrong schema version")
    if not isinstance(parsed.get("last_successful_refresh"), int):
        raise GenerationError("generated servers.json has no refresh timestamp")
    if parsed["last_successful_refresh"] <= 0:
        raise GenerationError("generated servers.json has an invalid refresh timestamp")

    servers = parsed.get("servers")
    if not isinstance(servers, list) or len(servers) != expected_count:
        raise GenerationError("generated servers.json has the wrong record count")
    if not servers:
        raise GenerationError("refusing to publish an empty server list")

    seen_ips = set()
    for server in servers:
        ip = server.get("ip")
        if not ip or ip in seen_ips:
            raise GenerationError("generated servers.json contains a duplicate or empty IP")
        seen_ips.add(ip)
        if not server.get("openvpn_config_base64"):
            raise GenerationError("generated servers.json contains a record without a profile")
        verification = server.get("verification") or {}
        if verification.get("state") != "UNKNOWN":
            raise GenerationError("generated servers.json claims an unverified validation state")

    data_lines = [
        line
        for line in servers_txt.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if len(data_lines) != expected_count:
        raise GenerationError("generated servers.txt has the wrong record count")

    # Round-trip the published TXT through the same parser the Android client
    # uses in spirit: every field must survive, including the OpenVPN profile.
    try:
        parsed_txt = parse_servers_txt(servers_txt, min_servers=1)
    except ServerListError as error:
        raise GenerationError(f"generated servers.txt failed verification: {error}") from error
    if len(parsed_txt.records) != expected_count:
        raise GenerationError("generated servers.txt round-trip has the wrong record count")
    if parsed_txt.refresh_ms != parsed["last_successful_refresh"]:
        raise GenerationError("generated servers.txt has the wrong refresh timestamp")
    if canonical_payload(parsed_txt.records) != servers:
        raise GenerationError(
            "generated servers.txt does not round-trip to the servers.json payload"
        )


def generate(
    root: str,
    raw: str,
    *,
    now_ms: Optional[int] = None,
    source_url: str = SOURCE_URL,
    min_servers: int = MIN_EXPECTED_SERVERS,
    force: bool = False,
) -> GenerationResult:
    """Validates the feed and writes the three files when content changed."""

    result = parse_source(raw, min_servers=min_servers)
    records = result.records
    payload = canonical_payload(records)
    digest = content_hash(payload)

    servers_json_path = os.path.join(root, SERVERS_JSON)
    servers_txt_path = os.path.join(root, SERVERS_TXT)
    metadata_path = os.path.join(root, METADATA_JSON)
    manifest_path = os.path.join(root, MANIFEST_JSON)
    signature_path = os.path.join(root, MANIFEST_SIG)

    previous_metadata = _read_json(metadata_path)
    previous_hash = previous_metadata.get("content_hash") if previous_metadata else None
    previous_format = (
        previous_metadata.get("list_format_version") if previous_metadata else None
    )
    content_unchanged = (
        not force
        and previous_hash == digest
        and previous_format == LIST_FORMAT_VERSION
        and os.path.isfile(servers_json_path)
        and os.path.getsize(servers_json_path) > 0
        and os.path.isfile(servers_txt_path)
        and os.path.getsize(servers_txt_path) > 0
    )

    # Rebuilding an unchanged list is deterministic: the same refresh timestamp
    # and records produce byte-identical files. That keeps manifest.json stable
    # (and therefore a detached signature valid) across 30-minute runs.
    refresh_ms = (
        int(previous_metadata.get("last_changed_at") or 0)
        if content_unchanged
        else int(now_ms if now_ms is not None else time.time() * 1000)
    )
    if refresh_ms <= 0:
        raise GenerationError("the refresh timestamp must be positive")

    servers_json = build_servers_json(records, refresh_ms)
    servers_txt = build_servers_txt(records, refresh_ms)
    manifest = build_manifest(servers_txt, servers_json, refresh_ms, len(records))
    metadata = build_metadata(records, refresh_ms, digest, result.stats, manifest, source_url)
    _verify_output(servers_json, servers_txt, len(records))
    _verify_manifest(manifest, servers_txt, servers_json, len(records))

    # Build every file before replacing any of them. A failure in validation or
    # serialization therefore leaves the previously published list intact.
    json_changed = _write_if_changed(servers_json_path, servers_json)
    txt_changed = _write_if_changed(servers_txt_path, servers_txt)
    _write_if_changed(metadata_path, metadata)
    manifest_changed = _write_if_changed(manifest_path, manifest)
    if manifest_changed:
        # A signature over the previous manifest cannot validate the new bytes.
        # The CI signing step recreates it; an unsigned run must not leave a
        # stale signature behind.
        _remove_if_exists(signature_path)

    return GenerationResult(
        changed=json_changed or txt_changed,
        server_count=len(records),
        content_hash=digest,
        refresh_ms=refresh_ms,
        stats=result.stats,
        protocol_counts=protocol_counts(records),
        validation_counts=validation_counts(records),
        manifest_sha256=_sha256_hex(manifest.encode("utf-8")),
        manifest_changed=manifest_changed,
    )


def regenerate_from_json(
    root: str,
    *,
    now_ms: Optional[int] = None,
    min_servers: int = MIN_EXPECTED_SERVERS,
    force: bool = False,
) -> GenerationResult:
    """Rebuilds servers.txt and metadata.json from the committed servers.json.

    The JSON file itself is never rewritten: it stays the authoritative record.
    This path lets a format upgrade be applied without downloading the upstream
    feed again, and it is exercised by the unit tests.
    """

    servers_json_path = os.path.join(root, SERVERS_JSON)
    servers_txt_path = os.path.join(root, SERVERS_TXT)
    metadata_path = os.path.join(root, METADATA_JSON)
    manifest_path = os.path.join(root, MANIFEST_JSON)
    signature_path = os.path.join(root, MANIFEST_SIG)

    try:
        with open(servers_json_path, "r", encoding="utf-8") as handle:
            servers_json = handle.read()
    except OSError as error:
        raise GenerationError(f"could not read {SERVERS_JSON}: {error}") from error

    parsed = parse_servers_json(servers_json, min_servers=min_servers)
    records = parsed.records
    payload = canonical_payload(records)
    digest = content_hash(payload)

    previous_metadata = _read_json(metadata_path)
    previous_hash = previous_metadata.get("content_hash") if previous_metadata else None
    previous_format = (
        previous_metadata.get("list_format_version") if previous_metadata else None
    )
    content_unchanged = (
        not force
        and previous_hash == digest
        and previous_format == LIST_FORMAT_VERSION
        and os.path.isfile(servers_txt_path)
        and os.path.getsize(servers_txt_path) > 0
    )
    refresh_ms = (
        int(previous_metadata.get("last_changed_at") or 0)
        if content_unchanged
        else int(now_ms if now_ms is not None else parsed.refresh_ms)
    )
    if refresh_ms <= 0:
        raise GenerationError("the refresh timestamp must be positive")

    servers_txt = build_servers_txt(records, refresh_ms)
    manifest = build_manifest(servers_txt, servers_json, refresh_ms, len(records))
    metadata = build_metadata(records, refresh_ms, digest, parsed.stats, manifest, SOURCE_URL)
    _verify_output(servers_json, servers_txt, len(records))
    _verify_manifest(manifest, servers_txt, servers_json, len(records))

    txt_changed = _write_if_changed(servers_txt_path, servers_txt)
    _write_if_changed(metadata_path, metadata)
    manifest_changed = _write_if_changed(manifest_path, manifest)
    if manifest_changed:
        _remove_if_exists(signature_path)

    return GenerationResult(
        changed=txt_changed,
        server_count=len(records),
        content_hash=digest,
        refresh_ms=refresh_ms,
        stats=parsed.stats,
        protocol_counts=protocol_counts(records),
        validation_counts=validation_counts(records),
        manifest_sha256=_sha256_hex(manifest.encode("utf-8")),
        manifest_changed=manifest_changed,
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root for output files")
    parser.add_argument("--raw", help="path to the raw VPN Gate feed")
    parser.add_argument(
        "--from-json",
        action="store_true",
        help="rebuild servers.txt and metadata.json from the committed servers.json",
    )
    parser.add_argument("--source-url", default=SOURCE_URL)
    parser.add_argument("--now", type=int, default=None, help="override refresh time (ms)")
    parser.add_argument("--min-servers", type=int, default=MIN_EXPECTED_SERVERS)
    parser.add_argument("--force", action="store_true", help="rewrite even without changes")
    args = parser.parse_args(argv)

    if not args.from_json and not args.raw:
        parser.error("either --raw or --from-json is required")

    try:
        if args.from_json:
            result = regenerate_from_json(
                args.root,
                now_ms=args.now,
                min_servers=args.min_servers,
                force=args.force,
            )
        else:
            with open(args.raw, "r", encoding="utf-8", errors="replace") as handle:
                raw = handle.read()
            result = generate(
                args.root,
                raw,
                now_ms=args.now,
                source_url=args.source_url,
                min_servers=args.min_servers,
                force=args.force,
            )
    except (OSError, ServerListError) as error:
        print(f"GENERATION_FAILED: {error}", file=sys.stderr)
        return 1

    summary = {
        "status": "CHANGED" if result.changed else "NO_CHANGE",
        "server_count": result.server_count,
        "content_hash": result.content_hash,
        "refresh_ms": result.refresh_ms,
        "manifest_sha256": result.manifest_sha256,
        "manifest_changed": result.manifest_changed,
        "protocol_counts": result.protocol_counts,
        "validation_counts": result.validation_counts,
        "skipped_invalid": result.stats.skipped_invalid if result.stats else 0,
        "skipped_duplicate": result.stats.skipped_duplicate if result.stats else 0,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
