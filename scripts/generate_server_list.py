"""Generate the versioned AJX VPN server list files from a raw VPN Gate feed.

Outputs (all in the repository root):

* ``servers.json`` - authoritative, Android-compatible schema v1 list. It
  carries the inline OpenVPN profiles the existing engine needs.
* ``servers.txt`` - human-readable, tab-separated summary of the same records.
* ``metadata.json`` - counts, source provenance, format versions and the
  content hash used for no-change detection.

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
    ServerListError,
    ServerRecord,
    ValidationStats,
    parse_source,
    protocol_counts,
    validation_counts,
)

SERVERS_JSON = "servers.json"
SERVERS_TXT = "servers.txt"
METADATA_JSON = "metadata.json"

VALIDATION_DETAIL = "structurally validated by the refresh workflow; not probed"
TXT_HEADER_COLUMNS = (
    "server_id",
    "ip",
    "country_code",
    "country_name",
    "hostname",
    "port",
    "protocol",
    "validation_state",
    "source",
    "last_updated",
)


@dataclass
class GenerationResult:
    changed: bool
    server_count: int
    content_hash: str
    refresh_ms: int
    stats: Optional[ValidationStats] = None
    protocol_counts: Optional[Dict[str, int]] = None
    validation_counts: Optional[Dict[str, int]] = None


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
        "# columns=" + "\t".join(TXT_HEADER_COLUMNS),
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
            "servers.json is the authoritative list consumed by the Android app.",
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

    previous_metadata = _read_json(metadata_path)
    previous_hash = previous_metadata.get("content_hash") if previous_metadata else None
    files_present = all(
        os.path.isfile(path) and os.path.getsize(path) > 0
        for path in (servers_json_path, servers_txt_path, metadata_path)
    )
    if not force and files_present and previous_hash == digest:
        return GenerationResult(
            changed=False,
            server_count=len(records),
            content_hash=digest,
            refresh_ms=int(previous_metadata.get("last_changed_at") or 0),
            stats=result.stats,
            protocol_counts=protocol_counts(records),
            validation_counts=validation_counts(records),
        )

    refresh_ms = int(now_ms if now_ms is not None else time.time() * 1000)
    if refresh_ms <= 0:
        raise GenerationError("the refresh timestamp must be positive")

    servers_json = build_servers_json(records, refresh_ms)
    servers_txt = build_servers_txt(records, refresh_ms)
    metadata = build_metadata(records, refresh_ms, digest, result.stats, source_url)
    _verify_output(servers_json, servers_txt, len(records))

    # Build every file before replacing any of them. A failure in validation or
    # serialization therefore leaves the previously published list intact.
    _write_atomic(servers_json_path, servers_json)
    _write_atomic(servers_txt_path, servers_txt)
    _write_atomic(metadata_path, metadata)

    return GenerationResult(
        changed=True,
        server_count=len(records),
        content_hash=digest,
        refresh_ms=refresh_ms,
        stats=result.stats,
        protocol_counts=protocol_counts(records),
        validation_counts=validation_counts(records),
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root for output files")
    parser.add_argument("--raw", required=True, help="path to the raw VPN Gate feed")
    parser.add_argument("--source-url", default=SOURCE_URL)
    parser.add_argument("--now", type=int, default=None, help="override refresh time (ms)")
    parser.add_argument("--min-servers", type=int, default=MIN_EXPECTED_SERVERS)
    parser.add_argument("--force", action="store_true", help="rewrite even without changes")
    args = parser.parse_args(argv)

    try:
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
        "protocol_counts": result.protocol_counts,
        "validation_counts": result.validation_counts,
        "skipped_invalid": result.stats.skipped_invalid if result.stats else 0,
        "skipped_duplicate": result.stats.skipped_duplicate if result.stats else 0,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
