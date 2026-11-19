"""Parse and validate the VPN Gate public relay feed for AJX VPN.

This module is intentionally dependency-free (Python standard library only) so
the GitHub Actions workflow does not need to install third-party packages.

The validation rules mirror the Android client's strict parser:

* every record must have a public IPv4 address;
* the embedded OpenVPN profile must decode, look like OpenVPN, and target the
  same host/port as the record;
* the protocol must be an explicit TCP or UDP profile;
* duplicate IPs are collapsed before the list is published.

Nothing here probes a server. A record that passes validation is only
DISCOVERED: it is structurally usable, not proven to accept a VPN tunnel.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

SOURCE_URL = "https://www.vpngate.net/api/iphone/"
SOURCE_NAME = "VPN Gate"
# v2 makes servers.txt self-sufficient: it now carries every field the Android
# client needs, including the inline OpenVPN profile. v1 was a lossy summary.
LIST_FORMAT_VERSION = 2
SERVER_JSON_SCHEMA_VERSION = 1

MAX_CONFIG_BASE64_CHARS = 1_500_000
MAX_CONFIG_CHARS = 1_000_000
MAX_SERVER_ID_CHARS = 96
MIN_EXPECTED_SERVERS = 5
FIELD_COUNT = 15
MAX_LIST_RECORDS = 10_000

# The canonical servers.txt column order. Parsers must map by name, not by
# position, so a future column can be inserted without breaking old clients.
TXT_COLUMNS = (
    "server_id",
    "ip",
    "country_code",
    "country_name",
    "hostname",
    "port",
    "protocol",
    "score",
    "ping",
    "speed",
    "sessions",
    "uptime",
    "total_users",
    "total_traffic",
    "log_type",
    "operator",
    "message",
    "openvpn_config_base64",
    "validation_state",
    "source",
    "last_updated",
)

REMOTE_LINE = re.compile(r"(?im)^\s*remote\s+(\S+)(?:\s+(\d+))?")
REMOTE_LINE_ANY = re.compile(r"(?im)^\s*remote\s+\S+")
PROTO_LINE = re.compile(r"(?im)^\s*proto\s+(\S+)")
CLIENT_OR_DEVICE_LINE = re.compile(r"(?im)^\s*(client|dev\s+tun)")
COUNTRY_CODE = re.compile(r"^[A-Z]{2}$")
SERVER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,96}$")


class ServerListError(Exception):
    """Base class for a refresh that must not replace the published list."""


class EmptySourceError(ServerListError):
    """The source produced no usable records (or too few to be trusted)."""


class SourceFormatError(ServerListError):
    """The source body is structurally unusable."""


@dataclass(frozen=True)
class ServerRecord:
    server_id: str
    ip: str
    hostname: str
    country: str
    country_code: str
    score: int
    ping: int
    speed: int
    sessions: int
    uptime: str
    total_users: int
    total_traffic: str
    log_type: str
    operator: str
    message: str
    openvpn_config_base64: str
    protocol: str
    port: int
    validation_state: str = "DISCOVERED"
    source: str = "vpngate"


@dataclass
class ValidationStats:
    source_rows: int = 0
    accepted: int = 0
    skipped_invalid: int = 0
    skipped_duplicate: int = 0
    rejection_reasons: Dict[str, int] = field(default_factory=dict)

    def reject(self, reason: str) -> None:
        self.skipped_invalid += 1
        self.rejection_reasons[reason] = self.rejection_reasons.get(reason, 0) + 1


@dataclass
class ValidationResult:
    records: List[ServerRecord]
    stats: ValidationStats
    header_seen: bool


@dataclass
class ParsedList:
    """A validated list plus the provenance needed to re-publish it."""

    records: List[ServerRecord]
    refresh_ms: int
    stats: ValidationStats


def parse_csv_line(line: str) -> List[str]:
    """RFC 4180 style line parser, tolerant of unclosed quotes.

    Mirrors the Android parser: quotes are removed, doubled quotes become one
    quote, and a malformed row is handled by its caller rather than aborting the
    whole feed.
    """

    result: List[str] = []
    current: List[str] = []
    in_quotes = False
    index = 0
    while index < len(line):
        char = line[index]
        if char == '"' and in_quotes and index + 1 < len(line) and line[index + 1] == '"':
            current.append('"')
            index += 1
        elif char == '"':
            in_quotes = not in_quotes
        elif char == "," and not in_quotes:
            result.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    result.append("".join(current))
    return result


def decode_config(encoded: str) -> Optional[str]:
    """Decodes a VPN Gate base64 OpenVPN profile, or returns None."""

    if not encoded or not encoded.strip():
        return None
    compact = "".join(encoded.split())
    if len(compact) > MAX_CONFIG_BASE64_CHARS:
        return None
    padding = "=" * (-len(compact) % 4)
    try:
        raw = base64.b64decode(compact + padding, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw or b"\x00" in raw:
        return None
    try:
        config = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not config.strip() or len(config) > MAX_CONFIG_CHARS:
        return None
    return config


def looks_like_openvpn(config: str) -> bool:
    return bool(REMOTE_LINE_ANY.search(config)) and bool(CLIENT_OR_DEVICE_LINE.search(config))


def remote_host_port(config: str) -> Tuple[Optional[str], Optional[int]]:
    match = REMOTE_LINE.search(config)
    if not match:
        return None, None
    host = (match.group(1) or "").strip() or None
    raw_port = match.group(2)
    port = int(raw_port) if raw_port and raw_port.isdigit() else None
    if port is not None and not (1 <= port <= 65535):
        port = None
    return host, port


def protocol_of(config: str) -> str:
    """Returns tcp/udp. OpenVPN defaults to UDP when proto is omitted."""

    match = PROTO_LINE.search(config)
    if not match:
        return "udp"
    raw = match.group(1).strip().lower().split("-", 1)[0]
    if raw in ("tcp", "udp"):
        return raw
    return "unknown"


def is_public_ipv4(value: str) -> bool:
    """Replicates the Android client's public-IPv4 policy exactly."""

    parts = value.split(".")
    if len(parts) != 4:
        return False
    octets: List[int] = []
    for part in parts:
        if not part or len(part) > 3 or not part.isdigit():
            return False
        number = int(part)
        if number < 0 or number > 255:
            return False
        octets.append(number)

    first, second, third = octets[0], octets[1], octets[2]
    if first == 0:
        return False
    if first == 10:
        return False
    if first == 127:
        return False
    if first == 100 and 64 <= second <= 127:
        return False
    if first == 169 and second == 254:
        return False
    if first == 172 and 16 <= second <= 31:
        return False
    if first == 192 and second == 168:
        return False
    if first == 192 and second == 0 and third in (0, 2):
        return False
    if first == 198 and second in (18, 19):
        return False
    if first == 198 and second == 51 and third == 100:
        return False
    if first == 203 and second == 0 and third == 113:
        return False
    if first >= 224:
        return False
    return True


def normalize_country_code(raw: str) -> str:
    value = (raw or "").strip().upper()
    return value if COUNTRY_CODE.match(value) else "??"


def clean_text(value: str, field_name: str, max_length: int) -> str:
    if value is None:
        value = ""
    cleaned = "".join(
        " " if (ord(char) < 32 and char != "\t") or ord(char) == 127 else char
        for char in value
    ).strip()
    if len(cleaned) > max_length:
        raise ValueError(f"{field_name} is too long")
    return cleaned


def stable_server_id(ip: str) -> str:
    digest = hashlib.sha256(ip.encode("utf-8")).hexdigest()
    return digest[:16]


def parse_int(value: str) -> int:
    try:
        number = int((value or "").strip().replace(",", ""))
    except ValueError:
        return 0
    return max(number, 0)


def parse_source(raw: str, min_servers: int = MIN_EXPECTED_SERVERS) -> ValidationResult:
    """Parses the raw feed and returns validated, deduplicated records.

    Raises [EmptySourceError] when the feed is blank, contains no usable rows,
    or falls below ``min_servers``. Callers must treat that as a failed refresh
    and leave the previously published files untouched.
    """

    if raw is None or not raw.strip():
        raise EmptySourceError("the source returned an empty body")

    stats = ValidationStats()
    header_seen = False
    by_ip: Dict[str, ServerRecord] = {}

    for raw_line in raw.splitlines():
        line = raw_line.rstrip("\r").lstrip("\ufeff").strip()
        if not line or line.startswith("*"):
            continue
        if line.startswith("#"):
            header_seen = True
            continue

        fields = parse_csv_line(line)
        if len(fields) < FIELD_COUNT:
            stats.reject("too_few_fields")
            continue

        hostname = fields[0].strip()
        if hostname.lower() == "hostname":
            # Some mirrors omit the leading '#' from the header.
            header_seen = True
            continue

        stats.source_rows += 1
        ip = fields[1].strip()
        if not is_public_ipv4(ip):
            stats.reject("invalid_ip")
            continue

        encoded = fields[-1].strip()
        if not encoded:
            stats.reject("missing_config")
            continue
        config = decode_config(encoded)
        if config is None:
            stats.reject("invalid_base64")
            continue
        if not looks_like_openvpn(config):
            stats.reject("invalid_openvpn_config")
            continue

        remote_host, port = remote_host_port(config)
        if not remote_host:
            stats.reject("missing_remote")
            continue
        if remote_host != ip:
            stats.reject("remote_mismatch")
            continue
        if port is None:
            stats.reject("missing_port")
            continue

        protocol = protocol_of(config)
        if protocol == "unknown":
            stats.reject("unsupported_protocol")
            continue

        try:
            country = clean_text(fields[5] or "Unknown", "country", 96) or "Unknown"
            country_code = normalize_country_code(fields[6])
            clean_hostname = clean_text(hostname or ip, "hostname", 255)
            uptime = clean_text(fields[8], "uptime", 64)
            total_traffic = clean_text(fields[10], "total traffic", 64)
            log_type = clean_text(fields[11], "log type", 64)
            operator = clean_text(fields[12], "operator", 160)
            if len(fields) > FIELD_COUNT:
                message_raw = ",".join(fields[13 : len(fields) - 1])
            else:
                message_raw = fields[13]
            message = clean_text(message_raw, "message", 512)
        except ValueError:
            stats.reject("field_too_long")
            continue

        ping = min(parse_int(fields[3]), 2_147_483_647)
        sessions = min(parse_int(fields[7]), 2_147_483_647)
        total_users = min(parse_int(fields[9]), 2_147_483_647)

        record = ServerRecord(
            server_id=stable_server_id(ip),
            ip=ip,
            hostname=clean_hostname,
            country=country,
            country_code=country_code,
            score=parse_int(fields[2]),
            ping=ping,
            speed=parse_int(fields[4]),
            sessions=sessions,
            uptime=uptime,
            total_users=total_users,
            total_traffic=total_traffic,
            log_type=log_type,
            operator=operator,
            message=message,
            # Re-encode so the published value is canonical base64.
            openvpn_config_base64=base64.b64encode(config.encode("utf-8")).decode("ascii"),
            protocol=protocol,
            port=port,
        )
        if len(record.server_id) > MAX_SERVER_ID_CHARS or not SERVER_ID_PATTERN.match(
            record.server_id
        ):
            stats.reject("invalid_server_id")
            continue

        previous = by_ip.get(ip)
        if previous is None:
            by_ip[ip] = record
        else:
            stats.skipped_duplicate += 1
            # Keep the higher-scored record; the IP tie-break keeps it stable.
            if (record.score, record.hostname) > (previous.score, previous.hostname):
                by_ip[ip] = record

    records = sorted(
        by_ip.values(), key=lambda item: (item.country_code, -item.score, item.ip)
    )
    stats.accepted = len(records)

    if not records:
        reasons = ", ".join(
            f"{reason}={count}" for reason, count in sorted(stats.rejection_reasons.items())
        )
        raise EmptySourceError(
            "the source produced no usable records" + (f" ({reasons})" if reasons else "")
        )
    if len(records) < min_servers:
        raise EmptySourceError(
            f"the source produced only {len(records)} usable records; "
            f"refusing to publish fewer than {min_servers}"
        )

    return ValidationResult(records=records, stats=stats, header_seen=header_seen)


def _parse_non_negative(value: object, maximum: Optional[int] = None) -> int:
    try:
        number = int(str(value if value is not None else "").strip().replace(",", ""))
    except ValueError:
        return 0
    number = max(number, 0)
    return min(number, maximum) if maximum is not None else number


def _clean_or_reject(value: str, field_name: str, max_length: int) -> str:
    try:
        return clean_text(value, field_name, max_length)
    except ValueError as error:
        raise SourceFormatError(str(error)) from error


def _build_record(
    *,
    server_id: object,
    ip: str,
    hostname: object,
    country: object,
    country_code: object,
    score: object,
    ping: object,
    speed: object,
    sessions: object,
    uptime: object,
    total_users: object,
    total_traffic: object,
    log_type: object,
    operator: object,
    message: object,
    encoded: str,
    protocol: object,
    port: object,
) -> ServerRecord:
    """Validates one record from any published format.

    The rules are identical for the raw VPN Gate feed, servers.json and
    servers.txt, so a record cannot become valid merely by changing formats.
    """

    address = (ip or "").strip()
    if not is_public_ipv4(address):
        raise SourceFormatError(f"invalid relay IP: {address!r}")

    if not encoded or not encoded.strip():
        raise SourceFormatError("record has no OpenVPN configuration")
    config = decode_config(encoded)
    if config is None:
        raise SourceFormatError("record OpenVPN configuration is not valid base64")
    if not looks_like_openvpn(config):
        raise SourceFormatError("record OpenVPN configuration is invalid")

    remote_host, config_port = remote_host_port(config)
    if not remote_host:
        raise SourceFormatError("record OpenVPN configuration has no remote")
    if remote_host != address:
        raise SourceFormatError("record OpenVPN remote does not match the record IP")
    if config_port is None:
        raise SourceFormatError("record OpenVPN remote has no valid port")

    config_protocol = protocol_of(config)
    if config_protocol == "unknown":
        raise SourceFormatError("record OpenVPN protocol is unsupported")
    reported_protocol = str(protocol or "").strip().lower()
    if reported_protocol and reported_protocol != config_protocol:
        raise SourceFormatError("record protocol does not match the OpenVPN configuration")

    try:
        reported_port = int(str(port if port is not None else "").strip())
    except ValueError as error:
        raise SourceFormatError("record port is invalid") from error
    if reported_port != config_port:
        raise SourceFormatError("record port does not match the OpenVPN configuration")

    identifier = str(server_id or "").strip()
    if not identifier:
        identifier = stable_server_id(address)
    if len(identifier) > MAX_SERVER_ID_CHARS or not SERVER_ID_PATTERN.match(identifier):
        raise SourceFormatError("record server id is invalid")

    return ServerRecord(
        server_id=identifier,
        ip=address,
        hostname=_clean_or_reject(str(hostname or address), "hostname", 255) or address,
        country=_clean_or_reject(str(country or "Unknown"), "country", 96) or "Unknown",
        country_code=normalize_country_code(str(country_code or "")),
        score=_parse_non_negative(score),
        ping=_parse_non_negative(ping, 2_147_483_647),
        speed=_parse_non_negative(speed),
        sessions=_parse_non_negative(sessions, 2_147_483_647),
        uptime=_clean_or_reject(str(uptime or ""), "uptime", 64),
        total_users=_parse_non_negative(total_users, 2_147_483_647),
        total_traffic=_clean_or_reject(str(total_traffic or ""), "total traffic", 64),
        log_type=_clean_or_reject(str(log_type or ""), "log type", 64),
        operator=_clean_or_reject(str(operator or ""), "operator", 160),
        message=_clean_or_reject(str(message or ""), "message", 512),
        # Re-encode so every format carries the same canonical base64.
        openvpn_config_base64=base64.b64encode(config.encode("utf-8")).decode("ascii"),
        protocol=config_protocol,
        port=config_port,
    )


def parse_servers_json(
    raw: str, min_servers: int = MIN_EXPECTED_SERVERS
) -> ParsedList:
    """Parses a committed servers.json back into validated records.

    This is the regeneration path: servers.txt and metadata.json can be rebuilt
    from the authoritative JSON without downloading the upstream feed again.
    """

    try:
        document = json.loads(raw)
    except ValueError as error:
        raise SourceFormatError(f"servers.json is not valid JSON: {error}") from error
    if not isinstance(document, dict):
        raise SourceFormatError("servers.json is not a JSON object")
    if document.get("schema_version") != SERVER_JSON_SCHEMA_VERSION:
        raise SourceFormatError("servers.json has an unsupported schema version")

    refresh_ms = document.get("last_successful_refresh")
    if not isinstance(refresh_ms, int) or isinstance(refresh_ms, bool) or refresh_ms <= 0:
        raise SourceFormatError("servers.json has no valid refresh timestamp")

    servers = document.get("servers")
    if not isinstance(servers, list):
        raise SourceFormatError("servers.json has no server array")
    if len(servers) > MAX_LIST_RECORDS:
        raise SourceFormatError("servers.json has too many records")
    if not servers:
        raise EmptySourceError("servers.json contains no servers")

    records: List[ServerRecord] = []
    seen_ips = set()
    for index, entry in enumerate(servers):
        if not isinstance(entry, dict):
            raise SourceFormatError(f"servers.json record {index} is not an object")
        address = str(entry.get("ip") or "").strip()
        if address in seen_ips:
            raise SourceFormatError(f"servers.json contains a duplicate relay IP: {address}")
        seen_ips.add(address)
        try:
            record = _build_record(
                server_id=entry.get("id"),
                ip=address,
                hostname=entry.get("hostname"),
                country=entry.get("country"),
                country_code=entry.get("country_code"),
                score=entry.get("score"),
                ping=entry.get("ping"),
                speed=entry.get("speed"),
                sessions=entry.get("sessions"),
                uptime=entry.get("uptime"),
                total_users=entry.get("total_users"),
                total_traffic=entry.get("total_traffic"),
                log_type=entry.get("log_type"),
                operator=entry.get("operator"),
                message=entry.get("message"),
                encoded=str(entry.get("openvpn_config_base64") or ""),
                protocol=entry.get("protocol"),
                port=entry.get("port"),
            )
        except SourceFormatError as error:
            raise SourceFormatError(f"servers.json record {index}: {error}") from error
        records.append(record)

    if len(records) < min_servers:
        raise EmptySourceError(
            f"servers.json contains only {len(records)} usable records; "
            f"refusing to publish fewer than {min_servers}"
        )

    stats = ValidationStats(source_rows=len(servers), accepted=len(records))
    return ParsedList(records=records, refresh_ms=int(refresh_ms), stats=stats)


def parse_servers_txt(
    raw: str, min_servers: int = MIN_EXPECTED_SERVERS
) -> ParsedList:
    """Parses the header-driven servers.txt format.

    The parser maps columns by name and rejects a v1 summary: a list without
    OpenVPN profiles cannot be used as the primary client source.
    """

    if raw is None or not raw.strip():
        raise EmptySourceError("servers.txt is empty")

    format_version: Optional[int] = None
    columns: Optional[List[str]] = None
    refresh_ms: Optional[int] = None
    rows: List[List[str]] = []

    for raw_line in raw.lstrip("\ufeff").splitlines():
        line = raw_line.rstrip("\r")
        if not line.strip():
            continue
        if line.startswith("#"):
            content = line[1:].strip()
            if "=" not in content:
                continue
            key, value = content.split("=", 1)
            key = key.strip()
            if key == "format_version":
                try:
                    format_version = int(value.strip())
                except ValueError as error:
                    raise SourceFormatError("servers.txt has an invalid format_version") from error
            elif key == "columns":
                columns = value.split("\t")
            elif key == "last_updated":
                try:
                    refresh_ms = int(value.strip())
                except ValueError as error:
                    raise SourceFormatError("servers.txt has an invalid last_updated") from error
            continue

        if columns is None:
            raise SourceFormatError("servers.txt data appears before the columns header")
        rows.append(line.split("\t"))

    if format_version is None:
        raise SourceFormatError("servers.txt has no format_version header")
    if format_version < 2:
        raise SourceFormatError(
            f"servers.txt format version {format_version} is a lossy summary and "
            "cannot be used as the primary list"
        )
    if columns is None:
        raise SourceFormatError("servers.txt has no columns header")
    if len(set(columns)) != len(columns):
        raise SourceFormatError("servers.txt has duplicate column names")
    missing = [name for name in TXT_COLUMNS if name not in columns]
    if missing:
        raise SourceFormatError(
            "servers.txt is missing required columns: " + ", ".join(missing)
        )
    if refresh_ms is None or refresh_ms <= 0:
        raise SourceFormatError("servers.txt has no valid last_updated header")
    if not rows:
        raise EmptySourceError("servers.txt contains no records")
    if len(rows) > MAX_LIST_RECORDS:
        raise SourceFormatError("servers.txt has too many records")

    index = {name: position for position, name in enumerate(columns)}

    def field(row: List[str], name: str) -> str:
        return row[index[name]]

    records: List[ServerRecord] = []
    seen_ips = set()
    for row_number, row in enumerate(rows, start=1):
        if len(row) != len(columns):
            raise SourceFormatError(
                f"servers.txt record {row_number} has {len(row)} fields; "
                f"expected {len(columns)}"
            )
        address = field(row, "ip").strip()
        if address in seen_ips:
            raise SourceFormatError(
                f"servers.txt contains a duplicate relay IP: {address}"
            )
        seen_ips.add(address)
        try:
            record = _build_record(
                server_id=field(row, "server_id"),
                ip=address,
                hostname=field(row, "hostname"),
                country=field(row, "country_name"),
                country_code=field(row, "country_code"),
                score=field(row, "score"),
                ping=field(row, "ping"),
                speed=field(row, "speed"),
                sessions=field(row, "sessions"),
                uptime=field(row, "uptime"),
                total_users=field(row, "total_users"),
                total_traffic=field(row, "total_traffic"),
                log_type=field(row, "log_type"),
                operator=field(row, "operator"),
                message=field(row, "message"),
                encoded=field(row, "openvpn_config_base64"),
                protocol=field(row, "protocol"),
                port=field(row, "port"),
            )
        except SourceFormatError as error:
            raise SourceFormatError(
                f"servers.txt record {row_number}: {error}"
            ) from error
        if not field(row, "validation_state").strip():
            raise SourceFormatError(
                f"servers.txt record {row_number}: validation_state is empty"
            )
        if not field(row, "source").strip():
            raise SourceFormatError(
                f"servers.txt record {row_number}: source is empty"
            )
        records.append(record)

    if len(records) < min_servers:
        raise EmptySourceError(
            f"servers.txt contains only {len(records)} usable records; "
            f"refusing to publish fewer than {min_servers}"
        )

    stats = ValidationStats(source_rows=len(rows), accepted=len(records))
    return ParsedList(records=records, refresh_ms=int(refresh_ms), stats=stats)


def protocol_counts(records: List[ServerRecord]) -> Dict[str, int]:
    counts = {"tcp": 0, "udp": 0}
    for record in records:
        counts[record.protocol] = counts.get(record.protocol, 0) + 1
    return counts


def validation_counts(records: List[ServerRecord]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for record in records:
        counts[record.validation_state] = counts.get(record.validation_state, 0) + 1
    return counts
