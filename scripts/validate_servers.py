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
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

SOURCE_URL = "https://www.vpngate.net/api/iphone/"
SOURCE_NAME = "VPN Gate"
LIST_FORMAT_VERSION = 1
SERVER_JSON_SCHEMA_VERSION = 1

MAX_CONFIG_BASE64_CHARS = 1_500_000
MAX_CONFIG_CHARS = 1_000_000
MAX_SERVER_ID_CHARS = 96
MIN_EXPECTED_SERVERS = 5
FIELD_COUNT = 15

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
