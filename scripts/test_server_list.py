"""Unit tests for the AJX VPN server-list generation pipeline.

Run from the repository root:

    python -m unittest discover -s scripts -p "test_*.py" -v
"""

from __future__ import annotations

import base64
import csv
import io
import json
import os
import tempfile
import unittest
from typing import List, Optional

from generate_server_list import (
    METADATA_JSON,
    SERVERS_JSON,
    SERVERS_TXT,
    GenerationError,
    generate,
)
from validate_servers import (
    EmptySourceError,
    is_public_ipv4,
    parse_source,
    protocol_of,
)

HEADER = (
    "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
    "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,"
    "OpenVPN_ConfigData_Base64"
)


def make_config(
    host: str = "1.2.3.4",
    port: int = 1194,
    proto: str = "udp",
    include_proto: bool = True,
) -> str:
    lines = ["client", "dev tun"]
    if include_proto:
        lines.append(f"proto {proto}")
    lines.extend([f"remote {host} {port}", "cipher AES-128-CBC", "auth SHA1"])
    return "\n".join(lines) + "\n"


def make_row(
    ip: str = "1.2.3.4",
    *,
    country: str = "Japan",
    code: str = "JP",
    score: int = 1000,
    hostname: Optional[str] = None,
    config: Optional[str] = None,
    encoded: Optional[str] = None,
) -> str:
    if encoded is None:
        encoded = base64.b64encode((config or make_config(host=ip)).encode()).decode()
    fields = [
        hostname or f"public-vpn-{ip}",
        ip,
        str(score),
        "30",
        "273048039",
        country,
        code,
        "119",
        "1659351416",
        "11368548",
        "658827788456190",
        "2weeks",
        "Example operator",
        "",
        encoded,
    ]
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="").writerow(fields)
    return buffer.getvalue()


def make_feed(rows: List[str]) -> str:
    return "\n".join(["*vpn_servers", HEADER, *rows, "*"]) + "\n"


class ValidationTest(unittest.TestCase):
    def test_valid_row_is_accepted_and_normalized(self) -> None:
        result = parse_source(make_feed([make_row()]), min_servers=1)

        self.assertEqual(1, len(result.records))
        record = result.records[0]
        self.assertEqual("1.2.3.4", record.ip)
        self.assertEqual("JP", record.country_code)
        self.assertEqual("udp", record.protocol)
        self.assertEqual(1194, record.port)
        self.assertEqual("DISCOVERED", record.validation_state)
        self.assertEqual(16, len(record.server_id))

    def test_invalid_base64_is_skipped(self) -> None:
        result = parse_source(
            make_feed(
                [
                    make_row(ip="1.2.3.4"),
                    make_row(ip="5.6.7.8", encoded="not-base64!!"),
                ]
            ),
            min_servers=1,
        )

        self.assertEqual(1, len(result.records))
        self.assertEqual("1.2.3.4", result.records[0].ip)
        self.assertIn("invalid_base64", result.stats.rejection_reasons)

    def test_invalid_base64_only_source_raises(self) -> None:
        with self.assertRaises(EmptySourceError):
            parse_source(
                make_feed([make_row(ip="1.2.3.4", encoded="not-base64!!")]),
                min_servers=1,
            )

    def test_private_ip_is_rejected(self) -> None:
        for ip in ("10.0.0.1", "127.0.0.1", "192.168.1.1", "169.254.1.1"):
            self.assertFalse(is_public_ipv4(ip), ip)
        with self.assertRaises(EmptySourceError):
            parse_source(make_feed([make_row(ip="192.168.1.1")]), min_servers=1)

    def test_duplicate_ip_keeps_highest_score(self) -> None:
        result = parse_source(
            make_feed(
                [
                    make_row(ip="1.2.3.4", score=100),
                    make_row(ip="1.2.3.4", score=900),
                ]
            ),
            min_servers=1,
        )

        self.assertEqual(1, len(result.records))
        self.assertEqual(900, result.records[0].score)
        self.assertEqual(1, result.stats.skipped_duplicate)

    def test_empty_source_raises(self) -> None:
        with self.assertRaises(EmptySourceError):
            parse_source("", min_servers=1)
        with self.assertRaises(EmptySourceError):
            parse_source("*vpn_servers\n" + HEADER + "\n*\n", min_servers=1)

    def test_remote_mismatch_is_rejected(self) -> None:
        config = make_config(host="1.2.3.99")
        with self.assertRaises(EmptySourceError):
            parse_source(make_feed([make_row(ip="1.2.3.4", config=config)]), min_servers=1)

    def test_missing_port_is_rejected(self) -> None:
        config = "client\ndev tun\nproto udp\nremote 1.2.3.4\n"
        with self.assertRaises(EmptySourceError):
            parse_source(make_feed([make_row(ip="1.2.3.4", config=config)]), min_servers=1)

    def test_protocol_classification(self) -> None:
        self.assertEqual("tcp", protocol_of(make_config(proto="tcp")))
        self.assertEqual("udp", protocol_of(make_config(proto="udp")))
        self.assertEqual("udp", protocol_of(make_config(include_proto=False)))
        self.assertEqual("unknown", protocol_of(make_config(proto="icmp")))

        with self.assertRaises(EmptySourceError):
            parse_source(
                make_feed([make_row(ip="1.2.3.4", config=make_config(proto="icmp"))]),
                min_servers=1,
            )

    def test_country_code_normalization(self) -> None:
        result = parse_source(make_feed([make_row(code="jp")]), min_servers=1)
        self.assertEqual("JP", result.records[0].country_code)

        result = parse_source(make_feed([make_row(code="J")]), min_servers=1)
        self.assertEqual("??", result.records[0].country_code)

    def test_minimum_server_threshold(self) -> None:
        with self.assertRaises(EmptySourceError):
            parse_source(make_feed([make_row()]), min_servers=2)


class GenerationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = self.temp.name

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _read(self, name: str) -> str:
        with open(os.path.join(self.root, name), "r", encoding="utf-8") as handle:
            return handle.read()

    def test_generates_all_files_and_metadata(self) -> None:
        feed = make_feed(
            [
                make_row(ip="1.2.3.4", code="JP", score=100),
                make_row(
                    ip="5.6.7.8",
                    code="US",
                    score=200,
                    config=make_config(host="5.6.7.8", proto="tcp", port=443),
                ),
            ]
        )
        result = generate(self.root, feed, now_ms=1_700_000_000_000, min_servers=1)

        self.assertTrue(result.changed)
        self.assertEqual(2, result.server_count)
        metadata = json.loads(self._read(METADATA_JSON))
        self.assertEqual(2, metadata["server_count"])
        self.assertEqual({"tcp": 1, "udp": 1}, metadata["protocol_counts"])
        self.assertEqual({"DISCOVERED": 2}, metadata["validation_counts"])
        self.assertEqual(result.content_hash, metadata["content_hash"])

        servers = json.loads(self._read(SERVERS_JSON))
        self.assertEqual(1, servers["schema_version"])
        self.assertEqual(1_700_000_000_000, servers["last_successful_refresh"])
        self.assertEqual(2, len(servers["servers"]))
        self.assertEqual("UNKNOWN", servers["servers"][0]["verification"]["state"])

    def test_servers_txt_is_versioned(self) -> None:
        generate(self.root, make_feed([make_row()]), now_ms=1_700_000_000_000, min_servers=1)
        text = self._read(SERVERS_TXT)
        self.assertIn("# format_version=1", text)
        self.assertIn("# columns=server_id\tip\t", text)
        data_lines = [line for line in text.splitlines() if line and not line.startswith("#")]
        self.assertEqual(1, len(data_lines))
        self.assertEqual(10, len(data_lines[0].split("\t")))

    def test_stable_output_for_same_input(self) -> None:
        feed = make_feed([make_row()])
        first = generate(self.root, feed, now_ms=1_700_000_000_000, min_servers=1)
        first_json = self._read(SERVERS_JSON)
        first_txt = self._read(SERVERS_TXT)
        first_meta = self._read(METADATA_JSON)

        second = generate(self.root, feed, now_ms=1_800_000_000_000, min_servers=1)

        self.assertFalse(second.changed)
        self.assertEqual(first.content_hash, second.content_hash)
        self.assertEqual(first_json, self._read(SERVERS_JSON))
        self.assertEqual(first_txt, self._read(SERVERS_TXT))
        self.assertEqual(first_meta, self._read(METADATA_JSON))

    def test_changed_input_rewrites_files(self) -> None:
        generate(self.root, make_feed([make_row()]), now_ms=1_700_000_000_000, min_servers=1)
        before = self._read(SERVERS_JSON)

        changed = generate(
            self.root,
            make_feed([make_row(ip="9.9.9.9", score=2000)]),
            now_ms=1_800_000_000_000,
            min_servers=1,
        )

        self.assertTrue(changed.changed)
        self.assertNotEqual(before, self._read(SERVERS_JSON))
        self.assertIn("9.9.9.9", self._read(SERVERS_TXT))

    def test_failed_refresh_preserves_previous_files(self) -> None:
        generate(self.root, make_feed([make_row()]), now_ms=1_700_000_000_000, min_servers=1)
        before = {
            name: self._read(name)
            for name in (SERVERS_JSON, SERVERS_TXT, METADATA_JSON)
        }

        with self.assertRaises(EmptySourceError):
            generate(self.root, "", now_ms=1_800_000_000_000, min_servers=1)

        for name, content in before.items():
            self.assertEqual(content, self._read(name), name)

    def test_failed_validation_preserves_previous_files(self) -> None:
        generate(self.root, make_feed([make_row()]), now_ms=1_700_000_000_000, min_servers=1)
        before = self._read(SERVERS_JSON)

        with self.assertRaises(EmptySourceError):
            generate(
                self.root,
                make_feed([make_row(ip="10.1.2.3")]),
                now_ms=1_800_000_000_000,
                min_servers=1,
            )

        self.assertEqual(before, self._read(SERVERS_JSON))

    def test_generated_json_is_android_compatible(self) -> None:
        generate(self.root, make_feed([make_row()]), now_ms=1_700_000_000_000, min_servers=1)
        servers = json.loads(self._read(SERVERS_JSON))

        required = {
            "id",
            "ip",
            "hostname",
            "country",
            "country_code",
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
            "protocol",
            "port",
            "verification",
        }
        self.assertEqual(required, set(servers["servers"][0].keys()))
        self.assertTrue(servers["servers"][0]["openvpn_config_base64"])

    def test_rejects_implausibly_small_list(self) -> None:
        with self.assertRaises(EmptySourceError):
            generate(self.root, make_feed([make_row()]), now_ms=1_700_000_000_000, min_servers=5)

    def test_output_verification_rejects_empty_payload(self) -> None:
        with self.assertRaises(GenerationError):
            from generate_server_list import _verify_output

            _verify_output(
                json.dumps(
                    {
                        "schema_version": 1,
                        "last_successful_refresh": 1,
                        "servers": [],
                    }
                ),
                "",
                0,
            )


if __name__ == "__main__":
    unittest.main()
