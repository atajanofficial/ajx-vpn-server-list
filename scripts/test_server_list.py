"""Unit tests for the AJX VPN server-list generation pipeline.

Run from the repository root:

    python -m unittest discover -s scripts -p "test_*.py" -v
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import tempfile
import unittest
from typing import List, Optional

from generate_server_list import (
    MANIFEST_JSON,
    MANIFEST_SIG,
    METADATA_JSON,
    SERVERS_JSON,
    SERVERS_TXT,
    GenerationError,
    build_manifest,
    build_servers_txt,
    canonical_payload,
    generate,
    regenerate_from_json,
)
from validate_servers import (
    EmptySourceError,
    SourceFormatError,
    TXT_COLUMNS,
    is_public_ipv4,
    parse_servers_json,
    parse_servers_txt,
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


def make_txt(feed: str, refresh_ms: int = 1_700_000_000_000) -> str:
    result = parse_source(feed, min_servers=1)
    return build_servers_txt(result.records, refresh_ms)


def split_txt(text: str):
    lines = text.splitlines()
    header_index = next(
        index for index, line in enumerate(lines) if line.startswith("# columns=")
    )
    columns = lines[header_index][len("# columns="):].split("\t")
    data = [
        line.split("\t")
        for line in lines
        if line.strip() and not line.startswith("#")
    ]
    return lines, header_index, columns, data


def join_txt(lines, header_index, columns, data) -> str:
    updated = list(lines)
    updated[header_index] = "# columns=" + "\t".join(columns)
    body = ["\t".join(row) for row in data]
    return "\n".join(updated[: header_index + 1] + body) + "\n"


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
        self.assertIn("# format_version=2", text)
        self.assertIn("# columns=server_id\tip\t", text)
        header = next(
            line for line in text.splitlines() if line.startswith("# columns=")
        )
        self.assertEqual(list(TXT_COLUMNS), header[len("# columns="):].split("\t"))
        data_lines = [line for line in text.splitlines() if line and not line.startswith("#")]
        self.assertEqual(1, len(data_lines))
        self.assertEqual(len(TXT_COLUMNS), len(data_lines[0].split("\t")))
        self.assertIn("openvpn_config_base64", header)

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

    def test_txt_round_trips_every_field(self) -> None:
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
        generate(self.root, feed, now_ms=1_700_000_000_000, min_servers=1)

        parsed = parse_servers_txt(self._read(SERVERS_TXT), min_servers=1)
        document = json.loads(self._read(SERVERS_JSON))

        self.assertEqual(2, len(parsed.records))
        self.assertEqual(document["servers"], canonical_payload(parsed.records))

    def test_regenerate_from_json_rebuilds_txt(self) -> None:
        generate(
            self.root,
            make_feed([make_row(ip="1.2.3.4")]),
            now_ms=1_700_000_000_000,
            min_servers=1,
        )
        json_before = self._read(SERVERS_JSON)

        # Simulate a repository still carrying the lossy v1 summary.
        metadata = json.loads(self._read(METADATA_JSON))
        metadata["list_format_version"] = 1
        with open(os.path.join(self.root, METADATA_JSON), "w", encoding="utf-8") as handle:
            json.dump(metadata, handle)
        with open(os.path.join(self.root, SERVERS_TXT), "w", encoding="utf-8") as handle:
            handle.write("# AJX VPN server list\n# format_version=1\n")

        result = regenerate_from_json(self.root, min_servers=1)

        self.assertTrue(result.changed)
        self.assertIn("# format_version=2", self._read(SERVERS_TXT))
        self.assertEqual(
            2, json.loads(self._read(METADATA_JSON))["list_format_version"]
        )
        self.assertEqual(json_before, self._read(SERVERS_JSON))
        self.assertFalse(regenerate_from_json(self.root, min_servers=1).changed)

    def test_format_upgrade_rewrites_unchanged_content(self) -> None:
        feed = make_feed([make_row()])
        generate(self.root, feed, now_ms=1_700_000_000_000, min_servers=1)

        metadata = json.loads(self._read(METADATA_JSON))
        metadata["list_format_version"] = 1
        with open(os.path.join(self.root, METADATA_JSON), "w", encoding="utf-8") as handle:
            json.dump(metadata, handle)

        result = generate(
            self.root,
            feed,
            now_ms=1_800_000_000_000,
            min_servers=1,
        )

        self.assertTrue(result.changed)
        self.assertIn("# format_version=2", self._read(SERVERS_TXT))


class TxtParsingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = make_txt(make_feed([make_row(ip="1.2.3.4")]))
        self.lines, self.header_index, self.columns, self.data = split_txt(self.text)

    def _parse(self, text: str):
        return parse_servers_txt(text, min_servers=1)

    def test_valid_txt_is_parsed(self) -> None:
        parsed = self._parse(self.text)

        self.assertEqual(1, len(parsed.records))
        self.assertEqual(1_700_000_000_000, parsed.refresh_ms)
        record = parsed.records[0]
        self.assertEqual("1.2.3.4", record.ip)
        self.assertEqual("udp", record.protocol)
        self.assertEqual(1194, record.port)
        self.assertTrue(record.openvpn_config_base64)

    def test_v1_is_rejected(self) -> None:
        v1 = self.text.replace("# format_version=2", "# format_version=1", 1)
        with self.assertRaises(SourceFormatError):
            self._parse(v1)

    def test_missing_column_is_rejected(self) -> None:
        index = self.columns.index("openvpn_config_base64")
        columns = [name for name in self.columns if name != "openvpn_config_base64"]
        data = [
            [value for position, value in enumerate(row) if position != index]
            for row in self.data
        ]
        with self.assertRaises(SourceFormatError):
            self._parse(join_txt(self.lines, self.header_index, columns, data))

    def test_wrong_field_count_is_rejected(self) -> None:
        data = [row[:-1] for row in self.data]
        with self.assertRaises(SourceFormatError):
            self._parse(join_txt(self.lines, self.header_index, self.columns, data))

    def test_duplicate_ip_is_rejected(self) -> None:
        data = self.data + [list(self.data[0])]
        with self.assertRaises(SourceFormatError):
            self._parse(join_txt(self.lines, self.header_index, self.columns, data))

    def test_empty_txt_is_rejected(self) -> None:
        with self.assertRaises(EmptySourceError):
            self._parse("")
        header_only = (
            "# AJX VPN server list\n"
            "# format_version=2\n"
            "# last_updated=1700000000000\n"
            "# columns=" + "\t".join(TXT_COLUMNS) + "\n"
        )
        with self.assertRaises(EmptySourceError):
            self._parse(header_only)

    def test_bad_base64_is_rejected(self) -> None:
        data = [list(row) for row in self.data]
        data[0][self.columns.index("openvpn_config_base64")] = "not-base64!!"
        with self.assertRaises(SourceFormatError):
            self._parse(join_txt(self.lines, self.header_index, self.columns, data))

    def test_remote_mismatch_is_rejected(self) -> None:
        data = [list(row) for row in self.data]
        data[0][self.columns.index("ip")] = "9.9.9.9"
        with self.assertRaises(SourceFormatError):
            self._parse(join_txt(self.lines, self.header_index, self.columns, data))

    def test_port_mismatch_is_rejected(self) -> None:
        data = [list(row) for row in self.data]
        data[0][self.columns.index("port")] = "443"
        with self.assertRaises(SourceFormatError):
            self._parse(join_txt(self.lines, self.header_index, self.columns, data))

    def test_protocol_mismatch_is_rejected(self) -> None:
        data = [list(row) for row in self.data]
        data[0][self.columns.index("protocol")] = "TCP"
        with self.assertRaises(SourceFormatError):
            self._parse(join_txt(self.lines, self.header_index, self.columns, data))

    def test_crlf_and_bom_are_accepted(self) -> None:
        crlf = "\ufeff" + self.text.replace("\n", "\r\n")
        parsed = self._parse(crlf)
        self.assertEqual(1, len(parsed.records))

    def test_utf8_country_is_preserved(self) -> None:
        text = make_txt(
            make_feed([make_row(ip="1.2.3.4", country="日本", code="JP")])
        )
        parsed = self._parse(text)
        self.assertEqual("日本", parsed.records[0].country)

    def test_columns_are_mapped_by_name(self) -> None:
        columns = list(self.columns)
        first = columns.index("country_code")
        second = columns.index("country_name")
        columns[first], columns[second] = columns[second], columns[first]
        data = []
        for row in self.data:
            row = list(row)
            row[first], row[second] = row[second], row[first]
            data.append(row)

        parsed = self._parse(join_txt(self.lines, self.header_index, columns, data))

        self.assertEqual("JP", parsed.records[0].country_code)
        self.assertEqual("Japan", parsed.records[0].country)


class ManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = self.temp.name

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _bytes(self, name: str) -> bytes:
        with open(os.path.join(self.root, name), "rb") as handle:
            return handle.read()

    def _text(self, name: str) -> str:
        return self._bytes(name).decode("utf-8")

    def test_manifest_matches_published_bytes(self) -> None:
        generate(self.root, make_feed([make_row()]), now_ms=1_700_000_000_000, min_servers=1)
        manifest = json.loads(self._text(MANIFEST_JSON))

        self.assertEqual(1, manifest["manifest_version"])
        self.assertEqual(2, manifest["list_format_version"])
        self.assertEqual(1, manifest["server_count"])
        self.assertEqual(1_700_000_000_000, manifest["generated_at"])
        self.assertNotIn("signature", manifest)

        entries = {entry["name"]: entry for entry in manifest["files"]}
        self.assertEqual({SERVERS_TXT, SERVERS_JSON}, set(entries))
        for name in (SERVERS_TXT, SERVERS_JSON):
            payload = self._bytes(name)
            self.assertEqual(len(payload), entries[name]["size"])
            self.assertEqual(hashlib.sha256(payload).hexdigest(), entries[name]["sha256"])

    def test_metadata_references_the_manifest(self) -> None:
        generate(self.root, make_feed([make_row()]), now_ms=1_700_000_000_000, min_servers=1)
        metadata = json.loads(self._text(METADATA_JSON))
        manifest = self._bytes(MANIFEST_JSON)

        self.assertEqual(MANIFEST_JSON, metadata["manifest"]["file"])
        self.assertEqual(
            hashlib.sha256(manifest).hexdigest(), metadata["manifest"]["sha256"]
        )
        self.assertEqual(
            hashlib.sha256(self._bytes(SERVERS_TXT)).hexdigest(),
            metadata["file_hashes"][SERVERS_TXT]["sha256"],
        )

    def test_manifest_is_stable_when_content_is_unchanged(self) -> None:
        feed = make_feed([make_row()])
        first = generate(self.root, feed, now_ms=1_700_000_000_000, min_servers=1)
        first_manifest = self._bytes(MANIFEST_JSON)

        second = generate(self.root, feed, now_ms=1_800_000_000_000, min_servers=1)

        self.assertTrue(first.manifest_changed)
        self.assertFalse(second.manifest_changed)
        self.assertEqual(first_manifest, self._bytes(MANIFEST_JSON))
        self.assertEqual(first.manifest_sha256, second.manifest_sha256)

    def test_manifest_rewrite_removes_a_stale_signature(self) -> None:
        generate(self.root, make_feed([make_row()]), now_ms=1_700_000_000_000, min_servers=1)
        with open(os.path.join(self.root, MANIFEST_SIG), "w", encoding="utf-8") as handle:
            handle.write("{}\n")

        generate(
            self.root,
            make_feed([make_row(ip="9.9.9.9", score=2000)]),
            now_ms=1_800_000_000_000,
            min_servers=1,
        )

        self.assertFalse(os.path.exists(os.path.join(self.root, MANIFEST_SIG)))

    def test_build_manifest_rejects_a_mismatched_size(self) -> None:
        manifest = build_manifest("a\n", "b\n", 1_700_000_000_000, 1)
        parsed = json.loads(manifest)
        parsed["files"][0]["size"] = 999
        from generate_server_list import _verify_manifest

        with self.assertRaises(GenerationError):
            _verify_manifest(json.dumps(parsed), "a\n", "b\n", 1)


if __name__ == "__main__":
    unittest.main()
