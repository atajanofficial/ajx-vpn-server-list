"""Tests for the Cloudflare Pages deployment builder."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from typing import List, Optional

from build_cloudflare_pages import (
    MANIFEST_JSON,
    MANIFEST_SIG,
    SERVERS_JSON,
    SERVERS_TXT,
    CloudflareBuildError,
    build,
)
from generate_server_list import (
    METADATA_JSON,
    SOURCE_URL,
    build_manifest,
    build_metadata,
    build_servers_json,
    build_servers_txt,
    canonical_payload,
    content_hash,
)
from validate_servers import parse_source

REFRESH = 1_700_000_000_000
IPS = ["45.32.10.9", "45.32.10.10", "45.32.10.11", "45.32.10.12", "45.32.10.13"]


def _config(ip: str) -> str:
    return "\n".join(
        [
            "client",
            "dev tun",
            "proto udp",
            f"remote {ip} 1194",
            "cipher AES-128-CBC",
            "auth SHA1",
        ]
    ) + "\n"


def _feed(ips: List[str]) -> str:
    header = (
        "*vpn_servers\n"
        "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
        "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,"
        "OpenVPN_ConfigData_Base64\n"
    )
    rows = []
    for index, ip in enumerate(ips):
        encoded = base64.b64encode(_config(ip).encode()).decode()
        rows.append(
            f"public-vpn-{ip},{ip},{1000 - index},30,273048039,Japan,JP,119,"
            f"1659351416,11368548,658827788456190,2weeks,Example,,{encoded}\n"
        )
    return header + "".join(rows) + "*\n"


def _write(path: str, data: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(data)


def write_dataset(
    root: str,
    *,
    ips: Optional[List[str]] = None,
    txt_override: Optional[str] = None,
    tamper_json: bool = False,
    count_override: Optional[int] = None,
    signature: bool = False,
) -> None:
    os.makedirs(root, exist_ok=True)
    selected = ips or IPS
    parsed = parse_source(_feed(selected), min_servers=5)
    txt = txt_override if txt_override is not None else build_servers_txt(
        parsed.records, REFRESH
    )
    json_text = build_servers_json(parsed.records, REFRESH)
    if tamper_json:
        document = json.loads(json_text)
        document["servers"][0]["score"] = 1
        json_text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"

    manifest = build_manifest(
        txt, json_text, REFRESH, count_override if count_override is not None else len(selected)
    )
    metadata = build_metadata(
        parsed.records,
        REFRESH,
        content_hash(canonical_payload(parsed.records)),
        parsed.stats,
        manifest,
        SOURCE_URL,
    )
    _write(os.path.join(root, SERVERS_TXT), txt)
    _write(os.path.join(root, SERVERS_JSON), json_text)
    _write(os.path.join(root, MANIFEST_JSON), manifest)
    _write(os.path.join(root, METADATA_JSON), metadata)
    if signature:
        payload = base64.b64encode(bytes(range(64))).decode()
        _write(
            os.path.join(root, MANIFEST_SIG),
            json.dumps(
                {
                    "algorithm": "ECDSA_P256_SHA256",
                    "key_id": "test-key",
                    "signature_base64": payload,
                }
            )
            + "\n",
        )


class CloudflarePagesBuilderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ajx-pages-test-")
        self.root = os.path.join(self.tmp, "repo")
        self.output = os.path.join(self.tmp, "cloudflare-pages")
        os.makedirs(self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _source_bytes(self, name: str) -> bytes:
        with open(os.path.join(self.root, name), "rb") as handle:
            return handle.read()

    def _output_bytes(self, name: str) -> bytes:
        with open(os.path.join(self.output, name), "rb") as handle:
            return handle.read()

    def test_builds_exact_validated_files(self) -> None:
        write_dataset(self.root, signature=True)

        summary = build(self.root, self.output)

        self.assertEqual(len(IPS), summary["server_count"])
        self.assertEqual(REFRESH, summary["generated_at"])
        for name in (SERVERS_TXT, SERVERS_JSON, MANIFEST_JSON, MANIFEST_SIG):
            self.assertEqual(self._source_bytes(name), self._output_bytes(name))
        self.assertEqual(
            hashlib.sha256(self._source_bytes(MANIFEST_JSON)).hexdigest(),
            summary["manifest_sha256"],
        )
        self.assertIn("servers.txt", self._output_bytes("index.html").decode())
        self.assertIn("Cache-Control: public, max-age=0", self._output_bytes("_headers").decode())

    def test_a_rejected_rebuild_does_not_replace_a_good_deployment(self) -> None:
        write_dataset(self.root)
        build(self.root, self.output)
        before = {name: self._output_bytes(name) for name in os.listdir(self.output)}

        _write(
            os.path.join(self.root, SERVERS_TXT),
            "<html><body>Service unavailable</body></html>\n",
        )
        with self.assertRaises(CloudflareBuildError):
            build(self.root, self.output)

        after = {name: self._output_bytes(name) for name in os.listdir(self.output)}
        self.assertEqual(before, after)

    def test_html_error_page_is_rejected(self) -> None:
        write_dataset(
            self.root,
            txt_override="<html><body>Bad gateway</body></html>\n",
        )
        with self.assertRaisesRegex(CloudflareBuildError, "failed validation"):
            build(self.root, self.output)
        self.assertFalse(os.path.exists(self.output))

    def test_manifest_hash_mismatch_is_rejected(self) -> None:
        write_dataset(self.root)
        original = self._source_bytes(SERVERS_TXT).decode()
        self.assertEqual(len(IPS), original.count("public-vpn-"))
        _write(
            os.path.join(self.root, SERVERS_TXT),
            original.replace("public-vpn-", "public-vpnX", 1),
        )
        with self.assertRaisesRegex(CloudflareBuildError, "SHA-256 mismatch"):
            build(self.root, self.output)
        self.assertFalse(os.path.exists(self.output))

    def test_different_txt_and_json_records_are_rejected(self) -> None:
        write_dataset(self.root, tamper_json=True)
        with self.assertRaisesRegex(CloudflareBuildError, "different records"):
            build(self.root, self.output)
        self.assertFalse(os.path.exists(self.output))

    def test_count_mismatch_is_rejected(self) -> None:
        write_dataset(self.root, count_override=len(IPS) + 1)
        with self.assertRaisesRegex(CloudflareBuildError, "record count mismatch"):
            build(self.root, self.output)
        self.assertFalse(os.path.exists(self.output))

    def test_missing_file_is_rejected(self) -> None:
        write_dataset(self.root)
        os.unlink(os.path.join(self.root, MANIFEST_JSON))
        with self.assertRaisesRegex(CloudflareBuildError, "missing required file"):
            build(self.root, self.output)
        self.assertFalse(os.path.exists(self.output))

    def test_invalid_signature_structure_is_rejected(self) -> None:
        write_dataset(self.root)
        _write(
            os.path.join(self.root, MANIFEST_SIG),
            json.dumps(
                {
                    "algorithm": "HMAC_SHA256",
                    "key_id": "test-key",
                    "signature_base64": base64.b64encode(bytes(64)).decode(),
                }
            ),
        )
        with self.assertRaisesRegex(CloudflareBuildError, "unsupported algorithm"):
            build(self.root, self.output)
        self.assertFalse(os.path.exists(self.output))


if __name__ == "__main__":
    unittest.main()
