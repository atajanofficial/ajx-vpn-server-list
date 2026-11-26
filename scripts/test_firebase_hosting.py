"""Tests for the Firebase Hosting deployment builder."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from typing import List, Optional

from build_firebase_hosting import (
    FIREBASERC,
    FIREBASE_CONFIG,
    FIREBASE_HOST,
    INDEX_HTML,
    MANIFEST_JSON,
    MANIFEST_SIG,
    PROJECT_ID,
    SERVERS_JSON,
    SERVERS_TXT,
    FirebaseBuildError,
    _firebase_config,
    _firebaserc,
    _validate_generated_config,
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
from validate_servers import TXT_COLUMNS, parse_source

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


class FirebaseHostingBuilderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="ajx-firebase-test-")
        self.root = os.path.join(self.tmp, "repo")
        self.output = os.path.join(self.tmp, "firebase-hosting")
        os.makedirs(self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _source_bytes(self, name: str) -> bytes:
        with open(os.path.join(self.root, name), "rb") as handle:
            return handle.read()

    def _output_bytes(self, name: str) -> bytes:
        with open(os.path.join(self.output, name), "rb") as handle:
            return handle.read()

    def test_builds_exactly_the_validated_dataset(self) -> None:
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
        self.assertEqual(21, len(TXT_COLUMNS))
        self.assertEqual(
            {
                SERVERS_TXT,
                SERVERS_JSON,
                MANIFEST_JSON,
                MANIFEST_SIG,
                INDEX_HTML,
                FIREBASE_CONFIG,
                FIREBASERC,
            },
            set(os.listdir(self.output)),
        )
        self.assertEqual(PROJECT_ID, summary["project"])
        self.assertEqual("ajx-vpn-servers.web.app", FIREBASE_HOST)

    def test_config_is_private_and_uses_revalidating_cache(self) -> None:
        write_dataset(self.root)
        build(self.root, self.output)

        document = json.loads(self._output_bytes(FIREBASE_CONFIG).decode("utf-8"))
        hosting = document["hosting"]
        self.assertEqual(".", hosting["public"])
        self.assertIn(FIREBASE_CONFIG, hosting["ignore"])
        self.assertIn(FIREBASERC, hosting["ignore"])
        self.assertNotIn("rewrites", hosting)
        self.assertNotIn("redirects", hosting)
        headers = {
            entry["source"]: {item["key"]: item["value"] for item in entry["headers"]}
            for entry in hosting["headers"]
        }
        self.assertEqual(
            "public, max-age=0, must-revalidate",
            headers["/servers.txt"]["Cache-Control"],
        )
        self.assertEqual(
            "public, max-age=0, must-revalidate",
            headers["/servers.json"]["Cache-Control"],
        )
        self.assertEqual(
            "public, max-age=0, must-revalidate",
            headers["/manifest.json"]["Cache-Control"],
        )
        self.assertEqual("nosniff", headers["**"]["X-Content-Type-Options"])
        self.assertNotIn("/firebase.json", headers)
        self.assertNotIn("/.firebaserc", headers)

    def test_a_rejected_rebuild_does_not_replace_a_good_deployment(self) -> None:
        write_dataset(self.root)
        build(self.root, self.output)
        before = {name: self._output_bytes(name) for name in os.listdir(self.output)}

        _write(
            os.path.join(self.root, SERVERS_TXT),
            "<html><body>Service unavailable</body></html>\n",
        )
        with self.assertRaises(FirebaseBuildError):
            build(self.root, self.output)

        after = {name: self._output_bytes(name) for name in os.listdir(self.output)}
        self.assertEqual(before, after)
        self.assertEqual(
            {"repo", "firebase-hosting"},
            set(os.listdir(self.tmp)),
        )

    def test_html_error_page_is_rejected(self) -> None:
        write_dataset(
            self.root,
            txt_override="<html><body>Bad gateway</body></html>\n",
        )
        with self.assertRaisesRegex(FirebaseBuildError, "failed validation"):
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
        with self.assertRaisesRegex(FirebaseBuildError, "SHA-256 mismatch"):
            build(self.root, self.output)
        self.assertFalse(os.path.exists(self.output))

    def test_different_txt_and_json_records_are_rejected(self) -> None:
        write_dataset(self.root, tamper_json=True)
        with self.assertRaisesRegex(FirebaseBuildError, "different records"):
            build(self.root, self.output)
        self.assertFalse(os.path.exists(self.output))

    def test_count_mismatch_is_rejected(self) -> None:
        write_dataset(self.root, count_override=len(IPS) + 1)
        with self.assertRaisesRegex(FirebaseBuildError, "record count mismatch"):
            build(self.root, self.output)
        self.assertFalse(os.path.exists(self.output))

    def test_missing_file_is_rejected(self) -> None:
        write_dataset(self.root)
        os.unlink(os.path.join(self.root, MANIFEST_JSON))
        with self.assertRaisesRegex(FirebaseBuildError, "missing required file"):
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
        with self.assertRaisesRegex(FirebaseBuildError, "unsupported algorithm"):
            build(self.root, self.output)
        self.assertFalse(os.path.exists(self.output))

    def test_stale_metadata_is_rejected(self) -> None:
        write_dataset(self.root)
        document = json.loads(self._source_bytes(METADATA_JSON).decode("utf-8"))
        document["manifest"]["sha256"] = "0" * 64
        _write(
            os.path.join(self.root, METADATA_JSON),
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        )
        with self.assertRaisesRegex(FirebaseBuildError, "metadata manifest SHA-256"):
            build(self.root, self.output)
        self.assertFalse(os.path.exists(self.output))

    def test_unsigned_dataset_omits_the_signature_file(self) -> None:
        write_dataset(self.root)
        build(self.root, self.output)
        self.assertNotIn(MANIFEST_SIG, os.listdir(self.output))

    def test_generated_config_validation_rejects_rewrites_and_root_changes(self) -> None:
        firebaserc = _firebaserc(PROJECT_ID)
        _validate_generated_config(_firebase_config(), firebaserc)

        rewritten = _firebase_config()
        rewritten["hosting"]["rewrites"] = [
            {"source": "**", "destination": "/index.html"}
        ]
        with self.assertRaisesRegex(FirebaseBuildError, "rewrite"):
            _validate_generated_config(rewritten, firebaserc)

        moved = _firebase_config()
        moved["hosting"]["public"] = "public"
        with self.assertRaisesRegex(FirebaseBuildError, "serve the deployment"):
            _validate_generated_config(moved, firebaserc)

        with self.assertRaises(FirebaseBuildError):
            _firebaserc("AJX_VPN")

    def test_failed_build_leaves_no_staging_directory(self) -> None:
        write_dataset(self.root, tamper_json=True)
        with self.assertRaises(FirebaseBuildError):
            build(self.root, self.output)
        self.assertEqual({"repo"}, set(os.listdir(self.tmp)))


if __name__ == "__main__":
    unittest.main()
