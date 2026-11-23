"""Tests for the detached manifest signature.

These tests generate an ephemeral EC P-256 key so no private key ever needs to
exist in the repository.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest

from generate_server_list import MANIFEST_JSON, MANIFEST_SIG, build_manifest

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTOGRAPHY = False

from sign_manifest import (
    ALGORITHM,
    SigningError,
    existing_signature_is_valid,
    parse_signature_document,
    sign_manifest,
    verify_bytes,
)


def write_ec_key(path: str) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as handle:
        handle.write(pem)


def public_key_for(path: str):
    with open(path, "rb") as handle:
        key = serialization.load_pem_private_key(handle.read(), password=None)
    return key.public_key()


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography is not installed")
class ManifestSignatureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = self.temp.name
        self.key_file = os.path.join(self.root, "signing-key.pem")
        write_ec_key(self.key_file)
        self.manifest_path = os.path.join(self.root, MANIFEST_JSON)
        with open(self.manifest_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(build_manifest("servers\n", "json\n", 1_700_000_000_000, 1))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _manifest_bytes(self) -> bytes:
        with open(self.manifest_path, "rb") as handle:
            return handle.read()

    def test_signs_and_verifies_the_exact_manifest_bytes(self) -> None:
        result = sign_manifest(self.root, self.key_file, key_id="test-key")

        self.assertEqual("SIGNED", result["status"])
        self.assertEqual("test-key", result["key_id"])
        with open(os.path.join(self.root, MANIFEST_SIG), "r", encoding="utf-8") as handle:
            document = json.loads(handle.read())
        self.assertEqual(ALGORITHM, document["algorithm"])
        self.assertEqual("test-key", document["key_id"])
        signature = base64.b64decode(document["signature_base64"], validate=True)
        self.assertTrue(
            verify_bytes(public_key_for(self.key_file), self._manifest_bytes(), signature)
        )

    def test_second_run_does_not_change_a_valid_signature(self) -> None:
        sign_manifest(self.root, self.key_file, key_id="test-key")
        with open(os.path.join(self.root, MANIFEST_SIG), "rb") as handle:
            first = handle.read()

        result = sign_manifest(self.root, self.key_file, key_id="test-key")

        self.assertEqual("NO_CHANGE", result["status"])
        with open(os.path.join(self.root, MANIFEST_SIG), "rb") as handle:
            self.assertEqual(first, handle.read())

    def test_a_changed_manifest_invalidates_the_old_signature(self) -> None:
        sign_manifest(self.root, self.key_file, key_id="test-key")
        with open(self.manifest_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(build_manifest("changed\n", "json\n", 1_700_000_000_001, 1))

        with open(os.path.join(self.root, MANIFEST_SIG), "r", encoding="utf-8") as handle:
            existing = handle.read()
        self.assertFalse(
            existing_signature_is_valid(
                self._manifest_bytes(),
                existing,
                public_key_for(self.key_file),
                "test-key",
            )
        )

        result = sign_manifest(self.root, self.key_file, key_id="test-key")
        self.assertEqual("SIGNED", result["status"])

    def test_a_tampered_signature_is_rejected(self) -> None:
        sign_manifest(self.root, self.key_file, key_id="test-key")
        with open(os.path.join(self.root, MANIFEST_SIG), "r", encoding="utf-8") as handle:
            parsed = parse_signature_document(handle.read())
        signature = bytearray(base64.b64decode(parsed["signature_base64"]))
        signature[-1] ^= 0xFF

        self.assertFalse(
            verify_bytes(public_key_for(self.key_file), self._manifest_bytes(), bytes(signature))
        )

    def test_a_non_p256_key_is_rejected(self) -> None:
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path = os.path.join(self.root, "rsa.pem")
        with open(path, "wb") as handle:
            handle.write(pem)

        with self.assertRaises(SigningError):
            sign_manifest(self.root, path)

    def test_a_wrong_key_id_does_not_reuse_the_signature(self) -> None:
        sign_manifest(self.root, self.key_file, key_id="key-a")
        with open(os.path.join(self.root, MANIFEST_SIG), "r", encoding="utf-8") as handle:
            existing = handle.read()

        self.assertFalse(
            existing_signature_is_valid(
                self._manifest_bytes(),
                existing,
                public_key_for(self.key_file),
                "key-b",
            )
        )


if __name__ == "__main__":
    unittest.main()
