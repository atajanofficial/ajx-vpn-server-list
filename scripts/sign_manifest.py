"""Create the detached signature for ``manifest.json``.

The Android client verifies ``manifest.json`` (and therefore the SHA-256 of the
server list) against a public key that is pinned in the APK at build time. The
matching private key exists only as a CI secret; it is never committed and never
shipped.

Design notes:

* The signature covers the *exact bytes* of ``manifest.json``. There is no JSON
  canonicalisation step that the client would have to reproduce, and no
  signature field inside the signed document (that would be circular).
* ``manifest.sig`` is a small JSON envelope so the algorithm and key id are
  explicit and can be rotated without ambiguity.
* ECDSA is randomised, so the script re-verifies an existing signature first and
  leaves the file untouched when it is still valid. A 30-minute refresh with no
  content change therefore does not create a new commit.

Usage (CI):

    python scripts/sign_manifest.py --root . --key-file /tmp/key.pem --key-id ajx-list

The printed JSON contains the base64 SubjectPublicKeyInfo that must be pinned as
``github.servers.manifest.publicKey`` in the Android build.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import tempfile
from typing import Dict, Optional

ALGORITHM = "ECDSA_P256_SHA256"
MANIFEST_JSON = "manifest.json"
MANIFEST_SIG = "manifest.sig"


class SigningError(RuntimeError):
    """The manifest could not be signed or verified."""


def _require_cryptography():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as error:  # pragma: no cover - exercised only without the dep
        raise SigningError(
            "the 'cryptography' package is required to sign the manifest"
        ) from error
    return hashes, serialization, ec


def load_private_key(path: str):
    _, serialization, ec = _require_cryptography()
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        raise SigningError(f"could not read the signing key: {error}") from error

    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as error:
        raise SigningError(f"the signing key is not a usable PEM private key: {error}") from error

    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise SigningError("the signing key must be an EC P-256 (secp256r1) private key")
    return key


def public_key_base64(key) -> str:
    _, serialization, _ = _require_cryptography()
    der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def default_key_id(key) -> str:
    _, serialization, _ = _require_cryptography()
    der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "ec-p256-" + hashlib.sha256(der).hexdigest()[:16]


def sign_bytes(key, manifest_bytes: bytes) -> bytes:
    hashes, _, ec = _require_cryptography()
    return key.sign(manifest_bytes, ec.ECDSA(hashes.SHA256()))


def verify_bytes(public_key, manifest_bytes: bytes, signature: bytes) -> bool:
    hashes, _, ec = _require_cryptography()
    try:
        public_key.verify(signature, manifest_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def build_signature_document(signature: bytes, key_id: str) -> str:
    document = {
        "algorithm": ALGORITHM,
        "key_id": key_id,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def parse_signature_document(text: str) -> Dict[str, str]:
    try:
        document = json.loads(text)
    except ValueError as error:
        raise SigningError(f"manifest.sig is not valid JSON: {error}") from error
    if not isinstance(document, dict):
        raise SigningError("manifest.sig must be a JSON object")
    algorithm = document.get("algorithm")
    key_id = document.get("key_id")
    value = document.get("signature_base64")
    if algorithm != ALGORITHM:
        raise SigningError(f"manifest.sig uses an unsupported algorithm: {algorithm!r}")
    if not isinstance(key_id, str) or not key_id:
        raise SigningError("manifest.sig has no key id")
    if not isinstance(value, str) or not value:
        raise SigningError("manifest.sig has no signature value")
    return {"algorithm": algorithm, "key_id": key_id, "signature_base64": value}


def _write_atomic(path: str, content: str) -> None:
    directory = os.path.dirname(path) or "."
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        dir=directory,
        prefix=".tmp-sig-",
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


def existing_signature_is_valid(
    manifest_bytes: bytes,
    signature_text: Optional[str],
    public_key,
    key_id: str,
) -> bool:
    if not signature_text:
        return False
    try:
        parsed = parse_signature_document(signature_text)
        signature = base64.b64decode(parsed["signature_base64"], validate=True)
    except (SigningError, ValueError):
        return False
    if parsed["key_id"] != key_id:
        return False
    return verify_bytes(public_key, manifest_bytes, signature)


def sign_manifest(
    root: str,
    key_file: str,
    key_id: Optional[str] = None,
    force: bool = False,
) -> Dict[str, object]:
    manifest_path = os.path.join(root, MANIFEST_JSON)
    signature_path = os.path.join(root, MANIFEST_SIG)

    try:
        with open(manifest_path, "rb") as handle:
            manifest_bytes = handle.read()
    except OSError as error:
        raise SigningError(f"could not read {MANIFEST_JSON}: {error}") from error
    if not manifest_bytes:
        raise SigningError(f"{MANIFEST_JSON} is empty")

    try:
        document = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise SigningError(f"{MANIFEST_JSON} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(document, dict) or document.get("manifest_version") != 1:
        raise SigningError(f"{MANIFEST_JSON} is not a supported manifest")

    key = load_private_key(key_file)
    resolved_key_id = key_id or default_key_id(key)

    existing = None
    try:
        with open(signature_path, "r", encoding="utf-8") as handle:
            existing = handle.read()
    except OSError:
        existing = None

    if not force and existing_signature_is_valid(
        manifest_bytes, existing, key.public_key(), resolved_key_id
    ):
        return {
            "status": "NO_CHANGE",
            "key_id": resolved_key_id,
            "public_key_base64": public_key_base64(key),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        }

    signature = sign_bytes(key, manifest_bytes)
    if not verify_bytes(key.public_key(), manifest_bytes, signature):
        raise SigningError("the freshly created signature does not verify")

    _write_atomic(signature_path, build_signature_document(signature, resolved_key_id))

    # Re-read what was actually written and verify it independently.
    with open(signature_path, "r", encoding="utf-8") as handle:
        written = handle.read()
    parsed = parse_signature_document(written)
    if not verify_bytes(
        key.public_key(), manifest_bytes, base64.b64decode(parsed["signature_base64"])
    ):
        raise SigningError("the written signature does not verify")

    return {
        "status": "SIGNED",
        "key_id": resolved_key_id,
        "public_key_base64": public_key_base64(key),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--key-file", required=True, help="PEM EC P-256 private key")
    parser.add_argument("--key-id", default=None, help="stable key identifier")
    parser.add_argument(
        "--force",
        action="store_true",
        help="re-sign even when the existing signature is still valid",
    )
    args = parser.parse_args(argv)

    try:
        summary = sign_manifest(
            args.root,
            args.key_file,
            key_id=args.key_id,
            force=args.force,
        )
    except (OSError, SigningError) as error:
        print(f"SIGNING_FAILED: {error}", file=sys.stderr)
        return 1

    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
