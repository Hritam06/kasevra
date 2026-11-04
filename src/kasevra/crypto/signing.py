"""Detached Ed25519 signatures for KASEVRA manifests."""

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from kasevra.crypto._safe_read import read_regular_file
from kasevra.crypto.keys import load_private_key, load_public_key
from kasevra.integrity.canonical import canonical_json_bytes


class SignatureError(Exception):
    """Raised when signature creation or validation fails."""


SIGNATURE_FORMAT = "kasevra-ed25519-signature-v1"


def sign_manifest(
    manifest_path: Path, private_key_path: Path, signature_path: Path
) -> dict:
    """Sign exact manifest bytes and write a detached signature record."""
    manifest_path = Path(manifest_path)
    signature_path = Path(signature_path)

    if signature_path.exists():
        raise FileExistsError(f"Refusing to overwrite signature: {signature_path}")

    try:
        manifest_bytes, _ = read_regular_file(
            manifest_path,
            limit=64 * 1024 * 1024,
            label="Manifest",
        )
    except OSError as exc:
        raise SignatureError(str(exc)) from exc
    key = load_private_key(private_key_path)
    signature = key.sign(manifest_bytes)
    public_bytes = key.public_key().public_bytes_raw()

    record = {
        "format": SIGNATURE_FORMAT,
        "algorithm": "Ed25519",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "public_key_sha256": hashlib.sha256(public_bytes).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
    }

    encoded = canonical_json_bytes(record) + bytes([10])
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(signature_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        signature_path.unlink(missing_ok=True)
        raise

    return record


def verify_signature(
    manifest_path: Path,
    signature_path: Path,
    public_key_path: Path,
) -> dict:
    """Verify a detached signature against a supplied public key."""

    try:
        manifest_bytes, _ = read_regular_file(
            Path(manifest_path),
            limit=64 * 1024 * 1024,
            label="Manifest",
        )
        signature_bytes, _ = read_regular_file(
            Path(signature_path),
            limit=1024 * 1024,
            label="Signature input",
        )
    except OSError as exc:
        raise SignatureError(str(exc)) from exc

    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SignatureError(f"Duplicate signature field: {key}")
            result[key] = value
        return result

    try:
        record = json.loads(
            signature_bytes.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SignatureError("Signature record is not valid JSON") from exc

    required = {
        "format",
        "algorithm",
        "manifest_sha256",
        "public_key_sha256",
        "signature",
    }
    if not isinstance(record, dict) or set(record) != required:
        raise SignatureError("Invalid signature record structure")

    if record["format"] != SIGNATURE_FORMAT or record["algorithm"] != "Ed25519":
        raise SignatureError("Unsupported signature format or algorithm")

    key = load_public_key(public_key_path)
    public_bytes = key.public_bytes_raw()

    for field in ("manifest_sha256", "public_key_sha256"):
        value = record[field]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise SignatureError(f"Invalid {field} in signature record")
    if not isinstance(record["signature"], str):
        raise SignatureError("Invalid signature encoding")

    if hashlib.sha256(manifest_bytes).hexdigest() != record["manifest_sha256"]:
        raise SignatureError("Manifest digest does not match signature record")

    if hashlib.sha256(public_bytes).hexdigest() != record["public_key_sha256"]:
        raise SignatureError("Public key does not match signature record")

    try:
        signature = base64.b64decode(record["signature"], validate=True)
        key.verify(signature, manifest_bytes)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise SignatureError("Ed25519 signature verification failed") from exc

    return {
        "status": "PASS",
        "algorithm": "Ed25519",
        "manifest_sha256": record["manifest_sha256"],
        "public_key_sha256": record["public_key_sha256"],
    }
