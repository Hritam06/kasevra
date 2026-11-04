"""Ed25519 key generation and secure key-file handling."""

import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from kasevra.crypto._safe_read import read_regular_file


class KeyError(Exception):
    """Raised when a signing key is invalid or unsafe."""


def generate_keypair(private_key_path: Path, public_key_path: Path) -> None:
    """Generate an Ed25519 keypair without overwriting existing files."""
    private_key_path = Path(private_key_path)
    public_key_path = Path(public_key_path)

    if private_key_path.resolve() == public_key_path.resolve():
        raise KeyError("Private and public key paths must differ")

    if private_key_path.exists() or public_key_path.exists():
        raise FileExistsError("Refusing to overwrite an existing key file")

    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)

    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_fd = os.open(
        private_key_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(private_fd, "wb") as stream:
            stream.write(private_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        private_key_path.unlink(missing_ok=True)
        raise

    try:
        public_fd = os.open(
            public_key_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o644,
        )
        with os.fdopen(public_fd, "wb") as stream:
            stream.write(public_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        private_key_path.unlink(missing_ok=True)
        public_key_path.unlink(missing_ok=True)
        raise


def _read_key_file(path: Path, *, private: bool) -> bytes:
    """Read a bounded regular key file without following its final link."""
    try:
        data, info = read_regular_file(
            path,
            limit=1024 * 1024,
            label="Key file",
        )
    except OSError as exc:
        raise KeyError("Unable to safely read key file") from exc

    # POSIX mode bits are meaningful on POSIX filesystems. Windows
    # security is governed by inherited NTFS ACLs, not chmod mode bits.
    if private and os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
        raise KeyError("Private key permissions must not allow group or other access")

    return data


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load a private key from a bounded, non-followed regular file."""
    try:
        key = serialization.load_pem_private_key(
            _read_key_file(path, private=True), password=None
        )
    except KeyError:
        raise
    except (ValueError, TypeError) as exc:
        raise KeyError("Invalid private key file") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyError("Expected an Ed25519 private key")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Load a public key from a bounded, non-followed regular file."""
    try:
        key = serialization.load_pem_public_key(_read_key_file(path, private=False))
    except KeyError:
        raise
    except (ValueError, TypeError) as exc:
        raise KeyError("Invalid public key file") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise KeyError("Expected an Ed25519 public key")
    return key
