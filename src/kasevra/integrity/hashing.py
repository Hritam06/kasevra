"""Streaming SHA-256 utilities for KASEVRA evidence integrity."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 hexadecimal digest of bytes."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return hashlib.sha256(data).hexdigest()


def sha256_stream(
    stream: BinaryIO,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """Calculate SHA-256 incrementally from a binary stream."""
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool):
        raise TypeError("chunk_size must be an integer")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    digest = hashlib.sha256()

    while chunk := stream.read(chunk_size):
        if not isinstance(chunk, bytes):
            raise TypeError("stream must return bytes")
        digest.update(chunk)

    return digest.hexdigest()


def sha256_file(
    path: str | Path,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """Calculate a file's SHA-256 digest without loading it all into memory."""
    file_path = Path(path)

    with file_path.open("rb") as stream:
        return sha256_stream(stream, chunk_size=chunk_size)
