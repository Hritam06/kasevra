import json
import os
import subprocess
from pathlib import Path

import pytest

from kasevra.crypto.keys import KeyError as SigningKeyError
from kasevra.crypto.keys import generate_keypair
from kasevra.crypto.signing import (
    SIGNATURE_FORMAT,
    SignatureError,
    sign_manifest,
    verify_signature,
)


@pytest.fixture
def signed_case(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    manifest = tmp_path / "manifest.json"
    signature = tmp_path / "signature.json"

    generate_keypair(private, public)

    manifest.write_text(
        json.dumps({"files": [], "version": "2.0.0"}),
        encoding="utf-8",
    )
    sign_manifest(manifest, private, signature)

    return {
        "tmp": tmp_path,
        "private": private,
        "public": public,
        "manifest": manifest,
        "signature": signature,
    }


def test_rejects_symlinked_manifest(signed_case):
    link = signed_case["tmp"] / "manifest-link.json"
    link.symlink_to(signed_case["manifest"])

    with pytest.raises(SignatureError):
        verify_signature(
            link,
            signed_case["signature"],
            signed_case["public"],
        )


def test_rejects_symlinked_public_key(signed_case):
    link = signed_case["tmp"] / "public-link.pem"
    link.symlink_to(signed_case["public"])

    with pytest.raises(SigningKeyError):
        verify_signature(
            signed_case["manifest"],
            signed_case["signature"],
            link,
        )


def test_rejects_malformed_base64(signed_case):
    data = json.loads(signed_case["signature"].read_text())
    data["signature"] = "%%%invalid-base64%%%"
    signed_case["signature"].write_text(json.dumps(data))

    with pytest.raises(SignatureError):
        verify_signature(
            signed_case["manifest"],
            signed_case["signature"],
            signed_case["public"],
        )


def test_rejects_duplicate_json_keys(signed_case):
    signed_case["signature"].write_text(
        '{"format":"' + SIGNATURE_FORMAT + '","format":"' + SIGNATURE_FORMAT + '"}'
    )

    with pytest.raises(SignatureError):
        verify_signature(
            signed_case["manifest"],
            signed_case["signature"],
            signed_case["public"],
        )


def test_rejects_oversized_signature_file(signed_case):
    signed_case["signature"].write_bytes(b"x" * (1024 * 1024 + 1))

    with pytest.raises(SignatureError, match="size"):
        verify_signature(
            signed_case["manifest"],
            signed_case["signature"],
            signed_case["public"],
        )


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows uses native CreateFileW opening",
)
def test_rejects_manifest_symlink_swap_before_open(signed_case, monkeypatch):
    original_open = os.open
    manifest = signed_case["manifest"]
    replacement = signed_case["tmp"] / "replacement.json"
    replacement.write_text('{"replacement": true}', encoding="utf-8")
    swapped = False

    def swap_before_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if Path(path) == manifest and not swapped:
            swapped = True
            manifest.unlink()
            manifest.symlink_to(replacement)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap_before_open)

    with pytest.raises(SignatureError):
        verify_signature(
            manifest,
            signed_case["signature"],
            signed_case["public"],
        )

    assert swapped


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction test")
def test_rejects_windows_directory_junction(signed_case):
    target = signed_case["tmp"] / "target-directory"
    junction = signed_case["tmp"] / "junction"
    target.mkdir()

    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        pytest.skip("Windows junction creation unavailable: " + result.stderr)

    try:
        with pytest.raises(SignatureError):
            verify_signature(
                signed_case["manifest"],
                junction,
                signed_case["public"],
            )
    finally:
        if junction.exists():
            junction.rmdir()
