import pytest

from kasevra.crypto.keys import KeyError as SigningKeyError
from kasevra.crypto.keys import generate_keypair
from kasevra.crypto.signing import SignatureError, sign_manifest, verify_signature


def test_ed25519_sign_and_verify(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    manifest = tmp_path / "manifest.json"
    signature = tmp_path / "manifest.sig"
    manifest.write_text('{"evidence": []}')

    generate_keypair(private_key, public_key)
    sign_manifest(manifest, private_key, signature)

    assert private_key.stat().st_mode & 0o777 == 0o600
    assert verify_signature(manifest, signature, public_key)["status"] == "PASS"


def test_signature_detects_manifest_change(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    manifest = tmp_path / "manifest.json"
    signature = tmp_path / "manifest.sig"
    manifest.write_text('{"evidence": []}')

    generate_keypair(private_key, public_key)
    sign_manifest(manifest, private_key, signature)
    manifest.write_text('{"evidence": ["changed"]}')

    with pytest.raises(SignatureError):
        verify_signature(manifest, signature, public_key)


def test_key_generation_refuses_overwrite(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_keypair(private_key, public_key)

    with pytest.raises(FileExistsError):
        generate_keypair(private_key, public_key)


def test_private_key_permissions_are_enforced(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_keypair(private_key, public_key)
    private_key.chmod(0o644)

    with pytest.raises(SigningKeyError):
        from kasevra.crypto.keys import load_private_key

        load_private_key(private_key)


def test_signature_file_cannot_be_overwritten(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    manifest = tmp_path / "manifest.json"
    signature = tmp_path / "manifest.sig"
    manifest.write_text("{}")
    generate_keypair(private_key, public_key)
    sign_manifest(manifest, private_key, signature)

    with pytest.raises(FileExistsError):
        sign_manifest(manifest, private_key, signature)


def test_signature_verification_rejects_symlinked_signature_file(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    manifest = tmp_path / "manifest.json"
    signature = tmp_path / "manifest.sig"
    linked = tmp_path / "linked.sig"
    manifest.write_text("{}")
    generate_keypair(private_key, public_key)
    sign_manifest(manifest, private_key, signature)
    linked.symlink_to(signature)
    with pytest.raises(SignatureError):
        verify_signature(manifest, linked, public_key)
