"""Local filesystem checks; no external services or model calls."""

from concurrent.futures import ThreadPoolExecutor
import os
import stat
import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from local_keys import load_or_create_key


def public_bytes(key):
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def test_first_run_creates_matching_keys_with_private_permissions(tmp_path):
    directory = tmp_path / "keys"
    key = load_or_create_key(directory)
    assert isinstance(key, Ed25519PrivateKey)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE((directory / "signer.key").stat().st_mode) == 0o600
    assert (directory / "signer-public.pem").read_bytes() == public_bytes(key)
    loaded = serialization.load_pem_private_key((directory / "signer.key").read_bytes(), password=None)
    assert public_bytes(loaded) == public_bytes(key)


def test_repeated_startup_preserves_identity_and_existing_files(tmp_path):
    first = load_or_create_key(tmp_path)
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in tmp_path.iterdir()}
    second = load_or_create_key(tmp_path)
    after = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in tmp_path.iterdir()}
    assert public_bytes(first) == public_bytes(second)
    assert before == after


def test_missing_public_key_is_reconstructed_without_changing_private_key(tmp_path):
    first = load_or_create_key(tmp_path)
    private_path = tmp_path / "signer.key"
    previous_private = private_path.read_bytes(), private_path.stat().st_mtime_ns
    (tmp_path / "signer-public.pem").unlink()
    second = load_or_create_key(tmp_path)
    assert public_bytes(first) == public_bytes(second)
    assert (tmp_path / "signer-public.pem").read_bytes() == public_bytes(first)
    assert (private_path.read_bytes(), private_path.stat().st_mtime_ns) == previous_private


@pytest.mark.parametrize("filename", ["signer.key", "signer-public.pem"])
def test_corrupt_existing_key_is_never_replaced(tmp_path, filename):
    load_or_create_key(tmp_path)
    (tmp_path / filename).write_bytes(b"corrupt key")
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    with pytest.raises(ValueError):
        load_or_create_key(tmp_path)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_public_key_without_private_key_never_rotates(tmp_path):
    key = load_or_create_key(tmp_path)
    (tmp_path / "signer.key").unlink()
    with pytest.raises(ValueError, match="refusing to rotate"):
        load_or_create_key(tmp_path)
    assert not (tmp_path / "signer.key").exists()
    assert (tmp_path / "signer-public.pem").read_bytes() == public_bytes(key)


def test_conflicting_public_key_is_rejected_and_preserved(tmp_path):
    load_or_create_key(tmp_path)
    other_public = public_bytes(Ed25519PrivateKey.generate())
    (tmp_path / "signer-public.pem").write_bytes(other_public)
    private_before = (tmp_path / "signer.key").read_bytes()
    with pytest.raises(ValueError, match="conflicts"):
        load_or_create_key(tmp_path)
    assert (tmp_path / "signer-public.pem").read_bytes() == other_public
    assert (tmp_path / "signer.key").read_bytes() == private_before


@pytest.mark.parametrize("permissions", [0o640, 0o604, 0o660, 0o644])
def test_insecure_existing_private_permissions_are_rejected(tmp_path, permissions):
    key = load_or_create_key(tmp_path)
    (tmp_path / "signer.key").chmod(permissions)
    with pytest.raises(ValueError, match="insecure permissions"):
        load_or_create_key(tmp_path)
    assert stat.S_IMODE((tmp_path / "signer.key").stat().st_mode) == permissions
    assert (tmp_path / "signer-public.pem").read_bytes() == public_bytes(key)


def test_owner_read_only_private_key_is_accepted(tmp_path):
    key = load_or_create_key(tmp_path)
    (tmp_path / "signer.key").chmod(0o400)
    assert public_bytes(load_or_create_key(tmp_path)) == public_bytes(key)


@pytest.mark.parametrize("filename", ["signer.key", "signer-public.pem"])
@pytest.mark.parametrize("dangling", [False, True])
def test_symlink_key_paths_are_rejected_without_touching_targets(tmp_path, filename, dangling):
    directory = tmp_path / "keys"
    key = load_or_create_key(directory)
    target = tmp_path / "outside.pem"
    old_bytes = (directory / filename).read_bytes()
    if not dangling:
        target.write_bytes(old_bytes)
        target.chmod(0o600)
    (directory / filename).unlink()
    (directory / filename).symlink_to(target)
    with pytest.raises(ValueError):
        load_or_create_key(directory)
    assert (directory / filename).is_symlink()
    if dangling:
        assert not target.exists()
    else:
        assert target.read_bytes() == old_bytes


def test_symlink_directory_is_rejected_without_creating_keys(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "keys"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError):
        load_or_create_key(link)
    assert list(target.iterdir()) == []


def test_nonregular_private_path_is_rejected_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "signer.key", mode=0o600)
    with pytest.raises(ValueError, match="regular file"):
        load_or_create_key(tmp_path)
    assert not (tmp_path / "signer-public.pem").exists()


def test_concurrent_startups_cannot_overwrite_each_others_identity(tmp_path):
    barrier = threading.Barrier(2)

    def startup():
        barrier.wait(timeout=5)
        try:
            return load_or_create_key(tmp_path)
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as workers:
        keys = list(workers.map(lambda _: startup(), range(2)))
    successes = [key for key in keys if key is not None]
    assert successes
    persisted = load_or_create_key(tmp_path)
    assert all(public_bytes(key) == public_bytes(persisted) for key in successes)
    assert (tmp_path / "signer-public.pem").read_bytes() == public_bytes(persisted)
