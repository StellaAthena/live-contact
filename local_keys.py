"""Persistent local signer keys, with exclusive creation and no silent rotation."""

import os
from pathlib import Path
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _read_key_file(directory_fd, name, private=False):
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ValueError(f"cannot safely open {name}; symlinks are not allowed") from error
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{name} must be a regular file")
        if private and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(f"{name} has insecure permissions; restrict it to its owner (0600)")
        data = stream.read(8193)
        if len(data) > 8192:
            raise ValueError(f"{name} is too large to be a PEM key")
        return data


def _create_key_file(directory_fd, name, data, mode):
    try:
        descriptor = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode, dir_fd=directory_fd,
        )
    except FileExistsError as error:
        raise ValueError(f"{name} appeared during startup; refusing to overwrite it") from error
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def load_or_create_key(directory):
    directory = Path(directory)
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise ValueError("key directory must be a directory, not a symlink") from error
    try:
        private_data = _read_key_file(directory_fd, "signer.key", private=True)
        public_data = _read_key_file(directory_fd, "signer-public.pem")
        if private_data is None:
            if public_data is not None:
                raise ValueError("public key exists without signer.key; refusing to rotate identity")
            key = Ed25519PrivateKey.generate()
        else:
            try:
                key = serialization.load_pem_private_key(private_data, password=None)
            except (TypeError, ValueError) as error:
                raise ValueError("signer.key is not a valid unencrypted private PEM key") from error
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError("signer.key must contain an Ed25519 private key")

        public_bytes = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if public_data is not None:
            try:
                public_key = serialization.load_pem_public_key(public_data)
            except (TypeError, ValueError) as error:
                raise ValueError("signer-public.pem is not a valid public PEM key") from error
            if not isinstance(public_key, Ed25519PublicKey) or public_key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ) != public_bytes:
                raise ValueError("signer-public.pem conflicts with signer.key")

        if private_data is None:
            _create_key_file(
                directory_fd, "signer.key",
                key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
                0o600,
            )
        if public_data is None:
            _create_key_file(directory_fd, "signer-public.pem", public_bytes, 0o644)
        return key
    finally:
        os.close(directory_fd)
