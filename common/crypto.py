from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common.protocol import MAX_FRAME_SIZE


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def load_private_key(path: str) -> rsa.RSAPrivateKey:
    with open(path, "rb") as f:
        raw = f.read()
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("private key is not an RSA private key")
    return key


def load_public_key(path: str):
    with open(path, "rb") as f:
        raw = f.read()
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("public key is not an RSA public key")
    return key


def pubkey_to_der(pubkey: rsa.RSAPublicKey) -> bytes:
    return pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def pubkey_fingerprint(pubkey: rsa.RSAPublicKey) -> str:
    return hashlib.sha256(pubkey_to_der(pubkey)).hexdigest()


def rsa_encrypt(pubkey: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    return pubkey.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(privkey: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return privkey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_sign(privkey: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return privkey.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_verify(pubkey: rsa.RSAPublicKey, data: bytes, signature: bytes) -> None:
    pubkey.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def derive_key(premaster: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return kdf.derive(premaster)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    nonce = os.urandom(12)
    aead = AESGCM(key)
    ciphertext = aead.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def aes_gcm_decrypt(key: bytes, data: bytes, aad: bytes | None = None) -> bytes:
    if len(data) < 12 + 16:
        raise ValueError("ciphertext frame too short")
    nonce = data[:12]
    ciphertext = data[12:]
    aead = AESGCM(key)
    return aead.decrypt(nonce, ciphertext, aad)


def generate_token() -> str:
    return os.urandom(16).hex()


def generate_session_key() -> bytes:
    return os.urandom(32)


def random_bytes(n: int = 32) -> bytes:
    return os.urandom(n)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def auth_key_proof(auth_key: str, server_random: bytes) -> str:
    digest = hmac.new(auth_key.encode("utf-8"), server_random, hashlib.sha256).digest()
    return b64e(digest)


def verify_auth_key_proof(auth_key: str, server_random: bytes, proof_b64: str) -> bool:
    expected = hmac.new(auth_key.encode("utf-8"), server_random, hashlib.sha256).digest()
    actual = b64d(proof_b64)
    return hmac.compare_digest(expected, actual)


async def encrypted_send(
    writer: asyncio.StreamWriter,
    data_key: bytes,
    plaintext: bytes,
) -> None:
    encrypted = aes_gcm_encrypt(data_key, plaintext)
    frame_len = len(encrypted)
    if frame_len > MAX_FRAME_SIZE:
        raise ValueError("encrypted frame too large")
    writer.write(frame_len.to_bytes(4, "big") + encrypted)
    await writer.drain()


async def encrypted_recv(reader: asyncio.StreamReader, data_key: bytes) -> bytes:
    frame_len = int.from_bytes(await reader.readexactly(4), "big")
    if frame_len > MAX_FRAME_SIZE:
        raise ValueError("frame too large")
    encrypted = await reader.readexactly(frame_len)
    return aes_gcm_decrypt(data_key, encrypted)

