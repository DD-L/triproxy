from __future__ import annotations

import argparse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from common.crypto import pubkey_fingerprint


def generate_keys(output_dir: str = "certs") -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    for role in ("agent", "relay", "client"):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        priv_path = out / f"{role}_private.pem"
        pub_path = out / f"{role}_public.pem"

        priv_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        pub_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        print(f"{role} fingerprint: SHA256:{pubkey_fingerprint(public_key)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate RSA-2048 key pairs for TriProxy")
    parser.add_argument("--output", default="certs", help="Output directory")
    args = parser.parse_args()
    generate_keys(args.output)


if __name__ == "__main__":
    main()

