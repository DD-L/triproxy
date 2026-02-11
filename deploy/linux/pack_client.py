#!/usr/bin/env python3
"""
Pack TriProxy client (C) for Linux deployment → client.tar.bz2.
Run from project root: python deploy/linux/pack_client.py
"""
from __future__ import annotations

import io
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT_NAME = "client"
ARCHIVE = ROOT / "client.tar.bz2"
FILES = [
    ("client", True),
    ("common", True),
    ("requirements.txt", False),
]
CONFIG = [("config/client.example.yaml", "config/client.yaml")]
CERTS = ["certs/generate_keys.py", "certs/README.md"]

# C 本机 certs/ 必须有的文件（需从本地上传，不打包 .pem）
CERTS_FOR_CLIENT_TXT = """# C 本机 certs/ 目录必须有的文件（从本地上传，不随 tar 打包）

config/client.yaml 中配置了以下路径时，请把对应 .pem 放到 C 的 certs/ 下：

1. rsa_private_key 指向的文件
   例: certs/client_private.pem  → 本机/client 的私钥（与 relay 上 allowed_clients 里的 client 公钥成对）

2. rsa_public_key 指向的文件
   例: certs/relay_public.pem   → B(relay) 的公钥，用于连接并验证 B

路径须与 config/client.yaml 中一致。
"""
DEPLOY = [
    "deploy/linux/start_client.sh",
    "deploy/systemd/triproxy-client.service",
]

README_CLIENT = """# TriProxy Client (C) – Linux deploy

## Unpack and install

  tar -xjf client.tar.bz2
  cd client
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt

## Certificates (must put on C, not in this tarball)

Client does **not** bundle any .pem files. You must put these under certs/ on the C machine:

1. **certs/client_private.pem** — 本 client 的私钥（与 B 上 allowed_clients 里你的 client 公钥成对）
2. **certs/relay_public.pem** — B(relay) 的公钥，用于连接并验证 B

Paths must match config/client.yaml (rsa_private_key, rsa_public_key).

See certs/CERTS_FOR_CLIENT.txt for a short checklist.

## Run

  .venv/bin/python -m client.main config/client.yaml

Or with watchdog and systemd: see deploy/systemd/triproxy-client.service
(adjust paths in the .service file).
"""


def _skip(f: Path) -> bool:
    return "__pycache__" in f.parts or f.suffix == ".pyc"


def _add_tree(tf: tarfile.TarFile, src: Path, arc_prefix: str) -> None:
    for f in sorted(src.rglob("*")):
        if f.is_file() and not _skip(f):
            rel = f.relative_to(src)
            tf.add(f, arcname=arc_prefix + str(rel))


def _require_exists(path: Path, kind: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"required {kind} not found: {path}")


def main() -> None:
    print("== TriProxy Client pack (from", ROOT, ")")
    prefix = OUTPUT_NAME + "/"

    print("  creating", ARCHIVE.name)
    with tarfile.open(ARCHIVE, "w:bz2") as tf:
        for item, is_dir in FILES:
            src = ROOT / item
            _require_exists(src, "directory" if is_dir else "file")
            if is_dir:
                _add_tree(tf, src, prefix + item + "/")
            else:
                tf.add(src, arcname=prefix + item)

        for src_rel, dst_rel in CONFIG:
            src = ROOT / src_rel
            _require_exists(src, "config file")
            tf.add(src, arcname=prefix + dst_rel)

        for p in CERTS:
            src = ROOT / p
            _require_exists(src, "cert helper")
            tf.add(src, arcname=prefix + p)

        info = tarfile.TarInfo(name=prefix + "certs/CERTS_FOR_CLIENT.txt")
        info.size = len(CERTS_FOR_CLIENT_TXT.encode("utf-8"))
        info.mtime = 0
        tf.addfile(info, io.BytesIO(CERTS_FOR_CLIENT_TXT.encode("utf-8")))

        for p in DEPLOY:
            src = ROOT / p
            _require_exists(src, "deploy file")
            tf.add(src, arcname=prefix + p)

        data = README_CLIENT.encode("utf-8")
        info = tarfile.TarInfo(name=prefix + "README.client")
        info.size = len(data)
        info.mtime = 0
        tf.addfile(info, io.BytesIO(data))

    print("== Done:", ARCHIVE)


if __name__ == "__main__":
    main()
