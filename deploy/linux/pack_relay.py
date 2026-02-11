#!/usr/bin/env python3
"""
Pack TriProxy relay (B) for Linux deployment → relay.tar.bz2.
Run from project root: python deploy/linux/pack_relay.py
"""
from __future__ import annotations

import io
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT_NAME = "relay"
ARCHIVE = ROOT / "relay.tar.bz2"
FILES = [
    ("relay", True),           # dir
    ("common", True),          # dir
    ("requirements.txt", False),
]
CONFIG = [("config/relay.example.yaml", "config/relay.yaml")]
CERTS = ["certs/generate_keys.py", "certs/README.md"]

# 打包时生成的说明：B 服务器上 certs/ 里必须有的文件（需从本地上传，不打包 .pem）
CERTS_FOR_RELAY_TXT = """# B 服务器 certs/ 目录必须有的文件（从本地上传，不随 tar 打包）

config/relay.yaml 中配置了以下路径时，请把对应 .pem 文件放到 B 的 certs/ 下：

1. rsa_private_key 指向的文件
   例: certs/relay_private.pem  → 上传本地的 relay_private.pem

2. allowed_agents 列表中的每一个文件
   例: certs/agent_public.pem   → 上传本地的 agent_public.pem（或你为每个 agent 配置的公钥）

3. allowed_clients 列表中的每一个文件
   例: certs/client_public.pem → 上传本地的 client_public.pem（或你为每个 client 配置的公钥）

若多台 agent/client 用不同密钥，每台对应一份公钥，都要上传并在 config 里列出。
"""
DEPLOY = [
    "deploy/linux/start_relay.sh",
    "deploy/systemd/triproxy-relay.service",
]

README_RELAY = """# TriProxy Relay (B) – Linux deploy

## Unpack and install

  tar -xjf relay.tar.bz2
  cd relay
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt

## Certificates (must upload to B, not in this tarball)

Relay does **not** bundle any .pem files (security). You must put these under
certs/ on the B server; paths must match config/relay.yaml.

**B always needs:**

1. **certs/relay_private.pem** — Relay 自己的私钥（与 A/C 使用的 relay_public.pem 成对）  
   → 从你本地生成/保管的 certs/ 里上传这一份到 B。

2. **allowed_agents 里列出的每个公钥文件** — 例如 config 里写的是
   `allowed_agents: [ "certs/agent_public.pem" ]`，则 B 上要有 certs/agent_public.pem；
   若有多个 agent 且用不同密钥，就放多份（如 agent_public.pem, agent2_public.pem），
   config 里对应写多行。

3. **allowed_clients 里列出的每个公钥文件** — 同上，每个允许的 client 的公钥
   都要放到 B 的 certs/，且文件名/路径与 config 里 allowed_clients 一致。

若 agent / client 用的 cert 不一样（多台 A 或多台 C、每台不同密钥），则 B 上
必须有一份「每个允许连接的 A 的公钥」和「每个允许连接的 C 的公钥」，否则握手会失败。

可选：在 B 上用 certs/generate_keys.py 重新生成一套密钥，则需把生成的
relay_public.pem 分发给所有 A 和 C，并把你打算允许的 agent/client 公钥放到 B 的
certs/ 并写进 config。

## Run

  .venv/bin/python -m relay.main config/relay.yaml

Or with watchdog and systemd: see deploy/systemd/triproxy-relay.service
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
    print("== TriProxy Relay pack (from", ROOT, ")")
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

        info = tarfile.TarInfo(name=prefix + "certs/CERTS_FOR_RELAY.txt")
        info.size = len(CERTS_FOR_RELAY_TXT.encode("utf-8"))
        info.mtime = 0
        tf.addfile(info, io.BytesIO(CERTS_FOR_RELAY_TXT.encode("utf-8")))

        for p in DEPLOY:
            src = ROOT / p
            _require_exists(src, "deploy file")
            tf.add(src, arcname=prefix + p)

        data = README_RELAY.encode("utf-8")
        info = tarfile.TarInfo(name=prefix + "README.relay")
        info.size = len(data)
        info.mtime = 0
        tf.addfile(info, io.BytesIO(data))

    print("== Done:", ARCHIVE)


if __name__ == "__main__":
    main()
