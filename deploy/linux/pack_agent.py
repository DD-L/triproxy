#!/usr/bin/env python3
"""
Pack TriProxy agent (A) for Linux deployment → agent.tar.bz2.
Run from project root: python deploy/linux/pack_agent.py
"""
from __future__ import annotations

import io
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT_NAME = "agent"
ARCHIVE = ROOT / "agent.tar.bz2"
FILES = [
    ("agent", True),
    ("common", True),
    ("requirements.txt", False),
]
CERTS = ["certs/generate_keys.py", "certs/README.md"]

# A 本机 certs/ 必须有的文件（需从本地上传，不打包 .pem）
CERTS_FOR_AGENT_TXT = """# A 本机 certs/ 目录必须有的文件（从本地上传，不随 tar 打包）

config/agent.yaml 中配置了以下路径时，请把对应 .pem 放到 A 的 certs/ 下：

1. rsa_private_key 指向的文件
   例: certs/agent_private.pem  → 本机/agent 的私钥（与 relay 上 allowed_agents 里的 agent 公钥成对）

2. rsa_public_key 指向的文件
   例: certs/relay_public.pem   → B(relay) 的公钥，用于连接并验证 B

路径须与 config/agent.yaml 中一致。
"""
DEPLOY = [
    "deploy/linux/start_agent.sh",
    "deploy/systemd/triproxy-agent.service",
]

README_AGENT = """# TriProxy Agent (A) – Linux deploy

## Unpack and install

  tar -xjf agent.tar.bz2
  cd agent
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt

## Certificates (must put on A, not in this tarball)

Agent does **not** bundle any .pem files. You must put these under certs/ on the A machine:

1. **certs/agent_private.pem** — 本 agent 的私钥（与 B 上 allowed_agents 里你的 agent 公钥成对）
2. **certs/relay_public.pem** — B(relay) 的公钥，用于连接并验证 B

Paths must match config/agent.yaml (rsa_private_key, rsa_public_key).

See certs/CERTS_FOR_AGENT.txt for a short checklist.

## Run

  .venv/bin/python -m agent.main config/agent.yaml

Or with watchdog and systemd: see deploy/systemd/triproxy-agent.service
(adjust paths in the .service file).
"""


def _skip(f: Path) -> bool:
    return "__pycache__" in f.parts or f.suffix == ".pyc"


def main() -> None:
    print("== TriProxy Agent pack (from", ROOT, ")")
    prefix = OUTPUT_NAME + "/"

    print("  creating", ARCHIVE.name)
    with tarfile.open(ARCHIVE, "w:bz2") as tf:
        for item, is_dir in FILES:
            src = ROOT / item
            if is_dir:
                for f in src.rglob("*"):
                    if f.is_file() and not _skip(f):
                        rel = f.relative_to(src)
                        tf.add(f, arcname=prefix + item + "/" + str(rel))
            else:
                tf.add(src, arcname=prefix + item)

        cfg = ROOT / "config" / "agent.example.yaml"
        if cfg.exists():
            tf.add(cfg, arcname=prefix + "config/agent.yaml")

        for p in CERTS:
            src = ROOT / p
            if src.exists():
                tf.add(src, arcname=prefix + p)

        info = tarfile.TarInfo(name=prefix + "certs/CERTS_FOR_AGENT.txt")
        info.size = len(CERTS_FOR_AGENT_TXT.encode("utf-8"))
        info.mtime = 0
        tf.addfile(info, io.BytesIO(CERTS_FOR_AGENT_TXT.encode("utf-8")))

        for p in DEPLOY:
            src = ROOT / p
            if src.exists():
                tf.add(src, arcname=prefix + p)

        data = README_AGENT.encode("utf-8")
        info = tarfile.TarInfo(name=prefix + "README.agent")
        info.size = len(data)
        info.mtime = 0
        tf.addfile(info, io.BytesIO(data))

    print("== Done:", ARCHIVE)


if __name__ == "__main__":
    main()
