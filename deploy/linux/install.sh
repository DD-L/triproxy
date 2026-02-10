#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python certs/generate_keys.py --output certs/
echo "TriProxy Linux install complete."

