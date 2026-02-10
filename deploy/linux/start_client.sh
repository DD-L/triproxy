#!/usr/bin/env bash
set -euo pipefail
source .venv/bin/activate
python -m client.main config/client.yaml

