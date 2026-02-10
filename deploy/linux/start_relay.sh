#!/usr/bin/env bash
set -euo pipefail
source .venv/bin/activate
python -m relay.main config/relay.yaml

