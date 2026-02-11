#!/usr/bin/env bash
set -euo pipefail
source .venv/bin/activate
python -m agent.web_daemon config/agent.yaml

