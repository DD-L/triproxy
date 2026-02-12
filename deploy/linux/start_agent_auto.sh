#!/usr/bin/env bash
set -euo pipefail

# Backward-compatible entrypoint name used by some Auto/Nixpacks builds.
exec bash deploy/linux/start_agent_nixpacks.sh
