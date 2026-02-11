#!/usr/bin/env bash
set -euo pipefail

# Nixpacks entrypoint for running Agent web daemon.
# Supports writable config path (e.g. persistent volume) via env vars.
APP_ROOT="${TRIPROXY_APP_ROOT:-$(pwd)}"
CONFIG_PATH="${TRIPROXY_AGENT_CONFIG_PATH:-}"
if [ -z "${CONFIG_PATH}" ]; then
  CONFIG_DIR="${TRIPROXY_CONFIG_DIR:-${APP_ROOT}/config}"
  CONFIG_FILE="${TRIPROXY_AGENT_CONFIG_FILE:-agent.yaml}"
  CONFIG_PATH="${CONFIG_DIR}/${CONFIG_FILE}"
fi

DEFAULT_CONFIG_PATH="${APP_ROOT}/config/agent.yaml"
TEMPLATE_PATH="${TRIPROXY_AGENT_TEMPLATE_PATH:-${APP_ROOT}/config/agent.example.yaml}"

mkdir -p "$(dirname "${CONFIG_PATH}")"
if [ ! -f "${CONFIG_PATH}" ]; then
  if [ -f "${DEFAULT_CONFIG_PATH}" ]; then
    cp "${DEFAULT_CONFIG_PATH}" "${CONFIG_PATH}"
  elif [ -f "${TEMPLATE_PATH}" ]; then
    cp "${TEMPLATE_PATH}" "${CONFIG_PATH}"
  else
    echo "No agent config found. Checked: ${DEFAULT_CONFIG_PATH}, ${TEMPLATE_PATH}" >&2
    exit 1
  fi
fi

export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"
exec python -m agent.web_daemon "${CONFIG_PATH}"
