#!/usr/bin/env bash
set -euo pipefail

# Nixpacks entrypoint for running Agent web daemon.
# Supports writable config path (e.g. persistent volume) via env vars.
# Some platforms can inject a broken literal "$PATH" value, so force a safe baseline.
if [[ "${PATH:-}" == *'$PATH'* ]] || [[ -z "${PATH:-}" ]]; then
  export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
fi

APP_ROOT="${TRIPROXY_APP_ROOT:-$(pwd)}"
CONFIG_PATH="${TRIPROXY_AGENT_CONFIG_PATH:-}"
if [ -z "${CONFIG_PATH}" ]; then
  CONFIG_DIR="${TRIPROXY_CONFIG_DIR:-${APP_ROOT}/config}"
  CONFIG_FILE="${TRIPROXY_AGENT_CONFIG_FILE:-agent.yaml}"
  CONFIG_PATH="${CONFIG_DIR}/${CONFIG_FILE}"
fi

DEFAULT_CONFIG_PATH="${APP_ROOT}/config/agent.yaml"
TEMPLATE_PATH="${TRIPROXY_AGENT_TEMPLATE_PATH:-${APP_ROOT}/config/agent.example.yaml}"

CONFIG_DIR_PATH="${CONFIG_PATH%/*}"
if [ "${CONFIG_DIR_PATH}" = "${CONFIG_PATH}" ] || [ -z "${CONFIG_DIR_PATH}" ]; then
  CONFIG_DIR_PATH="."
fi
/bin/mkdir -p "${CONFIG_DIR_PATH}"
if [ ! -f "${CONFIG_PATH}" ]; then
  if [ -f "${DEFAULT_CONFIG_PATH}" ]; then
    /bin/cp "${DEFAULT_CONFIG_PATH}" "${CONFIG_PATH}"
  elif [ -f "${TEMPLATE_PATH}" ]; then
    /bin/cp "${TEMPLATE_PATH}" "${CONFIG_PATH}"
  else
    echo "No agent config found. Checked: ${DEFAULT_CONFIG_PATH}, ${TEMPLATE_PATH}" >&2
    exit 1
  fi
fi

export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"
# Most managed platforms route traffic to the process PORT.
# Prefer platform PORT for daemon web console unless explicitly overridden.
if [ -n "${PORT:-}" ] && [ -z "${TRIPROXY_WEB_CONSOLE_PORT:-}" ]; then
  export TRIPROXY_WEB_CONSOLE_PORT="${PORT}"
fi
if [ -n "${TRIPROXY_WEB_CONSOLE_PORT:-}" ] && [ -z "${TRIPROXY_WEB_CONSOLE_BIND:-}" ]; then
  # Containerized deploys need non-loopback bind for host port mapping.
  export TRIPROXY_WEB_CONSOLE_BIND="0.0.0.0"
fi
echo "TriProxy agent web_daemon boot: config=${CONFIG_PATH} bind=${TRIPROXY_WEB_CONSOLE_BIND:-from-config} port=${TRIPROXY_WEB_CONSOLE_PORT:-from-config}" >&2
if [ -x "/opt/venv/bin/python" ]; then
  exec /opt/venv/bin/python -m agent.web_daemon "${CONFIG_PATH}"
fi
exec python -m agent.web_daemon "${CONFIG_PATH}"
