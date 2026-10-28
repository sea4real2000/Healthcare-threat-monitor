#!/bin/sh
# Loads settings from a file before starting the background service. The one command demo keeps its generated
# secrets in a private Docker volume and points HTM_ENV_FILE at them. Without HTM_ENV_FILE,
# the service reads its settings from ordinary environment variables.
set -eu
if [ -n "${HTM_ENV_FILE:-}" ]; then
  if [ ! -r "$HTM_ENV_FILE" ]; then
    echo "cannot read $HTM_ENV_FILE" >&2
    exit 1
  fi
  set -a
  # shellcheck disable=SC1090
  . "$HTM_ENV_FILE"
  set +a
fi
# Set HTM_RESTART_ON_CHANGE to the settings file to start again whenever it changes, as after a restore.
if [ -n "${HTM_RESTART_ON_CHANGE:-}" ]; then
  exec /usr/local/bin/restart-on-change "$HTM_RESTART_ON_CHANGE" -- "$@"
fi
exec "$@"
