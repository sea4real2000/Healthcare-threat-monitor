#!/bin/sh
# Loads settings from a file before starting the console. The one command demo keeps its generated
# secrets in a private Docker volume and points HTM_ENV_FILE at them. Without HTM_ENV_FILE,
# the console reads its settings from ordinary environment variables.
set -eu
if [ -n "${HTM_ENV_FILE:-}" ]; then
  if [ ! -r "$HTM_ENV_FILE" ]; then
    echo "cannot read $HTM_ENV_FILE" >&2
    exit 1
  fi
  set -a
  . "$HTM_ENV_FILE"
  set +a
fi
exec "$@"
