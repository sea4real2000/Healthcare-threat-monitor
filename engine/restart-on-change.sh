#!/bin/sh
# Runs a command and stops it when any of the named files changes, so Docker starts the container again and
# the command reads them afresh. After a backup is restored, this is how the console, the background service
# and the HTTPS service pick up the restored keys and certificate authority, with no access to Docker itself.
# Usage: restart-on-change FILE [FILE...] -- COMMAND [ARGUMENTS...]
# The same file is engine/restart-on-change.sh, for the background service's image. CI checks they match.
set -u
files=""
while [ $# -gt 0 ] && [ "$1" != "--" ]; do files="$files $1"; shift; done
[ $# -gt 0 ] && shift
sums() { for f in $files; do cksum "$f" 2>/dev/null || echo "missing $f"; done; }
start=$(sums)
"$@" &
child=$!
# Docker's stop signal is passed on, so stopping the container still stops the command cleanly.
trap 'kill -TERM "$child" 2>/dev/null; wait "$child"; exit 143' TERM INT
while kill -0 "$child" 2>/dev/null; do
  sleep "${HTM_WATCH_SECONDS:-5}" &
  wait $! || true
  now=$(sums)
  [ "$now" = "$start" ] && continue
  # A file appearing for the first time, such as a certificate authority made on the first start, is only noted.
  changed=no
  for f in $files; do
    before=$(printf '%s\n' "$start" | grep -F " $f" | tail -n 1)
    after=$(printf '%s\n' "$now" | grep -F " $f" | tail -n 1)
    if [ "$before" != "$after" ] && [ "${before%% *}" != "missing" ]; then changed=yes; fi
  done
  start=$now
  if [ "$changed" = yes ]; then
    echo "restart-on-change: $files changed, starting again" >&2
    kill -TERM "$child" 2>/dev/null
    wait "$child"
    exit 0
  fi
done
wait "$child"
