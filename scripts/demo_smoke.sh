#!/bin/sh
# Starts the one command demo from nothing and proves it works: the console answers, the
# background service is running, and a ransomware scenario is caught at high confidence.
# Usage, from the repository root:  sh scripts/demo_smoke.sh
# Leaves the demo running. Stop it with: docker compose down --volumes
set -eu
db() { docker compose exec -T db psql -U htm -d htm -Atc "$1"; }
fail() { echo "FAIL: $1"; docker compose ps -a; docker compose logs --tail 40; exit 1; }

docker compose up -d --build
echo "waiting for the console"
i=0; until curl -sf http://localhost:3000/api/health >/dev/null; do i=$((i + 1)); [ $i -gt 120 ] && fail "console never became healthy"; sleep 2; done
echo "waiting for the background service to build its history and train"
i=0; until [ "$(db "select coalesce(value->>'trained', 'false') from engine_state where key = 'heartbeat'")" = "true" ]; do
  i=$((i + 1)); [ $i -gt 150 ] && fail "background service never reported trained"; sleep 2
done
[ "$(db "select value from settings where key = 'demo.enabled'")" = "true" ] || fail "demo login is not switched on"
db "update settings set value = '0.1', updated_at = now() where key = 'scenario.time_scale'" >/dev/null
db "insert into scenario_runs (scenario, requested_by) values ('ransomware', 'smoke test')" >/dev/null
echo "ransomware scenario requested, waiting for a high confidence incident"
i=0
until [ -n "$(db "select i.id from incidents i, scenario_runs r where r.requested_by = 'smoke test' and i.band = 'high'
                  and i.hosts && array(select jsonb_array_elements_text(r.target->'hosts')) limit 1")" ]; do
  i=$((i + 1)); [ $i -gt 90 ] && fail "the attack was not raised to high confidence"; sleep 2
done
[ "$(db "select ok from audit_verify()")" = "t" ] || fail "audit chain broken"
echo "PASS: one command demo started, the attack was caught at high confidence and the audit chain is intact"
