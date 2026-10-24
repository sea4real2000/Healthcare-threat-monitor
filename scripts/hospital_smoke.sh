#!/bin/sh
# Starts a hospital installation from nothing on this computer and proves it is safe to use:
# served over HTTPS with its own certificate, every page behind sign in, no simulator, no demo
# login, no test attacks, the database and console not reachable from outside, and a one time
# administrator link printed. Follows docs/hospital_install.md.
# Usage, from the repository root:  sh scripts/hospital_smoke.sh
# Leaves the installation running. Stop it with: docker compose -f docker-compose.hospital.yml down --volumes
set -eu
export COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.hospital.yml}"
export HTM_HOSTNAME="${HTM_HOSTNAME:-localhost}"
base="https://$HTM_HOSTNAME"
work="$(mktemp -d)"
db() { docker compose exec -T db psql -U htm -d htm -Atc "$1"; }
fail() { echo "FAIL: $1"; docker compose ps -a; docker compose logs --tail 40; exit 1; }
pass() { echo "PASS: $1"; }

docker compose up -d --build
echo "waiting for the certificate"
i=0; until docker compose cp https:/data/caddy/pki/authorities/local/root.crt "$work/root.crt" >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -gt 90 ] && fail "the HTTPS service never made its certificate"; sleep 2
done
echo "waiting for the console over HTTPS"
i=0; until curl -sf --cacert "$work/root.crt" "$base/api/health" >/dev/null; do
  i=$((i + 1)); [ $i -gt 120 ] && fail "the console never answered over HTTPS with the installation's own certificate"; sleep 2
done
pass "console answers over HTTPS, trusted through the copied root certificate"

redirect="$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "http://$HTM_HOSTNAME/console")"
case "$redirect" in 30[178]\ https://*) pass "plain http is sent to https ($redirect)" ;; *) fail "plain http was not sent to https: $redirect" ;; esac

# A browser that uses the IP address sends no server name. It must still get the installation's certificate.
echo | openssl s_client -connect 127.0.0.1:443 -noservername 2>/dev/null | grep -q "BEGIN CERTIFICATE" \
  || fail "a connection with no server name, as from a browser using the IP address, got no certificate"
pass "a browser using the IP address gets the installation's certificate"

# With no administrator yet, the first visit sets one up. Every page leads there, and nothing else is reachable.
for page in / /console /console/sources /console/incidents /signin; do
  location="$(curl -s --cacert "$work/root.crt" -o /dev/null -L --max-redirs 3 -w '%{url_effective}' "$base$page")"
  case "$location" in *"/welcome") ;; *) fail "$page did not lead a first visitor to setting up the administrator: $location" ;; esac
done
docker compose exec -T db psql -U htm -d htm -Atc "select 1 from engine_state where key = 'first_run'" | grep -q 1 || fail "no setup code was set for the first visit"
pass "every page leads a first visitor to setting up the administrator, which needs the code on the installation's screen"

for port in 3000 5432; do
  # curl exits with 7 when nothing accepts the connection. Any other result means something answered.
  code=0; curl -s --max-time 3 "http://$HTM_HOSTNAME:$port" >/dev/null 2>&1 || code=$?
  [ "$code" = "7" ] || fail "port $port is reachable from outside (curl exit $code)"
done
pass "the console and database ports are not published"

[ "$(db "select value from settings where key = 'engine.simulate'")" = "false" ] || fail "the simulator is switched on"
[ "$(db "select value from settings where key = 'demo.enabled'")" = "false" ] || fail "the public demo login is switched on"
[ "$(db "select value from settings where key = 'response.simulated_connector'")" = "false" ] || fail "the simulated endpoint product is switched on"
pass "no simulator, no demo login and no simulated endpoint product"

docker compose logs setup | grep -q "$base/setup?token=" || fail "no one time administrator link was printed"
pass "a one time administrator link was printed"

echo "waiting for the background service"
i=0; until [ -n "$(db "select 1 from engine_state where key = 'heartbeat' and (value->>'at')::timestamptz > now() - interval '2 minutes'")" ]; do
  i=$((i + 1)); [ $i -gt 90 ] && fail "the background service never reported in"; sleep 2
done
db "insert into scenario_runs (scenario, requested_by) values ('ransomware', 'hospital smoke test')" >/dev/null
i=0; until [ "$(db "select status from scenario_runs where requested_by = 'hospital smoke test' order by id desc limit 1")" = "failed" ]; do
  i=$((i + 1)); [ $i -gt 30 ] && fail "the background service did not refuse a test attack on a hospital installation"; sleep 2
done
[ "$(db "select count(*) from staff")" = "0" ] || fail "simulated staff were registered"
pass "the background service runs, refuses test attacks and registers nothing simulated"

echo "waiting for the log receiver"
i=0; until [ -n "$(db "select 1 from engine_state where key = 'receiver_heartbeat' and updated_at > now() - interval '1 minute'")" ]; do
  i=$((i + 1)); [ $i -gt 60 ] && fail "the log receiver never reported in"; sleep 2
done
python3 -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'<4>Oct 22 10:15:06 edge kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.45 DST=10.20.0.1 LEN=40 PROTO=TCP SPT=40000 DPT=22', ('$HTM_HOSTNAME', 514))"
i=0; until [ "$(db "select count(*) from log_senders where format = 'UFW' and state = 'pending'")" = "1" ]; do
  i=$((i + 1)); [ $i -gt 30 ] && fail "a syslog message on port 514 did not reach the receiver"; sleep 2
done
[ "$(db "select count(*) from events where source = 'firewall'")" = "0" ] || fail "logs from a device nobody accepted were kept"
pass "the log receiver listens on port 514 and keeps nothing from a device nobody accepted"

# The console reads the installation's root certificate for Windows collector installers. It must be the same
# root the HTTPS server's chain ends at, which is the one copied out above.
docker compose exec -T console node -e "fetch(process.env.HTM_TRUST_URL).then((r) => r.text()).then((t) => process.stdout.write(t))" > "$work/served_root.crt" || fail "the console could not read the root certificate"
[ "$(openssl x509 -in "$work/served_root.crt" -noout -fingerprint -sha256)" = "$(openssl x509 -in "$work/root.crt" -noout -fingerprint -sha256)" ] \
  || fail "the root certificate the console reads is not the installation's root"
pass "the console reads the installation's own root certificate for Windows installers"
[ "$(curl -s --cacert "$work/root.crt" -o /dev/null -w '%{http_code}' "$base/api/trust/root")" = "401" ] || fail "the certificate authority download is offered without sign in"
pass "the certificate authority download needs sign in"

[ "$(db "select ok from audit_verify()")" = "t" ] || fail "audit chain broken"
rm -rf "$work"
echo "PASS: hospital installation started from nothing, served over HTTPS, locked to signed in staff"
