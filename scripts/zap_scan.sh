#!/bin/sh
# Scans a running hospital installation with ZAP, first as a visitor and then signed in as an administrator,
# and fails if ZAP finds anything at or above the risk set by ZAP_FAIL_AT (default medium) that is not accepted,
# with a reason, in security/zap_accepted.tsv. Run after scripts/hospital_smoke.sh, from the repository root.
# TEST ONLY: the signed in scan adds an administrator and a session straight into the database. Never run
# this against an installation in use.
# ZAP is the zaproxy Docker image unless ZAP_CMD names a local zap.sh.
set -eu
export COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.hospital.yml}"
host="${HTM_HOSTNAME:-localhost}"
target="https://$host"
out="${ZAP_OUT:-$(pwd)/zap}"
image="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:2.16.1}"
mkdir -p "$out/visitor" "$out/signed_in"
chmod 777 "$out" "$out/visitor" "$out/signed_in"
db() { docker compose exec -T db psql -U htm -d htm -Atc "$1"; }
fail() { echo "FAIL: $1"; exit 1; }
pass() { echo "PASS: $1"; }
# The scan's administrator is removed at the end, with its sessions.
trap 'db "delete from users where email = '"'"'zap@scan.invalid'"'"'" >/dev/null 2>&1 || true' EXIT

scan() { # $1 report folder, $2 page to start from, $3 cookie
  # ZAP fills environment variables into most of a plan but not into the replacer's rules, so the cookie is
  # written into this run's copy of the plan.
  sed "s|\${COOKIE}|$3|" security/zap_plan.yaml > "$out/$1/plan.yaml"
  grep -q "$3" "$out/$1/plan.yaml" || fail "the cookie did not reach the scan's plan"
  if [ -n "${ZAP_CMD:-}" ]; then
    TARGET="$target" START="$2" REPORT_DIR="$out/$1" \
      "$ZAP_CMD" -cmd -silent -dir "$out/$1/home" -autorun "$out/$1/plan.yaml"
  else
    docker run --rm --network host -v "$out/$1:/zap/wrk" -e TARGET="$target" -e START="$2" -e REPORT_DIR=/zap/wrk \
      "$image" zap.sh -cmd -silent -autorun /zap/wrk/plan.yaml
  fi
}

echo "== Scanning as a visitor"
scan visitor "$target/" "htm_session=nothing"

# The accepted CSRF alert rests on Next.js refusing a server action posted from another site. Prove it here.
action="$(curl -sk "$target/welcome" | grep -o 'name="\$ACTION_ID_[^"]*"' | head -1 | cut -d'"' -f2)"
[ -n "$action" ] || fail "the setup form was not found, so the cross site check could not run"
code="$(curl -sk -o /dev/null -w '%{http_code}' -H 'Origin: https://another.example' -F "$action=" -F code=x -F name=x -F email=a@b.c "$target/welcome")"
[ "$code" = "500" ] || fail "a form posted from another site was not refused (HTTP $code)"
same="$(curl -sk -o /dev/null -w '%{http_code}' -H "Origin: $target" -F "$action=" -F code=x -F name=x -F email=a@b.c "$target/welcome")"
[ "$same" = "303" ] || fail "the same form posted from the installation itself did not work (HTTP $same), so the check above proves nothing"
pass "a form posted from another site is refused, and the same form from the installation works"

echo "== Scanning signed in as an administrator"
token="$(openssl rand -hex 32)"
hash="$(printf %s "$token" | sha256sum | cut -d' ' -f1)"
db "insert into users (email, display_name, role, status, created_by) values ('zap@scan.invalid', 'ZAP scan', 'admin', 'active', 'zap_scan.sh') on conflict (email) do nothing" >/dev/null
db "insert into sessions (token_hash, user_id, mfa_passed, expires_at) select '$hash', id, true, now() + interval '3 hours' from users where email = 'zap@scan.invalid'" >/dev/null
curl -sk -o /dev/null -w '%{http_code}' -b "htm_session=$token" "$target/console/incidents" | grep -q 200 || fail "the scan's session does not open the console"
scan signed_in "$target/console/incidents" "htm_session=$token"
grep -q "$target/console/" "$out/signed_in/zap_report.json" || fail "the signed in scan never reached a console page"
pages="$(python3 -c "import json,sys; r=json.load(open(sys.argv[1])); print(len({i['uri'] for s in r['site'] for a in s['alerts'] for i in a['instances'] if '/console/' in i['uri']}))" "$out/signed_in/zap_report.json")"
[ "$pages" -ge 10 ] || fail "the signed in scan reached only $pages console addresses, so it was not signed in"
pass "the signed in scan reached $pages console addresses"
[ -n "$(db "select 1 from sessions where token_hash = '$hash'")" ] && pass "the session lasted the whole scan" || echo "note: the scan signed itself out part way"

# The accepted card number alert (rule 10062) rests on every match being part of a server action number. Check
# each page ZAP named, signed in as the scan was.
for report in "$out/visitor/zap_report.json" "$out/signed_in/zap_report.json"; do
  python3 - "$report" "$token" <<'PY' || fail "a card number alert was not a server action number"
import json, re, ssl, sys, urllib.request
report, token = sys.argv[1], sys.argv[2]
context = ssl.create_default_context(); context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.ProxyHandler({}))
for site in json.load(open(report)).get('site', []):
    for alert in site.get('alerts', []):
        if str(alert.get('pluginid')) != '10062':
            continue
        for instance in alert['instances']:
            if instance.get('method') != 'GET':
                continue
            page = opener.open(urllib.request.Request(instance['uri'], headers={'Cookie': f'htm_session={token}'})).read().decode('utf8', 'replace')
            number = instance['evidence']
            found = [m.start() for m in re.finditer(re.escape(number), page)]
            inside = [i for i in found if re.search(r'(\$ACTION_ID_|"id":"|\\"id\\":\\")$', page[max(0, i - 20):i])
                      and re.match(r'[0-9a-f]{40,}', page[i:])]
            if found != inside:
                print(f'FAIL  {number} on {instance["uri"]} is not only inside server action numbers')
                sys.exit(1)
            print(f'checked  {number} on {instance["uri"]}: {len(found)} matches, all inside server action numbers')
PY
done

echo "== Checking the reports"
ok=0
python3 scripts/zap_check.py "$out/visitor/zap_report.json" || ok=1
python3 scripts/zap_check.py "$out/signed_in/zap_report.json" || ok=1
[ $ok = 0 ] || fail "ZAP found something that is not accepted. The reports are in $out"
pass "ZAP found nothing at or above ${ZAP_FAIL_AT:-medium} that is not accepted"
