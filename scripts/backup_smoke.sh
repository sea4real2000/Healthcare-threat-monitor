#!/bin/sh
# Backups and restores with clicks, end to end, on a hospital installation started by scripts/hospital_smoke.sh:
# makes a backup through the console, removes the whole installation, starts a new one with new keys and a new
# certificate authority, and restores the backup onto it from the first visit page with the setup code. Then checks
# that everything came back: the data, the accounts, the keys and the certificate authority, so Windows computers
# and browsers that trusted the old installation trust the new one.
# TEST ONLY: it signs in by adding an administrator and a session straight into the database, and removes the
# installation part way through. Never run it against an installation in use.
# Usage, from the repository root:  sh scripts/backup_smoke.sh
set -eu
export COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.hospital.yml}"
host="${HTM_HOSTNAME:-localhost}"
base="https://$host"
work="$(mktemp -d)"
passphrase="ward seven lantern quiet river"
db() { docker compose exec -T db psql -U htm -d htm -Atc "$1"; }
fail() { echo "FAIL: $1"; docker compose ps -a; docker compose logs --tail 30 backup console; exit 1; }
pass() { echo "PASS: $1"; }
api() { curl -sk -H "Origin: $base" "$@"; }
json() { python3 -c "import json,sys; print(json.load(sys.stdin).get('$1', ''))"; }
secret_keys() { docker compose exec -T backup cat /secrets/secrets.json | python3 -c "import json,sys; s=json.load(sys.stdin); s.pop('db_password'); print(json.dumps(s, sort_keys=True))"; }
db_password() { docker compose exec -T backup cat /secrets/db_password; }
ca_sum() { docker compose exec -T backup sha256sum /caddy/caddy/pki/authorities/local/root.crt | cut -d' ' -f1; }
healthy() {
  i=0; until curl -sfk "$base/api/health" >/dev/null; do i=$((i + 1)); [ $i -gt 150 ] && fail "$1"; sleep 2; done
}
follow() { # $1 job id, prints the final state
  i=0
  while :; do
    s="$(curl -sk "$base/api/backups/$1/status" || true)"
    state="$(echo "$s" | json state 2>/dev/null || true)"
    case "$state" in done|failed) echo "$s"; return ;; esac
    i=$((i + 1)); [ $i -gt 300 ] && { echo "$s"; return; }
    sleep 2
  done
}
until [ -n "$(docker compose exec -T backup cat /backups/service.json 2>/dev/null)" ]; do sleep 2; done
pass "the backup service is running"

echo "== Before: an installation in use"
token="$(openssl rand -hex 32)"
hash="$(printf %s "$token" | sha256sum | cut -d' ' -f1)"
db "insert into users (email, display_name, role, status, created_by) values ('backup@test.invalid', 'Backup test', 'admin', 'active', 'backup_smoke.sh') on conflict (email) do nothing" >/dev/null
db "insert into sessions (token_hash, user_id, mfa_passed, expires_at) select '$hash', id, true, now() + interval '1 hour' from users where email = 'backup@test.invalid'" >/dev/null
db "update settings set value = '5'::jsonb where key = 'learning.days'" >/dev/null
keys_before="$(secret_keys)"; ca_before="$(ca_sum)"
docker compose cp https:/data/caddy/pki/authorities/local/root.crt "$work/old_root.crt" >/dev/null
audit_before="$(db "select count(*) from audit_log")"

code="$(curl -sk -o /dev/null -w '%{http_code}' -b "htm_session=$token" -H 'Origin: https://another.example' -H 'Content-Type: application/json' -d "{\"passphrase\":\"$passphrase\"}" "$base/api/backups")"
[ "$code" = "403" ] || fail "a backup asked for from another site was not refused (HTTP $code)"
code="$(api -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d "{\"passphrase\":\"$passphrase\"}" "$base/api/backups")"
[ "$code" = "401" ] || fail "a backup asked for without signing in was not refused (HTTP $code)"
code="$(api -o /dev/null -w '%{http_code}' -b "htm_session=$token" -H 'Content-Type: application/json' -d '{"passphrase":"short"}' "$base/api/backups")"
[ "$code" = "400" ] || fail "a backup with a short passphrase was not refused (HTTP $code)"
pass "a backup can only be asked for by a signed in administrator, from the installation's own page, with a long passphrase"

# Made with clicks in a real browser, as an administrator does.
python3 scripts/backup_ui_check.py make "$base" "$token" "$passphrase" "$work/htm.htmbackup" || fail "the backup page did not work in a browser"
id="$(db "select subject_id from audit_log where action = 'backup.created' order by seq desc limit 1")"
head -c 10 "$work/htm.htmbackup" | grep -q HTMBACKUP || fail "the download is not a backup file"
if grep -q "$(echo "$keys_before" | python3 -c "import json,sys; print(json.load(sys.stdin)['auth'])")" "$work/htm.htmbackup"; then fail "a key can be read in the backup file"; fi
code="$(curl -sk -o /dev/null -w '%{http_code}' "$base/api/backups/$id/file")"
[ "$code" = "401" ] || fail "the backup could be downloaded without signing in (HTTP $code)"
[ -n "$(db "select 1 from audit_log where action = 'backup.created'")" ] || fail "the backup is not in the audit log"
pass "the backup was made, downloaded ($(wc -c < "$work/htm.htmbackup") bytes), locked, and written to the audit log"

echo "== A new installation, with new keys and a new certificate authority"
docker compose down --volumes >/dev/null 2>&1
docker compose up -d >/dev/null 2>&1
healthy "the new installation never answered"
until [ -n "$(docker compose exec -T backup cat /backups/service.json 2>/dev/null)" ]; do sleep 2; done
[ "$(secret_keys)" != "$keys_before" ] || fail "the new installation has the old keys before any restore, so the test proves nothing"
[ "$(ca_sum)" != "$ca_before" ] || fail "the new installation has the old certificate authority before any restore, so the test proves nothing"
fresh_password="$(db_password)"
setup_code="$(docker compose exec -T backup cat /secrets/setup_code | tr -d '\r\n')"
location="$(curl -sk -o /dev/null -w '%{redirect_url}' "$base/welcome/restore")"
[ -z "$location" ] || fail "the restore page for a new installation is not offered: $location"
pass "the new installation offers a restore on its first visit page"

upload() { api -H "X-Setup-Code: $1" -H 'Content-Type: application/octet-stream' --data-binary "@$work/htm.htmbackup" "$base/api/backups/upload"; }
code="$(api -o /dev/null -w '%{http_code}' -H 'X-Setup-Code: AAAAA AAAAA' -H 'Content-Type: application/octet-stream' --data-binary "@$work/htm.htmbackup" "$base/api/backups/upload")"
[ "$code" = "403" ] || fail "an upload with a wrong setup code was not refused (HTTP $code)"
pass "an upload with a wrong setup code is refused"

up="$(upload "$setup_code" | json upload)"
[ -n "$up" ] || fail "the backup could not be uploaded"
id="$(api -H "X-Setup-Code: $setup_code" -H 'Content-Type: application/json' -d "{\"upload\":\"$up\",\"passphrase\":\"not the passphrase at all\",\"confirm\":\"RESTORE\"}" "$base/api/backups/restore" | json id)"
result="$(follow "$id")"
[ "$(echo "$result" | json code)" = "wrong_passphrase" ] || fail "a wrong passphrase was not refused: $result"
[ "$(secret_keys)" != "$keys_before" ] && [ "$(db "select count(*) from users where email = 'backup@test.invalid'")" = "0" ] || fail "a refused restore changed something"
pass "a wrong passphrase is refused and changes nothing"

up="$(upload "$setup_code" | json upload)"
code="$(api -o /dev/null -w '%{http_code}' -H "X-Setup-Code: $setup_code" -H 'Content-Type: application/json' -d "{\"upload\":\"$up\",\"passphrase\":\"$passphrase\",\"confirm\":\"yes\"}" "$base/api/backups/restore")"
[ "$code" = "400" ] || fail "a restore without the confirmation word was not refused (HTTP $code)"
# Restored with clicks in a real browser, from the new installation's first visit page.
python3 scripts/backup_ui_check.py restore "$base" "$setup_code" "$passphrase" "$work/htm.htmbackup" || fail "the restore page did not work in a browser"
pass "the backup was restored onto the new installation from its first visit page"

echo "== After: everything came back"
sleep 15
healthy "the installation did not answer after the restore"
[ "$(db "select value from settings where key = 'learning.days'")" = "5" ] || fail "a changed setting did not come back"
[ "$(db "select count(*) from users where email = 'backup@test.invalid' and status = 'active'")" = "1" ] || fail "the accounts did not come back"
[ "$(db "select count(*) from sessions")" = "0" ] || fail "sessions were kept, so nobody had to sign in again"
[ "$(secret_keys)" = "$keys_before" ] || fail "the keys did not come back"
[ "$(db_password)" = "$fresh_password" ] || fail "the new installation's own database password was replaced"
[ "$(ca_sum)" = "$ca_before" ] || fail "the certificate authority did not come back"
location="$(curl -sk -o /dev/null -w '%{redirect_url}' "$base/welcome")"
case "$location" in *"/signin") ;; *) fail "the first visit page is still open after the restore: $location" ;; esac
[ "$(db "select ok from audit_verify()")" = "t" ] || fail "the restored audit log does not verify"
[ "$(db "select count(*) from audit_log")" -gt "$audit_before" ] || fail "the restore is not in the audit log"
[ -n "$(db "select 1 from audit_log where action = 'backup.restored'")" ] || fail "the restore is not in the audit log"
pass "the setting, the account, the keys and the certificate authority came back, sessions were ended and the audit log verifies"

# The console and background service started again with the restored keys: the console signs sessions with them,
# and the background service reports in.
i=0; until curl -sf --cacert "$work/old_root.crt" "$base/api/health" >/dev/null; do
  i=$((i + 1)); [ $i -gt 90 ] && fail "the new installation's certificate is not trusted through the old installation's certificate authority"; sleep 2
done
pass "a computer that trusted the old installation's certificate authority trusts the new installation, with no warning"
i=0; until [ -n "$(db "select 1 from engine_state where key = 'heartbeat' and (value->>'at')::timestamptz > now() - interval '1 minute'")" ]; do
  i=$((i + 1)); [ $i -gt 90 ] && fail "the background service did not report in after the restore"; sleep 2
done
docker compose logs console worker 2>&1 | grep -q "restart-on-change" || fail "the console and background service did not start again with the restored keys"
pass "the console and background service started again with the restored keys"
db "delete from users where email = 'backup@test.invalid'" >/dev/null
rm -rf "$work"
pass "backups and restores with clicks work end to end"
