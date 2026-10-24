-- 0012_round_two.sql
-- Connecting the rest of a hospital without programming: a built in receiver for router and firewall
-- logs, a collector for Windows computers, a FHIR connection to patient record systems, and a learning
-- period so a new installation learns what normal looks like before it judges unusual activity.
-- Safe to run more than once.

-- Collectors made in the console for groups of Windows computers. Each may only send the sources
-- listed in allowed_sources, so a secret copied off one computer cannot be used to send other kinds of records.
alter table collectors add column if not exists kind text not null default 'service';
alter table collectors add column if not exists allowed_sources text[];
alter table collectors add column if not exists created_by text;
alter table collectors drop constraint if exists collectors_kind_check;
alter table collectors add constraint collectors_kind_check check (kind in ('service', 'windows'));

-- Devices that send their logs to the built in receiver. A device's logs are only stored once an
-- administrator accepts it, so a stranger on the network cannot fill the platform with made up logs.
create table if not exists log_senders (
  id bigint generated always as identity primary key,
  address inet not null unique,
  name text not null default '',
  state text not null default 'pending' check (state in ('pending', 'accepted', 'blocked')),
  format text,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz,
  received bigint not null default 0,
  stored bigint not null default 0,
  not_understood bigint not null default 0,
  last_unparsed text,
  decided_by text,
  decided_at timestamptz,
  updated_at timestamptz not null default now()
);

-- FHIR connections live beside the database connections.
alter table record_sources drop constraint if exists record_sources_kind_check;
alter table record_sources add constraint record_sources_kind_check check (kind in ('postgres', 'mysql', 'fhir'));
alter table record_sources alter column host drop not null;
alter table record_sources alter column port drop not null;
alter table record_sources alter column database_name drop not null;
alter table record_sources alter column username drop not null;
alter table record_sources alter column password_sealed drop not null;
alter table record_sources add column if not exists base_url text;
alter table record_sources add column if not exists auth_kind text;
alter table record_sources add column if not exists client_id text;
alter table record_sources add column if not exists token_url text;
alter table record_sources add column if not exists scope text;
alter table record_sources add column if not exists public_jwk jsonb;
-- A hospital's own certificate authority, for a FHIR server inside its network. Public, so not sealed.
alter table record_sources add column if not exists ca_certificate text;
alter table record_sources drop constraint if exists record_sources_auth_kind_check;
alter table record_sources add constraint record_sources_auth_kind_check
  check (auth_kind is null or auth_kind in ('none', 'token', 'client_secret', 'private_key'));

-- One learning period per kind of log. It starts when the first record of that kind arrives.
create table if not exists learning_periods (
  source text primary key references sources (id) on delete cascade,
  started_at timestamptz not null default now(),
  ends_at timestamptz not null,
  finished_at timestamptz,
  finished_by text,
  events bigint not null default 0,
  values_learned bigint not null default 0
);

insert into settings (key, value, description) values
  ('learning.days',                '7',     'Days each kind of log is learned from, after its first record arrives, before unusual activity in it is reported. Clear signs of attack are reported straight away. Zero switches learning off'),
  ('receiver.max_message_bytes',   '8192',  'Longest single log message the receiver keeps. Longer messages are cut to this length'),
  ('receiver.batch_seconds',       '5',     'How often the receiver passes the logs it has collected on for storage'),
  ('receiver.sender_per_minute',   '60000', 'Most log messages kept from one device in a minute. More than this are counted and dropped'),
  ('windows.interval_minutes',     '1',     'How often each Windows collector sends new events. Takes effect when a computer next downloads its settings'),
  ('fhir.page_size',               '100',   'AuditEvent entries asked for in each request to a FHIR server'),
  ('fhir.max_pages',               '20',    'Most pages read from a FHIR server in one go')
on conflict (key) do nothing;

insert into copy (key, value) values
  ('settings.group.learning', 'Learning'),
  ('settings.group.receiver', 'Log receiver'),
  ('settings.group.windows', 'Windows collectors'),
  ('settings.group.fhir', 'FHIR connections'),
  ('audit.group.learning', 'Learning'),
  ('audit.group.receiver', 'Log receiver'),
  ('audit.group.windows', 'Windows collectors'),
  ('learning.title', 'Learning what normal looks like'),
  ('learning.note', 'For the first {days} days after each kind of log starts arriving, the platform learns what is normal in this hospital. Clear signs of attack are reported straight away. Activity that is only unusual is reported once learning ends. Change the length under Settings, Learning.'),
  ('learning.off', 'Learning is switched off under Settings, so unusual activity is reported from the first record.'),
  ('learning.empty', 'Nothing is being learned yet. Learning starts by itself when each kind of log first arrives.'),
  ('learning.col.events', 'Records learned from'),
  ('learning.col.values', 'Normal values learned'),
  ('learning.status.learning', 'Learning, day {day} of {days}'),
  ('learning.status.finishing', 'Finishing'),
  ('learning.status.done', 'Finished'),
  ('learning.finished_on', 'Finished {when}'),
  ('learning.until', 'Until {when}'),
  ('learning.finish', 'Finish now'),
  ('learning.again', 'Learn again'),
  ('learning.banner', 'Learning what normal looks like in this hospital until {until}. Clear signs of attack are reported straight away. Activity that is only unusual is reported once learning ends.'),
  ('learning.banner_link', 'See learning progress'),
  ('notice.sources.learning_finishing', 'Learning will finish within a minute, and the detectors will retrain on what was learned.'),
  ('notice.sources.learning_restarted', 'Learning started again for this kind of log.'),
  ('error.sources.learning_unknown', 'That learning period was not found.'),
  ('error.sources.learning_off', 'Learning is switched off. Set Learning days above zero under Settings first.')
on conflict (key) do nothing;

insert into copy (key, value) values
  ('receiver.title', 'Routers, firewalls and servers'),
  ('receiver.lede', 'Most routers, firewalls and servers can send their logs to another computer. Point them at this installation and the platform reads them: connections that were blocked or allowed, VPN sign ins, and secure shell sign ins. Nothing is installed on the devices.'),
  ('receiver.this_computer', 'this computer''s address'),
  ('receiver.where.title', 'Where devices send their logs'),
  ('receiver.where.address', 'Address'),
  ('receiver.where.port', 'Port'),
  ('receiver.where.protocol', 'Protocol'),
  ('receiver.where.protocol_value', 'Syslog, over UDP or TCP'),
  ('receiver.running', 'Receiver running'),
  ('receiver.not_running', 'Receiver not running'),
  ('receiver.not_running_note', 'The log receiver has not reported in the last minute. It is part of the hospital installation. Check it with: docker compose -f docker-compose.hospital.yml logs receiver'),
  ('receiver.hidden_addresses', 'Logs are arriving from {gateway}, the address Docker uses for its own network. Docker is hiding the devices'' real addresses, so every device looks like one, and accepting that one would accept them all. This happens with Docker Desktop and with rootless Docker, and when something on this same computer sends to localhost. For routers and firewalls, run the installation with the standard Docker Engine on Linux, and send to this computer''s network address.'),
  ('receiver.how.point', 'In the device''s settings, find remote logging, which may be called syslog, remote syslog or log server. Enter {address} and port 514. The guides below show where to find it on common devices.'),
  ('receiver.how.appears', 'Within a minute the device appears in the list below as waiting, with the kind of log the platform recognised.'),
  ('receiver.how.accept', 'Give it a name and accept it. Only logs from accepted devices are kept, because anyone on the network can send syslog. Logs a device sent before it was accepted are not kept.'),
  ('receiver.senders.title', 'Devices sending logs'),
  ('receiver.senders.note', 'Every address that has sent logs to this installation.'),
  ('receiver.senders.empty', 'No device has sent logs yet.'),
  ('receiver.col.device', 'Device'),
  ('receiver.col.received', 'Messages received'),
  ('receiver.col.stored', 'Records kept'),
  ('receiver.col.unread', 'Not read'),
  ('receiver.col.actions', 'Actions'),
  ('receiver.format_unknown', 'Log format not recognised yet'),
  ('receiver.sample', 'Last message not read'),
  ('receiver.state.pending', 'Waiting for you'),
  ('receiver.state.accepted', 'Accepted'),
  ('receiver.state.blocked', 'Blocked'),
  ('receiver.name', 'Name'),
  ('receiver.name_placeholder', 'Name, such as Main firewall'),
  ('receiver.accept', 'Accept'),
  ('receiver.rename', 'Save name'),
  ('receiver.block', 'Block'),
  ('receiver.remove', 'Remove'),
  ('receiver.devices.title', 'Guides for common devices'),
  ('receiver.devices.note', 'Menu names change between versions, so check your device''s manual if a step looks different.'),
  ('receiver.device.fortigate.name', 'Fortinet FortiGate'),
  ('receiver.device.fortigate.how', 'In the FortiGate command line, turn on remote logging to the platform''s address. Traffic is only logged for firewall policies with logging on, so in each policy set Log Allowed Traffic to All Sessions.'),
  ('receiver.device.fortigate.command', E'config log syslogd setting\n    set status enable\n    set server "{address}"\n    set port 514\nend'),
  ('receiver.device.pfsense.name', 'pfSense'),
  ('receiver.device.pfsense.how', 'Open Status, System Logs, Settings. Tick Enable Remote Logging, enter {address}:514 as a remote log server, tick Firewall Events under Remote Syslog Contents, and save.'),
  ('receiver.device.opnsense.name', 'OPNsense'),
  ('receiver.device.opnsense.how', 'Open System, Settings, Logging, then the Remote tab. Add a destination with transport UDP(4), the application filter, the hostname {address} and port 514. Save and apply.'),
  ('receiver.device.mikrotik.name', 'MikroTik RouterOS'),
  ('receiver.device.mikrotik.how', 'In a terminal on the router, add a remote logging action for the platform and send firewall messages to it. Only firewall rules with logging on write messages, so set log=yes on the rules you want watched.'),
  ('receiver.device.mikrotik.command', E'/system logging action add name=htm target=remote remote={address} remote-port=514 bsd-syslog=yes\n/system logging add topics=firewall action=htm'),
  ('receiver.device.cisco_asa.name', 'Cisco ASA'),
  ('receiver.device.cisco_asa.how', 'In configuration mode, send logs at the informational level to the platform''s address, through the interface that reaches it. Here that interface is called inside.'),
  ('receiver.device.cisco_asa.command', E'logging enable\nlogging trap informational\nlogging host inside {address}'),
  ('receiver.device.openwrt.name', 'OpenWrt'),
  ('receiver.device.openwrt.how', 'Open System, System, Logging. Set External system log server to {address}, port 514, protocol UDP, and save. To log blocked connections, open Network, Firewall, edit the WAN zone and tick Enable logging on this zone.'),
  ('receiver.device.ubiquiti.name', 'Ubiquiti EdgeRouter'),
  ('receiver.device.ubiquiti.how', 'In the command line, send all messages at the info level to the platform''s address. To log blocked connections, turn on logging for the default action of each firewall rule set.'),
  ('receiver.device.ubiquiti.command', E'configure\nset system syslog host {address} facility all level info\ncommit\nsave'),
  ('receiver.device.sophos.name', 'Sophos Firewall'),
  ('receiver.device.sophos.how', 'Open System services, Log settings, and add a syslog server with the address {address}, port 514, protocol UDP and the standard syslog format. Then tick Firewall rules for the new server in the log settings table, and save.'),
  ('receiver.device.linux.name', 'Linux servers'),
  ('receiver.device.linux.how', 'Add one line to the server''s rsyslog settings so it also sends its logs to the platform, then restart rsyslog with: sudo systemctl restart rsyslog. Secure shell sign ins, sudo and scheduled jobs are read. Two @ signs send over TCP, one over UDP.'),
  ('receiver.device.linux.command', E'echo ''*.* @@{address}:514'' | sudo tee /etc/rsyslog.d/90-healthcare-threat-monitor.conf'),
  ('notice.sources.sender_accepted', 'Device accepted. Its logs are kept from now on.'),
  ('notice.sources.sender_blocked', 'Device blocked. Its logs are counted but not kept.'),
  ('notice.sources.sender_renamed', 'Name saved.'),
  ('notice.sources.sender_removed', 'Device removed from the list. If it keeps sending, it appears again as waiting.'),
  ('error.sources.sender_unknown', 'That device was not found.'),
  ('sources.receiver.title', 'Routers, firewalls and servers'),
  ('sources.receiver.empty', 'No device sends its logs here yet.'),
  ('sources.receiver.waiting', '{n} waiting for you to accept or block'),
  ('sources.receiver.connect', 'Connect a router or firewall'),
  ('sources.receiver.manage', 'Manage devices')
on conflict (key) do nothing;

-- Router logs name addresses, and many hospitals do not list every address in the inventory. The shipped
-- port scan rule also counts addresses outside the inventory, and names the scanning address when the machine
-- is not listed. Only a rule still exactly as shipped is changed, so a hospital's own edits are kept.
update rules set definition = jsonb_set(jsonb_set(definition, '{where,1,value}', '["device", "server", "clinical", "admin", "internal"]'::jsonb),
    '{entity_fallback}', '"src_ip"'::jsonb), updated_at = now()
where id = 'internal_port_scan'
  and definition = '{"count": 25, "where": [{"op": "eq", "field": "category", "value": "network_flow"}, {"op": "in", "field": "attributes.dst_zone", "value": ["device", "server", "clinical", "admin"]}], "distinct": ["dst_ip", "dst_port"], "entity_field": "host", "window_seconds": 60}'::jsonb;

-- Windows records a command as it was typed, often with the full path and .exe, as in
-- "C:\Windows\system32\vssadmin.exe" delete shadows /all. The shipped rule matched only the short form.
-- Only a rule still exactly as shipped is changed.
update rules set definition = jsonb_set(definition, '{where,1,value}',
    '["delete shadows", "shadowcopy delete", "delete catalog", "resize shadowstorage", "recoveryenabled no"]'::jsonb), updated_at = now()
where id = 'ransom_shadow_copy_delete'
  and definition = '{"where": [{"op": "eq", "field": "category", "value": "process"}, {"op": "contains_any", "field": "attributes.command_line", "value": ["vssadmin delete shadows", "wmic shadowcopy delete", "wbadmin delete catalog", "recoveryenabled no"]}]}'::jsonb;

-- Clearing the Windows security log hides what an intruder did. Event 1102 is written when it happens.
insert into rules (id, name, description, category, kind, definition, severity, confidence, technique_id, technique_name) values
  ('windows_security_log_cleared', 'Windows security log cleared', 'Someone cleared the security log on a Windows computer. Intruders do this to hide what they did before ransomware runs.', 'ransomware', 'match',
   '{"where": [{"field": "category", "op": "eq", "value": "defense_evasion"}, {"field": "action", "op": "eq", "value": "audit_log_cleared"}], "entity_field": "host"}'::jsonb,
   3, 0.7, 'T1070.001', 'Indicator Removal: Clear Windows Event Logs')
on conflict (id) do nothing;

insert into copy (key, value) values
  ('windows.title', 'Windows computers'),
  ('windows.lede', 'A small collector on each Windows computer sends its security events to the platform: sign ins, failed sign ins, new accounts and administrators, programs started with their commands, scheduled tasks, stopped services and a cleared security log. It is a PowerShell script anyone can read. Nothing else is installed.'),
  ('windows.how.title', 'How to set up computers'),
  ('windows.how.group', 'Make a group for a set of computers, such as one ward or department. Each group has its own secret, so one group can be switched off without touching the others.'),
  ('windows.how.download', 'Download the group''s installer. It holds the group''s secret, so keep it like a password and delete it once the computers are set up.'),
  ('windows.how.run', 'On each computer, open PowerShell with Run as administrator, go to the folder with the installer and run:'),
  ('windows.how.command', 'powershell -ExecutionPolicy Bypass -File .\install_healthcare_threat_monitor_<group>.ps1'),
  ('windows.how.many', 'For many computers, your IT team can run the same file through Group Policy, Intune or any tool that runs a script as administrator.'),
  ('windows.how.appear', 'The installer runs the collector once and shows the result. The computer then appears below within a few minutes. Name computers in your inventory exactly as Windows names them, so alerts can say which ward a computer is in.'),
  ('windows.trust.pinned', 'Computers set up from these installers trust only this installation''s own certificate authority, fingerprint {fingerprint}, for this connection. Nothing is added to the computer''s list of trusted authorities.'),
  ('windows.trust.system', 'This installation''s own certificate authority could not be read, so computers will check the platform''s certificate the way they check any website. That works when the platform has a certificate from a public authority or one your computers already trust.'),
  ('windows.groups.title', 'Groups of computers'),
  ('windows.groups.note', 'Switching a group off refuses its computers'' events at once. Switch it on again to accept them.'),
  ('windows.groups.empty', 'No group yet. Make one to download an installer.'),
  ('windows.group.name', 'Group name'),
  ('windows.group.name_placeholder', 'Name, such as Emergency department'),
  ('windows.group.create', 'Make a group'),
  ('windows.col.group', 'Group'),
  ('windows.col.computers', 'Computers reporting'),
  ('windows.col.computer', 'Computer'),
  ('windows.status.reporting', 'Reporting'),
  ('windows.status.quiet', 'Quiet for over 2 hours'),
  ('windows.status.waiting', 'No computer yet'),
  ('windows.status.off', 'Switched off'),
  ('windows.download', 'Download installer'),
  ('windows.switch_off', 'Switch off'),
  ('windows.switch_on', 'Switch on'),
  ('windows.computers.title', 'Computers sending events'),
  ('windows.computers.note', 'Every computer that sent events in the last 7 days.'),
  ('windows.computers.empty', 'No computer has sent events yet.'),
  ('windows.computers.unlisted', 'Computers here that are not in your inventory: {n}. Add them under Setup, Computers and devices, with the same names, so alerts can say what each one is used for.'),
  ('windows.not_listed', 'Not in your inventory'),
  ('notice.sources.group_created', 'Group made. Download its installer below.'),
  ('notice.sources.group_enabled', 'Group switched on. Its computers'' events are accepted again.'),
  ('notice.sources.group_disabled', 'Group switched off. Its computers'' events are now refused.'),
  ('error.sources.group_name', 'Give the group a name.'),
  ('error.sources.group_unknown', 'That group was not found.'),
  ('sources.windows.title', 'Windows computers'),
  ('sources.windows.summary', 'Computers that sent events in the last 7 days: {computers}. Groups switched on: {groups}.'),
  ('sources.windows.empty', 'No Windows computer sends its events yet.'),
  ('sources.windows.connect', 'Set up Windows computers'),
  ('sources.windows.manage', 'Manage Windows computers'),
  ('row_problem.source_not_allowed', 'this connection may not send that kind of record.')
on conflict (key) do nothing;

insert into copy (key, value) values
  ('sources.connect_fhir', 'Connect a FHIR server'),
  ('source_kind.fhir', 'FHIR'),
  ('fhir.title', 'Connect a FHIR server'),
  ('fhir.lede', 'Many patient record systems offer FHIR, the standard for sharing health data. Its AuditEvent records say who opened which patient record, and when. The platform reads only those, and only reads.'),
  ('fhir.default_name', 'Patient records (FHIR)'),
  ('fhir.ask.body', 'Ask whoever looks after your patient record system for access to its FHIR API. You can send them this:'),
  ('fhir.ask.request', 'Please give our security monitoring platform read access to the FHIR AuditEvent resource, with no other access, as a system to system (backend services) client. Please send me the FHIR base address, the client ID and the token address. If you register clients with a public key, we will send you ours in a JWKS file.'),
  ('fhir.base_url', 'FHIR base address'),
  ('fhir.base_url_hint', 'The address the vendor gave you, such as https://ehr.hospital.local/fhir/R4. The platform reads AuditEvent from here and from nowhere else.'),
  ('fhir.auth', 'How the platform signs in'),
  ('fhir.auth_hint', 'Ask the vendor which they use. Most record systems use a key pair for system to system access.'),
  ('fhir.auth.private_key', 'Key pair (SMART Backend Services)'),
  ('fhir.auth.client_secret', 'Client ID and secret'),
  ('fhir.auth.token', 'An access token the vendor issued'),
  ('fhir.auth.none', 'No sign in (test servers only)'),
  ('fhir.client_id', 'Client ID'),
  ('fhir.client_id_hint', 'The ID the vendor gave this platform. Needed for a key pair or a client secret.'),
  ('fhir.secret', 'Client secret or access token'),
  ('fhir.secret_hint', 'Needed for a client secret or an access token. Stored encrypted. Leave empty for a key pair: the platform makes its own.'),
  ('fhir.token_url', 'Token address'),
  ('fhir.token_url_hint', 'Where the platform asks for access. Leave empty to find it in the server''s SMART configuration.'),
  ('fhir.scope', 'Scope'),
  ('fhir.scope_hint', 'What the platform asks to read. Usually system/AuditEvent.read, or system/AuditEvent.rs on newer servers.'),
  ('fhir.ca', 'Your hospital''s certificate authority (optional)'),
  ('fhir.ca_hint', 'Only if the FHIR server uses a certificate from your hospital''s own authority. Paste that authority''s certificate here. It is public, not a secret.'),
  ('fhir.encrypt', 'Require an encrypted (https) address. Keep this on unless the vendor says otherwise.'),
  ('fhir.submit', 'Connect'),
  ('fhir.step.connect', '1. Sign in'),
  ('fhir.step.preview', '2. Check the records'),
  ('fhir.step.running', '3. Reading'),
  ('fhir.pending.discover', 'Signing in, checking the server offers AuditEvent and reading a few recent ones.'),
  ('fhir.pending.activate', 'Starting.'),
  ('fhir.key.title', 'Register this key with the vendor'),
  ('fhir.key.body', 'The platform made a key pair for this connection. Send the vendor this public key, a JWKS file, to register with the client ID {client}. The private half never leaves this installation. Once the vendor confirms, check the connection below.'),
  ('fhir.key.download', 'Download the JWKS file'),
  ('fhir.check.title', 'Check the connection'),
  ('fhir.check.body', 'Signs in, checks the server offers AuditEvent and reads a few recent ones, so you can see the records look right.'),
  ('fhir.check', 'Check the connection'),
  ('fhir.preview.title', 'Recent records from the server'),
  ('fhir.preview.note', 'Check that each shows who, which patient and when. Then choose where to start reading.'),
  ('fhir.preview.empty', 'The server answered, but has no AuditEvent from the last 7 days. Reading can start, and new records will be read as they appear.'),
  ('fhir.col.time', 'When'),
  ('fhir.col.user', 'Who'),
  ('fhir.col.patient', 'Patient'),
  ('fhir.col.action', 'Action'),
  ('fhir.action.C', 'Created'),
  ('fhir.action.R', 'Read'),
  ('fhir.action.U', 'Changed'),
  ('fhir.action.D', 'Deleted'),
  ('fhir.action.E', 'Ran'),
  ('fhir.remove.body', 'Stops reading and deletes the stored secret or key. Records already read are kept.'),
  ('notice.sources.fhir_checking', 'Checking the connection. This page updates by itself.'),
  ('notice.sources.fhir_register_key', 'Connection saved. Register its public key with the vendor, then check the connection.'),
  ('error.sources.fhir_auth', 'Choose how the platform signs in.'),
  ('error.sources.fhir_auth_change', 'The way of signing in cannot be changed. Remove this connection and make a new one.'),
  ('error.sources.fhir_url', 'Enter the FHIR base address, starting with https://, with no user name or password in it.'),
  ('error.sources.fhir_token_url', 'Enter the token address starting with https://, or leave it empty.'),
  ('error.sources.fhir_scope', 'The scope may only hold letters, numbers and the signs / . * :'),
  ('error.sources.fhir_client_id', 'Enter the client ID the vendor gave you.'),
  ('error.sources.fhir_secret', 'Enter the client secret or access token.'),
  ('error.sources.fhir_ca', 'Paste the whole certificate, from -----BEGIN CERTIFICATE----- to -----END CERTIFICATE-----.'),
  ('error.sources.fhir_not_checked', 'Check the connection first.')
on conflict (key) do nothing;

-- The list of connections now holds FHIR servers as well as databases. Only wording still as shipped is changed.
update copy set value = 'Connected patient record systems' where key = 'sources.databases.title' and value = 'Connected records databases';
update copy set value = 'No patient record system is connected yet. Connect its database or FHIR server, or upload a report.'
  where key = 'sources.databases.empty' and value = 'No records database is connected yet.';


insert into schema_migrations (version) values ('0012_round_two') on conflict do nothing;
