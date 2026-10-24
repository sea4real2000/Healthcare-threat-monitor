-- 0010_demo.sql
-- A public demo login. When an administrator switches on demo.enabled, anyone can press
-- "Try the demo" and act as the shared demo visitor. The demo visitor may launch an attack
-- scenario and isolate or release a machine, and nothing else: no decisions, rules, models,
-- settings, labels, pictures or accounts. Off by default.
-- Safe to run more than once.

alter table users drop constraint if exists users_role_check;
alter table users add constraint users_role_check check (role in ('analyst', 'admin', 'demo'));

-- The one shared demo account. It has no password and no authenticator, so it can never sign in
-- through the sign in form. Disabling it in Settings, Accounts also ends every demo session.
insert into users (email, display_name, role, status, created_by)
values ('demo.visitor@demo.invalid', 'Demo visitor', 'demo', 'active', 'migration')
on conflict (email) do nothing;

insert into settings (key, value, description) values
  ('demo.enabled',              'false', 'Lets anyone use the public demo login. The demo visitor can launch scenarios and isolate or release machines, nothing else'),
  ('demo.session_minutes',      '60',    'A demo session ends this long after it starts'),
  ('demo.auto_release_minutes', '20',    'While the demo is on, a machine stays isolated this long, then the background service releases it. Zero turns this off'),
  ('limits.demo_per_minute',    '6',     'Demo logins, scenario launches and isolation requests one address may make each minute as the demo visitor')
on conflict (key) do nothing;

insert into copy (key, value) values
  ('settings.group.demo',        'Public demo'),
  ('role.demo',                  'Demo visitor'),
  ('signin.demo.title',          'Just looking?'),
  ('signin.demo.body',           'Try the demo without an account. You can launch a simulated attack, watch it being caught and isolate the machine. Everything else stays read only.'),
  ('signin.demo.button',         'Try the demo'),
  ('error.signin.demo_off',      'The public demo is switched off on this installation.'),
  ('demo.banner',                'You are in the public demo. You can launch scenarios and isolate or release machines. Decisions, rules and settings are read only, and other visitors share this simulated hospital with you.'),
  ('demo.release_note',          'Machines isolated in the demo are released automatically after a while, so the next visitor finds the hospital running.'),
  ('error.scenarios.too_many',   'Too many requests from your address. Wait a minute and try again.'),
  ('error.incident.too_many',    'Too many requests from your address. Wait a minute and try again.'),
  ('audit.actor_demo',           'Demo visitor')
on conflict (key) do nothing;

select htm_lockdown();

insert into schema_migrations (version) values ('0010_demo') on conflict do nothing;
