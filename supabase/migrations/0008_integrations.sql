-- 0008_integrations.sql
-- Integrations: permission for endpoint connectors, a collector for the webhook connector,
-- and a short log of emails the platform has tried to send.
-- Safe to run more than once.

-- Only a collector with this permission may read or acknowledge isolation requests.
alter table collectors add column if not exists can_respond boolean not null default false;

update collectors set can_respond = true where id = 'sim_hospital_01' and not exists (
  select 1 from schema_migrations where version = '0008_integrations');

insert into collectors (id, name, can_respond) values
  ('endpoint_webhook_01', 'Endpoint webhook connector', true)
on conflict (id) do nothing;

-- The most recent emails the platform tried to send. Bodies are never stored.
create table if not exists email_log (
  id bigint generated always as identity primary key,
  sent_at timestamptz not null default now(),
  purpose text not null,
  recipient text not null,
  transport text not null,
  status text not null check (status in ('sent', 'failed', 'skipped')),
  detail text
);

insert into settings (key, value, description) values
  ('email.from_address',           '""',    'Address invitations are sent from. Its domain must be verified with the email provider. Empty turns email off'),
  ('email.from_name',              '""',    'Name shown as the sender. Empty uses the platform name'),
  ('response.simulated_connector', 'true',  'Whether the background service acts as the endpoint. Switch off when a real connector is running')
on conflict (key) do nothing;

insert into copy (key, value) values
  ('settings.group.email',            'Email'),
  ('email.invite.subject',            'Set up your {platform} account'),
  ('email.invite.body',               'Hello {name}. You have been invited to {platform} as {role}. Open this link to choose a password and connect an authenticator app. The link works once and expires in {hours} hours. {link}'),
  ('notice.settings.invited_emailed', 'Invitation created and emailed.'),
  ('settings.users.link_emailed',     'An email with this link was sent to {email}. The link is also shown here once, in case the email does not arrive.'),
  ('settings.users.email_off',        'Email is not set up, so pass this link on yourself. To send invitations by email, set RESEND_API_KEY on the server and a sender address in Settings.'),
  ('settings.users.emails.title',     'Recent emails'),
  ('settings.users.emails.empty',     'No email has been sent yet.'),
  ('settings.users.emails.col.when',  'When'),
  ('settings.users.emails.col.to',    'To'),
  ('settings.users.emails.col.status','Result'),
  ('email_status.sent',               'Sent'),
  ('email_status.failed',             'Failed'),
  ('email_status.skipped',            'Not sent, email is off')
on conflict (key) do nothing;

select htm_lockdown();

insert into schema_migrations (version) values ('0008_integrations') on conflict do nothing;
