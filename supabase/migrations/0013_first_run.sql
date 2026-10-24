-- 0013_first_run.sql
-- Installing without typing commands: the first visit to a new hospital installation sets up its administrator,
-- with the setup code shown on the installation's own screen. Safe to run more than once.

insert into copy (key, value) values
  ('welcome.title', 'Finish setting up'),
  ('welcome.lede', 'This is a new installation of Healthcare Threat Monitor. Set up the first administrator, who can then invite colleagues.'),
  ('welcome.code', 'Setup code'),
  ('welcome.code_hint', 'Shown on the screen of the computer the platform runs on, under the address. Only someone who can see that screen can set up the administrator.'),
  ('welcome.name', 'Your name'),
  ('welcome.email', 'Your email'),
  ('welcome.email_hint', 'You sign in with this. Nothing is sent to it.'),
  ('welcome.continue', 'Continue'),
  ('welcome.next', 'Next you choose a password and connect an authenticator app on your phone, such as Google Authenticator or Microsoft Authenticator.'),
  ('error.welcome.code', 'That setup code does not match the one on the platform''s screen. Check the letters and try again.'),
  ('error.welcome.details', 'Enter your name and a full email address.'),
  ('error.welcome.taken', 'An account with that email is already set up. Use another email.'),
  ('error.welcome.too_many', 'Too many tries from this computer. Wait a minute and try again.')
on conflict (key) do nothing;

select htm_lockdown();

insert into schema_migrations (version) values ('0013_first_run') on conflict do nothing;
