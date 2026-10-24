-- 0014_appliance.sql
-- The appliance: staff can download the installation's certificate authority, so browsers stop warning.
-- Safe to run more than once.

insert into copy (key, value) values
  ('windows.trust.browsers', 'Browsers warn about this installation''s certificate until hospital computers trust its certificate authority. Give this file to whoever manages your computers to add as a trusted root.'),
  ('windows.trust.download', 'Download the certificate authority (htm-root.crt)')
on conflict (key) do nothing;

-- Wording that assumed every installation is run with Docker commands. Changed only where nobody edited it.
update copy set value = 'The log receiver has not reported in the last minute. It is part of the hospital installation. Restarting the installation usually starts it again. On a Docker installation, check it with: docker compose -f docker-compose.hospital.yml logs receiver'
  where key = 'receiver.not_running_note'
    and value = 'The log receiver has not reported in the last minute. It is part of the hospital installation. Check it with: docker compose -f docker-compose.hospital.yml logs receiver';
update copy set value = 'Connecting a records database needs SOURCES_SECRET to be set on the server, for both the console and the background service. The appliance and the one command installs set it for you.'
  where key = 'error.sources.sources_not_configured'
    and value = 'Connecting a records database needs SOURCES_SECRET to be set on the server, for both the console and the background service. The one command installs set it for you.';

select htm_lockdown();

insert into schema_migrations (version) values ('0014_appliance') on conflict do nothing;
