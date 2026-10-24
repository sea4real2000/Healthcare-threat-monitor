-- 0003_seed.sql
-- Starting values for sources, settings, copy and the simulator's collector.
-- Every insert skips rows that already exist, so running this again never
-- overwrites a value you have edited.

insert into sources (id, label, description, sort_order) values
  ('ehr',            'EHR access records',   'Who opened which patient record, as FHIR audit events', 10),
  ('edr',            'Endpoint detection',   'Process, file and registry activity on workstations and servers', 20),
  ('windows',        'Windows logs',         'Logons, privileges and service changes', 30),
  ('linux',          'Linux logs',           'Secure shell logons, sudo and scheduled jobs', 40),
  ('firewall',       'Firewall',             'Allowed and denied flows between network zones', 50),
  ('vpn',            'VPN',                  'Remote access sessions and failed sign ins', 60),
  ('dns',            'DNS',                  'Name lookups from every machine', 70),
  ('email',          'Email security',       'Delivery verdicts for inbound mail', 80),
  ('medical_device', 'Medical devices',      'Traffic from pumps, monitors, ventilators and imaging', 90),
  ('cloud',          'Cloud audit',          'Storage and identity activity in the cloud account', 100)
on conflict (id) do nothing;

insert into settings (key, value, description) values
  ('platform.name',                        '"Healthcare Threat Monitor"', 'Working title shown in the console and the browser tab'),
  ('console.refresh_seconds',              '15',      'How often the console asks for fresh data. Zero turns refresh off'),
  ('console.overview_window_minutes',      '60',      'Length of the window the overview and asset counts cover'),
  ('console.source_silent_after_minutes',  '10',      'A source with no event for this long is shown as silent'),
  ('console.recent_events_limit',          '15',      'Rows in the latest events table'),
  ('console.assets_page_limit',            '500',     'Most assets listed at once'),
  ('ingest.max_batch_records',             '1000',    'Most records accepted in one batch'),
  ('ingest.max_body_bytes',                '4000000', 'Largest request body the ingestion API reads'),
  ('ingest.max_skew_seconds',              '300',     'How far a request timestamp may differ from server time')
on conflict (key) do nothing;

insert into collectors (id, name) values
  ('sim_hospital_01', 'Hospital simulator')
on conflict (id) do nothing;

insert into copy (key, value) values
  ('nav.label',                      'Console sections'),
  ('nav.overview',                   'Overview'),
  ('nav.assets',                     'Assets'),
  ('banner.simulated',               'Simulated hospital. No real patient data is used anywhere on this platform.'),
  ('refresh.updated',                'Updated {time} UTC'),
  ('refresh.pause',                  'Pause refresh'),
  ('refresh.resume',                 'Resume refresh'),

  ('overview.title',                 'Overview'),
  ('overview.summary',               '{reporting} of {total} log sources are reporting. {events} events arrived in the last {minutes} minutes.'),
  ('overview.figure.events',         'Events, last {minutes} minutes'),
  ('overview.figure.sources',        'Sources reporting'),
  ('overview.figure.assets',         'Assets seen, last {minutes} minutes'),
  ('overview.figure.rejects',        'Rejected records, last {minutes} minutes'),
  ('overview.figure.of',             'of {total}'),
  ('overview.rate.title',            'Events per minute, all sources'),
  ('overview.rate.note',             'Times are UTC. The last bar is the current minute and is still filling.'),
  ('overview.rate.aria',             'Bar chart of events per minute. {events} events in the last {minutes} minutes.'),
  ('overview.rate.tip',              '{time} UTC: {events} events'),
  ('overview.rate.table',            'Show these numbers as a table'),
  ('overview.rate.col.minute',       'Minute (UTC)'),
  ('overview.rate.col.events',       'Events'),
  ('overview.sources.title',         'Log sources'),
  ('overview.sources.note',          'Each trend is scaled to its own busiest minute.'),
  ('overview.sources.col.source',    'Source'),
  ('overview.sources.col.status',    'Status'),
  ('overview.sources.col.events',    'Events'),
  ('overview.sources.col.rate',      'Per minute'),
  ('overview.sources.col.last',      'Last event'),
  ('overview.sources.col.trend',     'Last {minutes} minutes'),
  ('overview.sources.trend_aria',    'Events per minute for {source}. Busiest minute had {peak} events.'),
  ('overview.recent.title',          'Latest events'),
  ('overview.recent.col.time',       'Time (UTC)'),
  ('overview.recent.col.source',     'Source'),
  ('overview.recent.col.action',     'Action'),
  ('overview.recent.col.outcome',    'Outcome'),
  ('overview.recent.col.user',       'User'),
  ('overview.recent.col.host',       'Asset'),

  ('status.reporting',               'Reporting'),
  ('status.silent',                  'Silent'),
  ('status.never',                   'No events yet'),
  ('outcome.success',                'Success'),
  ('outcome.failure',                'Failure'),
  ('outcome.unknown',                'Unknown'),
  ('empty.events',                   'No events yet. Start the simulator to send the first batch.'),

  ('assets.title',                   'Assets'),
  ('assets.summary',                 '{total} assets registered: {workstations} workstations, {servers} servers, {devices} medical devices and {network} network devices. {isolated} isolated.'),
  ('assets.list.title',              'Inventory'),
  ('assets.list.shown',              'Showing {shown} of {total}'),
  ('assets.filter.search',           'Search name, role or address'),
  ('assets.filter.kind',             'Kind'),
  ('assets.filter.department',       'Department'),
  ('assets.filter.status',           'Status'),
  ('assets.filter.any',              'Any'),
  ('assets.filter.apply',            'Apply filters'),
  ('assets.filter.clear',            'Clear filters'),
  ('assets.col.asset',               'Asset'),
  ('assets.col.kind',                'Kind'),
  ('assets.col.department',          'Department'),
  ('assets.col.zone',                'Zone'),
  ('assets.col.address',             'Address'),
  ('assets.col.status',              'Status'),
  ('assets.col.last_seen',           'Last seen'),
  ('assets.col.events',              'Events, last {minutes} minutes'),
  ('assets.none',                    'No assets registered yet. The simulator registers the inventory when it starts.'),
  ('assets.empty',                   'No assets match these filters.'),

  ('kind.workstation',               'Workstation'),
  ('kind.server',                    'Server'),
  ('kind.medical_device',            'Medical device'),
  ('kind.network',                   'Network device'),
  ('asset_status.active',            'Active'),
  ('asset_status.isolated',          'Isolated'),
  ('asset_status.offline',           'Offline'),

  ('time.never',                     'Never'),
  ('time.just_now',                  'Just now'),
  ('time.minutes_ago',               '{n} min ago'),
  ('time.hours_ago',                 '{n} h ago'),
  ('time.days_ago',                  '{n} days ago')
on conflict (key) do nothing;

select htm_lockdown();

insert into schema_migrations (version) values ('0003_seed') on conflict do nothing;
