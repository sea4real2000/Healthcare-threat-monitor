-- 0009_media.sql
-- Photographs for the landing page. Each row is one place a picture can appear.
-- An administrator uploads, replaces or removes them in the console, under Settings, Images.
-- Safe to run more than once.

create table if not exists site_images (
  slot text primary key check (slot ~ '^[a-z_]{2,30}$'),
  position smallint not null default 0,
  content_type text check (content_type in ('image/jpeg', 'image/png', 'image/webp')),
  bytes bytea,
  size_bytes integer,
  width integer,
  height integer,
  sha256 text,
  alt text not null default '',
  updated_at timestamptz not null default now(),
  updated_by text
);

-- A slot with no picture is simply left out of the page.
insert into site_images (slot, position) values
  ('hero', 1),
  ('watches', 2),
  ('how', 3),
  ('close', 4)
on conflict (slot) do nothing;

insert into settings (key, value, description) values
  ('media.max_bytes', '3000000', 'Largest picture an administrator may upload, in bytes. Hosting limits a single upload to about 4 MB')
on conflict (key) do nothing;

insert into copy (key, value) values
  ('settings.tab.images',              'Images'),
  ('settings.group.media',             'Images'),
  ('settings.images.lede',             'Photographs shown on the landing page. Upload, replace or remove each one here. A place with no picture is left out of the page.'),
  ('settings.images.rules',            'JPEG, PNG or WebP, up to {limit} MB each. Pictures are cropped to fit, so keep the subject near the middle. Use only pictures you have the right to publish, and none that show a real patient.'),
  ('settings.images.current',          'Current picture'),
  ('settings.images.none',             'No picture yet. The landing page shows this section without one.'),
  ('settings.images.details',          '{width} by {height} pixels, {size} KB'),
  ('settings.images.file',             'Picture file'),
  ('settings.images.file_keep',        'Leave empty to keep the current picture.'),
  ('settings.images.alt',              'Description for people who cannot see the picture'),
  ('settings.images.alt_hint',         'One short sentence that says what the picture shows.'),
  ('settings.images.save',             'Save'),
  ('settings.images.remove',           'Remove picture'),
  ('settings.images.shape',            'Best shape'),
  ('settings.images.slot.hero.title',  'Top of the page'),
  ('settings.images.slot.hero.guide',  'Sits beside the headline, with the live activity card over its lower edge. A clinician at a hospital workstation works well.'),
  ('settings.images.slot.hero.shape',  'Landscape, 4 by 3. At least 1600 by 1200 pixels.'),
  ('settings.images.slot.watches.title', 'What it watches'),
  ('settings.images.slot.watches.guide', 'Sits to the left of the four threat cards. Bedside medical equipment such as an infusion pump or a patient monitor works well.'),
  ('settings.images.slot.watches.shape', 'Portrait, 4 by 5. At least 1200 by 1500 pixels.'),
  ('settings.images.slot.how.title',   'How it works'),
  ('settings.images.slot.how.guide',   'Sits above the summary card, beside the five steps. A security analyst reviewing screens works well.'),
  ('settings.images.slot.how.shape',   'Landscape, 4 by 3. At least 1200 by 900 pixels.'),
  ('settings.images.slot.close.title', 'Closing banner'),
  ('settings.images.slot.close.guide', 'Fills the background of the last banner under a dark blue tint, with text on top. A calm, uncluttered scene such as a hospital corridor or a building at dusk works well.'),
  ('settings.images.slot.close.shape', 'Wide, 21 by 9. At least 2000 by 860 pixels.'),
  ('notice.images.saved',              'Picture saved. It is live on the landing page.'),
  ('notice.images.described',          'Description saved.'),
  ('notice.images.removed',            'Picture removed.'),
  ('error.images.slot',                'That place for a picture does not exist.'),
  ('error.images.type',                'That file is not a JPEG, PNG or WebP picture.'),
  ('error.images.size',                'That picture is larger than the upload limit. Export a smaller copy and try again.'),
  ('error.images.alt',                 'Add a short description of the picture before saving.'),
  ('error.images.missing',             'Choose a picture file first.')
on conflict (key) do nothing;

select htm_lockdown();

insert into schema_migrations (version) values ('0009_media') on conflict do nothing;
