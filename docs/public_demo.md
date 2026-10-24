# Running a public demo

This guide puts the platform on the internet so anyone can try it in a browser, without installing anything. It needs no domain of your own: the console gets a free address from Vercel. For a demo on your own computer, the one command Docker demo in the README is simpler.

A public demo has three parts:

| Part | Where | Cost |
| --- | --- | --- |
| Database | Supabase | Free plan |
| Console | Vercel | Free plan, at an address such as `your-project.vercel.app` |
| Background service | Any computer that stays on and runs Docker | Free only on some providers |

Free plans change. Check each provider's current terms before relying on them. At the time of writing, Supabase pauses a free project after about a week with no activity, and Vercel's free plan is for non commercial use.

## 1. Database on Supabase

1. Create a Supabase project and keep its database password.
2. On your own computer, in the `web` folder, run `npm install`.
3. Apply the migrations. Use the direct connection string from Project Settings, Database. If your network cannot reach it, use the session pooler string instead.

   ```bash
   DATABASE_URL="postgres://..." npm run db:migrate
   ```

   It prints the ten migrations it recorded. Running it again is safe. You can instead paste each file in `supabase/migrations` into the SQL editor, in order.

4. Load the starter photographs: `DATABASE_URL="postgres://..." npm run images:seed`

## 2. Console on Vercel

1. Import the GitHub repository into Vercel and set the root directory to `web`.
2. Add these environment variables. Generate each secret with `openssl rand -hex 32` and keep them out of the repository.

   | Variable | Value |
   | --- | --- |
   | `DATABASE_URL` | Supabase connection string, Transaction pooler |
   | `INGEST_SIGNING_KEY` | A new secret |
   | `AUTH_SECRET` | A new secret |
   | `SIEM_WEBHOOK_KEY` | A new secret |
   | `AUDIT_EXPORT_KEY` | A new secret |

3. Deploy. Open `https://your-project.vercel.app/api/health`. It should report the database as up and list ten migrations.
4. Create your administrator account:

   ```bash
   DATABASE_URL="postgres://..." npm run admin:invite -- you@example.org "Your Name" https://your-project.vercel.app
   ```

   Open the printed link, choose a password and connect an authenticator app.

## 3. Background service

The background service simulates the hospital, detects attacks and plays the endpoint product. It must run all the time. It makes outgoing connections only and needs no open port.

1. On a computer that stays on, install Docker and clone the repository.
2. Print the collector secret. On your own computer, in the `web` folder:

   ```bash
   INGEST_SIGNING_KEY=the_vercel_value npm run --silent collector:key -- sim_hospital_01
   ```

3. On the always on computer, in the repository folder:

   ```bash
   cp engine/worker.env.example engine/worker.env
   ```

   Fill in the four values in `engine/worker.env`. Git ignores this file.

4. Start it: `docker compose -f docker-compose.worker.yml up -d --build`
5. Within a minute or two the console overview shows "Detection service running".

## 4. Open the demo to visitors

Sign in as the administrator, open **Settings, Public demo**, and set `demo.enabled` to true. The sign in page then shows **Try the demo**.

A demo visitor can:

- launch any of the three attack scenarios, one at a time across all visitors
- isolate a machine named in a high confidence incident, and release an isolated machine

A demo visitor cannot decide incidents, so visitors cannot teach the detectors to ignore an attack. They cannot change rules, models, settings, labels, photographs or accounts, export the audit log, or see the names of real accounts. Every action they take is recorded in the audit log as "Demo visitor".

Limits that keep a public demo usable:

| Setting | Default | What it does |
| --- | --- | --- |
| `demo.session_minutes` | 60 | A demo session ends after this long |
| `demo.auto_release_minutes` | 20 | Isolated machines are released after this long, so the next visitor finds the hospital running |
| `limits.demo_per_minute` | 6 | Demo logins, launches and isolations allowed from one address each minute |
| `scenario.auto_interval_minutes` | 0 | Set it to 30, say, so a visitor who arrives finds recent incidents to look at |

To close the demo, set `demo.enabled` back to false. Every demo session stops working at once. Disabling the "Demo visitor" account under Settings, Accounts does the same.

## Connecting a records database

A public demo does not need `SOURCES_SECRET`, and connecting a records database or FHIR server is refused while the demo login is on. The log receiver for routers and firewalls, and the learning period, are part of the hospital installation too. A hospital should use its own installation instead: see [hospital_install.md](hospital_install.md).

## What has and has not been tested

The demo login, its limits and its refusals have been tested end to end, including attempts to submit the forms it is not allowed to use. The worker only setup has been tested against a separately run console and database. It has not been tested against Supabase, Vercel or any particular server provider, because those need your accounts.
