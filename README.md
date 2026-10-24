# Healthcare Threat Monitor

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15859/badge)](https://www.bestpractices.dev/projects/15859)

*Working title. The name is one row in the settings table, so renaming the platform is a data change.*

An open source platform that watches the security logs of a hospital, detects threats such as ransomware and improper access to patient records, and keeps a human analyst in charge of every response.

> **The demo is simulated.** The demo ships with a hospital simulator. No real patient, staff member or hospital is represented anywhere in this repository, and no real malware is used. A hospital installation watches the hospital's own systems instead. It is a research prototype: it has had no independent security review and has not been assessed for use with real patient information.

## Try it in one command

You need Docker. From the repository folder:

```bash
docker compose up
```

The first start builds the images, which takes a few minutes. Then open http://localhost:3000, press **Sign in**, then **Try the demo**. Launch the ransomware scenario, watch the incident climb to high confidence, and isolate the machine.

Everything runs on your computer: the database, the console and the background service that simulates a hospital and attacks it. Secrets are generated on the first start and kept in a private Docker volume. The console listens on your computer only.

- To change rules and settings, use the one time administrator link printed by `docker compose logs setup`.
- To stop, press Ctrl and C, or run `docker compose down`. Your data stays for next time.
- To start again from nothing: `docker compose down --volumes`

To put a demo on the internet for anyone to try in a browser, see [docs/public_demo.md](docs/public_demo.md).

## Install it in your hospital

A separate installation watches your hospital's own systems instead of a simulation. It installs with clicks: download one file from this repository's **Releases** and either

- import the `.ova` into VirtualBox or VMware,
- attach the `.vhdx` from the `-hyperv.zip` to a new Hyper-V virtual machine, or
- write the `-usb.img.xz` to a USB stick with balenaEtcher or Rufus and start a spare computer from it.

The installation's screen then shows its address and a setup code. Open the address in a browser on another computer and enter the code to set up the administrator. Nothing is typed in a terminal. Hospitals that already run Docker can instead use `docker-compose.hospital.yml` on their own Linux server.

The console then takes you through the rest with spreadsheets, short forms and one file installers, with no programming:

- departments, staff, computers and devices, from a spreadsheet or typed in, in the **Setup** wizard
- your patient record system: a read only connection to its database (PostgreSQL, MySQL or MariaDB), its FHIR server (with SMART Backend Services sign in), or an uploaded access report
- routers, firewalls and servers, which send their logs to the built in receiver on port 514 once you accept them
- Windows computers, through a small collector installed from one downloaded file, as one group per ward or department

The **Sources** page then shows whether each connection is working. For the first 7 days after each kind of log arrives, the platform learns what is normal in your hospital: clear signs of attack are reported straight away, and activity that is only unusual once learning ends. There is no simulator, no test attack and no public demo login on a hospital installation, and every page needs sign in. The full guide, including backups and what has not been tested yet, is [docs/hospital_install.md](docs/hospital_install.md).

## What it does

| Step | What happens |
| --- | --- |
| Collect | Signed collectors send raw logs from ten kinds of hospital systems. Each record is mapped into one common event format. |
| Detect | Twenty one editable rules catch known attack behaviour. Three anomaly models flag activity that departs from normal. |
| Correlate | Alerts about the same machine or person become one incident with one confidence score and a band: low, medium or high. |
| Review | An analyst sees the evidence, the ATT&CK techniques and the features that drove each alert, then confirms or dismisses. |
| Respond | On a high confidence incident an analyst can approve isolation of a machine. Incidents are forwarded to a SIEM as CEF and signed JSON. |
| Record | Every alert, decision and action lands in a hash chained audit log that shows any tampering. |
| Learn | A dismissal teaches the detectors that raised it, so the same false alarm is not raised again. |

The ten log sources: EHR access records (FHIR AuditEvent), endpoint detection, Windows logs, Linux logs (syslog), firewall, VPN, DNS, email security, medical device traffic, and cloud audit.

## How the parts connect

```
Hospital simulator --signed API--> Console and APIs <----> Postgres <----> Background service
   (inside the service)              (Next.js)             (Supabase)        (Python)
                                         |                                      |
                                    Analysts and visitors            detection, scenarios,
                                                                     forwarding, connector
```

| Part | Folder | Runs on |
| --- | --- | --- |
| Database migrations and tests | `supabase` | Supabase, or any Postgres 15 or newer |
| Console, landing page and APIs | `web` | Vercel, or any Node host |
| Background service | `engine` | Render, Railway, Fly.io, or any host that runs a container |

The background service is one process that runs the simulator, detection, attack scenarios, the simulated endpoint connector, SIEM forwarding and retention.

## What you need

- Docker, for the one command demo. The rest of this section is for running the parts yourself.
- Node 22 or newer
- Python 3.11 or newer
- A Postgres 15 or newer database. A free Supabase project works. Expect about 250 MB of use with the default retention.

## Set up from a clean clone

### 1. Create the database

Open the Supabase SQL editor and run the files in `supabase/migrations` in order, from `0001_core.sql` to `0010_demo.sql`. Each file is safe to run again. To confirm, run:

```sql
select version from schema_migrations order by version;
```

You should see ten rows. From the `web` folder, `npm run db:migrate` applies them all in one step instead.

### 2. Configure and start the console

```bash
cd web
npm install
cp ../.env.example .env.local
```

Fill in `.env.local`. Generate each secret with `openssl rand -hex 32`.

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | The connection string from Supabase (Project Settings, Database, Connection string, Transaction pooler) |
| `INGEST_SIGNING_KEY` | Collector secrets are derived from this |
| `AUTH_SECRET` | Protects sign in |
| `SIEM_WEBHOOK_KEY` | Signs forwarded incidents. The background service needs the same value |

```bash
npm run dev
```

Open http://localhost:3000 for the landing page and http://localhost:3000/console for the console.

### 3. Start the background service

```bash
cd web
INGEST_SIGNING_KEY=your_key_here npm run --silent collector:key -- sim_hospital_01    # prints the collector secret

cd ../engine
pip install -r requirements.txt
export DATABASE_URL=the_same_connection_string
export HTM_API_URL=http://localhost:3000
export HTM_COLLECTOR_SECRET=the_value_printed_above
export SIEM_WEBHOOK_KEY=the_same_value_as_the_console
python -m worker
```

On a new database the service first builds 24 hours of simulated history, which takes under a minute, and trains the models. Then it sends logs at real speed. The overview page shows "Detection service running" once it is ready.

### 4. Create the first administrator

```bash
cd web
DATABASE_URL=... npm run --silent admin:invite -- you@example.org "Your Name" http://localhost:3000
```

Open the printed link, choose a password, and scan the QR code with an authenticator app. Every account signs in with a password and a six digit code. Further accounts are invited from Settings, Accounts.

Invitations are emailed when email is set up, and the link is always shown on screen as well. To set email up, add `RESEND_API_KEY` to the console's environment, verify your sending domain with Resend, and enter the sender address in Settings, Email.

### 5. Watch it catch an attack

Sign in, open **Scenarios**, and launch the ransomware intrusion. Within a minute or two an incident appears in **Incidents** and climbs to the high band. Open it, read why it was flagged, and isolate the workstation. The scenario ends as contained and the encryption never happens. Then look at **Forwarding** to see what a SIEM received, and **Audit log** to see every step recorded.

## Measuring detection

The evaluation harness measures the platform against ground truth with one command. Use a separate database for it, because it fills the tables with three simulated days.

```bash
cd engine
python -m evaluate
```

It trains on 24 hours of normal activity, then runs two 24 hour phases with twelve scripted attacks each. Between the phases a simulated analyst rules on every incident and the detectors learn. It prints a report, saves it under `engine/runs`, and stores the results in that database. To show them on your live site, run `python -m evaluate --publish runs/evaluation_report.json` with `DATABASE_URL` pointing at the live database. `--seed` changes the random draw and `--min-detection-rate 1` makes the command fail if an attack is missed.

Results are measured on simulated data with scripted attacks. They show that the method works and can be measured. They are not a claim about performance in a live hospital.

## Connecting a real endpoint product

Isolation requests wait in a queue that a connector reads through the signed API. Out of the box the background service plays the endpoint itself. To act on real machines:

1. Run the webhook connector, which posts each approved request to an address you choose, such as an automation webhook in your endpoint product:

   ```bash
   cd web && INGEST_SIGNING_KEY=your_key_here npm run --silent collector:key -- endpoint_webhook_01   # prints the connector secret
   cd ../engine
   export HTM_API_URL=... HTM_CONNECTOR_SECRET=the_value_printed_above
   export CONNECTOR_TARGET_URL=https://your.endpoint.product/webhook
   python -m connectors.webhook_connector
   ```

2. Switch off `response.simulated_connector` in Settings, Response, so the two do not race.

The asset is marked isolated only after the target accepts the call. If the target refuses or cannot be reached, the request is retried, then reported as failed, and the asset's status does not change. `CONNECTOR_TARGET_KEY` signs each call and `CONNECTOR_TARGET_AUTH` sets an Authorization header. For a product with its own API, copy `engine/connectors/webhook_connector.py` and replace `deliver()`.

Only a collector with the respond permission (`collectors.can_respond`) may read or acknowledge these requests.

## Using the CICIoMT2024 medical device dataset

The [CICIoMT2024 dataset](https://www.unb.ca/cic/datasets/iomt-dataset-2024.html) holds traffic captured from 40 medical devices under 18 attacks. It is not included here. Download the feature CSV files yourself, then:

```bash
cd engine
python -m simulator dataset /path/to/csv/folder           # shows what was found, by attack class
python -m evaluate --device-dataset /path/to/csv/folder   # device attacks take their traffic shape from the dataset
```

Set `HTM_DEVICE_DATASET` to the same folder for the background service. The dataset rows carry packet rates, sizes and flag counts but no addresses, so the dataset supplies the shape of the attack traffic and the simulator supplies which device sends it. The loader was written from the dataset's published description and tested against files in that format, not against the dataset itself. Run the first command to confirm it reads your copy.

## Landing page photographs

The landing page has four places for a photograph: the top of the page, the "What it watches" section, the "How it works" section and the closing banner. All four are optional. A place with no picture is left out and the page closes up around it.

An administrator uploads, replaces or removes each one under **Settings, Images**. That page says what shape suits each place and asks for a short description, which screen readers read aloud. Pictures are stored in the database, so there is no storage service to set up and nothing to redeploy.

Four starter photographs ship in `web/seed/images`. To load them into a new installation:

```bash
cd web
DATABASE_URL=... npm run images:seed
```

It fills only the places that have no picture, so it never overwrites one you uploaded. Add `-- --replace` to load the starter set over what is there.

- JPEG, PNG and WebP are accepted. The file is checked by its contents, not its name. SVG is refused because it can carry script.
- The upload limit is the `media.max_bytes` setting, 3 MB by default. Vercel refuses request bodies over about 4.5 MB, so keep the setting below 4 MB. A photograph exported at the suggested size as JPEG or WebP is usually under 400 KB, and smaller files load faster for visitors.
- Pictures are served as uploaded, with no resizing, so export them at roughly the suggested size.
- Use only pictures you have the right to publish, and none that show a real patient.

## Deploying

For a public demo on free plans, follow [docs/public_demo.md](docs/public_demo.md). The notes below cover a deployment for your own use.


**Database, on Supabase.** Run the migrations as above.

**Console, on Vercel.** Import the repository, set the root directory to `web`, and add the four variables from step 2. Add `AUDIT_EXPORT_KEY` to sign audit exports and `DIAGNOSE_TOKEN` for the detailed health report.

**Background service, on a container host.** `engine/Dockerfile` runs it as a worker with no public port. Set `DATABASE_URL`, `HTM_API_URL` (the deployed console address), `HTM_COLLECTOR_SECRET` and `SIEM_WEBHOOK_KEY`. It must run all the time, so choose a plan that does not sleep when idle.

**Checking a deployment.** `GET /api/health` reports whether the database is reachable and which migrations are applied. With `?diagnose=1` and the header `x-htm-diagnose-token` it adds table counts and whether each secret is set. It never returns a secret. From outside, `node scripts/check_lockdown.mjs` confirms the public Supabase key can read and write nothing.

## Changing things without changing code

| To change | Where |
| --- | --- |
| A detection rule, or add one | Console, Rules |
| Any threshold, limit, interval or band | Console, Settings |
| Any label or sentence, including the landing page | Console, Settings, Labels and copy |
| The photographs on the landing page | Console, Settings, Images |
| Whether the public demo login is open | Console, Settings, Public demo |
| The platform name, repository link and contact address | Console, Settings, Platform |
| The compliance mapping | Rows in the `compliance_controls` table |
| The simulated hospital and its activity | `engine/config/hospital.json` |
| Colours, type and spacing | The token block at the top of `web/app/globals.css` |
| A SIEM destination | Console, Settings, SIEM forwarding |

## The API

Every request except the plain health check and the SIEM receiver must be signed by a registered collector. The signature is an HMAC SHA256, in hex, of this string:

```
v1:{timestamp}:{METHOD}:{path}:{sha256 of the body in hex}
```

sent with three headers: `x-htm-key-id` (the collector id), `x-htm-timestamp` (Unix seconds) and `x-htm-signature`. A request whose timestamp is more than five minutes from server time is refused.

| Route | Purpose |
| --- | --- |
| `POST /api/ingest` | Send a batch of raw log records |
| `POST /api/inventory` | Register or update departments, staff, assets and patients |
| `GET /api/runs/{run_id}` | Counts the database holds for one simulator run |
| `GET /api/response/actions` | Isolation and release requests waiting to be carried out. Needs the respond permission |
| `POST /api/response/actions/{id}/ack` | Report that a request was carried out |
| `POST /api/siem/receive` | The built in SIEM receiver. Signed with `SIEM_WEBHOOK_KEY` |
| `GET /api/health` | Health check, unsigned |

`engine/simulator/client.py` is a complete reference client. To connect a real endpoint product, write a connector that polls the response actions route, acts on the endpoint, and acknowledges. The simulated connector in `engine/worker.py` does exactly this.

## Tests

```bash
cd web && npm test && npm run typecheck                                   # normalizers, signing, passwords, one time codes
cd engine && python -m unittest discover -s tests                          # simulator, rules, models, receiver, FHIR, forwarding, connector
node scripts/check_copy.mjs                                                # every label the console uses is seeded
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/tests/lockdown.sql     # visitor roles can read and write nothing
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/tests/audit_chain.sql  # the audit log refuses and detects tampering
python scripts/verify_audit_export.py audit_export.json                    # check an exported audit log independently
cd engine && python -m db_checks.learning_period                           # the learning period, on a fresh database
cd engine && python -m db_checks.windows_rules                             # the rules catch ransomware steps as Windows records them
cd web/collectors/windows/tests && dotnet run -- unit                      # the Windows collector's core, compiled as C# 5
```

The same checks run on every pull request through `.github/workflows/ci.yml`, together with a short end to end evaluation that fails if an attack is missed, `scripts/demo_smoke.sh`, which starts the one command demo from nothing and fails unless it catches an attack, `scripts/hospital_smoke.sh`, which starts a hospital installation from nothing and fails unless it is served over HTTPS with every page behind sign in, no simulator, demo login or test attack, and a log receiver that keeps nothing from devices nobody accepted, and a check on a Windows computer that installs the Windows collector, makes events and checks what it sends.

For each version, `.github/workflows/release.yml` builds the appliance, starts the virtual machine and the USB installer in QEMU and sets each one up in a browser with the code from its screen, then publishes the downloads. To run the same locally, see [appliance/README.md](appliance/README.md).

## More to read

- [CHANGELOG.md](CHANGELOG.md): what changed in each version, and the vulnerabilities each one fixed.
- Bugs and feature requests: [GitHub issues](https://github.com/sea4real2000/Healthcare-threat-monitor/issues). Security problems: privately, as in [SECURITY.md](SECURITY.md).
- [docs/hospital_install.md](docs/hospital_install.md): installing in a hospital, connecting patient records, backups
- [docs/detection.md](docs/detection.md): how rules, models, confidence and feedback work
- [docs/threat_model.md](docs/threat_model.md): how the platform itself could be attacked, and what stands in the way
- [SECURITY.md](SECURITY.md): reporting a vulnerability
- [CONTRIBUTING.md](CONTRIBUTING.md)

## Limits to know about

- Medical device traffic is generated by the simulator unless you supply the CICIoMT2024 dataset. The loader has not been run against the real files.
- The simulator creates its own synthetic patient identifiers. It can load a Synthea `patients.csv` instead.
- Isolation acts on simulated endpoints by default. The webhook connector has been tested against a local stand in, not against a real endpoint product.
- Email has been tested against a local stand in for Resend, not against Resend itself.
- Records databases: PostgreSQL, MySQL and MariaDB have been tested with sample databases, not with any real patient record product. FHIR was tested with a test server that follows the standard, not a vendor's. Microsoft SQL Server and Oracle are not supported, and encrypted database connections are untested.
- The hospital installation's HTTPS was tested with Caddy 2.6.2 from Ubuntu, not the official Caddy image. A check against the official image runs in CI.
- The appliance and the USB installer were tested in QEMU, with BIOS and with UEFI and Secure Boot, carrying stand in images. They have not been tried in VirtualBox, VMware or Hyper-V themselves or on a real computer. The release workflow tests each version's official build the same way before publishing. Backups and updates on the appliance still need typed commands.
- The Windows collector's core was tested on Linux against the real installation. Its installer, scheduled task and event reading have not run on Windows outside CI, where a check on a Windows computer runs on every pull request.
- Router and firewall log formats were tested with example messages written to each vendor's documented layout, not captured from devices.
- The platform has had no independent security review.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
