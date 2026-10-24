# Changes

Each version's notes say what changed, what an existing installation needs to do, and which publicly known vulnerabilities were fixed. Versions follow [Semantic Versioning](https://semver.org).

## 0.8.1

The appliance's first start, found stuck on a real laptop running VirtualBox in slow mode, now recovers and explains itself.

**Fixed**

- The first start can be switched off at any point and carries on from where it was on the next start. A part that fails to load is tried again, and nothing is cut short on a slow computer. Before, a first start stopped part way could leave the platform unable to start.
- The screen shows which part of the first start it is on and for how long, and after 25 minutes explains that the computer is running it slowly, with what to change in VirtualBox and Windows.
- Start up messages no longer print over the screen.
- The maintenance account has its own first password, shown on the screen from the very first start, so it can be used even before the platform runs. It was the setup code, which only appears once the platform runs.
- The screen says that nothing needs to be typed, and gives the VirtualBox key for maintenance (Right Ctrl and F2).

**Upgrading**

- Nothing to do for a running installation. A new appliance from this release replaces an earlier one that never finished its first start.

## 0.8.0

Installing in a hospital no longer needs typed commands.

**New**

- A ready made virtual machine for VirtualBox and VMware (`.ova`) and for Hyper-V (`.vhdx`), and a USB installer that puts the platform on a spare computer. They are built and tested for every release by `.github/workflows/release.yml`.
- The installation's screen shows the address to open and a ten character setup code. The first visit asks for the code to set up the first administrator, then the setup page closes for good.
- Signed in administrators can download the installation's certificate authority, so hospital computers stop warning about its certificate.
- A project page for GitHub Pages, in `docs/index.html`.
- Code scanning with CodeQL, weekly dependency updates, and a linter for the Python code.

**Fixed**

- Browsers that opened the installation by its IP address got a protocol error, because they send no server name. Caddy now uses the installation's address in that case.
- The database setup refuses a database that is not UTF8, with a plain message, instead of reading text back wrongly.

**Security**

- Next.js updated from 15.5.27 to 15.5.28, fixing [GHSA-2464-fhr4-w9xw](https://github.com/advisories/GHSA-2464-fhr4-w9xw) (critical: remote code execution in the image optimisation API when SVG files are used) and [GHSA-p3m5-59mp-jv5r](https://github.com/advisories/GHSA-p3m5-59mp-jv5r) (denial of service in the App Router with server actions).

**Upgrading**

- Docker installations: take a backup, then `git pull` and `docker compose up -d --build` as in [docs/hospital_install.md](docs/hospital_install.md). Migrations `0013` and `0014` run by themselves.
- Moving a Docker installation onto the appliance: take a backup, install the appliance, and restore the backup onto it before setting up the administrator.

## 0.7.0

**New**

- A receiver for router, firewall and server logs over syslog, which keeps logs only from devices an administrator accepted.
- A Windows collector, installed from one downloaded file per group of computers, that signs what it sends and trusts only the installation's own certificate authority.
- A FHIR connection to the patient record system, with SMART Backend Services sign in.
- A learning period, so activity that is only unusual is reported once the platform has learned what is normal for each source.

**Upgrading**

- Migration `0012` runs by itself. Publish port 514 if routers and firewalls will send logs.

## 0.6.0

**New**

- A hospital installation, `docker-compose.hospital.yml`, served over HTTPS with no simulator, test attacks or public demo login, and every page behind sign in.
- A setup wizard that loads departments, staff, computers and patients from spreadsheets.
- A read only connection to the patient record database (PostgreSQL, MySQL or MariaDB), and uploaded access reports.
- Documented backups and restores.

## Earlier versions

Versions before 0.6.0 ran the simulated hospital only. They built the detection rules, models, incidents, isolation with human approval, the audit log and the measured evaluation described in the white paper.
