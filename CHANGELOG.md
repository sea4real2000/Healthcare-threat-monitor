# Changes

Each version's notes say what changed, what an existing installation needs to do, and which publicly known vulnerabilities were fixed. Versions follow [Semantic Versioning](https://semver.org).

## 0.9.0

Backups and moving to a new version are done with clicks, the appliance can be given a fixed address on its own screen, and every pull request now scans a running installation for security problems.

**New**

- Backups with clicks, under **Settings**, **Backups**: a backup of everything, locked with a passphrase, to download; and a restore that replaces everything on the installation. A backup holds the certificate authority and keys too, so Windows computers and browsers that trusted the old installation trust the new one.
- On a new installation, the first visit page can restore a backup from an earlier one with the setup code from its screen. This is how an appliance moves to a new version or a new computer.
- A new backup service in `docker-compose.hospital.yml` does the work, and the console, background service and HTTPS service start again by themselves when a restore changes their keys or certificate authority.
- A fixed network address, set on the appliance's screen by pressing **N**, for networks that cannot keep the same address for it. It can be switched back to an address from the network the same way.
- A ZAP scan of a running hospital installation on every pull request, as a visitor and signed in as an administrator, which fails on any alert of medium risk or higher not accepted with a reason in `security/zap_accepted.tsv`. Each reason is proven again on every run.
- Coverage reports for the console and engine tests, with a floor in CI that only goes up.
- Runtime checks in the detection pipeline, and the end to end evaluation runs in Python's development mode.

**Changed**

- Dependencies: React 19.3.1, Vitest 5, newer engine packages, and the GitHub Actions used by CI at their current versions. Dependabot now groups React updates and holds back TypeScript 7, `@types/node` 26 and Node 26 until they are tested.

**Upgrading**

- Docker installations: `git pull` and `docker compose up -d --build` as before. Migration `0015` runs by itself and the new backup service starts with the rest.
- Appliances: an appliance from 0.8 has no backup service, so it cannot make a backup with clicks. To move one with data to this version, use the commands under Backups without the console in the install guide, on the old appliance and then on the new one. From this version on, use Settings, Backups.

## 0.8.1

The appliance's first start, found stuck on a real laptop running VirtualBox in slow mode, now recovers and explains itself.

**Fixed**

- The first start can be switched off at any point and carries on from where it was on the next start. A part that fails to load is tried again, and nothing is cut short on a slow computer. Before, a first start stopped part way could leave the platform unable to start.
- A power cut just after a part of the platform had loaded could leave that part damaged on the disk, so the HTTPS server crashed and the address never opened. Each part is now written to the disk for certain before it counts as loaded.
- If a part still fails or keeps crashing before the platform has ever answered, Docker's store is rebuilt from the image files, which now stay on the disk. This only happens before first use, so no data can be lost.
- The screen shows which part of the first start it is on and for how long, and after 25 minutes explains that the computer is running it slowly, with what to change in VirtualBox and Windows.
- On a slow computer the screen could stay on "Starting" with no setup code, though the platform was running, because its own checks timed out. It now reads the setup code straight from the installation's storage and tolerates slow answers.
- On a slow computer the console could give up reading the installation's certificate authority after 3 seconds, leaving it off the Windows computers page and out of Windows installers. It now waits up to 20 seconds and keeps the certificate once read.
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
