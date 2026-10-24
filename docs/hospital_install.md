# Installing in your hospital

This guide puts Healthcare Threat Monitor on one computer inside your hospital network, watching your hospital's own systems. It is free and stays on your own computer: nothing is sent to us or to anyone else.

You do not need to program, and you do not need to type commands. You need someone who can import a virtual machine or start a computer from a USB stick, and, for the patient records connection, someone who looks after your patient record system.

> This is a research prototype. It has had no independent security review and has not been assessed for use with real patient information. Read [Limits](#what-has-and-has-not-been-tested) before you rely on it.

## What you need

- One computer that stays on, inside the hospital network, with at least 2 processors, 4 GB of memory and 20 GB of disk. Either a virtual machine on a server you already run, or a spare computer.
- An address on the hospital network for it. Ask whoever runs the network to give it a fixed address, so the address staff use does not change.
- Ports 80, 443 and 514 reachable on it from the hospital network. Staff browsers use 80 and 443, Windows computers send their events to 443, and routers, firewalls and servers send logs to 514.
- If you will connect your patient record database or FHIR server: that computer must be allowed through any firewall to reach it.

## 1. Install

Download one file from the project's GitHub page, under **Releases**, for the version you want. Each release lists a SHA256 checksum for every file, so you can check the download is complete and unchanged.

### A. VirtualBox or VMware (the `.ova` file)

1. In VirtualBox choose **File**, **Import Appliance**. In VMware Workstation or ESXi choose **File**, **Open** or **Deploy OVF Template**. Pick the `.ova` file and accept the settings.
2. Make sure its network is **Bridged**, so other computers can reach it. In VirtualBox: **Settings**, **Network**, **Attached to: Bridged Adapter**. On ESXi, choose the hospital network when asked.
3. Start it.

### B. Hyper-V (the `-hyperv.zip` file)

1. Unzip it. It holds one `.vhdx` disk. Move it to where your virtual machine disks are kept.
2. In Hyper-V Manager choose **New**, **Virtual Machine**. Choose **Generation 2**, give it 4096 MB of memory, connect it to an external virtual switch, and choose **Use an existing virtual hard disk** with the `.vhdx` file.
3. Before starting it, open its **Settings**, **Security**, and set the Secure Boot template to **Microsoft UEFI Certificate Authority**. Set **Processor** to 2.
4. Start it.

### C. A spare computer (the `-usb.img.xz` file)

1. On any computer, write the file to a USB stick of 8 GB or more with balenaEtcher (balena.io/etcher) or Rufus (rufus.ie). Both accept the file as it is. Everything on the stick is replaced.
2. Put the stick in the spare computer and start it from the stick. Most computers show a key for the boot menu when starting, often F12, F11 or Esc.
3. The installer lists the computer's disks. Type the number of the disk to use and press Enter, then type ERASE and press Enter. **Everything on that disk is erased.**
4. When it says so, remove the stick and press Enter. The computer restarts into the platform.

The stick can be used again for other computers. The computer must allow starting from USB; if Secure Boot refuses the stick, see the computer's firmware settings.

### D. Your own Linux server with Docker

If you already run Docker on a Linux server and prefer it, see [Installing with Docker](#installing-with-docker) at the end of this guide.

## 2. Create the administrator account

The first start takes a few minutes while the platform prepares itself. Then the installation's own screen shows:

- the address to open, such as `https://10.0.0.5`
- a **setup code** of ten letters and numbers

On another computer, open that address in a web browser. Use the address exactly as shown: a name for the computer, such as one added to your hospital's DNS, shows a blank page unless the HTTPS settings are changed to that name. The browser warns about the certificate the first time; choose **Advanced**, then **Continue** (the wording differs between browsers). See [The certificate warning](#the-certificate-warning).

The page asks for the setup code, your name and your email. Then choose a password and connect an authenticator app such as Google Authenticator or Microsoft Authenticator. Every account needs both. The password must be at least 12 characters and must not contain the name part of your email.

The setup code works only until the first administrator is set up. After that, the page is closed and the screen stops showing the code. Anyone who can see the installation's screen can see the code, so set up the administrator straight after installing.

If the screen warns that the address looks like VirtualBox's private network, the virtual machine's network is not Bridged: shut it down, change it as in 1A, and start it again. If the screen says the address changed, give the computer a fixed address; Windows computers set up before must be set up again.

### The certificate warning

The console is served over HTTPS with a certificate made by the installation, so browsers warn the first time. Two choices:

- For a quick start, accept the warning on each browser.
- For staff use, install the installation's certificate authority on hospital computers, so the warning goes away. Sign in as an administrator, open **Sources**, **Windows computers**, and choose **Download the certificate authority (htm-root.crt)**. Give the file to whoever manages your computers to add as a trusted root. On Windows, double click it and choose Install Certificate, Local Machine, Trusted Root Certification Authorities.

If you have your own certificate or a hospital domain name, the HTTPS settings are in `docker/Caddyfile`. See caddyserver.com/docs.

### The installation's screen and maintenance sign in

The screen shows the address and whether the platform is running, and refreshes by itself. You do not need to sign in to it for day to day use.

For maintenance, such as backups, press **Alt** and **F2** on the installation's keyboard (in a virtual machine, send the key combination from its menu) and sign in as `htm`. The first password is the setup code, without the space, and it must be changed at first sign in. Keep the new password with your other administrator passwords.

## 3. Run the setup wizard

Sign in and open **Setup** in the console. Each step takes a spreadsheet (CSV, which Excel and Google Sheets can save) or a short form. Every step can be skipped and finished later.

| Step | What it is for |
| --- | --- |
| Hospital details | The name shown in the console and the time zone your records use. |
| Departments | So alerts can say which ward something happened in. |
| Staff | So an alert names a person and their role. Accepts columns such as `staff_id`, `full_name`, `role`, `department_code`. |
| Computers and devices | So an alert can say a machine is a nurses' station, a server or an infusion pump. Types such as computer, PC or laptop are understood. |
| Patients | Optional. Mark patients who need extra protection, such as staff who are also patients or public figures. |
| Connect patient records | Opens the connection page, step 4 below. |

Each step has a **template** to download, and the wizard understands common column names, so an export from your HR or asset system often works without changes. If anything in a file is wrong, nothing from that file is imported, and every problem is listed with its row number so you can fix it and upload again.

## 4. Connect your patient records

The platform's most valuable signal is who opened which patient record, and when. There are three ways to give it that.

### A. Connect the database (recommended)

The platform reads the access log table straight from your patient record system's database, every 30 seconds. It only ever reads, and only the table you choose.

Supported: **PostgreSQL**, and **MySQL or MariaDB**. Microsoft SQL Server and Oracle are not supported yet; use FHIR or the report upload below.

1. **Ask for a read only account.** The connection page has a ready made request you can send to your vendor or database owner. They will need to create an account that can read the access log table and nothing else. For example:

   PostgreSQL:
   ```sql
   CREATE ROLE htm_reader LOGIN PASSWORD 'a long random password';
   GRANT CONNECT ON DATABASE ehr TO htm_reader;
   GRANT USAGE ON SCHEMA public TO htm_reader;
   GRANT SELECT ON public.access_log TO htm_reader;
   ```

   MySQL or MariaDB:
   ```sql
   CREATE USER 'htm_reader'@'10.0.0.5' IDENTIFIED BY 'a long random password';
   GRANT SELECT ON ehr.access_log TO 'htm_reader'@'10.0.0.5';
   ```

   The table and database names are examples; your vendor knows the real ones.

2. In the console, open **Sources**, then **Connect a records database**, and enter the server address, port, database name, user name and password.
3. **Choose the table.** The platform lists the tables the account can read.
4. **Match the columns.** You see a few example rows. Most columns are guessed for you: when, who, which patient, what they did, whether it worked, which computer, and the entry number. Time, user and patient are required.
5. **Start reading,** from now on, or from the last day, 7 days or 30 days.

The **Sources** page then shows, for each connection, whether it is working, when it last read, and how many entries it has read. If something goes wrong it says what, in a plain sentence, such as "The database refused the user name or password."

Even if the account were allowed to write, the platform opens every session as read only, so the database refuses any change. The password is stored encrypted, and removing a connection deletes it.

### B. Connect a FHIR server

Many record systems offer FHIR, the standard for sharing health data. Its AuditEvent records say who opened which patient record, and when. Under **Sources**, choose **Connect a FHIR server** and enter the FHIR base address the vendor gave you.

How the platform signs in depends on the vendor:

| Choice | When to use it |
| --- | --- |
| Key pair (SMART Backend Services) | What most record systems use for system to system access. The platform makes a key pair. You download its public key as a JWKS file and send it to the vendor to register with your client ID. The private key never leaves the installation. |
| Client ID and secret | The vendor gives you both. |
| An access token | The vendor gives you a fixed token. |
| No sign in | Test servers only. |

Leave the token address empty and the platform finds it in the server's SMART configuration. If the server's certificate comes from your hospital's own certificate authority, paste that authority's certificate into the connection, so the platform trusts it for this connection only.

Then press **Check the connection**. The platform signs in, checks the server offers AuditEvent, and shows a few recent records so you can see who, which patient and when look right. Choose where to start reading, and it reads new records every 30 seconds.

The platform only ever reads AuditEvent, and only from the address you entered: if the server points to another server for the next page of results, the platform refuses and says so.

### C. Upload a report

If you cannot get database or FHIR access, export the audit or access report from your patient record system as a spreadsheet and upload it under **Sources**, **Upload a report**. You match the columns once; the platform remembers the matching for the next file with the same columns. Uploading the same report twice does not store anything twice. The file itself is deleted once it is imported.

Uploads are a good start, but they are only as current as the last upload. A database or FHIR connection watches continuously.

## 5. Connect routers, firewalls and servers

Most routers, firewalls and servers can send their logs to another computer, a setting usually called syslog or remote logging. Nothing is installed on them.

1. In the device's settings, enter this computer's address and port 514. **Sources**, **Routers, firewalls and servers** shows the address and has short guides for FortiGate, pfSense, OPNsense, MikroTik, Cisco ASA, OpenWrt, Ubiquiti, Sophos and Linux servers.
2. Within a minute the device appears in the list as waiting, with the kind of log the platform recognised.
3. Give it a name and **Accept** it.

Only logs from accepted devices are kept, because anyone on the network can send syslog. Logs a device sent before you accepted it are not kept. If a device sends something the platform cannot read, the page shows its last such message, so you can see what it sends.

The platform reads connections that were blocked or allowed (FortiGate, pfSense and OPNsense, Cisco ASA, MikroTik, OpenWrt and other Linux based routers, Ubiquiti, Sophos and other key and value formats), VPN sign ins from FortiGate, and secure shell, sudo and scheduled job messages from Linux servers. It works out from the inventory whether an address is a server, a medical device or a ward computer, so the network rules apply, such as a scan of internal addresses or a medical device talking to the internet.

Docker must pass on each device's own address. The standard Docker Engine on Linux does. Docker Desktop and rootless Docker do not, and the page warns you if every device seems to come from one address.

## 6. Connect Windows computers

A small collector on each Windows computer sends its security events: sign ins and failed sign ins, accounts created and added to groups, special privileges, programs started with their command lines, scheduled tasks created, services stopped or installed, and the security log being cleared. It is a PowerShell script and a C# file that Windows compiles itself. Nothing else is installed.

1. Under **Sources**, **Windows computers**, make a group, for example one per ward. Each group has its own secret, so one group can be switched off without touching the others.
2. Download the group's installer. It is one file that holds the group's secret, so keep it like a password and delete it once the computers are set up.
3. On each computer, open PowerShell with **Run as administrator** in the folder with the installer and run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\install_healthcare_threat_monitor_<group>.ps1
   ```

   For many computers, your IT team can run the same file through Group Policy, Intune or any tool that runs a script as administrator.

The installer copies the collector to `C:\ProgramData\HealthcareThreatMonitor`, which only SYSTEM and administrators can open. It turns on the Windows auditing the platform reads, including the command line of new processes. Add `-SkipAuditPolicy` if Group Policy already sets auditing. It registers a scheduled task that runs every minute as SYSTEM, runs it once, and shows the result.

On the first run the collector sends the last day of events, then only what is new. If the network is down, nothing is lost: the next run sends it. Each computer trusts only this installation's own certificate authority for this connection, and nothing is added to the computer's list of trusted authorities.

Name computers in your inventory exactly as Windows names them, so alerts can say what each computer is for. The Windows computers page lists computers that are not in the inventory. To remove the collector from a computer, run `C:\ProgramData\HealthcareThreatMonitor\uninstall.ps1` as administrator.

## 7. The learning period

Every hospital is different. For the first 7 days after each kind of log starts arriving, the platform learns what is normal in your hospital: which addresses and domains are usual, and how much each person and computer normally does. During that time it reports clear signs of attack straight away, such as backups being deleted, a ransom note, a cleared security log, a port scan or a flagged patient's record being opened. Activity that is only unusual is reported once learning ends.

**Sources** shows each kind of log's learning, with **Finish now** to end it early and **Learn again** after a big change. The overview says when learning is under way. Change the length under **Settings**, **Learning**. Zero switches learning off.

If an intruder is already inside during the learning period, what they do may be learned as normal. Clear signs of attack are still reported, and you can **Learn again** once the hospital is clean.

## 8. Day to day

- **Sources** shows whether every connection, device, Windows group and upload is working, and how learning is going.
- **Overview** and **Incidents** show what the platform found. Every response, such as isolating a machine, is approved by a person and recorded in the audit log.
- Invite colleagues under **Settings**, **Users**. Analysts can review and respond; only administrators change settings and connections.

This installation has no simulated hospital, no test attacks and no public demo login. The console requires everyone to sign in.

## Backups

Back up two things, and keep them together and somewhere safe. The secrets file unlocks the stored database passwords, FHIR secrets and keys, and every account's authenticator, and Windows group secrets are made from it, so treat it like a password.

Backups are not yet made with clicks. On the appliance, sign in for maintenance (Alt and F2, user `htm`), then:

```bash
cd /opt/htm
sudo docker compose exec -T db pg_dump -U htm -d htm --format=custom > htm-database.dump
sudo docker compose run --rm --no-deps -T secrets tar -C /secrets -cf - . > htm-secrets.tar
```

Copy both files off the computer, for example to a USB stick, and delete them from it. On a Docker installation, run the same two commands in the repository folder.

To restore onto a fresh installation, restore the secrets **first**, then the database. The first command removes everything the fresh installation made, so only use this on a new installation. On an appliance, sign in for maintenance, go to `/opt/htm` and put `sudo` before each command; on Docker, run them in the repository folder.

```bash
docker compose down --volumes
docker compose run --rm --no-deps -T secrets tar -C /secrets -xf - < htm-secrets.tar
docker compose up -d db
docker compose exec -T db pg_restore -U htm -d htm --clean --if-exists --no-owner < htm-database.dump
docker compose up -d
```

On Docker, put `HTM_HOSTNAME=10.0.0.5` before the last command, as when installing.

A database backup restored without its secrets still opens, but every account must set up its authenticator again, every records database or FHIR connection must have its password, secret or key entered again, and every Windows computer must be set up again with a new installer. The connection says so on the Sources page.

## Updating

Updating is not yet done with clicks. To move an appliance to a new version: take a backup as above, install the new version's appliance as a new virtual machine or on the computer, restore the backup onto it, then switch the old one off. Give the new one the old one's address, or Windows computers must be set up again.

On a Docker installation, in the repository folder:

```bash
git pull
HTM_HOSTNAME=10.0.0.5 docker compose up -d --build
```

Your data, secrets, settings and connections are kept. Take a backup first.

## Stopping and removing

- Appliance: shut it down from your virtual machine software, or press the computer's power button briefly. It starts again by itself when switched on, with its data.
- Docker: `docker compose down` stops it and keeps the data. `docker compose down --volumes` removes everything, including all data and secrets, and cannot be undone.

## What has and has not been tested

Tested, end to end, on a Linux computer:

- The appliance, started in a QEMU virtual machine from a fresh copy of its disk, with BIOS: the screen showing the address and setup code, the system growing to fill a larger disk, the first administrator set up in a real browser with the code from the screen, the certificate authority download making the browser trust the installation, and the code leaving the screen once used.
- The USB installer, started in QEMU from a USB stick with UEFI and Secure Boot on, using Microsoft's keys: the disk listed without the stick, the disk number and ERASE typed at the keyboard, the copy, the stick left unchanged, and then the installed disk started on its own and set up as above.
- The full installation started from nothing over HTTPS: the redirect from http to https, the administrator account, sign in required for every page, secure session cookies.
- The setup wizard: importing departments, staff, computers and patients from spreadsheets, refusing faulty files with row numbers.
- Connecting a PostgreSQL 16 and a MariaDB 10.11 database from inside the installation: listing tables, guessing columns, reading 300 entries, picking up new ones, refusing writes, plain error messages.
- Uploading an access report, with unreadable rows explained and repeats not stored twice.
- The log receiver over UDP and TCP: a new device waiting until accepted, nothing kept before, firewall records kept after, zones worked out from the inventory, a port scan detected, the warning when Docker hides device addresses. Each log format was tested with example messages written to each vendor's documented layout.
- Windows: the console's installer, carrying this installation's root certificate, and the collector's core sending the platform real Windows event records through the HTTPS chain. Only the pinned authority was trusted; a different authority and an unpinned untrusted certificate were refused. Backups being deleted, the security log cleared and the shadow copy service stopped each raised an alert. A switched off group was refused. A Windows group's secret could not be used to send patient record entries.
- FHIR against a test FHIR server: signing in with a key pair whose signed request the server verified, finding the token address, the preview, reading 240 records and then new ones, and refusing a next page link to another server.
- The learning period: new values learned instead of reported, clear signs of attack still reported, finishing early with retraining, and everything in the audit log.
- Backup, a full restore onto an empty installation, and updating with data kept.

Not yet tested:

- The appliance in VirtualBox, VMware or Hyper-V themselves, and the USB installer on a real computer. They were tested in QEMU, which emulates a standard computer; each product's own virtual hardware, and each computer's firmware, can differ. The `.ova` and the Hyper-V file were built but not imported anywhere.
- The appliance with the official images. The appliance tested here carried compatible stand ins, because the official images could not be downloaded in our test environment. The release workflow builds each version's appliance from the official images and runs the same tests on it, with KVM, before publishing; until that has run, treat the downloads as untested.
- Backups, restoring and moving to a new version on the appliance itself. The commands are the ones tested on a Docker installation, run in `/opt/htm`.
- The maintenance sign in at the appliance's keyboard. Its password is set from the setup code on the first start, but signing in with it was not tried.
- HTTPS was tested with Caddy 2.6.2 from Ubuntu, not the official Caddy image, for the same reason. `scripts/hospital_smoke.sh` checks it against the official image on every pull request once the repository is on GitHub.
- The Windows installer, scheduled task, audit policy and event reading on a real Windows computer. Windows was not available in our test environment. A check that does all of this on a Windows computer runs on every pull request once the repository is on GitHub; until it has run, treat them as untested.
- Real routers and firewalls. The formats were tested with example messages, not captured from devices. A device that writes its logs differently may need a new reader, and the page shows what it sends.
- A real FHIR server from a record system vendor. The test server follows the FHIR and SMART standards, but each vendor has its own details.
- Docker Desktop on Windows or macOS.
- Encrypted (TLS) connections to the records database.
- Any real patient record product or vendor database. Your access log table may need columns this version does not read.
- Microsoft SQL Server and Oracle are not supported.

## Installing with Docker

For hospitals that already run Docker with the Compose plugin on a Linux server. Download the code from the project's GitHub page, then start it. Replace `10.0.0.5` with the address or name staff will type to reach this computer.

```bash
git clone <the repository address from the GitHub page>
cd <the folder it creates>
export COMPOSE_FILE=docker-compose.hospital.yml
HTM_HOSTNAME=10.0.0.5 docker compose up -d
docker compose logs setup
```

The first start builds everything and takes a few minutes. It makes its own secrets and keeps them in a private storage area on this computer. The last command prints the address to open and the setup code; continue at [step 2](#2-create-the-administrator-account). It also prints a one time link that skips the setup code, for the email in `HTM_ADMIN_EMAIL` (left out, `admin@hospital.local`).

Docker hides the addresses of devices sending logs on some setups, such as Docker Desktop. The receiver page warns when it sees this.

