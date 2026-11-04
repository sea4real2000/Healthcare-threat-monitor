# Installing in your hospital

This guide puts Healthcare Threat Monitor on one computer inside your hospital network, watching your hospital's own systems. It is free and stays on your own computer: nothing is sent to us or to anyone else.

You do not need to program, and you do not need to type commands. You need someone who can import a virtual machine or start a computer from a USB stick, and, for the patient records connection, someone who looks after your patient record system.

## What you need

- One computer that stays on, inside the hospital network, with at least 2 processors, 4 GB of memory and 20 GB of disk. Either a virtual machine on a server you already run, or a spare computer.
- An address on the hospital network for it that does not change, so the address staff use stays the same. Ask whoever runs the network to keep one address for it (a DHCP reservation), or set a fixed address on the installation's own screen: see [A fixed network address](#a-fixed-network-address).
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

If the screen warns that the address looks like VirtualBox's private network, the virtual machine's network is not Bridged: shut it down, change it as in 1A, and start it again. If the screen says the address changed, give the computer an address that does not change, as in [A fixed network address](#a-fixed-network-address); Windows computers set up before must be set up again.

### The certificate warning

The console is served over HTTPS with a certificate made by the installation, so browsers warn the first time. Two choices:

- For a quick start, accept the warning on each browser.
- For staff use, install the installation's certificate authority on hospital computers, so the warning goes away. Sign in as an administrator, open **Sources**, **Windows computers**, and choose **Download the certificate authority (htm-root.crt)**. Give the file to whoever manages your computers to add as a trusted root. On Windows, double click it and choose Install Certificate, Local Machine, Trusted Root Certification Authorities.

If you have your own certificate or a hospital domain name, the HTTPS settings are in `docker/Caddyfile`. See caddyserver.com/docs.

### The installation's screen and maintenance sign in

The screen shows the address and whether the platform is running, and refreshes by itself. You do not need to sign in to it for day to day use.

Nothing needs to be typed on it for day to day use. Two things can be done on it: pressing **N** sets a fixed network address (below), and for maintenance only, press **Alt** and **F2** on the installation's keyboard (in VirtualBox, **Right Ctrl** and **F2**, because VirtualBox catches Alt and F2) and sign in as `htm`. The first password is shown at the bottom of the screen from the very first start; type it without the space. It must be changed at first sign in, and the screen stops showing it once it has been. Keep the new password with your other administrator passwords.

### A fixed network address

The installation asks the network for its address (DHCP). If the network cannot keep the same address for it, set one on the installation's own screen:

1. Ask whoever runs the network for a free address, the size of the network (such as `/24`), the router's address (the gateway) and the DNS servers.
2. On the installation's screen, press **N**.
3. Press **1**, then type the address with the network size, such as `192.168.1.50/24`, the router, such as `192.168.1.1`, and the DNS servers separated by spaces (press Enter to use the router). Each is checked before anything changes: the router must be on the same network as the address.
4. Type **Y** to confirm.

The new address takes effect straight away, and the platform starts again at it with a certificate made for it, which takes a minute or two. The screen then shows the new address and says it was set there. Windows computers set up at an earlier address must be set up again.

To go back to an address from the network, press **N**, then **2**, then **Y**. Pressing **N** with nothing else changes nothing.

### If the first start seems stuck

The first start loads the platform's software in five parts, and the screen says which part it is on and how long it has been going. On a normal computer it takes 5 to 15 minutes. It is safe to switch the installation off at any point: on the next start it carries on from where it was, and a part that failed to load is tried again.

If it takes much longer, the computer is running it slowly. The screen says so after 25 minutes.

- **VirtualBox on Windows.** A **green turtle** at the bottom right of the VirtualBox window means it is running without hardware acceleration, many times slower. Switch the appliance off, then in Windows open **Turn Windows features on or off** and untick **Hyper-V**, **Virtual Machine Platform** and **Windows Hypervisor Platform**. In **Windows Security**, **Device security**, **Core isolation details**, set **Memory integrity** to **Off**. Restart the computer and start the appliance again. The turtle becomes a blue chip with a V.
- **Memory.** The appliance needs 4096 MB for itself. On a laptop, close other programs while it runs.
- **Any computer.** Hardware virtualisation (Intel VT-x or AMD-V) must be switched on in the computer's firmware settings.
- **The browser says "refused to connect".** The address is right but the platform is not running yet. Wait until the screen says **Running.**, and type the address with `https://`.
- **The browser says "can't be reached" in VirtualBox over Wi-Fi.** Some Wi-Fi cards do not allow Bridged Adapter. For a test on one laptop, use **Host-only Adapter** instead and open the `192.168.56.` address it shows.

To send a log to whoever supports you: in VirtualBox, with the appliance switched off, open **Settings**, **Serial Ports**, **Port 1**, tick **Enable Serial Port**, choose **Raw File**, type a path such as `C:\Users\Public\htm-log.txt`, start the appliance, and send that file.

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

A backup holds everything: incidents, sources, settings, accounts, connections, the keys that unlock stored passwords and authenticators, and the installation's certificate authority. Restored onto a new installation, every account, connection and Windows computer keeps working.

To make one, sign in as an administrator, open **Settings**, **Backups**, choose a passphrase and press **Make the backup**. Then press **Download the backup** and copy the file somewhere off the installation, such as a USB stick or the hospital's file server.

The backup is locked with its passphrase (AES 256 GCM, with a key made from the passphrase by scrypt). Nobody can open it without the passphrase, and the passphrase is not kept anywhere, so keep it with your other administrator passwords. A finished backup waits on the installation for 24 hours to be downloaded, then is removed; change this with the `backups.keep_hours` setting. Every backup made, downloaded and restored is in the audit log.

To restore one, open **Settings**, **Backups**, **Restore a backup**, choose the file, type its passphrase and type `RESTORE` to confirm. Everything on the installation is replaced by the backup, everyone is signed out, and the installation starts again with the backup's keys, which takes a minute. Then sign in with an account from the backup.

On a new installation nobody has set up yet, the first visit page offers **Restore its backup instead**, which asks for the setup code from the screen. This is how an installation moves to a new version or a new computer, below.

A backup made by a newer version cannot be restored onto an older one: update the installation first. A backup made by an older version is brought up to date as it is restored.

### Backups without the console

If the console cannot start, a backup can still be made with commands. These copy the database and the secrets only, not the certificate authority. On the appliance, sign in for maintenance (Alt and F2, user `htm`), go to `/opt/htm` and put `sudo` before each command; on Docker, run them in the repository folder.

```bash
docker compose exec -T db pg_dump -U htm -d htm --format=custom > htm-database.dump
docker compose run --rm --no-deps -T secrets tar -C /secrets -cf - . > htm-secrets.tar
```

Copy both files off the computer and delete them from it. To restore them onto a fresh installation, restore the secrets **first**, then the database. The first command removes everything the fresh installation made, so only use this on a new installation.

```bash
docker compose down --volumes
docker compose run --rm --no-deps -T secrets tar -C /secrets -xf - < htm-secrets.tar
docker compose up -d db
docker compose exec -T db pg_restore -U htm -d htm --clean --if-exists --no-owner < htm-database.dump
docker compose up -d
```

On Docker, put `HTM_HOSTNAME=10.0.0.5` before the last command, as when installing.

## Updating

To move an appliance to a new version:

1. On the old installation, make a backup and download it, as above.
2. Install the new version's appliance as a new virtual machine or on the computer, and start it. Leave the old one running for now.
3. Open the new installation's address. On the first visit page, choose **Restore its backup instead**, type the setup code from its screen, choose the backup file, type its passphrase and `RESTORE`.
4. Sign in with your usual account and check the console.
5. Switch the old installation off, then give the new one the old one's address: ask whoever runs the network to move the address to it, or set it on the new one's screen with **N** as in [A fixed network address](#a-fixed-network-address).

Because the backup carries the certificate authority and the keys, Windows computers and browsers that trusted the old installation trust the new one, once it has the old address.

On a Docker installation, in the repository folder:

```bash
git pull
HTM_HOSTNAME=10.0.0.5 docker compose up -d --build
```

Your data, secrets, settings and connections are kept. Take a backup first.

## Stopping and removing

- Appliance: shut it down from your virtual machine software, or press the computer's power button briefly. It starts again by itself when switched on, with its data.
- Docker: `docker compose down` stops it and keeps the data. `docker compose down --volumes` removes everything, including all data and secrets, and cannot be undone.

## How it has been tested

Each of these is tested end to end:

- The appliance, started in a virtual machine from a fresh copy of its disk, with BIOS, including being switched off part way through its first start: the screen showing the address and setup code, the system growing to fill a larger disk, the first administrator set up in a real browser with the code from the screen, the certificate authority download making the browser trust the installation, and the code leaving the screen once used.
- The USB installer, started from a USB stick with UEFI and Secure Boot on, using Microsoft's keys: the disk listed without the stick, the disk number and ERASE typed at the keyboard, the copy, the stick left unchanged, and then the installed disk started on its own and set up as above.
- The full installation started from nothing over HTTPS: the redirect from http to https, the administrator account, sign in required for every page, secure session cookies.
- The setup wizard: importing departments, staff, computers and patients from spreadsheets, refusing faulty files with row numbers.
- Connecting a PostgreSQL 16 and a MariaDB 10.11 database from inside the installation: listing tables, guessing columns, reading 300 entries, picking up new ones, refusing writes, plain error messages.
- Uploading an access report, with unreadable rows explained and repeats not stored twice.
- The log receiver over UDP and TCP: a new device waiting until accepted, nothing kept before, firewall records kept after, zones worked out from the inventory, a port scan detected, the warning when Docker hides device addresses. Each log format was tested with example messages written to each vendor's documented layout.
- Windows: the console's installer, carrying this installation's root certificate, and the collector's core sending the platform real Windows event records through the HTTPS chain. Only the pinned authority was trusted; a different authority and an unpinned untrusted certificate were refused. Backups being deleted, the security log cleared and the shadow copy service stopped each raised an alert. A switched off group was refused. A Windows group's secret could not be used to send patient record entries.
- FHIR against a test FHIR server: signing in with a key pair whose signed request the server verified, finding the token address, the preview, reading 240 records and then new ones, and refusing a next page link to another server.
- The learning period: new values learned instead of reported, clear signs of attack still reported, finishing early with retraining, and everything in the audit log.
- Backups with clicks (`scripts/backup_smoke.sh`, on every pull request): a backup made through the console and downloaded, refused from another site, without signing in and with a short passphrase; the whole installation removed and a new one started with new keys and a new certificate authority; a wrong setup code and a wrong passphrase refused with nothing changed; the restore from the new installation's first visit page; and then the setting, the account, the keys and the certificate authority back, everyone signed out, the audit log verifying, the console and background service started again with the restored keys, and a computer that trusted the old certificate authority trusting the new installation with no warning.
- A security scan with ZAP of a running installation, as a visitor and signed in as an administrator, on every pull request (`scripts/zap_scan.sh`). It fails on any alert of medium risk or higher that is not accepted, with a reason proven on every run, in `security/zap_accepted.tsv`.
- The fixed network address on the appliance's screen, typed at the keyboard: a fixed address taking effect, the platform answering there, the screen saying so, and going back to an address from the network. This runs in the release workflow for each version.
- Updating a Docker installation with data kept.

### Compatibility

- **Virtual machines and computers.** The appliance is a standard virtual machine: `.ova` for VirtualBox and VMware, `.vhdx` for Hyper-V. The USB installer starts any standard computer with BIOS, or with UEFI and Secure Boot on. Every release is built from the official images and tested before it is published, as a virtual machine and installed from a USB stick.
- **Windows computers.** The collector runs on Windows PowerShell 5.1, which every supported version of Windows includes. It is installed, run and removed on a Windows computer on every change.
- **Routers and firewalls.** Cisco ASA, Fortinet FortiGate, pfSense and OPNsense, Linux netfilter (including UFW and iptables), MikroTik, Linux sign in messages, and other key=value firewall logs, as each vendor documents them. A device that writes its logs differently shows its messages on the Sources page, so a reader can be added for it.
- **Patient record systems.** A read only connection to PostgreSQL, MySQL or MariaDB, a FHIR R4 server with SMART Backend Services, or an access report uploaded as a spreadsheet. The connection page previews the rows it would read, so columns named differently can be matched. For Microsoft SQL Server or Oracle, upload an exported access report.
- **Docker installations.** Linux with Docker Engine and its Compose plugin.

Found something that does not work with your systems? Open an issue on GitHub, or report a security problem privately as [SECURITY.md](../SECURITY.md) describes.

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

