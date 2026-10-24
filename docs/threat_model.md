# Threat model of the platform itself

A security platform is a target. This page states what the platform protects, who might attack it, and what stands in their way. It covers this codebase, not a hospital that deploys it.

## What is worth protecting

| Asset | Why it matters |
| --- | --- |
| The event store | Shows who accessed which patient record. In a real deployment this is sensitive. |
| The ability to isolate machines | Misused, it takes clinical systems offline. |
| The detectors and their feedback | Weakened, they stop seeing an attack. |
| The audit log | It is the record of what happened and who decided. |
| Secrets | The signing key, the sign in secret and the database connection string. |

## Who might attack, and how

### 1. An outsider on the internet

| Attempt | What stops it |
| --- | --- |
| Send fake logs to bury or frame someone | Every ingestion request needs an HMAC signature from a registered collector. Timestamps older than five minutes are refused. |
| Replay a captured request | The timestamp window, and each batch being stored only once. |
| Read the database with the public Supabase key | Row level security is on for every table and the public roles hold no privileges. A test proves it and a second test proves the first can fail. |
| Guess a password | Scrypt hashing, lockout after repeated failures, a per address rate limit, and a second factor on every account. |
| Inject script into the console | A strict content security policy with a per response nonce. All database values are rendered as text. |
| Flood the API | A per address rate limit on every API route. This is a basic control and is not a substitute for network level protection. |
| Forge a SIEM message to the built in receiver | The receiver accepts only correctly signed messages. |

### 2. A visitor to the open demo

A visitor can read the console. They cannot change anything: every change goes through a server action that requires a signed in session with the second factor passed. Analyst names are hidden from visitors.

### 3. A malicious or careless analyst

| Attempt | What limits it |
| --- | --- |
| Isolate a machine without cause | Isolation is offered only on a high confidence incident naming that machine. The approval is recorded with the analyst's name. |
| Dismiss a real attack to hide it | The decision, reason and analyst are in the audit log and forwarded to the SIEM. |
| Teach the detectors to ignore an attacker | Each change from feedback is specific to one entity, listed on the Rules page, recorded in the audit log, and can be undone. |
| Switch off a rule | Recorded in the audit log with who did it. |
| Edit the audit log | Updates and deletes are refused by a trigger. |

### 4. Someone with full database access

This attacker can remove the trigger and edit anything. The hash chain makes a changed or removed entry detectable, because every later hash stops matching. Cutting entries off the end of the log is not detectable from inside the database, so each message forwarded to the SIEM carries the newest audit hash. A copy held outside the platform exposes a truncated log.

### 5. A compromised collector

A collector can send false events for the systems it covers. It cannot read the database or create accounts. Only a collector with the respond permission can read or acknowledge isolation requests. Each collector has its own derived secret, so one can be disabled without touching the others.

### 6. Someone after a hospital installation's records connection

A hospital installation can read the access log of the hospital's patient record database. That account is worth stealing.

| Attempt | What limits it |
| --- | --- |
| Read the stored database password | It is sealed with AES 256 GCM under a key derived from `SOURCES_SECRET`, which is kept in the installation's private secrets volume, not in the database. Removing a connection deletes the sealed password. |
| Use the connection to change patient records | Every session is opened read only by the platform itself (`default_transaction_read_only` on PostgreSQL, `SET SESSION TRANSACTION READ ONLY` on MySQL and MariaDB), so writes are refused even if the account was given more than read access. Tested with an account that was allowed to write. |
| Inject SQL through a table or column name | Table and column names are only ever taken from the lists the database itself returned, and are quoted. Values are always passed as parameters. |
| Add or change a connection | Administrators only, with the second factor passed. Refused while the public demo login is on. Recorded in the audit log. |
| Read staff and patient identifiers in the console | A hospital installation requires sign in for every console page, and the landing page sends visitors to sign in. |
| Plant fake events through the test scenarios | Scenarios are refused on an installation with the simulator off, by the console page, the server action and the background service. |

### 7. Someone faking or flooding router, firewall and server logs

Syslog carries no proof of who sent it, so the built in receiver is the easiest place to feed the platform false logs.

| Attempt | What limits it |
| --- | --- |
| Send made up logs from a new address | Nothing from a new address is kept until an administrator accepts it. Accepting, blocking and removing are recorded in the audit log. |
| Flood the receiver | Each device is capped per minute (`receiver.sender_per_minute`), each message is cut to `receiver.max_message_bytes`, at most 200 TCP connections are served at once, and at most 100,000 records wait to be stored. Drops are counted and shown. |
| Inject code or SQL through a log message | Messages are parsed by fixed patterns into plain values, and every value is stored as a parameter. A message the platform cannot read is kept only as a short sample for administrators. |

### 8. Someone with a Windows computer's collector secret

Each group of Windows computers shares one secret, kept in `C:\ProgramData\HealthcareThreatMonitor`, which only SYSTEM and administrators can open.

| Attempt | What limits it |
| --- | --- |
| Use the secret to send other kinds of records, such as patient record entries | A Windows group's collector may only send Windows events. Anything else is refused and counted. Tested. |
| Keep sending after the computer is lost | Switching the group off in the console refuses its events at once. |
| Read the secret from the installer | The installer can only be downloaded by a signed in administrator, and every download is in the audit log. The page tells administrators to delete it once computers are set up. |
| Intercept the collector's connection | The collector trusts only the installation's own certificate authority, carried in its configuration, for this connection. Nothing is added to the computer's trusted authorities. Tested with a right authority, a wrong one and none. |
| Send events that hide an attack | Every collector can send false events for the systems it covers, as in section 5. |

### 9. Someone after a FHIR connection

| Attempt | What limits it |
| --- | --- |
| Read the stored FHIR secret, token or private key | Each is sealed with `SOURCES_SECRET`, like database passwords. For a key pair only the public half is ever shown. Removing the connection deletes it. |
| Use the platform to make requests to other servers | Data is only ever read from the address the administrator entered: a next page link to any other server is refused. Tested. The token address may be another server, as sign in services often are, and is set by an administrator or the FHIR server's own SMART configuration. |
| Change patient records through the connection | The platform only ever sends GET requests for AuditEvent and the server's description, and asks for a read scope. |

### 10. Someone who acts during the learning period

| Attempt | What limits it |
| --- | --- |
| Act while the platform learns what is normal, so it is learned as normal | Clear signs of attack are reported during learning. Learning only stops new values and unusual activity from being reported. An administrator can learn again once the hospital is clean. |
| Switch learning on or off to hide something | Starting, finishing and learning again are recorded in the audit log with who did it. The length is a setting, and changing it is audited like any other setting. |

### 11. Someone on the hospital network when an appliance is new

| Attempt | What limits it |
| --- | --- |
| Reach a new installation before the hospital does and become its administrator | Until the first administrator is set up, every page leads to one setup page, which needs the ten character setup code shown only on the installation's own screen. Wrong codes are rate limited per address. The database holds only a hash of the code; the code itself is kept in the private secrets storage, for the screen. The page closes for good once an administrator exists. Claiming it is recorded in the audit log. |
| Guess the setup code | 31 possible characters in 10 places, about 8 x 10^14 codes, with tries limited per minute. |
| Sign in to the appliance itself | There is no remote sign in: no SSH or other remote shell is installed. The maintenance account `htm` signs in only at the installation's own keyboard or serial console, its first password is the setup code, and it must be changed at first sign in. The `root` account is locked. |
| Start the computer from the USB installer to wipe or copy it | The installer erases nothing until a disk number and the word ERASE are typed at the computer's own keyboard. Physical access to the computer is outside this model. |

## Known gaps

- The console connects to the database with one privileged connection. A narrower role for reads would shrink the impact of a flaw in the console.
- The built in simulator holds the respond permission so the demo works. In a real deployment, remove it from every collector except the endpoint connector.
- The webhook connector trusts the address it is given. Point it only at a system you control, over TLS.
- Rate limits are counted in the database, per address. An attacker with many addresses is not slowed.
- Rule definitions accept regular expressions written by signed in analysts. A badly written pattern could slow detection.
- Landing page pictures are uploaded by administrators and shown to every visitor. Only JPEG, PNG and WebP are accepted, judged by the file's own bytes, and each is served with a fixed type and a policy that stops a browser treating it as a page. Pictures are published exactly as uploaded, so any metadata inside a file, such as a camera location, is published with it.
- The public demo login, when switched on, lets anyone act as one shared demo account. It can launch scenarios and isolate or release machines, and nothing else. Every other action and page checks for a real account, so the demo is refused there exactly like an anonymous visitor. It is rate limited per address, its sessions are short, and switching `demo.enabled` off ends them all. Visitors share one simulated hospital, so one visitor can release a machine another isolated.
- The one command demo keeps its generated secrets in a Docker volume readable by its own containers. It publishes the console on this computer only, over plain http, and allows the sign in cookie without HTTPS for that reason. Publishing that port to a network without adding HTTPS would expose sign in cookies.
- Rate limits trust the first address in the `X-Forwarded-For` header. Vercel sets that header itself. A console reached directly, without a proxy that sets it, can be given a false address, which weakens per address limits.
- An administrator can point a records connection at any address and port the background service can reach, and the plain error messages say whether something answered there. This is limited to administrators and audited, but it lets an administrator probe the internal network from the platform's computer.
- A records connection with encryption switched off sends the database password and the access log unencrypted across the hospital network. Encrypted connections have not been tested yet.
- Whoever holds both the database and the secrets volume, or a backup of both, can unseal the records database password. Keep backups as carefully as the passwords themselves.
- On a hospital installation, rate limits rely on the `X-Forwarded-For` header set by the bundled Caddy server, which replaces the header a client sends unless told to trust it.
- An attacker on the hospital network can forge syslog messages that appear to come from an accepted device's address, since UDP addresses are easily faked. Network controls that stop address spoofing are the only defence.
- The receiver trusts Docker to pass on each device's own address. Docker Desktop and rootless Docker do not, and then every device looks like one. The console warns when this happens.
- A Windows group's computers share one secret. One compromised computer can send false Windows events in the name of the others in its group. Smaller groups limit this.
- The installation's root certificate is served to the internal Docker network over plain HTTP, for the console to put in installers. A root certificate is public, and only that one file is served. Its fingerprint is shown on the Windows computers page and in each installer so it can be compared.
- Anyone who can see a new installation's screen, in person or through the virtual machine software's console, can read the setup code until the administrator is set up. Set up the administrator straight after installing.
- The appliance's disk is not encrypted. Someone who takes the disk, or a copy of the virtual machine, can read the database and the secrets. Use the encryption your virtual machine software or the computer offers, and keep the computer in a locked room.
- The maintenance account's first password is the setup code, which was on the screen. It must be changed at first sign in, but until then anyone who saw the code can sign in at the keyboard.
- Appliance updates are not automatic. Operating system security updates reach an appliance only when a new version is installed.
- There is no automatic rotation of secrets.
- The platform has had no independent security review.

## Assumptions

- TLS terminates in front of the console, as it does on Vercel and on a hospital installation with its bundled Caddy server.
- The database is reachable only by the console and the background service.
- Environment variables are kept secret by the hosting providers.
