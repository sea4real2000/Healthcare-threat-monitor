# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use the "Report a vulnerability" button under the Security tab of this repository, which opens a private advisory that only the maintainers can see.

Include what you found, how to reproduce it, and what an attacker could do with it. We aim to reply within five working days.

## What is in place

- **Signed ingestion.** Every write from a collector carries an HMAC SHA256 signature over the time, method, path and body. Requests more than five minutes old are refused.
- **No stored collector secrets.** Collector secrets are derived from one server key and are never written to the database.
- **Replay safe.** A batch sent twice is stored once, and an event sent twice is stored once.
- **Default deny database.** Row level security is on for every table and the public Supabase roles hold no table privileges. The console reads on the server only.
- **Sign in with two factors.** Passwords are hashed with scrypt. Every account needs a code from an authenticator app, and a code cannot be used twice. Authenticator secrets are encrypted at rest. Accounts lock after repeated failures.
- **Sessions.** Only a hash of each session token is stored. Cookies are HTTP only. Sessions expire, and end early when idle.
- **Every change is authorised and recorded.** Each console action checks the signed in user, then makes the change and writes the audit entry in one transaction.
- **Tamper evident audit log.** Entries are hash chained. Updates and deletes are refused by a trigger. An exported log can be verified with a standalone script.
- **Least privilege for connectors.** Only a collector with the respond permission can read or acknowledge isolation requests.
- **Human approval for isolation.** Isolation is offered only on a high confidence incident, and high confidence needs two independent log sources.
- **Content security policy.** Scripts run only with a nonce made for that one response.
- **Rate limits.** Per address limits on API routes and on sign in.
- **Input limits.** Body size, batch size and identifier formats are checked before anything is parsed or stored.
- **No secrets in the repository.** Configuration comes from environment variables.

The full analysis, including known gaps, is in [docs/threat_model.md](docs/threat_model.md).

## Using this safely

- Treat every value in `.env.example` like a password. Rotate `INGEST_SIGNING_KEY` if it is ever exposed. Every collector secret changes with it.
- Turn on secret scanning and push protection in the repository settings.
- Keep the database reachable only by the console and the background service.
- This project is a research prototype running on simulated data. It has not been assessed for use with real patient information and has had no independent security review.
