# Contributing

Thank you for helping. A few rules keep the project consistent.

## Reporting a bug or asking for a feature

Open an issue on GitHub at https://github.com/sea4real2000/Healthcare-threat-monitor/issues. Say what you did, what you expected and what happened instead, and include the version from the release you installed. Issues are public, so never include patient data, passwords or anything from a real hospital. Security problems are reported privately instead, as described in [SECURITY.md](SECURITY.md).

Issues and pull requests are written in English.

## Tests for new functionality

Every new feature or connection comes with automated tests in the same pull request, and every bug fix comes with a test that fails without the fix. A pull request that adds behaviour without tests is not merged. The checks in `.github/workflows/ci.yml` run on every pull request and must all pass.

## Before you open a pull request

1. Run the tests listed in the README. All of them must pass.
2. If you add a table, call `select htm_lockdown();` at the end of the migration so the table is locked by default.
3. Migrations are numbered, are never edited after they are merged, and must be safe to run twice.
4. Nothing a user reads is written in code. Labels and sentences go in the `copy` table, and limits and other values go in the `settings` table, both through a migration. `node scripts/check_copy.mjs` finds any label you forgot to seed.
5. Never commit a secret, a real hostname, or data about a real person. The simulator is the only source of data.

## Adding a log source

1. Add a row to the `sources` table in a new migration.
2. Add a mapper in `web/lib/normalize/sources.ts` and register it at the bottom of the file.
3. Add tests for it in `web/tests/normalize.test.ts`, including a record it should reject.
4. Add an activity to `engine/simulator/generators.py` so the simulator can emit it.

## Adding a detection rule

Most rules need no code. Add the rule from the console, or add a row to the `rules` table in a new migration so everyone gets it. `docs/detection.md` explains the three kinds of rule. If the rule covers a new attack behaviour, add a step to a scenario in `engine/simulator/scenarios.py` and run the evaluation to show it fires.

## Changing detection

Run `python -m evaluate` before and after, with the same seed, and include both sets of numbers in the pull request. A change that raises detection by flooding the analyst queue is not an improvement.

## Style

Plain sentences in comments and documents. Keep changes small enough to deploy and verify on their own.

## License

By contributing you agree that your contribution is licensed under the Apache License, Version 2.0.
