# CyberSleuth AI — Member 4 Synthetic Security Dataset

## Purpose

A small, deterministic starter dataset for defensive testing of CyberSleuth AI. It contains benign events, suspicious sequences, malformed records, and adversarial instruction-like text embedded in logs.

## Safety and scope

* All usernames and hosts are fictional.
* IP addresses use documentation/test ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
* This is synthetic data, not evidence of real activity.
* Labels are scenario-level ground truth for testing. A `suspicious` label means the pattern should be investigated, not that a compromise is proven.
* The `invalid\\\_input` scenarios are for ingestion/schema validation, not threat-classification metrics.
* The prompt-injection scenario checks that log contents are treated as untrusted data.

## Files

* `all\\\_events.json` / `all\\\_events.csv`: all event records.
* `benign\\\_events.json`: benign scenario events.
* `suspicious\\\_events.json`: suspicious scenario events.
* `invalid\\\_input\\\_events.json`: malformed inputs.
* `adversarial\\\_input\\\_events.json`: instruction-like text embedded in a log.
* `scenario\\\_definitions.json`: scenario descriptions and expected outcomes.

## Important implementation note

Agree the schema with Member 2 before integrating. In particular, `SCN007` has an intentionally malformed timestamp, `SCN008` contains a duplicate event ID, and `SCN012` is missing `event\\\_type`. These are deliberate test fixtures; do not silently repair them in the raw test data.

## Suggested next steps

1. Run schema/ingestion tests against the invalid input scenarios.
2. Connect the valid scenarios to the actual detection function/API.
3. Keep expected outcomes separate from observed results.
4. Calculate precision/recall only on a clearly defined labeled set of valid cases, not on malformed-input tests.

