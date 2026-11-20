# triage

Turn security findings into a priority queue you can explain, and record what
people decide about each item.

`triage` is a small command-line tool. You import findings from a JSON file,
and it ranks them with a few explicit rules. For any item, it shows the points
each rule contributed and why. A person then records a decision on each item
(confirmed, dismissed, deferred or duplicate) along with a reason. Everything
is stored in a local directory and can be exported as JSON.

> **Status: early (v0.1).** The commands, input format and export format may
> change before 1.0. Changes will be noted in the release notes.

## What it does and doesn't do

| Area                | v0.1                                                                       |
| ------------------- | -------------------------------------------------------------------------- |
| Input               | One documented JSON format ([docs/input-format.md](docs/input-format.md))  |
| Storage             | A local workspace directory (`.triage` by default)                         |
| Prioritization      | Fixed, explicit rules, each giving a reason ([docs/prioritization.md](docs/prioritization.md)) |
| Decisions           | Confirm, dismiss, defer, or mark as duplicate, always with a reason       |
| Output              | Terminal views and JSON export                                             |
| Network access      | None. `triage` makes no network calls.                                     |
| Changes to other systems | None. It does not create tickets, comment on pull requests or call other tools. |

It does not use AI to make or suggest decisions, and there is no hosted
service. Every decision is made by a person and recorded with their reason.

## Install

With Go 1.24 or later:

```bash
go install github.com/gosentrixlabs/triage/cmd/triage@latest
```

Or build from source:

```bash
git clone https://github.com/gosentrixlabs/triage.git
cd triage
go build ./cmd/triage
```

`triage` uses only the Go standard library. It has no third-party dependencies.

## Quick start

The `examples/` directory has two sample files: an initial scan, and a later
rescan of the same systems.

```bash
triage import examples/findings.json
```

```text
Created workspace .triage
Imported 8 items from examples/findings.json: 8 new, 0 updated, 0 unchanged.
Run "triage list --status new" to see the queue.
```

View the queue, highest priority first:

```bash
triage list --status new
```

```text
ID  PRIORITY  SCORE  STATUS  SEVERITY  TITLE                                                      LOCATION
1   P1        105    new     critical  Log4Shell remote code execution in log4j-core 2.14.1       payments-api/pom.xml
4   P1        80     new     critical  Spring4Shell remote code execution in spring-beans 5.3.17  reporting-service/build.gradle
2   P2        60     new     high      SQL injection in order search                              payments-api/src/orders/search.go:88
3   P2        45     new     medium    Tainted query parameter reaches database call              payments-api/src/orders/search.go:91
5   P3        35     new     high      Hard-coded database password in worker configuration       batch-worker/config/settings.yaml:14
6   P3        35     new     medium    TLS 1.0 still enabled on public load balancer              infra/load-balancer.tf:42
8   P4        5      new     medium    Debug endpoint enabled in offline batch environment        batch-worker/config/app.yaml:3
7   P4        5      new     low       Stack traces returned in error responses                   reporting-service/src/errors.py:31

Showing 8 of 8 items.
```

See why an item got its priority:

```bash
triage explain 1
```

```text
Item 1: Log4Shell remote code execution in log4j-core 2.14.1
Priority P1, score 105.

  POINTS  RULE               REASON
     +50  severity           Severity is critical
     +30  known-exploited    Input marks this as known to be exploited
     +15  exposure           Reachable from the internet
     +10  asset-criticality  Asset criticality is high
     105  total

Bands: P1 is 70 or more, P2 is 45 to 69, P3 is 20 to 44, P4 is below 20.
The rules are described in docs/prioritization.md.
```

Record decisions:

```bash
triage decide 2 --status confirmed --reason "Reproduced on staging"
triage decide 3 --status duplicate --duplicate-of 2 --reason "Same handler as item 2"
triage decide 5 --status deferred --reason "Owner is away until Monday"
```

Import the rescan. Items already in the workspace are matched and updated, and
they keep their decisions. If an item that already has a decision changes,
`triage` lists it so someone can check the decision still holds:

```bash
triage import examples/findings-rescan.json
```

```text
Imported 3 items from examples/findings-rescan.json: 1 new, 1 updated, 1 unchanged.
Changed after a decision: item 5. Run "triage show <id>" to check each decision still holds.
Run "triage list --status new" to see the queue.
```

`triage show 5` now shows the new data, the decision history, and a note that
the finding changed after the last decision.

Export everything, including each item's priority factors and decision history:

```bash
triage export --format json --output triage-export.json
```

## Commands

| Command                                      | What it does                                         |
| -------------------------------------------- | ---------------------------------------------------- |
| `triage import <file>`                       | Import findings. Use `-` to read standard input.      |
| `triage list [--status S] [--priority P]`    | List items in priority order, optionally filtered.    |
| `triage show <id>`                           | Show an item's finding, priority, status and decisions. |
| `triage explain <id>`                        | Show each rule's points and reason.                   |
| `triage decide <id> --status S --reason TEXT` | Record a decision. `--duplicate-of ID` for duplicates. |
| `triage export [--format json] [--output FILE]` | Export items, priorities and decisions.            |
| `triage help [command]`                      | Show help.                                            |

Flags can come before or after the item ID. `--status` and `--priority` on
`list` take comma-separated values, for example `--status new,deferred`.

Exit codes: `0` success, `1` error (such as invalid input or an unknown item),
`2` the command was used incorrectly.

## Input format

```json
{
  "schema_version": "1",
  "source": "my-scanner",
  "items": [
    {
      "source_id": "SAST-0142",
      "title": "SQL injection in order search",
      "severity": "high",
      "location": "src/orders/search.go:88",
      "rule": "CWE-89",
      "asset": "payments-api",
      "exposure": "internet",
      "asset_criticality": "high",
      "known_exploited": false
    }
  ]
}
```

Only `title` and `severity` are required on each item. The full field
reference, the matching rules for repeat imports, and the validation behaviour
are in [docs/input-format.md](docs/input-format.md). A JSON Schema is in
[schema/triage-input-v1.schema.json](schema/triage-input-v1.schema.json).

To triage output from another tool, convert it to this format first, for
example with `jq` or a short script.

## How priority is calculated

Four rules each add or subtract points. The total maps to a band.

| Rule              | Points                                                         |
| ----------------- | -------------------------------------------------------------- |
| severity          | critical +50, high +35, medium +20, low +10, info 0            |
| known-exploited   | +30 if the input marks it as known exploited, otherwise 0      |
| exposure          | internet +15, internal 0, isolated −10, unknown or not given 0 |
| asset-criticality | high +10, medium 0, low −5, unknown or not given 0             |

| Band | Score       |
| ---- | ----------- |
| P1   | 70 or more  |
| P2   | 45 to 69    |
| P3   | 20 to 44    |
| P4   | below 20    |

`triage` only uses what the input says. It does not look up exploitation data
or exposure itself. See [docs/prioritization.md](docs/prioritization.md) for
the reasoning and worked examples.

## The workspace

- By default the workspace is `.triage` in the current directory. Use
  `--workspace DIR` or set `TRIAGE_WORKSPACE` to use another one.
- State is one JSON file, `.triage/state.json`. It is replaced atomically on
  every change, so an interrupted command never leaves it half-written.
- The directory and its files are readable only by your user, because findings
  are often sensitive.
- You can commit `.triage/state.json` to a repository to share decisions.
  `triage` treats its contents as untrusted when displaying them.
- One command at a time can change a workspace. If a command is interrupted
  and leaves `.triage/lock` behind, delete that file.

## Known limitations

- Importing a later file does not remove or flag items that are missing from
  it. Mark fixed or retired items yourself, for example as dismissed.
- The rules and their points are fixed. Changing them means changing the code.
- Priority is calculated when you view or export an item, from its current
  data, so a future release that changes the rules will change priorities.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a
security issue, follow [SECURITY.md](SECURITY.md) instead of opening a public
issue.

## License

Apache License 2.0. See [LICENSE](LICENSE).

Maintained by [GoSentrix Labs](https://gosentrix.com).
