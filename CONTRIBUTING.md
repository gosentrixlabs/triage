# Contributing to triage

Thanks for helping. This guide covers how to propose changes and what a change
needs before it can be merged.

## Before you start

- **Bugs:** open an issue with the command you ran, what you expected, and what
  happened. Include a small input file if you can. Remove anything sensitive
  from findings first.
- **Features and larger changes:** open an issue to discuss the idea before
  writing code. `triage` keeps a deliberately small scope (see "What it does
  and doesn't do" in the [README](README.md)), so it's worth agreeing on the
  approach first.
- **Security issues:** don't open a public issue. Follow [SECURITY.md](SECURITY.md).

## Development setup

You need Go 1.24 or later. There are no other dependencies.

```bash
git clone https://github.com/gosentrixlabs/triage.git
cd triage
go test ./...
go run ./cmd/triage help
```

Before you open a pull request, run:

```bash
gofmt -l .
go vet ./...
go test -race ./...
```

`gofmt -l .` must print nothing. CI runs the same checks on Linux, macOS and
Windows.

## Code layout

| Path                  | Contents |
| --------------------- | -------- |
| `cmd/triage`          | Entry point |
| `internal/cli`        | Commands, help text, terminal output |
| `internal/input`      | Input format parsing and validation |
| `internal/priority`   | Prioritization rules |
| `internal/workspace`  | Workspace storage, import matching, decisions |
| `schema/`             | JSON Schema for the input format |
| `docs/`               | Input format and prioritization reference |
| `examples/`           | Sample input files, also used by the tests |

## What a change needs

- **Tests.** New behaviour needs tests, and bug fixes need a test that fails
  without the fix. CLI behaviour is tested end to end in
  `internal/cli/cli_test.go`.
- **Docs that match the code.** Several things are documented in more than one
  place:
  - Changing a rule or its points means updating `docs/prioritization.md` and
    the table in the README.
  - Changing the input format means updating `docs/input-format.md` and the
    JSON Schema. `TestSchemaMatchesParser` checks that the schema agrees with
    the parser.
  - Changing a command or flag means updating its help text in
    `internal/cli/help.go` and the README.
- **No new dependencies** without discussing it in an issue first. `triage`
  uses only the Go standard library, which keeps it easy to audit and install.
- **No network access.** `triage` makes no network calls, and documentation
  says so. A change that needs network access needs an issue first.
- **Safe output.** Finding data comes from other tools and shared files, so
  treat it as untrusted. Pass any finding or decision text through `cleanLine`
  or `cleanText` (in `internal/cli/output.go`) before printing it to the
  terminal.
- **Versioned formats.** The input format (`schema_version`), the workspace
  state (`version`) and the export (`format_version`) are versioned. A change
  that older files or readers can't handle needs a version bump and a note in
  the pull request.

## Pull requests

- Keep each pull request to one change.
- Explain what changed and why in the description, and link the issue.
- Write commit messages that say what the commit does, in the imperative
  ("Reject duplicate source IDs"), with detail in the body if needed.

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
