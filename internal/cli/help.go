package cli

const mainHelp = `triage turns security findings into a priority queue you can explain, and
records the decisions people make about each item.

Usage:
  triage <command> [arguments] [flags]

Commands:
  import    Import findings from a JSON file
  list      List items in priority order
  show      Show one item in full
  explain   Explain why an item has its priority
  decide    Record a triage decision
  export    Export items, priorities and decisions
  version   Print the version
  help      Show help for a command

Every command that uses a workspace accepts --workspace DIR. Without it, triage
uses $TRIAGE_WORKSPACE, or .triage in the current directory.

Run "triage help <command>" for details. The input format is described in
docs/input-format.md.
`

const importHelp = `Usage: triage import <file> [--workspace DIR]

Import findings from a JSON file in the triage input format (schema version 1).
Use - as the file to read from standard input. Creates the workspace if it does
not exist yet.

Importing is repeatable. An item matching one already in the workspace (same
source and source_id, or, without a source_id, same source, title, location,
rule and CVEs) is updated in place and keeps its status and decisions. If an
item that already has a decision changes, import lists it so you can check
the decision still holds.

The whole file is validated before anything is written. If any item is
invalid, nothing is imported and every problem is listed.

Flags:
  --workspace DIR   Workspace directory (default .triage)
`

const listHelp = `Usage: triage list [--status S] [--priority P] [--workspace DIR]

List items, highest priority first. Ties are ordered by severity, then ID.

Flags:
  --status S        Show only these statuses, comma-separated:
                    new, confirmed, dismissed, deferred, duplicate
  --priority P      Show only these priority bands, comma-separated: P1, P2, P3, P4
  --workspace DIR   Workspace directory (default .triage)

Examples:
  triage list --status new
  triage list --status new,deferred --priority P1,P2
`

const showHelp = `Usage: triage show <id> [--workspace DIR]

Show everything recorded for one item: the finding, its priority, its status,
and every decision made about it.

Flags:
  --workspace DIR   Workspace directory (default .triage)
`

const explainHelp = `Usage: triage explain <id> [--workspace DIR]

Show how an item's priority was calculated. Each rule contributes points with
a reason, the points add up to the score, and the score maps to a band:

  P1   70 or more
  P2   45 to 69
  P3   20 to 44
  P4   below 20

The rules are described in docs/prioritization.md.

Flags:
  --workspace DIR   Workspace directory (default .triage)
`

const decideHelp = `Usage: triage decide <id> --status S --reason TEXT [flags]

Record a triage decision. The item's status changes and the decision is added
to its history; earlier decisions are kept.

Statuses:
  confirmed   The finding is real and needs action
  dismissed   The finding does not need action (false positive, accepted, not applicable)
  deferred    Decide later
  duplicate   Another item covers the same problem (needs --duplicate-of)

Flags:
  --status S          Required. One of the statuses above. The verbs confirm,
                      dismiss and defer also work.
  --reason TEXT       Required. Why the decision was made.
  --duplicate-of ID   The item this one duplicates. Required for duplicate.
  --by NAME           Who made the decision (default: your username)
  --workspace DIR     Workspace directory (default .triage)

Examples:
  triage decide 3 --status confirmed --reason "Reproduced on staging"
  triage decide 7 --status duplicate --duplicate-of 3 --reason "Same handler"
`

const exportHelp = `Usage: triage export [--format json] [--output FILE] [--workspace DIR]

Export every item with its finding, priority (including each rule's points and
reason), status and decision history. Items are ordered by ID so exports diff
cleanly.

Flags:
  --format json     Output format. Only json is supported.
  --output FILE     Write to FILE instead of standard output
  --workspace DIR   Workspace directory (default .triage)
`

const versionHelp = `Usage: triage version

Print the version of triage.
`
