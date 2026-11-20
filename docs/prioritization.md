# How priority is calculated

`triage` gives every item a score and a priority band (P1 to P4). The score is
the sum of the points from four rules. Every rule reports a factor for every
item, even when it adds nothing, so `triage explain` accounts for every input
the score depends on.

The rules are defined in
[`internal/priority/priority.go`](../internal/priority/priority.go). Keep this
page in step with that file.

## Rules

### severity

| Severity | Points |
| -------- | ------ |
| critical | +50    |
| high     | +35    |
| medium   | +20    |
| low      | +10    |
| info     | 0      |

Severity is the starting point. On its own, a critical finding lands in P2 and
a high finding in P3. The other rules decide whether it moves up or down.

### known-exploited

| `known_exploited` | Points |
| ----------------- | ------ |
| `true`            | +30    |
| `false`           | 0      |
| not given         | 0      |

Known exploitation is the strongest single signal. A critical finding that is
known to be exploited reaches P1 even with no other information.

### exposure

| `exposure`          | Points |
| ------------------- | ------ |
| `internet`          | +15    |
| `internal`          | 0      |
| `isolated`          | −10    |
| `unknown` or not given | 0   |

### asset-criticality

| `asset_criticality` | Points |
| ------------------- | ------ |
| `high`              | +10    |
| `medium`            | 0      |
| `low`               | −5     |
| `unknown` or not given | 0   |

## Bands

| Band | Score      |
| ---- | ---------- |
| P1   | 70 or more |
| P2   | 45 to 69   |
| P3   | 20 to 44   |
| P4   | below 20   |

Within the queue, items are ordered by score (highest first), then by
severity, then by ID.

## Worked examples

| Item                                                  | Points               | Score | Band |
| ----------------------------------------------------- | -------------------- | ----- | ---- |
| critical, known exploited, internet, high criticality | 50 + 30 + 15 + 10    | 105   | P1   |
| critical, known exploited, isolated                   | 50 + 30 − 10         | 70    | P1   |
| critical, nothing else given                          | 50                   | 50    | P2   |
| high, internet                                        | 35 + 15              | 50    | P2   |
| medium, known exploited, low criticality              | 20 + 30 − 5          | 45    | P2   |
| high, internal                                        | 35                   | 35    | P3   |
| low, nothing else given                               | 10                   | 10    | P4   |
| info, isolated, low criticality                       | 0 − 10 − 5           | −15   | P4   |

## Design choices

- **The rules only use what the input says.** `triage` does not look up
  exploitation data, exposure or asset inventories. If you want those signals,
  add them to the input file from a source you trust. This keeps every score
  reproducible from the input alone, and `triage` makes no network calls.
- **Missing information adds nothing.** A field that isn't given neither raises
  nor lowers the score, and the explanation says it was not given. This makes
  the gaps visible without guessing.
- **The rules are fixed.** There is no configuration file in v0.1, so a given
  input always produces the same priority for everyone using the same version.
- **Decisions don't change priority.** A dismissed item keeps its score so you
  can compare it with the rest of the queue. Use `list --status` to hide
  decided items.
- **Priority is calculated when it's shown.** Scores are not stored. If a
  future release changes the rules, existing workspaces show the new
  priorities, and `export` records the factors that applied at export time.
