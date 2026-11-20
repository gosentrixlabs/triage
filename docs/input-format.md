# Input format (schema version 1)

`triage import` reads one JSON document. This page describes every field, how
items are matched across imports, and how the file is validated. A machine-readable
JSON Schema is in [`schema/triage-input-v1.schema.json`](../schema/triage-input-v1.schema.json).

## Document

```json
{
  "schema_version": "1",
  "source": "my-scanner",
  "items": [ ... ]
}
```

| Field            | Required | Description |
| ---------------- | -------- | ----------- |
| `schema_version` | yes      | Must be `"1"` (a string). |
| `source`         | no       | Name of the tool or process that produced the findings. Used to match items across imports, so keep it the same between runs. |
| `items`          | yes      | Array of items. Use `[]` for a file with no findings. |

## Item

| Field               | Required | Type             | Description |
| ------------------- | -------- | ---------------- | ----------- |
| `title`             | yes      | string           | Short description of the finding. |
| `severity`          | yes      | string           | One of `critical`, `high`, `medium`, `low`, `info`. |
| `source_id`         | no       | string           | Stable ID for this finding in the source tool. Must be unique within the file. Strongly recommended (see [Matching](#matching-across-imports)). |
| `description`       | no       | string           | Longer description. Line breaks are kept. |
| `location`          | no       | string           | Where the finding is, in any form: `path/file.go:42`, a URL, a resource name. |
| `rule`              | no       | string           | Rule, check or weakness ID, such as `CWE-89`. |
| `cves`              | no       | array of strings | CVE IDs in the form `CVE-YYYY-NNNN`. |
| `asset`             | no       | string           | System, service or repository the finding belongs to. |
| `exposure`          | no       | string           | `internet`, `internal`, `isolated` or `unknown`. |
| `asset_criticality` | no       | string           | `high`, `medium`, `low` or `unknown`. |
| `known_exploited`   | no       | boolean          | Whether the vulnerability is known to be exploited in the wild, according to a source you trust. Leave it out if you don't know. |
| `metadata`          | no       | object           | Extra string values, shown by `show` and included in `export`. Not used for prioritization. |

Enumerated values are accepted in any letter case and stored in lowercase.
Leading and trailing spaces are removed from strings. CVE IDs are stored in
uppercase.

`exposure`, `asset_criticality` and `known_exploited` affect priority. Leaving
them out never raises or lowers an item's score, and `triage explain` says the
value was not given. See [prioritization.md](prioritization.md).

## Matching across imports

You can import the same or updated files repeatedly. Each item is matched to
one already in the workspace like this:

- **With a `source_id`:** same `source` and same `source_id`.
- **Without a `source_id`:** same `source`, `title`, `location`, `rule` and
  set of `cves`.

A matched item is updated with the new data and keeps its ID, status and
decision history. If the data changed and the item already has a decision,
`import` lists it so someone can check the decision still holds. Items that
don't match anything are added as new.

Without a `source_id`, changing the title or moving the finding to a new line
makes it a new item. Use a stable `source_id` whenever the source tool provides
one.

Items missing from a later file are left as they are.

## Validation

The whole file is checked before anything is written. If anything is wrong,
nothing is imported and every problem is listed with its position, for example:

```text
triage import: invalid input (2 problems):
  - items[0]: severity "severe" is not one of critical, high, medium, low, info
  - items[3]: "CVE-21-1" is not a CVE ID (expected CVE-YYYY-NNNN)
```

The file is rejected if:

- it is not a single JSON object, or has data after the object
- it contains a field not listed on this page (this catches typos such as
  `severty`)
- `schema_version` is missing or not `"1"`, or `items` is missing
- an item has no `title` or `severity`, or an enumerated field has another value
- a CVE ID is malformed
- two items share a `source_id`, or two items without a `source_id` match each
  other under the rules above
- it is larger than 64 MiB

## Example

[`examples/findings.json`](../examples/findings.json) uses every field.
