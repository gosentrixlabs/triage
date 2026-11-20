// Package input reads and validates the triage input format (schema version 1).
//
// The format is documented in docs/input-format.md and described by
// schema/triage-input-v1.schema.json.
package input

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// SchemaVersion is the only input schema version this release accepts.
const SchemaVersion = "1"

// DefaultMaxSize is the largest input file Parse accepts, in bytes.
const DefaultMaxSize = 64 << 20

// Allowed values for the enumerated fields, in display order.
var (
	Severities       = []string{"critical", "high", "medium", "low", "info"}
	Exposures        = []string{"internet", "internal", "isolated", "unknown"}
	AssetCriticality = []string{"high", "medium", "low", "unknown"}
)

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// File is one input document.
type File struct {
	SchemaVersion string `json:"schema_version"`
	Source        string `json:"source,omitempty"`
	Items         []Item `json:"items"`
}

// Item is one finding to triage.
type Item struct {
	SourceID         string            `json:"source_id,omitempty"`
	Title            string            `json:"title"`
	Severity         string            `json:"severity"`
	Description      string            `json:"description,omitempty"`
	Location         string            `json:"location,omitempty"`
	Rule             string            `json:"rule,omitempty"`
	CVEs             []string          `json:"cves,omitempty"`
	Asset            string            `json:"asset,omitempty"`
	Exposure         string            `json:"exposure,omitempty"`
	AssetCriticality string            `json:"asset_criticality,omitempty"`
	KnownExploited   *bool             `json:"known_exploited,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// ValidationError lists every problem found in an input file.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return "invalid input: " + e.Problems[0]
	}
	return fmt.Sprintf("invalid input (%d problems):\n  - %s", len(e.Problems), strings.Join(e.Problems, "\n  - "))
}

// Parse reads, normalizes and validates an input document of at most maxSize bytes.
func Parse(r io.Reader, maxSize int64) (*File, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}
	if int64(len(data)) > maxSize {
		limit := fmt.Sprintf("%d bytes", maxSize)
		if maxSize >= 1<<20 && maxSize%(1<<20) == 0 {
			limit = fmt.Sprintf("%d MiB", maxSize>>20)
		}
		return nil, fmt.Errorf("input is larger than the %s limit", limit)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("input is not valid triage JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("input is not valid triage JSON: unexpected data after the top-level object")
	}

	f.normalize()
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

func (f *File) normalize() {
	f.SchemaVersion = strings.TrimSpace(f.SchemaVersion)
	f.Source = strings.TrimSpace(f.Source)
	for i := range f.Items {
		it := &f.Items[i]
		it.SourceID = strings.TrimSpace(it.SourceID)
		it.Title = strings.TrimSpace(it.Title)
		it.Severity = strings.ToLower(strings.TrimSpace(it.Severity))
		it.Location = strings.TrimSpace(it.Location)
		it.Rule = strings.TrimSpace(it.Rule)
		it.Asset = strings.TrimSpace(it.Asset)
		it.Exposure = strings.ToLower(strings.TrimSpace(it.Exposure))
		it.AssetCriticality = strings.ToLower(strings.TrimSpace(it.AssetCriticality))
		for j, c := range it.CVEs {
			it.CVEs[j] = strings.ToUpper(strings.TrimSpace(c))
		}
		if len(it.CVEs) == 0 {
			it.CVEs = nil
		}
		if len(it.Metadata) == 0 {
			it.Metadata = nil
		}
	}
}

func (f *File) validate() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	switch f.SchemaVersion {
	case SchemaVersion:
	case "":
		add(`schema_version is missing (expected "%s")`, SchemaVersion)
	default:
		add(`schema_version %q is not supported (expected "%s")`, f.SchemaVersion, SchemaVersion)
	}
	if f.Items == nil {
		add("items is missing (use [] for a file with no findings)")
	}

	seenSourceID := map[string]int{}
	seenFingerprint := map[string]int{}
	for i, it := range f.Items {
		at := fmt.Sprintf("items[%d]", i)
		if it.Title == "" {
			add("%s: title is required", at)
		}
		if it.Severity == "" {
			add("%s: severity is required (one of %s)", at, strings.Join(Severities, ", "))
		} else if !contains(Severities, it.Severity) {
			add("%s: severity %q is not one of %s", at, it.Severity, strings.Join(Severities, ", "))
		}
		if it.Exposure != "" && !contains(Exposures, it.Exposure) {
			add("%s: exposure %q is not one of %s", at, it.Exposure, strings.Join(Exposures, ", "))
		}
		if it.AssetCriticality != "" && !contains(AssetCriticality, it.AssetCriticality) {
			add("%s: asset_criticality %q is not one of %s", at, it.AssetCriticality, strings.Join(AssetCriticality, ", "))
		}
		for _, c := range it.CVEs {
			if !cvePattern.MatchString(c) {
				add("%s: %q is not a CVE ID (expected CVE-YYYY-NNNN)", at, c)
			}
		}
		if it.SourceID != "" {
			if prev, ok := seenSourceID[it.SourceID]; ok {
				add("%s: source_id %q is already used by items[%d]", at, it.SourceID, prev)
			}
			seenSourceID[it.SourceID] = i
		} else {
			fp := it.Fingerprint(f.Source)
			if prev, ok := seenFingerprint[fp]; ok {
				add("%s: same title, location, rule and CVEs as items[%d]; give each a distinct source_id", at, prev)
			}
			seenFingerprint[fp] = i
		}
	}
	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

// Fingerprint identifies an item across imports. Items with a source_id are
// matched on source and source_id. Items without one are matched on source,
// title, location, rule and CVEs.
func (it Item) Fingerprint(source string) string {
	var key string
	if it.SourceID != "" {
		key = strings.Join([]string{"id", source, it.SourceID}, "\x00")
	} else {
		cves := append([]string(nil), it.CVEs...)
		sort.Strings(cves)
		key = strings.Join([]string{"content", source, it.Title, it.Location, it.Rule, strings.Join(cves, ",")}, "\x00")
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
