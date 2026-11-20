package input

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func parse(doc string) (*File, error) {
	return Parse(strings.NewReader(doc), DefaultMaxSize)
}

func TestParseNormalizes(t *testing.T) {
	f, err := parse(`{
		"schema_version": "1",
		"source": " scan ",
		"items": [{
			"source_id": " A-1 ",
			"title": "  SQL injection ",
			"severity": "HIGH",
			"exposure": "Internet",
			"asset_criticality": "Low",
			"cves": [" cve-2021-44228 "],
			"known_exploited": true,
			"metadata": {}
		}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if f.Source != "scan" {
		t.Errorf("source = %q, want %q", f.Source, "scan")
	}
	it := f.Items[0]
	checks := map[string][2]string{
		"source_id":         {it.SourceID, "A-1"},
		"title":             {it.Title, "SQL injection"},
		"severity":          {it.Severity, "high"},
		"exposure":          {it.Exposure, "internet"},
		"asset_criticality": {it.AssetCriticality, "low"},
		"cve":               {it.CVEs[0], "CVE-2021-44228"},
	}
	for field, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", field, c[0], c[1])
		}
	}
	if it.KnownExploited == nil || !*it.KnownExploited {
		t.Error("known_exploited should be true")
	}
	if it.Metadata != nil {
		t.Error("empty metadata should normalize to nil")
	}
}

func TestParseExampleFiles(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "examples", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no example files found")
	}
	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			f, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := Parse(f, DefaultMaxSize); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	item := func(fields string) string {
		return `{"schema_version":"1","items":[{` + fields + `}]}`
	}
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"not JSON", `nope`, "not valid triage JSON"},
		{"wrong type", `{"schema_version":1,"items":[]}`, "not valid triage JSON"},
		{"trailing data", `{"schema_version":"1","items":[]} {}`, "unexpected data after the top-level object"},
		{"unknown field", item(`"title":"t","severity":"high","severty":"x"`), `unknown field "severty"`},
		{"missing schema version", `{"items":[]}`, "schema_version is missing"},
		{"missing items", `{"schema_version":"1"}`, "items is missing"},
		{"null items", `{"schema_version":"1","items":null}`, "items is missing"},
		{"unsupported schema version", `{"schema_version":"2","items":[]}`, `schema_version "2" is not supported`},
		{"missing title", item(`"severity":"high"`), "items[0]: title is required"},
		{"missing severity", item(`"title":"t"`), "items[0]: severity is required"},
		{"bad severity", item(`"title":"t","severity":"severe"`), `items[0]: severity "severe" is not one of`},
		{"bad exposure", item(`"title":"t","severity":"high","exposure":"public"`), `exposure "public" is not one of`},
		{"bad asset criticality", item(`"title":"t","severity":"high","asset_criticality":"vital"`), `asset_criticality "vital" is not one of`},
		{"bad CVE", item(`"title":"t","severity":"high","cves":["CVE-21-1"]`), `"CVE-21-1" is not a CVE ID`},
		{
			"duplicate source_id",
			`{"schema_version":"1","items":[{"source_id":"A","title":"t","severity":"high"},{"source_id":"A","title":"u","severity":"low"}]}`,
			`items[1]: source_id "A" is already used by items[0]`,
		},
		{
			"identical items without source_id",
			`{"schema_version":"1","items":[{"title":"t","severity":"high"},{"title":"t","severity":"low"}]}`,
			"items[1]: same title, location, rule and CVEs as items[0]",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parse(c.doc)
			if err == nil {
				t.Fatalf("expected an error containing %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err, c.want)
			}
		})
	}
}

func TestParseReportsEveryProblem(t *testing.T) {
	_, err := parse(`{"schema_version":"1","items":[{"severity":"high"},{"title":"t","severity":"nope"}]}`)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected a ValidationError, got %v", err)
	}
	if len(ve.Problems) != 2 {
		t.Fatalf("got %d problems, want 2: %v", len(ve.Problems), ve.Problems)
	}
}

func TestParseSizeLimit(t *testing.T) {
	_, err := Parse(strings.NewReader(`{"schema_version":"1","items":[]}`), 10)
	if err == nil || !strings.Contains(err.Error(), "larger than the 10 bytes limit") {
		t.Fatalf("expected a size-limit error, got %v", err)
	}
}

func TestFingerprint(t *testing.T) {
	withID := Item{SourceID: "A-1", Title: "one"}
	renamed := Item{SourceID: "A-1", Title: "two"}
	if withID.Fingerprint("scan") != renamed.Fingerprint("scan") {
		t.Error("items with the same source_id should match even if other fields change")
	}
	if withID.Fingerprint("scan") == withID.Fingerprint("other-scan") {
		t.Error("the same source_id from different sources should not match")
	}

	a := Item{Title: "t", Location: "x.go:1", CVEs: []string{"CVE-2021-0002", "CVE-2021-0001"}}
	b := Item{Title: "t", Location: "x.go:1", CVEs: []string{"CVE-2021-0001", "CVE-2021-0002"}}
	if a.Fingerprint("s") != b.Fingerprint("s") {
		t.Error("CVE order should not affect the fingerprint")
	}
	moved := Item{Title: "t", Location: "x.go:2", CVEs: a.CVEs}
	if a.Fingerprint("s") == moved.Fingerprint("s") {
		t.Error("without a source_id, a different location should be a different item")
	}
	// A source_id and content that happen to produce the same key text must not collide.
	if (Item{SourceID: "t"}).Fingerprint("s") == (Item{Title: "t"}).Fingerprint("s") {
		t.Error("ID-based and content-based fingerprints should never collide")
	}
}

// The JSON Schema is for people and other tools; this test keeps it in step
// with what the parser accepts.
func TestSchemaMatchesParser(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "triage-input-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Const string `json:"const"`
		} `json:"properties"`
		Defs struct {
			Item struct {
				Required   []string `json:"required"`
				Properties map[string]struct {
					Enum  []string `json:"enum"`
					Items struct {
						Pattern string `json:"pattern"`
					} `json:"items"`
				} `json:"properties"`
			} `json:"item"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if got := schema.Properties["schema_version"].Const; got != SchemaVersion {
		t.Errorf("schema_version const = %q, want %q", got, SchemaVersion)
	}
	if !reflect.DeepEqual(schema.Required, []string{"schema_version", "items"}) {
		t.Errorf("top-level required = %v", schema.Required)
	}
	item := schema.Defs.Item
	if !reflect.DeepEqual(item.Required, []string{"title", "severity"}) {
		t.Errorf("item required = %v", item.Required)
	}
	for field, want := range map[string][]string{
		"severity":          Severities,
		"exposure":          Exposures,
		"asset_criticality": AssetCriticality,
	} {
		if got := item.Properties[field].Enum; !reflect.DeepEqual(got, want) {
			t.Errorf("%s enum = %v, want %v", field, got, want)
		}
	}
	if got := item.Properties["cves"].Items.Pattern; got != cvePattern.String() {
		t.Errorf("cves pattern = %q, want %q", got, cvePattern.String())
	}

	// Every field in the schema must exist in Item, and the other way round.
	var fields []string
	typ := reflect.TypeOf(Item{})
	for i := 0; i < typ.NumField(); i++ {
		fields = append(fields, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
	}
	if len(fields) != len(item.Properties) {
		t.Errorf("Item has %d fields, schema has %d properties", len(fields), len(item.Properties))
	}
	for _, f := range fields {
		if _, ok := item.Properties[f]; !ok {
			t.Errorf("field %q is missing from the schema", f)
		}
	}
}
