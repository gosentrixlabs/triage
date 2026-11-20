package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var (
	examples = filepath.Join("..", "..", "examples")
	findings = filepath.Join(examples, "findings.json")
	rescan   = filepath.Join(examples, "findings-rescan.json")
)

type harness struct {
	t     *testing.T
	ws    string
	now   time.Time
	stdin string
}

func newHarness(t *testing.T) *harness {
	return &harness{t: t, ws: filepath.Join(t.TempDir(), "ws"), now: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)}
}

// run executes the CLI with TRIAGE_WORKSPACE pointing at the harness workspace.
func (h *harness) run(args ...string) (stdout, stderr string, code int) {
	h.t.Helper()
	var out, errOut bytes.Buffer
	app := &App{
		Stdin:   strings.NewReader(h.stdin),
		Stdout:  &out,
		Stderr:  &errOut,
		Getenv:  func(k string) string { return map[string]string{"TRIAGE_WORKSPACE": h.ws}[k] },
		Now:     func() time.Time { return h.now },
		User:    func() string { return "alice" },
		Version: "test-version",
	}
	code = app.Run(args)
	return out.String(), errOut.String(), code
}

// ok runs a command that must succeed and returns its standard output.
func (h *harness) ok(args ...string) string {
	h.t.Helper()
	out, errOut, code := h.run(args...)
	if code != ExitOK {
		h.t.Fatalf("triage %s exited %d\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), code, out, errOut)
	}
	return out
}

// fails runs a command that must exit with code and returns its standard error.
func (h *harness) fails(code int, args ...string) string {
	h.t.Helper()
	out, errOut, got := h.run(args...)
	if got != code {
		h.t.Fatalf("triage %s exited %d, want %d\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), got, code, out, errOut)
	}
	return errOut
}

// listIDs returns the ID column of "triage list" output, in order.
func listIDs(out string) []string {
	var ids []string
	for _, line := range strings.Split(out, "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "Showing" {
			continue
		}
		ids = append(ids, fields[0])
	}
	return ids
}

func mustContain(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("output does not contain %q:\n%s", w, got)
		}
	}
}

func TestWorkflow(t *testing.T) {
	h := newHarness(t)

	out := h.ok("import", findings)
	mustContain(t, out, "Created workspace", "Imported 8 items", "8 new, 0 updated, 0 unchanged")

	out = h.ok("list", "--status", "new")
	if got, want := strings.Join(listIDs(out), ","), "1,4,2,3,5,6,8,7"; got != want {
		t.Fatalf("queue order = %s, want %s\n%s", got, want, out)
	}
	mustContain(t, out, "Showing 8 of 8 items.")

	out = h.ok("explain", "1")
	mustContain(t, out, "Priority P1, score 105.", "+50  severity", "+30  known-exploited",
		"+15  exposure", "+10  asset-criticality", "105  total")

	mustContain(t, h.ok("decide", "2", "--status", "confirmed", "--reason", "Reproduced"), "Item 2 is now confirmed.")
	mustContain(t, h.ok("decide", "3", "--status", "duplicate", "--duplicate-of", "2", "--reason", "Same handler"),
		"Item 3 is now marked as a duplicate of item 2.")
	h.ok("decide", "5", "--status", "defer", "--reason", "Owner away")

	out = h.ok("show", "3")
	mustContain(t, out, "Item 3: Tainted query parameter", "Status:", "duplicate of item 2",
		"2026-03-04 05:06 UTC  duplicate of item 2 by alice: Same handler")

	if got := listIDs(h.ok("list", "--status", "new")); len(got) != 5 {
		t.Errorf("after three decisions, %d items should be new, got %v", 5, got)
	}

	h.now = h.now.Add(time.Hour)
	out = h.ok("import", rescan)
	mustContain(t, out, "1 new, 1 updated, 1 unchanged", "Changed after a decision: item 5.")
	mustContain(t, h.ok("show", "5"), "after the last decision", "Exposure:", "internet")

	var doc struct {
		Format  string `json:"format"`
		Version string `json:"format_version"`
		Tool    string `json:"tool_version"`
		Items   []struct {
			ID       int    `json:"id"`
			Status   string `json:"status"`
			Priority struct {
				Band    string `json:"band"`
				Score   int    `json:"score"`
				Factors []struct {
					Points int `json:"points"`
				} `json:"factors"`
			} `json:"priority"`
			Decisions []struct {
				Status string `json:"status"`
				By     string `json:"by"`
			} `json:"decisions"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(h.ok("export", "--format", "json")), &doc); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	if doc.Format != "triage-export" || doc.Version != "1" || doc.Tool != "test-version" {
		t.Errorf("export header = %q %q %q", doc.Format, doc.Version, doc.Tool)
	}
	if len(doc.Items) != 9 {
		t.Fatalf("export has %d items, want 9", len(doc.Items))
	}
	for i, it := range doc.Items {
		if it.ID != i+1 {
			t.Errorf("export item %d has ID %d; items should be in ID order", i, it.ID)
		}
		sum := 0
		for _, f := range it.Priority.Factors {
			sum += f.Points
		}
		if sum != it.Priority.Score {
			t.Errorf("item %d factors add up to %d, score is %d", it.ID, sum, it.Priority.Score)
		}
		if it.Decisions == nil {
			t.Errorf("item %d decisions should be [] rather than null", it.ID)
		}
	}
	if it := doc.Items[1]; it.Status != "confirmed" || len(it.Decisions) != 1 || it.Decisions[0].By != "alice" {
		t.Errorf("item 2 in export = %+v", it)
	}
}

func TestListFilters(t *testing.T) {
	h := newHarness(t)
	h.ok("import", findings)
	h.ok("decide", "6", "--status", "dismissed", "--reason", "Load balancer retired")

	if got := strings.Join(listIDs(h.ok("list", "--priority", "P1")), ","); got != "1,4" {
		t.Errorf("--priority P1 = %s, want 1,4", got)
	}
	if got := strings.Join(listIDs(h.ok("list", "--priority", "p3,P4", "--status", "new")), ","); got != "5,8,7" {
		t.Errorf("--priority p3,P4 --status new = %s, want 5,8,7", got)
	}
	if got := strings.Join(listIDs(h.ok("list", "--status", "dismissed")), ","); got != "6" {
		t.Errorf("--status dismissed = %s, want 6", got)
	}
	mustContain(t, h.ok("list", "--status", "duplicate"), "No items match (the workspace has 8 items).")
	mustContain(t, h.fails(ExitUsage, "list", "--status", "closed"), `status "closed" is not one of`)
	mustContain(t, h.fails(ExitUsage, "list", "--priority", "P5"), `priority "P5" is not one of`)
}

func TestFlagsMayFollowArguments(t *testing.T) {
	h := newHarness(t)
	h.ok("import", findings, "--workspace", h.ws)
	h.ok("decide", "--status", "confirmed", "1", "--reason", "Before and after")
	h.ok("decide", "2", "--reason", "All after", "--status", "dismiss")
	mustContain(t, h.ok("show", "--", "#2"), "Status:", "dismissed")
}

func TestUsageErrors(t *testing.T) {
	h := newHarness(t)
	h.ok("import", findings)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"frobnicate"}, `unknown command "frobnicate"`},
		{[]string{"import"}, "expected one input file"},
		{[]string{"import", "a.json", "b.json"}, "expected one input file"},
		{[]string{"show"}, "an item ID is required"},
		{[]string{"show", "abc"}, `"abc" is not an item ID`},
		{[]string{"show", "1", "2"}, "expected one item ID"},
		{[]string{"explain", "0"}, `"0" is not an item ID`},
		{[]string{"decide", "1", "--reason", "x"}, "--status is required"},
		{[]string{"decide", "1", "--status", "confirmed"}, "--reason is required"},
		{[]string{"decide", "1", "--status", "new", "--reason", "x"}, "cannot set the status back to new"},
		{[]string{"decide", "1", "--status", "duplicate", "--duplicate-of", "x", "--reason", "x"}, `--duplicate-of "x" is not an item ID`},
		{[]string{"export", "--format", "csv"}, `format "csv" is not supported`},
		{[]string{"list", "--colour"}, "flag provided but not defined: -colour"},
		{[]string{"list", "extra"}, `unexpected argument "extra"`},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			mustContain(t, h.fails(ExitUsage, c.args...), c.want)
		})
	}
	if _, errOut, code := h.run(); code != ExitUsage || !strings.Contains(errOut, "Commands:") {
		t.Errorf("no arguments: exit %d, stderr %q", code, errOut)
	}
}

func TestRuntimeErrors(t *testing.T) {
	h := newHarness(t)
	mustContain(t, h.fails(ExitError, "list"), "no triage workspace at", `Run "triage import <file>"`)
	mustContain(t, h.fails(ExitError, "decide", "1", "--status", "confirmed", "--reason", "x"), "no triage workspace at")

	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"schema_version":"1","items":[{"title":"t","severity":"severe"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	mustContain(t, h.fails(ExitError, "import", bad), `items[0]: severity "severe" is not one of`)
	if _, err := os.Stat(h.ws); !os.IsNotExist(err) {
		t.Error("a failed import should not create the workspace")
	}

	h.ok("import", findings)
	mustContain(t, h.fails(ExitError, "show", "99"), "no item with ID 99")
	mustContain(t, h.fails(ExitError, "decide", "2", "--status", "duplicate", "--duplicate-of", "2", "--reason", "x"),
		"cannot be a duplicate of itself")
}

func TestHelp(t *testing.T) {
	h := newHarness(t)
	mustContain(t, h.ok("help"), "Commands:", "explain")
	mustContain(t, h.ok("--help"), "Commands:")
	mustContain(t, h.ok("help", "decide"), "--duplicate-of ID")
	mustContain(t, h.ok("decide", "-h"), "Usage: triage decide")
	mustContain(t, h.ok("list", "--help"), "Usage: triage list")
	mustContain(t, h.fails(ExitUsage, "help", "nope"), `unknown command "nope"`)
	mustContain(t, h.ok("version"), "triage test-version")
	mustContain(t, h.ok("--version"), "triage test-version")
}

func TestImportFromStdin(t *testing.T) {
	h := newHarness(t)
	h.stdin = `{"schema_version":"1","source":"pipe","items":[{"title":"From a pipe","severity":"low"}]}`
	mustContain(t, h.ok("import", "-"), "Imported 1 item from standard input")
	mustContain(t, h.ok("show", "1"), "From a pipe", "pipe")
}

func TestUntrustedTextIsEscaped(t *testing.T) {
	h := newHarness(t)
	h.stdin = `{"schema_version":"1","source":"evil\u001b[2J","items":[{
		"title": "\u001b]0;pwned\u0007Title\u202eabc",
		"severity": "high",
		"location": "a\nb\tc",
		"description": "line one\nline two\r\u001b[31mred",
		"metadata": {"k\u001b": "v\u009b"}
	}]}`
	h.ok("import", "-")
	for _, args := range [][]string{{"list"}, {"show", "1"}, {"explain", "1"}} {
		out := h.ok(args...)
		for _, bad := range []string{"\x1b", "\x07", "\u202e", "\r", "\u009b"} {
			if strings.Contains(out, bad) {
				t.Errorf("triage %s printed raw %q:\n%s", strings.Join(args, " "), bad, out)
			}
		}
		mustContain(t, out, `\u001b`)
	}
	out := h.ok("show", "1")
	mustContain(t, out, "  line one\n  line two", `\u202e`, "a b c")

	// The export is JSON, which escapes control characters itself; the data must
	// survive unchanged.
	var doc struct {
		Items []struct {
			Finding struct {
				Title string `json:"title"`
			} `json:"finding"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(h.ok("export")), &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc.Items[0].Finding.Title; got != "\x1b]0;pwned\x07Title\u202eabc" {
		t.Errorf("export changed the title: %q", got)
	}
}

func TestExportToFile(t *testing.T) {
	h := newHarness(t)
	h.ok("import", findings)
	path := filepath.Join(t.TempDir(), "out.json")
	out, errOut, code := h.run("export", "--output", path)
	if code != ExitOK || out != "" {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
	mustContain(t, errOut, "Exported 8 items to "+path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("export file mode %o, want 600", info.Mode().Perm())
	}
}

func TestDefaultWorkspaceIsInCurrentDirectory(t *testing.T) {
	input := mustAbs(t, findings) // resolve before changing directory
	dir := t.TempDir()
	t.Chdir(dir)
	h := newHarness(t)
	h.ws = "" // no TRIAGE_WORKSPACE
	h.ok("import", input)
	if _, err := os.Stat(filepath.Join(dir, ".triage", "state.json")); err != nil {
		t.Fatalf("expected .triage/state.json in the current directory: %v", err)
	}
	other := filepath.Join(t.TempDir(), "elsewhere")
	h.ok("import", input, "--workspace", other)
	if _, err := os.Stat(filepath.Join(other, "state.json")); err != nil {
		t.Fatalf("--workspace was ignored: %v", err)
	}
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}
