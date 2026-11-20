package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gosentrixlabs/triage/internal/input"
)

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func sampleFile() *input.File {
	return &input.File{
		SchemaVersion: "1",
		Source:        "scan",
		Items: []input.Item{
			{SourceID: "A", Title: "first", Severity: "high"},
			{SourceID: "B", Title: "second", Severity: "low"},
			{Title: "third", Severity: "medium", Location: "x.go:1"},
		},
	}
}

func newState() *State { return &State{Version: StateVersion, NextID: 1} }

func TestOpenMissing(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "nope"))
	if !errors.Is(err, ErrNoWorkspace) {
		t.Fatalf("got %v, want ErrNoWorkspace", err)
	}
}

func TestOpenOrCreateAndRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".triage")
	ws, created, err := OpenOrCreate(dir)
	if err != nil || !created {
		t.Fatalf("OpenOrCreate: created=%v err=%v", created, err)
	}
	st, err := ws.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.NextID != 1 || len(st.Items) != 0 {
		t.Fatalf("new workspace should be empty, got %+v", st)
	}

	st.Import(sampleFile(), t0)
	if err := ws.Save(st); err != nil {
		t.Fatal(err)
	}
	if _, created, _ := OpenOrCreate(dir); created {
		t.Error("second OpenOrCreate should open, not create")
	}
	got, err := ws.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 3 || got.NextID != 4 || got.Items[2].Finding.Title != "third" {
		t.Fatalf("round trip lost data: %+v", got)
	}

	if runtime.GOOS != "windows" {
		for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, stateFile): 0o600} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != want {
				t.Errorf("%s has mode %o, want %o", path, perm, want)
			}
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(`{"version":99,"next_id":1,"items":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := (&Workspace{Dir: dir}).Load()
	if err == nil || !strings.Contains(err.Error(), "version 99 is not supported") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadRejectsCorruptState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(`{"version":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Workspace{Dir: dir}).Load(); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("got %v", err)
	}
}

func TestImportIsRepeatable(t *testing.T) {
	st := newState()
	sum := st.Import(sampleFile(), t0)
	if sum.New != 3 || sum.Updated != 0 || sum.Unchanged != 0 {
		t.Fatalf("first import: %+v", sum)
	}
	sum = st.Import(sampleFile(), t0.Add(time.Hour))
	if sum.New != 0 || sum.Updated != 0 || sum.Unchanged != 3 {
		t.Fatalf("identical re-import: %+v", sum)
	}
	if len(st.Items) != 3 {
		t.Fatalf("re-import duplicated items: %d", len(st.Items))
	}
	if !st.Items[0].UpdatedAt.Equal(t0) {
		t.Error("an unchanged item should keep its UpdatedAt")
	}
}

func TestImportUpdatesAndFlagsDecidedItems(t *testing.T) {
	st := newState()
	st.Import(sampleFile(), t0)
	if err := st.Decide(1, Decision{Status: StatusConfirmed, Reason: "real", At: t0.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}

	changed := sampleFile()
	changed.Items[0].Severity = "critical" // decided item
	changed.Items[1].Severity = "medium"   // undecided item
	changed.Items = append(changed.Items, input.Item{SourceID: "C", Title: "fourth", Severity: "info"})
	sum := st.Import(changed, t0.Add(time.Hour))

	if sum.New != 1 || sum.Updated != 2 || sum.Unchanged != 1 {
		t.Fatalf("summary: %+v", sum)
	}
	if len(sum.ChangedAfterDecision) != 1 || sum.ChangedAfterDecision[0] != 1 {
		t.Fatalf("ChangedAfterDecision = %v, want [1]", sum.ChangedAfterDecision)
	}
	it, _ := st.Get(1)
	if it.Finding.Severity != "critical" || it.Status != StatusConfirmed || len(it.Decisions) != 1 {
		t.Fatalf("update should replace the finding and keep the decision: %+v", it)
	}
	if !it.ChangedSinceDecision() {
		t.Error("ChangedSinceDecision should be true")
	}
	if fourth, ok := st.Get(4); !ok || fourth.Finding.Title != "fourth" {
		t.Error("new item should get the next ID")
	}
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name string
		id   int
		d    Decision
		want string // empty means success
	}{
		{"confirm", 1, Decision{Status: StatusConfirmed, Reason: "reproduced"}, ""},
		{"dismiss", 1, Decision{Status: StatusDismissed, Reason: "test code"}, ""},
		{"defer", 1, Decision{Status: StatusDeferred, Reason: "later"}, ""},
		{"duplicate", 2, Decision{Status: StatusDuplicate, Reason: "same", DuplicateOf: 1}, ""},
		{"unknown item", 9, Decision{Status: StatusConfirmed, Reason: "x"}, "no item with ID 9"},
		{"missing reason", 1, Decision{Status: StatusConfirmed, Reason: "  "}, "a reason is required"},
		{"status new", 1, Decision{Status: StatusNew, Reason: "x"}, `status "new" is not one of`},
		{"duplicate without target", 2, Decision{Status: StatusDuplicate, Reason: "x"}, "needs the ID"},
		{"duplicate of itself", 2, Decision{Status: StatusDuplicate, Reason: "x", DuplicateOf: 2}, "duplicate of itself"},
		{"duplicate of missing item", 2, Decision{Status: StatusDuplicate, Reason: "x", DuplicateOf: 9}, "no item with ID 9"},
		{"target for non-duplicate", 2, Decision{Status: StatusConfirmed, Reason: "x", DuplicateOf: 1}, "only a duplicate decision"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := newState()
			st.Import(sampleFile(), t0)
			err := st.Decide(c.id, c.d)
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				it, _ := st.Get(c.id)
				if it.Status != c.d.Status {
					t.Errorf("status = %s, want %s", it.Status, c.d.Status)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestDecidePointsChainsAtTheOriginal(t *testing.T) {
	st := newState()
	st.Import(sampleFile(), t0)
	if err := st.Decide(2, Decision{Status: StatusDuplicate, Reason: "same", DuplicateOf: 1}); err != nil {
		t.Fatal(err)
	}
	err := st.Decide(3, Decision{Status: StatusDuplicate, Reason: "same", DuplicateOf: 2})
	if err == nil || !strings.Contains(err.Error(), "use 1 instead") {
		t.Fatalf("got %v", err)
	}
}

func TestDecideKeepsHistory(t *testing.T) {
	st := newState()
	st.Import(sampleFile(), t0)
	_ = st.Decide(1, Decision{Status: StatusDeferred, Reason: "later", At: t0})
	_ = st.Decide(1, Decision{Status: StatusConfirmed, Reason: "reproduced", At: t0.Add(time.Hour)})
	it, _ := st.Get(1)
	if len(it.Decisions) != 2 || it.Status != StatusConfirmed {
		t.Fatalf("history not kept: %+v", it)
	}
	if last, _ := it.LastDecision(); last.Reason != "reproduced" {
		t.Errorf("last decision = %q", last.Reason)
	}
	if it.ChangedSinceDecision() {
		t.Error("finding has not changed since the decision")
	}
}

func TestParseStatus(t *testing.T) {
	cases := map[string]Status{
		"new": StatusNew, "Confirmed": StatusConfirmed, "confirm": StatusConfirmed,
		"dismiss": StatusDismissed, "defer": StatusDeferred, " duplicate ": StatusDuplicate,
	}
	for in, want := range cases {
		got, err := ParseStatus(in)
		if err != nil || got != want {
			t.Errorf("ParseStatus(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseStatus("closed"); err == nil {
		t.Error("ParseStatus should reject unknown statuses")
	}
}

func TestLockIsExclusive(t *testing.T) {
	ws := &Workspace{Dir: t.TempDir()}
	unlock, err := ws.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Lock(); err == nil || !strings.Contains(err.Error(), "another triage command") {
		t.Fatalf("second lock should fail, got %v", err)
	}
	unlock()
	unlock2, err := ws.Lock()
	if err != nil {
		t.Fatalf("lock after unlock: %v", err)
	}
	unlock2()
}
