// Package workspace stores imported items and triage decisions in a local
// directory (".triage" by default).
//
// State lives in one JSON file that is replaced atomically on every save, so
// readers never see a partial write. Commands that change state hold a lock
// file for the duration of the load-modify-save cycle.
package workspace

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosentrixlabs/triage/internal/input"
)

// DefaultDir is the workspace directory used when none is given.
const DefaultDir = ".triage"

// StateVersion is the version of the state file this release reads and writes.
const StateVersion = 1

const (
	stateFile = "state.json"
	lockFile  = "lock"
)

// Status is an item's triage state.
type Status string

// Item statuses. Every item starts as StatusNew; a decision moves it to one
// of the others.
const (
	StatusNew       Status = "new"
	StatusConfirmed Status = "confirmed"
	StatusDismissed Status = "dismissed"
	StatusDeferred  Status = "deferred"
	StatusDuplicate Status = "duplicate"
)

// Statuses lists every status in display order.
var Statuses = []Status{StatusNew, StatusConfirmed, StatusDismissed, StatusDeferred, StatusDuplicate}

// DecisionStatuses lists the statuses a decision can set.
var DecisionStatuses = []Status{StatusConfirmed, StatusDismissed, StatusDeferred, StatusDuplicate}

// ErrNoWorkspace is returned when the workspace directory does not exist.
var ErrNoWorkspace = errors.New("no triage workspace")

// Decision records one triage decision. Items keep every decision, newest last.
type Decision struct {
	Status      Status    `json:"status"`
	Reason      string    `json:"reason"`
	DuplicateOf int       `json:"duplicate_of,omitempty"`
	By          string    `json:"by,omitempty"`
	At          time.Time `json:"at"`
}

// Item is an imported finding plus its triage state.
type Item struct {
	ID          int        `json:"id"`
	Fingerprint string     `json:"fingerprint"`
	Source      string     `json:"source,omitempty"`
	Finding     input.Item `json:"finding"`
	Status      Status     `json:"status"`
	Decisions   []Decision `json:"decisions,omitempty"`
	ImportedAt  time.Time  `json:"imported_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// LastDecision returns the most recent decision, if any.
func (it *Item) LastDecision() (Decision, bool) {
	if len(it.Decisions) == 0 {
		return Decision{}, false
	}
	return it.Decisions[len(it.Decisions)-1], true
}

// ChangedSinceDecision reports whether the finding data changed after the
// most recent decision.
func (it *Item) ChangedSinceDecision() bool {
	d, ok := it.LastDecision()
	return ok && it.UpdatedAt.After(d.At)
}

// State is the full contents of a workspace.
type State struct {
	Version int     `json:"version"`
	NextID  int     `json:"next_id"`
	Items   []*Item `json:"items"`
}

// Get returns the item with the given ID.
func (s *State) Get(id int) (*Item, bool) {
	for _, it := range s.Items {
		if it.ID == id {
			return it, true
		}
	}
	return nil, false
}

// ImportSummary reports what an import changed.
type ImportSummary struct {
	New       int
	Updated   int
	Unchanged int
	// ChangedAfterDecision lists items whose finding data changed although
	// they already had a decision.
	ChangedAfterDecision []int
}

// Import adds new items and updates existing ones, matched by fingerprint.
// Updating an item replaces its finding data and keeps its status and decisions.
func (s *State) Import(f *input.File, now time.Time) ImportSummary {
	var sum ImportSummary
	byFingerprint := make(map[string]*Item, len(s.Items))
	for _, it := range s.Items {
		byFingerprint[it.Fingerprint] = it
	}
	for _, fi := range f.Items {
		fp := fi.Fingerprint(f.Source)
		existing, ok := byFingerprint[fp]
		if !ok {
			it := &Item{
				ID:          s.NextID,
				Fingerprint: fp,
				Source:      f.Source,
				Finding:     fi,
				Status:      StatusNew,
				ImportedAt:  now,
				UpdatedAt:   now,
			}
			s.NextID++
			s.Items = append(s.Items, it)
			byFingerprint[fp] = it
			sum.New++
			continue
		}
		if reflect.DeepEqual(existing.Finding, fi) {
			sum.Unchanged++
			continue
		}
		existing.Finding = fi
		existing.UpdatedAt = now
		sum.Updated++
		if existing.Status != StatusNew {
			sum.ChangedAfterDecision = append(sum.ChangedAfterDecision, existing.ID)
		}
	}
	return sum
}

// Decide records a decision on an item and sets its status.
func (s *State) Decide(id int, d Decision) error {
	it, ok := s.Get(id)
	if !ok {
		return fmt.Errorf("no item with ID %d", id)
	}
	if !isDecisionStatus(d.Status) {
		return fmt.Errorf("status %q is not one of %s", d.Status, joinStatuses(DecisionStatuses))
	}
	d.Reason = strings.TrimSpace(d.Reason)
	if d.Reason == "" {
		return errors.New("a reason is required")
	}
	if d.Status == StatusDuplicate {
		if d.DuplicateOf == 0 {
			return errors.New("a duplicate decision needs the ID of the item it duplicates")
		}
		if d.DuplicateOf == id {
			return errors.New("an item cannot be a duplicate of itself")
		}
		target, ok := s.Get(d.DuplicateOf)
		if !ok {
			return fmt.Errorf("no item with ID %d to mark this as a duplicate of", d.DuplicateOf)
		}
		if target.Status == StatusDuplicate {
			last, _ := target.LastDecision()
			return fmt.Errorf("item %d is itself a duplicate of item %d; use %d instead", target.ID, last.DuplicateOf, last.DuplicateOf)
		}
	} else if d.DuplicateOf != 0 {
		return errors.New("only a duplicate decision can name the item it duplicates")
	}
	it.Decisions = append(it.Decisions, d)
	it.Status = d.Status
	return nil
}

// ParseStatus accepts a status name or its verb form ("confirm" for "confirmed").
func ParseStatus(s string) (Status, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "confirm":
		return StatusConfirmed, nil
	case "dismiss":
		return StatusDismissed, nil
	case "defer":
		return StatusDeferred, nil
	}
	for _, st := range Statuses {
		if string(st) == s {
			return st, nil
		}
	}
	return "", fmt.Errorf("status %q is not one of %s", s, joinStatuses(Statuses))
}

func isDecisionStatus(s Status) bool {
	for _, st := range DecisionStatuses {
		if st == s {
			return true
		}
	}
	return false
}

func joinStatuses(list []Status) string {
	names := make([]string, len(list))
	for i, s := range list {
		names[i] = string(s)
	}
	return strings.Join(names, ", ")
}

// Workspace is a workspace directory on disk.
type Workspace struct {
	Dir string
}

// Open returns the workspace at dir, which must already exist.
func Open(dir string) (*Workspace, error) {
	info, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w at %s", ErrNoWorkspace, dir)
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s exists but is not a directory", dir)
	}
	return &Workspace{Dir: dir}, nil
}

// OpenOrCreate returns the workspace at dir, creating it if needed. The
// directory is private to the current user because findings are sensitive.
func OpenOrCreate(dir string) (*Workspace, bool, error) {
	ws, err := Open(dir)
	if err == nil {
		return ws, false, nil
	}
	if !errors.Is(err, ErrNoWorkspace) {
		return nil, false, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, fmt.Errorf("creating workspace: %w", err)
	}
	return &Workspace{Dir: dir}, true, nil
}

// Load reads the workspace state. A workspace with no state file yet is empty.
func (w *Workspace) Load() (*State, error) {
	data, err := os.ReadFile(filepath.Join(w.Dir, stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return &State{Version: StateVersion, NextID: 1}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading workspace: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("workspace state in %s is corrupt: %w", w.Dir, err)
	}
	if s.Version != StateVersion {
		return nil, fmt.Errorf("workspace state version %d is not supported by this release (expected %d)", s.Version, StateVersion)
	}
	if s.NextID < 1 {
		s.NextID = 1
	}
	sort.Slice(s.Items, func(i, j int) bool { return s.Items[i].ID < s.Items[j].ID })
	return &s, nil
}

// Save writes the workspace state atomically.
func (w *Workspace) Save(s *State) error {
	s.Version = StateVersion
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return WriteFileAtomic(filepath.Join(w.Dir, stateFile), data)
}

// Lock takes the workspace lock and returns a function that releases it.
func (w *Workspace) Lock() (func(), error) {
	path := filepath.Join(w.Dir, lockFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("another triage command is changing this workspace (lock file %s). If none is running, delete the lock file and try again", path)
	}
	if err != nil {
		return nil, fmt.Errorf("locking workspace: %w", err)
	}
	_, _ = f.WriteString(strconv.Itoa(os.Getpid()) + "\n")
	_ = f.Close()
	return func() { _ = os.Remove(path) }, nil
}

// WriteFileAtomic writes data to path through a temporary file in the same
// directory, so the file is either fully replaced or left untouched. The file
// is readable and writable by the current user only (os.CreateTemp uses 0600).
func WriteFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
