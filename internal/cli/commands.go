package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gosentrixlabs/triage/internal/input"
	"github.com/gosentrixlabs/triage/internal/priority"
	"github.com/gosentrixlabs/triage/internal/workspace"
)

func (a *App) cmdImport(args []string) error {
	fs := newFlagSet("import")
	wsFlag := fs.String("workspace", "", "")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("import", "expected one input file (use - for standard input), got %d arguments", len(pos))
	}

	name := pos[0]
	var r io.Reader
	if name == "-" {
		r = a.Stdin
		name = "standard input"
	} else {
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	in, err := input.Parse(r, input.DefaultMaxSize)
	if err != nil {
		return err
	}

	dir := a.workspaceDir(*wsFlag)
	ws, created, err := workspace.OpenOrCreate(dir)
	if err != nil {
		return err
	}
	unlock, err := ws.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	st, err := ws.Load()
	if err != nil {
		return err
	}
	sum := st.Import(in, a.Now().UTC())
	if err := ws.Save(st); err != nil {
		return fmt.Errorf("saving workspace: %w", err)
	}

	out := a.Stdout
	if created {
		fmt.Fprintf(out, "Created workspace %s\n", dir)
	}
	fmt.Fprintf(out, "Imported %s from %s: %d new, %d updated, %d unchanged.\n",
		plural(len(in.Items), "item"), name, sum.New, sum.Updated, sum.Unchanged)
	if len(sum.ChangedAfterDecision) > 0 {
		fmt.Fprintf(out, "Changed after a decision: %s. Run \"triage show <id>\" to check each decision still holds.\n",
			joinIDs(sum.ChangedAfterDecision))
	}
	if sum.New > 0 {
		fmt.Fprintln(out, "Run \"triage list --status new\" to see the queue.")
	}
	return nil
}

type scored struct {
	item *workspace.Item
	pri  priority.Result
}

func (a *App) cmdList(args []string) error {
	fs := newFlagSet("list")
	wsFlag := fs.String("workspace", "", "")
	statusFlag := fs.String("status", "", "")
	priorityFlag := fs.String("priority", "", "")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("list", "unexpected argument %q", pos[0])
	}

	statuses := map[workspace.Status]bool{}
	for _, s := range splitList(*statusFlag) {
		st, err := workspace.ParseStatus(s)
		if err != nil {
			return usagef("list", "%s", err)
		}
		statuses[st] = true
	}
	bands := map[string]bool{}
	for _, p := range splitList(*priorityFlag) {
		p = strings.ToUpper(p)
		if !isBand(p) {
			return usagef("list", "priority %q is not one of P1, P2, P3, P4", p)
		}
		bands[p] = true
	}

	st, err := a.loadState(*wsFlag)
	if err != nil {
		return err
	}
	out := a.Stdout
	if len(st.Items) == 0 {
		fmt.Fprintln(out, "The workspace has no items. Import some with \"triage import <file>\".")
		return nil
	}

	var rows []scored
	for _, it := range st.Items {
		if len(statuses) > 0 && !statuses[it.Status] {
			continue
		}
		res := priority.Evaluate(it.Finding)
		if len(bands) > 0 && !bands[res.Band] {
			continue
		}
		rows = append(rows, scored{it, res})
	}
	if len(rows) == 0 {
		fmt.Fprintf(out, "No items match (the workspace has %s).\n", plural(len(st.Items), "item"))
		return nil
	}
	sortQueue(rows)

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPRIORITY\tSCORE\tSTATUS\tSEVERITY\tTITLE\tLOCATION")
	for _, r := range rows {
		f := r.item.Finding
		fmt.Fprintf(tw, "%d\t%s\t%d\t%s\t%s\t%s\t%s\n",
			r.item.ID, r.pri.Band, r.pri.Score, cleanLine(string(r.item.Status)), cleanLine(f.Severity),
			truncate(cleanLine(f.Title), 60), truncate(cleanLine(f.Location), 40))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nShowing %d of %s.\n", len(rows), plural(len(st.Items), "item"))
	return nil
}

// sortQueue orders items by score (highest first), then severity, then ID.
func sortQueue(rows []scored) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.pri.Score != b.pri.Score {
			return a.pri.Score > b.pri.Score
		}
		if sa, sb := severityRank(a.item.Finding.Severity), severityRank(b.item.Finding.Severity); sa != sb {
			return sa < sb
		}
		return a.item.ID < b.item.ID
	})
}

func severityRank(s string) int {
	for i, v := range input.Severities {
		if v == s {
			return i
		}
	}
	return len(input.Severities)
}

func (a *App) cmdShow(args []string) error {
	fs := newFlagSet("show")
	wsFlag := fs.String("workspace", "", "")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	id, err := parseID("show", pos)
	if err != nil {
		return err
	}
	st, err := a.loadState(*wsFlag)
	if err != nil {
		return err
	}
	it, ok := st.Get(id)
	if !ok {
		return fmt.Errorf("no item with ID %d", id)
	}
	res := priority.Evaluate(it.Finding)
	f := it.Finding
	out := a.Stdout

	fmt.Fprintf(out, "Item %d: %s\n\n", it.ID, cleanLine(f.Title))
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	row := func(label, value string) {
		if value != "" {
			fmt.Fprintf(tw, "%s:\t%s\n", label, value)
		}
	}
	status := cleanLine(string(it.Status))
	if last, ok := it.LastDecision(); ok && it.Status == workspace.StatusDuplicate {
		status += fmt.Sprintf(" of item %d", last.DuplicateOf)
	}
	row("Status", status)
	row("Priority", fmt.Sprintf("%s, score %d (run \"triage explain %d\" for the reasons)", res.Band, res.Score, it.ID))
	row("Severity", cleanLine(f.Severity))
	row("Source", cleanLine(it.Source))
	row("Source ID", cleanLine(f.SourceID))
	row("Rule", cleanLine(f.Rule))
	row("Location", cleanLine(f.Location))
	row("Asset", cleanLine(f.Asset))
	row("Exposure", cleanLine(f.Exposure))
	row("Asset criticality", cleanLine(f.AssetCriticality))
	if f.KnownExploited != nil {
		row("Known exploited", yesNo(*f.KnownExploited))
	}
	row("CVEs", cleanLine(strings.Join(f.CVEs, ", ")))
	row("Imported", formatTime(it.ImportedAt))
	if !it.UpdatedAt.Equal(it.ImportedAt) {
		row("Updated", formatTime(it.UpdatedAt))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(f.Metadata) > 0 {
		fmt.Fprintln(out, "\nMetadata:")
		keys := make([]string, 0, len(f.Metadata))
		for k := range f.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, k := range keys {
			fmt.Fprintf(tw, "  %s:\t%s\n", cleanLine(k), cleanLine(f.Metadata[k]))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if strings.TrimSpace(f.Description) != "" {
		fmt.Fprintf(out, "\nDescription:\n%s\n", indent(cleanText(f.Description), "  "))
	}

	if len(it.Decisions) == 0 {
		fmt.Fprintf(out, "\nNo decisions yet. Record one with \"triage decide %d --status <status> --reason <text>\".\n", it.ID)
		return nil
	}
	fmt.Fprintln(out, "\nDecisions:")
	for _, d := range it.Decisions {
		what := cleanLine(string(d.Status))
		if d.Status == workspace.StatusDuplicate {
			what += fmt.Sprintf(" of item %d", d.DuplicateOf)
		}
		by := ""
		if d.By != "" {
			by = " by " + cleanLine(d.By)
		}
		fmt.Fprintf(out, "  %s  %s%s: %s\n", formatTime(d.At), what, by, cleanLine(d.Reason))
	}
	if it.ChangedSinceDecision() {
		fmt.Fprintf(out, "\nThe finding changed on %s, after the last decision. Check that the decision still holds.\n", formatTime(it.UpdatedAt))
	}
	return nil
}

func (a *App) cmdExplain(args []string) error {
	fs := newFlagSet("explain")
	wsFlag := fs.String("workspace", "", "")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	id, err := parseID("explain", pos)
	if err != nil {
		return err
	}
	st, err := a.loadState(*wsFlag)
	if err != nil {
		return err
	}
	it, ok := st.Get(id)
	if !ok {
		return fmt.Errorf("no item with ID %d", id)
	}
	res := priority.Evaluate(it.Finding)
	out := a.Stdout

	fmt.Fprintf(out, "Item %d: %s\n", it.ID, cleanLine(it.Finding.Title))
	fmt.Fprintf(out, "Priority %s, score %d.\n\n", res.Band, res.Score)
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  POINTS\tRULE\tREASON")
	for _, f := range res.Factors {
		fmt.Fprintf(tw, "  %6s\t%s\t%s\n", fmt.Sprintf("%+d", f.Points), f.Rule, cleanLine(f.Reason))
	}
	fmt.Fprintf(tw, "  %6d\ttotal\n", res.Score)
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nBands: %s\nThe rules are described in docs/prioritization.md.\n", priority.BandSummary)
	return nil
}

func (a *App) cmdDecide(args []string) error {
	fs := newFlagSet("decide")
	wsFlag := fs.String("workspace", "", "")
	statusFlag := fs.String("status", "", "")
	reasonFlag := fs.String("reason", "", "")
	dupFlag := fs.String("duplicate-of", "", "")
	byFlag := fs.String("by", "", "")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	id, err := parseID("decide", pos)
	if err != nil {
		return err
	}
	if *statusFlag == "" {
		return usagef("decide", "--status is required (confirmed, dismissed, deferred or duplicate)")
	}
	status, err := workspace.ParseStatus(*statusFlag)
	if err != nil {
		return usagef("decide", "%s", err)
	}
	if status == workspace.StatusNew {
		return usagef("decide", "a decision cannot set the status back to new; use confirmed, dismissed, deferred or duplicate")
	}
	if strings.TrimSpace(*reasonFlag) == "" {
		return usagef("decide", "--reason is required, so others can see why the decision was made")
	}
	var dupOf int
	if *dupFlag != "" {
		dupOf, err = strconv.Atoi(strings.TrimPrefix(*dupFlag, "#"))
		if err != nil || dupOf < 1 {
			return usagef("decide", "--duplicate-of %q is not an item ID", *dupFlag)
		}
	}
	by := *byFlag
	if by == "" {
		by = a.User()
	}

	ws, err := a.openWorkspace(*wsFlag)
	if err != nil {
		return err
	}
	unlock, err := ws.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	st, err := ws.Load()
	if err != nil {
		return err
	}
	d := workspace.Decision{Status: status, Reason: *reasonFlag, DuplicateOf: dupOf, By: by, At: a.Now().UTC()}
	if err := st.Decide(id, d); err != nil {
		return err
	}
	if err := ws.Save(st); err != nil {
		return fmt.Errorf("saving workspace: %w", err)
	}
	if status == workspace.StatusDuplicate {
		fmt.Fprintf(a.Stdout, "Item %d is now marked as a duplicate of item %d.\n", id, dupOf)
	} else {
		fmt.Fprintf(a.Stdout, "Item %d is now %s.\n", id, status)
	}
	return nil
}

// ExportFormat identifies the export document; bump ExportVersion on
// incompatible changes.
const (
	ExportFormat  = "triage-export"
	ExportVersion = "1"
)

type exportDoc struct {
	Format      string       `json:"format"`
	Version     string       `json:"format_version"`
	ToolVersion string       `json:"tool_version"`
	GeneratedAt time.Time    `json:"generated_at"`
	Items       []exportItem `json:"items"`
}

type exportItem struct {
	ID          int                  `json:"id"`
	Fingerprint string               `json:"fingerprint"`
	Source      string               `json:"source,omitempty"`
	Status      workspace.Status     `json:"status"`
	Priority    priority.Result      `json:"priority"`
	Finding     input.Item           `json:"finding"`
	Decisions   []workspace.Decision `json:"decisions"`
	ImportedAt  time.Time            `json:"imported_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
}

func (a *App) cmdExport(args []string) error {
	fs := newFlagSet("export")
	wsFlag := fs.String("workspace", "", "")
	formatFlag := fs.String("format", "json", "")
	outputFlag := fs.String("output", "", "")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("export", "unexpected argument %q", pos[0])
	}
	if strings.ToLower(*formatFlag) != "json" {
		return usagef("export", "format %q is not supported (only json is)", *formatFlag)
	}
	st, err := a.loadState(*wsFlag)
	if err != nil {
		return err
	}

	doc := exportDoc{
		Format:      ExportFormat,
		Version:     ExportVersion,
		ToolVersion: a.Version,
		GeneratedAt: a.Now().UTC(),
		Items:       make([]exportItem, 0, len(st.Items)),
	}
	for _, it := range st.Items {
		decisions := it.Decisions
		if decisions == nil {
			decisions = []workspace.Decision{}
		}
		doc.Items = append(doc.Items, exportItem{
			ID:          it.ID,
			Fingerprint: it.Fingerprint,
			Source:      it.Source,
			Status:      it.Status,
			Priority:    priority.Evaluate(it.Finding),
			Finding:     it.Finding,
			Decisions:   decisions,
			ImportedAt:  it.ImportedAt,
			UpdatedAt:   it.UpdatedAt,
		})
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if *outputFlag == "" || *outputFlag == "-" {
		_, err := a.Stdout.Write(data)
		return err
	}
	if err := workspace.WriteFileAtomic(*outputFlag, data); err != nil {
		return err
	}
	fmt.Fprintf(a.Stderr, "Exported %s to %s\n", plural(len(doc.Items), "item"), *outputFlag)
	return nil
}

func (a *App) cmdVersion(args []string) error {
	fs := newFlagSet("version")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("version", "unexpected argument %q", pos[0])
	}
	fmt.Fprintf(a.Stdout, "triage %s\n", a.Version)
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isBand(p string) bool {
	if p == priority.LowestBand {
		return true
	}
	for _, b := range priority.Bands {
		if b.Name == p {
			return true
		}
	}
	return false
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func joinIDs(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	if len(ids) == 1 {
		return "item " + parts[0]
	}
	return "items " + strings.Join(parts, ", ")
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
