// Package cli implements the triage command line.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/gosentrixlabs/triage/internal/workspace"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
)

// App holds everything a command needs from its environment, so tests can
// substitute their own.
type App struct {
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Getenv  func(string) string
	Now     func() time.Time
	User    func() string
	Version string
}

// New returns an App wired to the real process environment.
func New(version string) *App {
	return &App{
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Getenv:  os.Getenv,
		Now:     time.Now,
		User:    currentUser,
		Version: version,
	}
}

func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	for _, k := range []string{"USER", "USERNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

type command struct {
	name    string
	summary string
	help    string
	run     func(a *App, args []string) error
}

var commands []command

func init() {
	commands = []command{
		{"import", "Import findings from a JSON file", importHelp, (*App).cmdImport},
		{"list", "List items in priority order", listHelp, (*App).cmdList},
		{"show", "Show one item in full", showHelp, (*App).cmdShow},
		{"explain", "Explain why an item has its priority", explainHelp, (*App).cmdExplain},
		{"decide", "Record a triage decision", decideHelp, (*App).cmdDecide},
		{"export", "Export items, priorities and decisions", exportHelp, (*App).cmdExport},
		{"version", "Print the version", versionHelp, (*App).cmdVersion},
	}
}

func findCommand(name string) (command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// usageError is a mistake in how a command was called. It exits with ExitUsage.
type usageError struct {
	cmd string
	msg string
}

func (e *usageError) Error() string { return e.msg }

func usagef(cmd, format string, args ...any) error {
	return &usageError{cmd: cmd, msg: fmt.Sprintf(format, args...)}
}

// errHelpShown means a command printed its help because of -h or --help.
var errHelpShown = errors.New("help shown")

// Run executes the command line and returns the process exit code.
func (a *App) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.Stderr, mainHelp)
		return ExitUsage
	}
	name, rest := args[0], args[1:]
	switch name {
	case "help", "-h", "--help", "-help":
		return a.runHelp(rest)
	case "--version", "-version":
		name = "version"
	}
	cmd, ok := findCommand(name)
	if !ok {
		fmt.Fprintf(a.Stderr, "triage: unknown command %q\nRun \"triage help\" to see the commands.\n", name)
		return ExitUsage
	}
	err := cmd.run(a, rest)
	var ue *usageError
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, errHelpShown):
		fmt.Fprint(a.Stdout, cmd.help)
		return ExitOK
	case errors.As(err, &ue):
		fmt.Fprintf(a.Stderr, "triage %s: %s\nRun \"triage help %s\" for usage.\n", cmd.name, ue.msg, cmd.name)
		return ExitUsage
	default:
		fmt.Fprintf(a.Stderr, "triage %s: %s\n", cmd.name, err)
		return ExitError
	}
}

func (a *App) runHelp(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.Stdout, mainHelp)
		return ExitOK
	}
	cmd, ok := findCommand(args[0])
	if !ok {
		fmt.Fprintf(a.Stderr, "triage: unknown command %q\nRun \"triage help\" to see the commands.\n", args[0])
		return ExitUsage
	}
	fmt.Fprint(a.Stdout, cmd.help)
	return ExitOK
}

// newFlagSet returns a flag set that reports errors to the caller instead of
// printing them.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseArgs parses flags that may appear before, between or after positional
// arguments, so "triage decide 3 --status confirmed" works. Arguments after
// "--" are always positional.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, errHelpShown
			}
			return nil, usagef(fs.Name(), "%s", err)
		}
		rest := fs.Args()
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" {
			return append(positional, rest...), nil
		}
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// workspaceDir resolves the workspace directory from the flag, then
// $TRIAGE_WORKSPACE, then the default.
func (a *App) workspaceDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := a.Getenv("TRIAGE_WORKSPACE"); v != "" {
		return v
	}
	return workspace.DefaultDir
}

// loadState reads an existing workspace without locking it. Saves replace the
// state file atomically, so a read always sees a complete state.
func (a *App) loadState(flagValue string) (*workspace.State, error) {
	ws, err := a.openWorkspace(flagValue)
	if err != nil {
		return nil, err
	}
	return ws.Load()
}

// openWorkspace opens an existing workspace, explaining how to create one if
// it is missing.
func (a *App) openWorkspace(flagValue string) (*workspace.Workspace, error) {
	dir := a.workspaceDir(flagValue)
	ws, err := workspace.Open(dir)
	if errors.Is(err, workspace.ErrNoWorkspace) {
		return nil, fmt.Errorf("no triage workspace at %s. Run \"triage import <file>\" to create one, or pass --workspace", dir)
	}
	return ws, err
}

func parseID(cmd string, positional []string) (int, error) {
	if len(positional) == 0 {
		return 0, usagef(cmd, "an item ID is required")
	}
	if len(positional) > 1 {
		return 0, usagef(cmd, "expected one item ID, got %d arguments", len(positional))
	}
	id, err := strconv.Atoi(strings.TrimPrefix(positional[0], "#"))
	if err != nil || id < 1 {
		return 0, usagef(cmd, "%q is not an item ID (IDs are positive numbers, as shown by \"triage list\")", positional[0])
	}
	return id, nil
}
