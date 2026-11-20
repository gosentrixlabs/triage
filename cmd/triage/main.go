// Command triage turns security findings into an explainable priority queue
// and records triage decisions.
package main

import (
	"os"
	"runtime/debug"

	"github.com/gosentrixlabs/triage/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
var version = ""

func main() {
	os.Exit(cli.New(resolveVersion()).Run(os.Args[1:]))
}

// resolveVersion prefers the build-time version, then the module version
// recorded by "go install module@version", then "dev".
func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
