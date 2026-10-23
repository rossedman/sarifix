// Package version holds build information injected with -ldflags.
package version

import "runtime/debug"

// Set by goreleaser: -X github.com/rossedman/sarifix/internal/version.Version=...
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// Info is the build information printed by `sarifix version`.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Get returns the build info, falling back to the module version and VCS
// stamp recorded by `go install`.
func Get() Info {
	i := Info{Version: Version, Commit: Commit, Date: Date}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return i
	}
	if i.Version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		i.Version = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch {
		case s.Key == "vcs.revision" && i.Commit == "":
			i.Commit = s.Value
		case s.Key == "vcs.time" && i.Date == "":
			i.Date = s.Value
		}
	}
	return i
}
