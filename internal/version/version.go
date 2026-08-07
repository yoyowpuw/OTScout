// Package version exposes build metadata. Values are injected at link time by
// the release build, and fall back to values useful during development.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

var (
	// Version is the release tag, set with -ldflags at build time.
	Version = "dev"
	// Commit is the git revision the binary was built from.
	Commit = ""
	// BuildDate is the UTC build timestamp in RFC 3339 form.
	BuildDate = ""
)

// Short returns just the version string.
func Short() string { return Version }

// UserAgent is sent when downloading advisory corpora, so that upstream
// operators can see who is fetching and contact the project if the traffic ever
// becomes a problem.
func UserAgent() string {
	return fmt.Sprintf("otscout/%s (+https://github.com/yoyowpuw/OTScout)", Version)
}

// Full renders the multi line version banner.
func Full() string {
	commit := Commit
	if commit == "" {
		commit = revisionFromBuildInfo()
	}
	if commit == "" {
		commit = "unknown"
	}
	date := BuildDate
	if date == "" {
		date = "unknown"
	}
	return fmt.Sprintf("otscout %s\n  commit:     %s\n  built:      %s\n  go:         %s\n  platform:   %s/%s",
		Version, commit, date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func revisionFromBuildInfo() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			if len(setting.Value) > 12 {
				return setting.Value[:12]
			}
			return setting.Value
		}
	}
	return ""
}
