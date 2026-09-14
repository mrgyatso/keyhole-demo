// Package version carries the build version, stamped at link time:
//
//	go build -ldflags "-X github.com/mrgyatso/keyhole/internal/version.Version=v0.1.0"
package version

// Version is "dev" in untagged builds.
var Version = "dev"
