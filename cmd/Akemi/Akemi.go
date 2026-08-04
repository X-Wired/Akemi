// Akemi — Surface Map Attack Framework
// Version 2.1.0 (Stable)
//
// Entry point. All CLI logic has been moved to cmd/Akemi/commands/.
// The original v1.x monolithic behavior is preserved on the root command
// for backward compatibility. New subcommands (scan, discover, probe, etc.)
// provide a cleaner structured interface.
//
// Build: go build -ldflags="-X main.Version=2.1.0" ./cmd/Akemi
package main

import (
	"Akemi/cmd/Akemi/commands"
	"Akemi/internal/version"
)

// Version is set at build time via ldflags.
var Version = version.Current

func main() {
	commands.SetVersion(Version)
	commands.Execute()
}
