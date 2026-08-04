// Package version contains the canonical Akemi release identity.
package version

const (
	// Current is the pre-stable Akemi release candidate represented by this source tree.
	Current = "2.1.0"

	// UserAgent is the default HTTP User-Agent sent by Akemi components.
	UserAgent = "Akemi/" + Current + " (Security Assessment Framework)"
)
