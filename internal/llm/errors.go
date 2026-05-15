package llm

import "fmt"

// ErrProviderNotImplemented is returned for configured providers without adapters.
type ErrProviderNotImplemented struct {
	Provider string
}

func (e ErrProviderNotImplemented) Error() string {
	return fmt.Sprintf("llm provider %q is configured but not implemented yet", e.Provider)
}

// ErrUnknownProvider is returned for unsupported provider names.
type ErrUnknownProvider struct {
	Provider string
}

func (e ErrUnknownProvider) Error() string {
	return fmt.Sprintf("unknown llm provider %q", e.Provider)
}
