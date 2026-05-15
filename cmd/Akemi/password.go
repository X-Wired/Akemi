package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// readPasswordTerm reads a password from the terminal without echo.
func readPasswordTerm() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("stdin is not a terminal")
	}

	state, err := term.GetState(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to get terminal state: %w", err)
	}

	// Restore terminal state on exit.
	defer func() {
		_ = term.Restore(fd, state)
	}()

	password, err := term.ReadPassword(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	return password, nil
}
