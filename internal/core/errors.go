package core

import (
	"errors"
	"fmt"
)

// Sentinel errors that callers can check with errors.Is.
var (
	ErrScopeViolation   = errors.New("target is outside authorized scope")
	ErrTimeout          = errors.New("operation timed out")
	ErrRateLimited      = errors.New("rate limit exceeded")
	ErrAuthRequired     = errors.New("authentication required")
	ErrNetworkUnreachable = errors.New("network unreachable")
	ErrTargetNotFound   = errors.New("target not found or not resolvable")
	ErrToolNotFound     = errors.New("requested tool not found in registry")
	ErrPlanInvalid      = errors.New("execution plan is invalid")
	ErrSafetyDenied     = errors.New("operation denied by safety guard")
	ErrNotImplemented   = errors.New("feature not yet implemented")
)

// AkemiError wraps an error with structured context.
type AkemiError struct {
	Op       string // Operation that failed (e.g., "Scanner.Scan")
	Target   string // Target being operated on
	Err      error  // Underlying error
	Severity string // debug, info, warn, error
	Recoverable bool // Can the operation be retried or worked around?
}

func (e *AkemiError) Error() string {
	if e.Target != "" {
		return fmt.Sprintf("[%s] %s on %s: %v", e.Severity, e.Op, e.Target, e.Err)
	}
	return fmt.Sprintf("[%s] %s: %v", e.Severity, e.Op, e.Err)
}

func (e *AkemiError) Unwrap() error {
	return e.Err
}

// NewError creates a new AkemiError.
func NewError(op, target string, err error) *AkemiError {
	return &AkemiError{
		Op:       op,
		Target:   target,
		Err:      err,
		Severity: "error",
	}
}

// NewWarnError creates a warning-level AkemiError.
func NewWarnError(op, target string, err error) *AkemiError {
	return &AkemiError{
		Op:          op,
		Target:      target,
		Err:         err,
		Severity:    "warn",
		Recoverable: true,
	}
}

// ScopeError creates an error for scope violations.
func ScopeError(target string, reason string) *AkemiError {
	return &AkemiError{
		Op:       "ScopeValidator.Check",
		Target:   target,
		Err:      fmt.Errorf("%w: %s", ErrScopeViolation, reason),
		Severity: "warn",
	}
}

// TimeoutError creates an error for timeouts.
func TimeoutError(op, target string, duration string) *AkemiError {
	return &AkemiError{
		Op:          op,
		Target:      target,
		Err:         fmt.Errorf("%w after %s", ErrTimeout, duration),
		Severity:    "warn",
		Recoverable: true,
	}
}

// IsNotFound checks if an error indicates a target was not found.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrTargetNotFound)
}

// IsScopeViolation checks if an error is a scope violation.
func IsScopeViolation(err error) bool {
	return errors.Is(err, ErrScopeViolation)
}

// IsRetryable checks if an error suggests the operation can be retried.
func IsRetryable(err error) bool {
	var akemiErr *AkemiError
	if errors.As(err, &akemiErr) {
		return akemiErr.Recoverable
	}
	return errors.Is(err, ErrTimeout) || errors.Is(err, ErrRateLimited)
}
