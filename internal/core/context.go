package core

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// contextKey is an unexported type to avoid key collisions.
type contextKey string

const (
	// TraceIDKey carries a unique scan/operation trace ID.
	TraceIDKey contextKey = "akemi_trace_id"
	// ScanIDKey carries the current scan session ID.
	ScanIDKey contextKey = "akemi_scan_id"
	// TargetKey carries the current target being operated on.
	TargetKey contextKey = "akemi_target"
)

// WithTraceID attaches a trace ID to the context.
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, TraceIDKey, traceID)
}

// TraceIDFromContext extracts the trace ID, or returns "unknown".
func TraceIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(TraceIDKey).(string); ok {
		return v
	}
	return "unknown"
}

// WithScanID attaches a scan session ID to the context.
func WithScanID(ctx context.Context, scanID string) context.Context {
	return context.WithValue(ctx, ScanIDKey, scanID)
}

// ScanIDFromContext extracts the scan ID.
func ScanIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ScanIDKey).(string); ok {
		return v
	}
	return ""
}

// WithTarget attaches the current target to the context.
func WithTarget(ctx context.Context, target string) context.Context {
	return context.WithValue(ctx, TargetKey, target)
}

// TargetFromContext extracts the current target.
func TargetFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(TargetKey).(string); ok {
		return v
	}
	return ""
}

// =============================================================================
// Structured Logging Helpers
// =============================================================================

// Logger returns the default structured logger.
// In production, this would be configured via config.
var defaultLogger *slog.Logger

func init() {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	defaultLogger = slog.New(handler)
}

// SetLogger replaces the default logger.
func SetLogger(l *slog.Logger) {
	defaultLogger = l
}

// Logger returns the default logger.
func Logger() *slog.Logger {
	return defaultLogger
}

// LogAttr creates common log attributes from context.
func LogAttr(ctx context.Context, extra ...slog.Attr) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("trace_id", TraceIDFromContext(ctx)),
	}
	if sid := ScanIDFromContext(ctx); sid != "" {
		attrs = append(attrs, slog.String("scan_id", sid))
	}
	if t := TargetFromContext(ctx); t != "" {
		attrs = append(attrs, slog.String("target", t))
	}
	attrs = append(attrs, extra...)
	return attrs
}

// LogDuration logs the duration of an operation. Use as:
//
//	defer core.LogDuration(ctx, "Crawl", time.Now())
func LogDuration(ctx context.Context, op string, start time.Time) {
	elapsed := time.Since(start)
	defaultLogger.Debug("operation completed",
		slog.String("op", op),
		slog.Duration("elapsed", elapsed),
		slog.String("trace_id", TraceIDFromContext(ctx)),
	)
}

// =============================================================================
// Utility: Generate unique IDs
// =============================================================================

// NewTraceID generates a compact unique trace ID.
// In production, use a proper UUID library; this is a simple fallback.
func NewTraceID() string {
	return fmtTraceID(time.Now().UnixNano())
}

func fmtTraceID(n int64) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = charset[n%int64(len(charset))]
		n /= int64(len(charset))
	}
	return string(b)
}
