package execution

import "context"

type contextKey struct{}

// WithRunContext attaches immutable run policy to a context shared by nested
// service, tool, and agent calls.
func WithRunContext(ctx context.Context, run *RunContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, contextKey{}, run)
}

// RunContextFromContext retrieves the shared run policy, when one exists.
func RunContextFromContext(ctx context.Context) (*RunContext, bool) {
	if ctx == nil {
		return nil, false
	}
	run, ok := ctx.Value(contextKey{}).(*RunContext)
	return run, ok && run != nil
}
