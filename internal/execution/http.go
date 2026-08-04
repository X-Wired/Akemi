package execution

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// WrapHTTPClient applies the active run's request budget, concurrency limit,
// response-size cap, and cancellation to an existing client. A nil or
// context-only run leaves the client unchanged for compatibility.
func WrapHTTPClient(ctx context.Context, client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	run, ok := RunContextFromContext(ctx)
	if !ok || run == nil {
		return client
	}
	copy := *client
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	copy.Transport = &runRoundTripper{ctx: ctx, run: run, base: base}
	originalRedirect := client.CheckRedirect
	copy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := ValidateTarget(run.Scope, req.URL.String()); err != nil {
			return fmt.Errorf("redirect outside authorized scope: %w", err)
		}
		if originalRedirect != nil {
			return originalRedirect(req, via)
		}
		return nil
	}
	return &copy
}

type runRoundTripper struct {
	ctx  context.Context
	run  *RunContext
	base http.RoundTripper
}

func (t *runRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	if err := ValidateTarget(t.run.Scope, req.URL.String()); err != nil {
		return nil, err
	}
	release, err := t.run.reserveRequest(t.ctx)
	if err != nil {
		return nil, err
	}
	request := req
	if req.Context() == context.Background() {
		request = req.WithContext(t.ctx)
	}
	resp, err := t.base.RoundTrip(request)
	if err != nil || resp == nil || resp.Body == nil {
		release()
		return resp, err
	}
	limit := t.run.Policy.MaxResponseBytes
	if limit <= 0 {
		limit = DefaultPolicy().MaxResponseBytes
	}
	resp.Body = &boundedBody{ReadCloser: resp.Body, remaining: limit, release: release}
	return resp, nil
}

type boundedBody struct {
	io.ReadCloser
	remaining int64
	release   func()
	once      sync.Once
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		b.once.Do(b.release)
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	if b.remaining <= 0 || err != nil {
		b.once.Do(b.release)
	}
	return n, err
}

func (b *boundedBody) Close() error {
	b.once.Do(b.release)
	return b.ReadCloser.Close()
}
