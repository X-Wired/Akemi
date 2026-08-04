package execution

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"Akemi/internal/engagement"
)

func TestWrapHTTPClientRejectsOutOfScopeRedirect(t *testing.T) {
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.test/out", http.StatusFound)
	}))
	defer inside.Close()

	policy := DefaultPolicy()
	run, err := NewRunContext("run-redirect", engagement.TargetProfile{Domain: "127.0.0.1"}, ScopePolicy{ExactHosts: []string{"127.0.0.1"}}, policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRunContext(context.Background(), run)
	client := WrapHTTPClient(ctx, &http.Client{})
	if _, err := client.Get(inside.URL); err == nil {
		t.Fatal("out-of-scope redirect should be rejected")
	}
}
