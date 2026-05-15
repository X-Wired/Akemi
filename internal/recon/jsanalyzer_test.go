package recon

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestAnalyzeJSDoesNotPrintWhenPageHasNoScripts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><head><title>No scripts</title></head><body>ok</body></html>"))
	}))
	defer server.Close()

	originalStdout := os.Stdout
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	os.Stdout = writePipe

	_, analyzeErr := AnalyzeJS(server.URL)

	_ = writePipe.Close()
	os.Stdout = originalStdout

	var captured bytes.Buffer
	_, _ = io.Copy(&captured, readPipe)
	_ = readPipe.Close()

	if analyzeErr != nil {
		t.Fatalf("AnalyzeJS failed: %v", analyzeErr)
	}
	if captured.Len() > 0 {
		t.Fatalf("AnalyzeJS printed to stdout: %q", captured.String())
	}
}
