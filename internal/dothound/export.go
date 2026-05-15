package dothound

import (
	"fmt"
	"strings"
)

// ExportCURL converts a workflow graph to a series of cURL commands.
func ExportCURL(graph *WorkflowGraph) string {
	var sb strings.Builder
	sb.WriteString("# DotHound Workflow — cURL commands\n")
	sb.WriteString(fmt.Sprintf("# Generated from: %s\n", graph.StartURL))
	sb.WriteString(fmt.Sprintf("# Exchanges: %d\n\n", len(graph.Exchanges)))

	for _, ex := range graph.Exchanges {
		sb.WriteString(fmt.Sprintf("# %s %s\n", ex.Request.Method, ex.Request.Target))
		sb.WriteString(fmt.Sprintf("curl -X %s", ex.Request.Method))

		// Headers
		for _, h := range ex.Request.Headers {
			if h.Sensitive && h.Value == "<redacted>" {
				sb.WriteString(fmt.Sprintf(" \\\n  -H '%s: <REDACTED>'", h.Name))
			} else {
				escaped := strings.ReplaceAll(h.Value, "'", "'\\''")
				sb.WriteString(fmt.Sprintf(" \\\n  -H '%s: %s'", h.Name, escaped))
			}
		}

		// Body
		if ex.Request.Body != nil && ex.Request.Body.Text != "" {
			escaped := strings.ReplaceAll(ex.Request.Body.Text, "'", "'\\''")
			sb.WriteString(fmt.Sprintf(" \\\n  -d '%s'", escaped))
		}

		sb.WriteString(fmt.Sprintf(" \\\n  '%s'\n\n", ex.Request.Target))
	}

	return sb.String()
}

// ExportPython converts a workflow graph to a Python requests script.
func ExportPython(graph *WorkflowGraph) string {
	var sb strings.Builder
	sb.WriteString("#!/usr/bin/env python3\n")
	sb.WriteString("# DotHound Workflow — Python requests replay\n")
	sb.WriteString(fmt.Sprintf("# Generated from: %s\n", graph.StartURL))
	sb.WriteString(fmt.Sprintf("# Exchanges: %d\n\n", len(graph.Exchanges)))
	sb.WriteString("import requests\n\n")
	sb.WriteString("session = requests.Session()\n\n")

	for i, ex := range graph.Exchanges {
		method := strings.ToLower(ex.Request.Method)
		url := ex.Request.Target

		sb.WriteString(fmt.Sprintf("# Step %d: %s %s\n", i+1, ex.Request.Method, url))

		// Headers
		sb.WriteString("headers = {\n")
		for _, h := range ex.Request.Headers {
			if h.Sensitive && h.Value == "<redacted>" {
				sb.WriteString(fmt.Sprintf("    '%s': '<REDACTED>',\n", h.Name))
			} else {
				escaped := strings.ReplaceAll(h.Value, "\\", "\\\\")
				escaped = strings.ReplaceAll(escaped, "'", "\\'")
				sb.WriteString(fmt.Sprintf("    '%s': '%s',\n", h.Name, escaped))
			}
		}
		sb.WriteString("}\n")

		// Body
		if ex.Request.Body != nil && ex.Request.Body.Text != "" {
			contentType := ex.Request.Body.ContentType
			if strings.Contains(contentType, "json") {
				sb.WriteString(fmt.Sprintf("response = session.%s(\n    '%s',\n    headers=headers,\n    json=%s\n)\n",
					method, url, ex.Request.Body.Text))
			} else {
				escaped := strings.ReplaceAll(ex.Request.Body.Text, "'", "\\'")
				sb.WriteString(fmt.Sprintf("response = session.%s(\n    '%s',\n    headers=headers,\n    data='%s'\n)\n",
					method, url, escaped))
			}
		} else {
			sb.WriteString(fmt.Sprintf("response = session.%s('%s', headers=headers)\n", method, url))
		}

		sb.WriteString(fmt.Sprintf("print(f'Step %d: {response.status_code}')\n\n", i+1))
	}

	return sb.String()
}

// ExportHAR converts a workflow graph to HAR (HTTP Archive) JSON format.
func ExportHAR(graph *WorkflowGraph) string {
	var entries []string
	for _, ex := range graph.Exchanges {
		reqHeaders := make([]string, 0, len(ex.Request.Headers))
		for _, h := range ex.Request.Headers {
			reqHeaders = append(reqHeaders, fmt.Sprintf(
				`{"name":"%s","value":"%s"}`, h.Name, strings.ReplaceAll(h.Value, `"`, `\"`)))
		}

		respHeaders := "[]"
		respStatus := 0
		if ex.Response != nil {
			rh := make([]string, 0, len(ex.Response.Headers))
			for _, h := range ex.Response.Headers {
				rh = append(rh, fmt.Sprintf(
					`{"name":"%s","value":"%s"}`, h.Name, strings.ReplaceAll(h.Value, `"`, `\"`)))
			}
			respHeaders = "[" + strings.Join(rh, ",") + "]"
			respStatus = ex.Response.StatusCode
		}

		entry := fmt.Sprintf(`{
      "startedDateTime": "%d",
      "request": {
        "method": "%s",
        "url": "%s",
        "headers": [%s]
      },
      "response": {
        "status": %d,
        "headers": %s
      }
    }`, ex.StartedAt, ex.Request.Method, ex.Request.Target,
			strings.Join(reqHeaders, ","), respStatus, respHeaders)

		entries = append(entries, entry)
	}

	return fmt.Sprintf(`{
  "log": {
    "version": "1.2",
    "creator": {"name": "DotHound", "version": "0.1.0"},
    "entries": [
%s
    ]
  }
}`, strings.Join(entries, ",\n"))
}
