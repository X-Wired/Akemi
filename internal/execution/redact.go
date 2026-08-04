package execution

import (
	"fmt"
	"regexp"
	"strings"
)

type RedactionNotice struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

var sensitiveKey = regexp.MustCompile(`(?i)(pass(word)?|secret|token|cookie|csrf|authorization|api[_-]?key|credential|private[_-]?key)`)

// RedactValue returns a deep-copied, JSON-compatible value with sensitive
// fields masked. It is intentionally conservative for maps and structs that
// have already been converted to interface values.
func RedactValue(value interface{}) (interface{}, []RedactionNotice) {
	notices := make([]RedactionNotice, 0)
	return redactAt(value, "$", &notices), notices
}

func redactAt(value interface{}, path string, notices *[]RedactionNotice) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, item := range v {
			childPath := path + "." + key
			if sensitiveKey.MatchString(key) {
				if item != nil && strings.TrimSpace(fmt.Sprint(item)) != "" {
					*notices = append(*notices, RedactionNotice{Path: childPath, Reason: "sensitive field"})
				}
				out[key] = "[REDACTED]"
				continue
			}
			out[key] = redactAt(item, childPath, notices)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, item := range v {
			out[i] = redactAt(item, fmt.Sprintf("%s[%d]", path, i), notices)
		}
		return out
	case string:
		return redactText(v, path, notices)
	default:
		return value
	}
}

func redactText(value, path string, notices *[]RedactionNotice) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return value
	}
	// Do not attempt to identify arbitrary secrets in prose. Structured
	// sensitive keys are masked above; this catches common bearer/cookie text.
	if strings.Contains(strings.ToLower(trimmed), "bearer ") || strings.Contains(strings.ToLower(trimmed), "set-cookie:") {
		*notices = append(*notices, RedactionNotice{Path: path, Reason: "sensitive text"})
		return "[REDACTED]"
	}
	return value
}
