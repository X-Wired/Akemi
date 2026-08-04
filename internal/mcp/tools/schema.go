package tools

import (
	"fmt"
	"strings"

	"Akemi/internal/mcp"
)

// validateToolArgs implements the supported subset of the MCP input schema.
// Unknown fields are intentionally ignored for compatibility with older
// clients, but known fields must have the documented type and enum value.
func validateToolArgs(schema mcp.ToolInputSchema, args map[string]interface{}) error {
	if args == nil {
		args = map[string]interface{}{}
	}
	for _, required := range schema.Required {
		if _, ok := args[required]; !ok {
			return fmt.Errorf("missing required argument %q", required)
		}
	}
	for name, value := range args {
		property, ok := schema.Properties[name]
		if !ok {
			continue
		}
		if err := validateProperty(name, property, value); err != nil {
			return err
		}
	}
	return nil
}

func validateProperty(name string, property mcp.Property, value interface{}) error {
	if value == nil {
		return nil
	}
	if len(property.Enum) > 0 {
		valueText := fmt.Sprint(value)
		matched := false
		for _, option := range property.Enum {
			if valueText == option {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("argument %q must be one of %s", name, strings.Join(property.Enum, ", "))
		}
	}
	switch property.Type {
	case "", "any":
		return nil
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("argument %q must be a string", name)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("argument %q must be a boolean", name)
		}
	case "integer":
		if !isInteger(value) {
			return fmt.Errorf("argument %q must be an integer", name)
		}
	case "number":
		if !isNumber(value) {
			return fmt.Errorf("argument %q must be a number", name)
		}
	case "array":
		items, ok := value.([]interface{})
		if !ok {
			if strings.HasPrefix(fmt.Sprintf("%T", value), "[]string") {
				return nil
			}
			return fmt.Errorf("argument %q must be an array", name)
		}
		if property.Items != nil {
			for index, item := range items {
				if err := validateProperty(fmt.Sprintf("%s[%d]", name, index), *property.Items, item); err != nil {
					return err
				}
			}
		}
	case "object":
		if _, ok := value.(map[string]interface{}); !ok {
			return fmt.Errorf("argument %q must be an object", name)
		}
	}
	return nil
}

func isInteger(value interface{}) bool {
	switch number := value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case float64:
		return number == float64(int64(number))
	case float32:
		return number == float32(int64(number))
	default:
		return false
	}
}

func isNumber(value interface{}) bool {
	switch value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return true
	default:
		return false
	}
}
