package tools

import (
	"context"
	"fmt"

	"Akemi/internal/mcp"
	"Akemi/internal/reportfiles"
)

func handleReadReport(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = ctx
	path := getString(args, "path")
	maxBytes := int64(getInt(args, "max_bytes", int(reportfiles.MaxReportBytes)))
	resolved, data, err := reportfiles.Read(reportRoot(svc), path, maxBytes)
	if err != nil {
		return nil, err
	}
	text := fmt.Sprintf("Report read: %s (%d bytes)\n\n%s", resolved, len(data), string(data))
	return []mcp.ContentBlock{mcp.TextContent(text)}, nil
}

func handleWriteReport(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = ctx
	path := getString(args, "path")
	content := getString(args, "content")
	overwrite := getBoolDefault(args, "overwrite", true)
	resolved, bytesWritten, err := reportfiles.Write(reportRoot(svc), path, content, overwrite)
	if err != nil {
		return nil, err
	}
	text := fmt.Sprintf("Report written: %s (%d bytes)", resolved, bytesWritten)
	return []mcp.ContentBlock{mcp.TextContent(text)}, nil
}

func reportRoot(svc *Services) string {
	if svc == nil || svc.ReportDir == "" {
		return "."
	}
	return svc.ReportDir
}
