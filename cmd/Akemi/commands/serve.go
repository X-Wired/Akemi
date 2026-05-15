package commands

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"Akemi/internal/mcp"
	"Akemi/internal/mcp/prompts"
	"Akemi/internal/mcp/resources"
	mcpstate "Akemi/internal/mcp/state"
	"Akemi/internal/mcp/tools"

	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start Akemi as an MCP server for LLM integration",
		Long: `Start Akemi in MCP (Model Context Protocol) server mode.

This exposes all of Akemi's capabilities — port scanning, web discovery,
vulnerability probing, subdomain enumeration, and more — as callable tools
to MCP-compatible LLM hosts like Claude Desktop, Cursor, and Continue.dev.

Two transport modes are supported:
  --transport stdio   For local tools like Claude Desktop (default)
  --transport http    Streamable HTTP on a single MCP endpoint

Examples:
  akemi serve                                    # stdio mode for Claude Desktop
  akemi serve --transport http --port 9090       # Streamable HTTP server
  akemi serve --transport http --host 0.0.0.0 --port 9090 --api-key my-secret`,
		RunE: runServe,
	}

	cmd.Flags().String("transport", "stdio", "Transport mode: stdio or http")
	cmd.Flags().String("host", "127.0.0.1", "Host to bind HTTP server to")
	cmd.Flags().Int("port", 9090, "Port for HTTP server")
	cmd.Flags().String("mcp-path", "/mcp", "Streamable HTTP MCP endpoint path")
	cmd.Flags().String("api-key", "", "Bearer token required for HTTP transport")
	cmd.Flags().StringSlice("allowed-origin", nil, "Allowed HTTP Origin for browser MCP clients; repeatable")
	cmd.Flags().String("probe-dir", "./probes", "Directory containing YAML probe templates")

	return cmd
}

func runServe(cmd *cobra.Command, args []string) error {
	transport, _ := cmd.Flags().GetString("transport")
	host, _ := cmd.Flags().GetString("host")
	port, _ := cmd.Flags().GetInt("port")
	mcpPath, _ := cmd.Flags().GetString("mcp-path")
	apiKey, _ := cmd.Flags().GetString("api-key")
	allowedOrigins, _ := cmd.Flags().GetStringSlice("allowed-origin")
	probeDir, _ := cmd.Flags().GetString("probe-dir")

	logLevel := slog.LevelInfo
	if rootVerbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Initialize Phase 1 services
	svc := initServices(logger, rootOutputDir)

	// Load probe templates
	if probeDir != "" {
		svc.Vuln.LoadTemplates(probeDir)
	}

	logger.Info("Akemi MCP Server starting",
		slog.String("version", "2.0.0-dev"),
		slog.String("transport", transport),
		slog.Int("templates_loaded", len(svc.Vuln.ListTemplates())),
	)

	runtimeState := mcpstate.NewStore(svc.MCPContext)

	// Build the tool registry with all services
	toolReg := tools.NewToolRegistry(tools.ToolRegistryConfig{
		Scanner:       svc.Scanner,
		Discoverer:    svc.Discovery,
		Prober:        svc.Vuln,
		SubEnumerator: svc.Subdomain,
		Reporter:      svc.Reporting,
		Context:       svc.MCPContext,
		ReportDir:     rootOutputDir,
		Logger:        logger,
		State:         runtimeState,
	})

	// Build resource and prompt providers
	resourceProv := resources.NewResourceProvider(resources.Config{
		Context: svc.MCPContext,
		Prober:  svc.Vuln,
		State:   runtimeState,
	})
	promptProv := prompts.NewPromptProvider()

	// Create transport
	var t mcp.Transport
	switch transport {
	case "stdio":
		t = mcp.NewStdioTransport(logger)
		fmt.Fprintf(os.Stderr, "[akemi] MCP server ready. Waiting for client connection via stdio...\n")
		fmt.Fprintf(os.Stderr, "[akemi] Available tools: %d\n", len(toolReg.List()))
		fmt.Fprintf(os.Stderr, "[akemi] Available prompts: %s\n", promptProv.CollectPromptNames())

	case "http":
		t = mcp.NewStreamableHTTPTransport(mcp.StreamableHTTPConfig{
			Host:           host,
			Port:           port,
			Path:           mcpPath,
			APIKey:         apiKey,
			AllowedOrigins: allowedOrigins,
			Logger:         logger,
		})
		fmt.Fprintf(os.Stderr, "[akemi] MCP Streamable HTTP server starting on http://%s:%d%s\n", host, port, mcpPath)
		fmt.Fprintf(os.Stderr, "[akemi] Health check: http://%s:%d/health\n", host, port)

	default:
		return fmt.Errorf("unknown transport: %s (use 'stdio' or 'http')", transport)
	}

	// Create MCP server with all providers
	server := mcp.NewServer(mcp.ServerConfig{
		Transport: t,
		Logger:    logger,
		Tools:     toolReg,
		Resources: resourceProv,
		Prompts:   promptProv,
	})

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("shutting down MCP server...")
		t.Close()
		os.Exit(0)
	}()

	if err := server.Run(); err != nil {
		return fmt.Errorf("MCP server error: %w", err)
	}

	return nil
}
