package commands

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"Akemi/internal/assistant"
	akemiconfig "Akemi/internal/config"
	"Akemi/internal/engagement"
	"Akemi/internal/llm"
	mcptools "Akemi/internal/mcp/tools"
	"Akemi/internal/mcpclient"
	"Akemi/internal/tui/dashboard"
)

type errLLMAPIKeyRequired struct {
	Provider string
}

func (e errLLMAPIKeyRequired) Error() string {
	return fmt.Sprintf("llm provider %q has no API key configured", e.Provider)
}

func buildAssistantSession(svc *Services, logger *slog.Logger) (*assistant.Session, error) {
	cfg, err := akemiconfig.Load("")
	if err != nil {
		return nil, err
	}
	activateConfiguredLLMProvider(&cfg.LLM)
	if strings.TrimSpace(cfg.LLM.ActiveAPIKey()) == "" {
		return nil, errLLMAPIKeyRequired{Provider: cfg.LLM.Provider}
	}
	return buildAssistantSessionFromConfig(svc, logger, cfg)
}

func buildAssistantSessionWithAPIKey(svc *Services, logger *slog.Logger, provider, apiKey string) (*assistant.Session, error) {
	cfg, err := akemiconfig.Load("")
	if err != nil {
		return nil, err
	}
	originalProvider := provider
	provider = akemiconfig.NormalizeLLMProvider(provider)
	if provider == "" {
		return nil, fmt.Errorf("unsupported llm provider %q", originalProvider)
	}
	cfg.LLM.Provider = provider
	switch provider {
	case "openai":
		cfg.LLM.OpenAI.APIKey = strings.TrimSpace(apiKey)
	case "deepseek":
		cfg.LLM.DeepSeek.APIKey = strings.TrimSpace(apiKey)
	case "local":
		cfg.LLM.Local.APIKey = strings.TrimSpace(apiKey)
	case "anthropic":
		cfg.LLM.Anthropic.APIKey = strings.TrimSpace(apiKey)
	case "google":
		cfg.LLM.Google.APIKey = strings.TrimSpace(apiKey)
	default:
		return nil, fmt.Errorf("unsupported llm provider %q", provider)
	}
	if strings.TrimSpace(cfg.LLM.ActiveAPIKey()) == "" {
		return nil, errLLMAPIKeyRequired{Provider: cfg.LLM.Provider}
	}
	return buildAssistantSessionFromConfig(svc, logger, cfg)
}

func activateConfiguredLLMProvider(cfg *akemiconfig.LLMConfig) {
	if strings.TrimSpace(cfg.ActiveAPIKey()) != "" {
		return
	}
	if provider := cfg.FirstProviderWithAPIKey(cfg.Provider, cfg.FallbackProvider); provider != "" {
		cfg.Provider = provider
	}
}

func buildDashboardAssistantSetup(svc *Services, logger *slog.Logger) func(provider, apiKey string) (*assistant.Session, error) {
	return func(provider, apiKey string) (*assistant.Session, error) {
		return buildAssistantSessionWithAPIKey(svc, logger, provider, apiKey)
	}
}

func buildDashboardAPISettingsLoad() func() (dashboard.APISettings, error) {
	return func() (dashboard.APISettings, error) {
		cfg, err := akemiconfig.Load("")
		if err != nil {
			return dashboard.APISettings{}, err
		}
		activateConfiguredLLMProvider(&cfg.LLM)
		return dashboardAPISettingsFromConfig(cfg.LLM), nil
	}
}

func buildDashboardAPISettingsTest() func(dashboard.APISettings) error {
	return func(settings dashboard.APISettings) error {
		cfg, err := akemiconfig.Load("")
		if err != nil {
			return err
		}
		applyDashboardAPISettings(&cfg.LLM, settings)
		if strings.TrimSpace(cfg.LLM.ActiveAPIKey()) == "" && cfg.LLM.Provider != "local" {
			return errLLMAPIKeyRequired{Provider: cfg.LLM.Provider}
		}
		client, _, err := llm.NewClient(cfg.LLM)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return client.Ping(ctx)
	}
}

func buildDashboardAPISettingsApply(svc *Services, logger *slog.Logger) func(dashboard.APISettings) (*assistant.Session, error) {
	return func(settings dashboard.APISettings) (*assistant.Session, error) {
		provider := akemiconfig.NormalizeLLMProvider(settings.Provider)
		if provider != "deepseek" && provider != "openai" {
			return nil, fmt.Errorf("unsupported dashboard provider %q", settings.Provider)
		}
		if _, err := akemiconfig.UpdateLLMProviderSettings("", akemiconfig.LLMProviderSettings{
			Provider:        provider,
			APIKey:          settings.APIKey,
			Model:           settings.Model,
			BaseURL:         settings.BaseURL,
			MaxTokens:       settings.MaxTokens,
			Temperature:     settings.Temperature,
			ReasoningEffort: settings.ReasoningEffort,
			Thinking:        settings.Thinking,
		}); err != nil {
			return nil, err
		}
		cfg, err := akemiconfig.Load("")
		if err != nil {
			return nil, err
		}
		applyDashboardAPISettings(&cfg.LLM, settings)
		if strings.TrimSpace(cfg.LLM.ActiveAPIKey()) == "" {
			return nil, errLLMAPIKeyRequired{Provider: cfg.LLM.Provider}
		}
		return buildAssistantSessionFromConfig(svc, logger, cfg)
	}
}

func buildDashboardAssistantLoad(svc *Services, logger *slog.Logger) func() (*assistant.Session, error) {
	return func() (*assistant.Session, error) {
		return buildAssistantSession(svc, logger)
	}
}

func buildAssistantSessionFromConfig(svc *Services, logger *slog.Logger, cfg *akemiconfig.AkemiConfig) (*assistant.Session, error) {
	return buildAssistantSessionFromConfigWithConversation(svc, logger, cfg, "")
}

func buildAssistantSessionFromConfigWithConversation(svc *Services, logger *slog.Logger, cfg *akemiconfig.AkemiConfig, conversationID string) (*assistant.Session, error) {
	client, _, err := llm.NewClient(cfg.LLM)
	if err != nil {
		return nil, err
	}

	var sources []mcpclient.Source
	if cfg.MCPClient.Enabled {
		for _, server := range cfg.MCPClient.Servers {
			if !server.Enabled || server.Transport != "inprocess" || server.Name != "akemi" {
				continue
			}
			toolReg := mcptools.NewToolRegistry(mcptools.ToolRegistryConfig{
				Scanner:       svc.Scanner,
				Discoverer:    svc.Discovery,
				Prober:        svc.Vuln,
				SubEnumerator: svc.Subdomain,
				Reporter:      svc.Reporting,
				Context:       svc.MCPContext,
				ReportDir:     rootOutputDir,
				Logger:        logger,
			})
			sources = append(sources, mcpclient.Source{
				Name:     server.Name,
				Provider: toolReg,
			})
		}
	}
	router := mcpclient.NewRouter(sources...)

	vendor := cfg.LLM.GetActive()
	approvalMode := engagement.ApprovalMode(cfg.MCPClient.ApprovalPolicy)
	if approvalMode == "" {
		approvalMode = engagement.ApprovalAsk
	}
	return assistant.NewSession(client, router, engagement.NewManager(approvalMode), assistant.Config{
		MaxTokens:      vendor.MaxTokens,
		Temperature:    vendor.Temperature,
		HistoryStore:   assistant.NewFileHistoryStore(assistant.DefaultHistoryPath(rootOutputDir)),
		ConversationID: conversationID,
		Provider: assistant.ProviderMetadata{
			Provider: cfg.LLM.Provider,
			Model:    vendor.Model,
			BaseURL:  vendor.BaseURL,
		},
	}), nil
}

func dashboardAPISettingsFromConfig(cfg akemiconfig.LLMConfig) dashboard.APISettings {
	provider := akemiconfig.NormalizeLLMProvider(cfg.Provider)
	if provider != "openai" {
		provider = "deepseek"
	}
	vendor := cfg.GetProvider(provider)
	if vendor == nil {
		vendor = cfg.GetProvider("deepseek")
	}
	return dashboard.APISettings{
		Provider:        provider,
		Model:           vendor.Model,
		BaseURL:         vendor.BaseURL,
		APIKey:          cfg.APIKeyForProvider(provider),
		MaxTokens:       vendor.MaxTokens,
		Temperature:     vendor.Temperature,
		ReasoningEffort: vendor.ReasoningEffort,
		Thinking:        vendor.Thinking,
	}
}

func applyDashboardAPISettings(cfg *akemiconfig.LLMConfig, settings dashboard.APISettings) {
	provider := akemiconfig.NormalizeLLMProvider(settings.Provider)
	if provider == "" {
		provider = "deepseek"
	}
	cfg.Provider = provider
	vendor := cfg.GetProvider(provider)
	if vendor == nil {
		return
	}
	if strings.TrimSpace(settings.Model) != "" {
		vendor.Model = strings.TrimSpace(settings.Model)
	}
	if strings.TrimSpace(settings.BaseURL) != "" {
		vendor.BaseURL = strings.TrimSpace(settings.BaseURL)
	}
	if settings.MaxTokens > 0 {
		vendor.MaxTokens = settings.MaxTokens
	}
	if settings.Temperature >= 0 {
		vendor.Temperature = settings.Temperature
	}
	vendor.ReasoningEffort = strings.TrimSpace(settings.ReasoningEffort)
	vendor.Thinking = settings.Thinking
	vendor.APIKey = strings.TrimSpace(settings.APIKey)
}
