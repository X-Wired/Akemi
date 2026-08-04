package dashboard

import (
	"testing"
)

func TestDefaultAPISettingsGemini(t *testing.T) {
	settings := defaultAPISettings("gemini")
	if settings.Provider != "gemini" {
		t.Errorf("Provider = %q; want gemini", settings.Provider)
	}
	if settings.Model != "gemini-3.6-flash" {
		t.Errorf("Model = %q; want gemini-3.6-flash", settings.Model)
	}
	if settings.BaseURL != "https://generativelanguage.googleapis.com/v1beta/openai" {
		t.Errorf("BaseURL = %q; want https://generativelanguage.googleapis.com/v1beta/openai", settings.BaseURL)
	}
}

func TestAPISettingsModalCycleProvider(t *testing.T) {
	modal := newAPISettingsModal()
	if modal.settings.Provider != "deepseek" {
		t.Fatalf("Initial provider = %q; want deepseek", modal.settings.Provider)
	}

	modal.cycleProvider()
	if modal.settings.Provider != "openai" {
		t.Errorf("After 1st cycle provider = %q; want openai", modal.settings.Provider)
	}

	modal.cycleProvider()
	if modal.settings.Provider != "gemini" {
		t.Errorf("After 2nd cycle provider = %q; want gemini", modal.settings.Provider)
	}
	if modal.settings.Model != "gemini-3.6-flash" {
		t.Errorf("Gemini model = %q; want gemini-3.6-flash", modal.settings.Model)
	}

	modal.cycleProvider()
	if modal.settings.Provider != "deepseek" {
		t.Errorf("After 3rd cycle provider = %q; want deepseek", modal.settings.Provider)
	}
}
