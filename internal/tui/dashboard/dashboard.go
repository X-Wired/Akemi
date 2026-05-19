package dashboard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	akemiarchive "Akemi/internal/archive"
	"Akemi/internal/assistant"
	core "Akemi/internal/core"
	"Akemi/internal/dothound"
	"Akemi/internal/engagement"
	proxy "Akemi/internal/platform/proxy"
	"Akemi/internal/project"
	"Akemi/internal/session"
	"Akemi/internal/surface"
	"Akemi/internal/toolbridge"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/sync/errgroup"
)

const (
	defaultSplitH = 0.40
	defaultSplitV = 0.76

	eventBufferSize = 200
)

type layoutDragMode int

const (
	layoutDragNone layoutDragMode = iota
	layoutDragVertical
	layoutDragHorizontal
)

// DashboardServices contains the service adapters the TUI can call.
type DashboardServices struct {
	Scanner       core.Scanner
	Discoverer    core.Discoverer
	Prober        core.Prober
	SubEnumerator core.SubEnumerator
	Reporter      core.Reporter

	Project        *project.Project
	SessionState   *session.State
	ArchiveDir     string
	InitialArchive *akemiarchive.File
	MCPContext     engagement.ContextStore

	Assistant      *assistant.Session
	AssistantLoad  func() (*assistant.Session, error)
	AssistantSetup func(provider, apiKey string) (*assistant.Session, error)

	APISettingsLoad  func() (APISettings, error)
	APISettingsTest  func(APISettings) error
	APISettingsApply func(APISettings) (*assistant.Session, error)
}

// Services is kept as a friendly alias for callers/tests that name the TUI
// dependency bundle directly.
type Services = DashboardServices

// ConvertServices adapts the application service container into dashboard
// services without making the TUI depend on concrete service implementations.
func ConvertServices(scanner core.Scanner, discoverer core.Discoverer, prober core.Prober, subEnumerator core.SubEnumerator, reporter core.Reporter) DashboardServices {
	return DashboardServices{
		Scanner:       scanner,
		Discoverer:    discoverer,
		Prober:        prober,
		SubEnumerator: subEnumerator,
		Reporter:      reporter,
	}
}

// Dashboard is the Bubble Tea model for the four-panel terminal dashboard.
type Dashboard struct {
	width  int
	height int

	splitH       float64
	splitV       float64
	focus        FocusMsg
	dragMode     layoutDragMode
	mouseEnabled bool

	workspace FocusMsg

	target      *TargetPanel
	discovery   *DiscoveryPanel
	system      *SystemPanel
	agent       *AgentPanel
	apiSettings *apiSettingsModal

	services DashboardServices
	events   chan tea.Msg
	polling  bool

	showBanner bool
	ready      bool

	workCancel context.CancelFunc
	workConfig ScanConfig
	workActive bool

	currentConfig      ScanConfig
	currentArchive     *akemiarchive.File
	currentArchivePath string
	authSession        *engagement.AuthSession
	authCookies        []string

	assistant            *assistant.Session
	historyStore         assistant.HistoryStore
	historyPath          string
	historyUsesAssistant bool
}

type archiveLoadedMsg struct {
	Path    string
	Archive *akemiarchive.File
	Error   string
}

type conversationLoadedMsg struct {
	ID         string
	Title      string
	Transcript []assistant.TranscriptEntry
	Error      string
	Offline    bool
}

type conversationStartedMsg struct {
	Error   string
	Offline bool
}

type dashboardPolledMsg struct {
	Msg tea.Msg
}

type clipboardCopyDoneMsg struct {
	Label string
	Bytes int
	Error string
}

// NewDashboard creates a dashboard model using the provided service bundle.
func NewDashboard(services DashboardServices) *Dashboard {
	d := &Dashboard{
		splitH:       defaultSplitH,
		splitV:       defaultSplitV,
		focus:        FocusTarget,
		mouseEnabled: true,
		workspace:    FocusAgent,
		target:       NewTargetPanel(),
		discovery:    NewDiscoveryPanel(),
		system:       NewSystemPanel(),
		agent:        NewAgentPanel(),
		apiSettings:  newAPISettingsModal(),
		services:     services,
		events:       make(chan tea.Msg, eventBufferSize),
		showBanner:   true,
	}
	d.updateFocus()

	if services.InitialArchive != nil {
		d.applyArchive(services.InitialArchive, "")
	}
	if services.Assistant != nil {
		d.assistant = services.Assistant
		d.attachAssistantBridge()
	}

	return d
}

// Init implements tea.Model.
func (d *Dashboard) Init() tea.Cmd {
	return tea.Batch(
		d.target.Init(),
		d.discovery.Init(),
		d.system.Init(),
		d.agent.Init(),
		d.scheduleEventPoll(),
	)
}

// PushAgentEvent allows external code/tests to enqueue agent events.
func (d *Dashboard) PushAgentEvent(msg tea.Msg) {
	d.send(msg)
}

// Update implements tea.Model.
func (d *Dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmds := make([]tea.Cmd, 0, 8)

	switch msg := msg.(type) {
	case dashboardPolledMsg:
		d.polling = false
		model, cmd := d.Update(msg.Msg)
		return model, batchCmds(cmd, d.scheduleEventPoll())

	case AgentTickMsg:
		cmds = append(cmds, d.scheduleEventPoll())
		return d, batchCmds(cmds...)

	case tea.WindowSizeMsg:
		d.width = msg.Width
		d.height = msg.Height
		d.ready = true
		d.layoutPanels()
		return d, nil

	case toolbridge.Event:
		cmds = append(cmds, d.handleToolBridgeEvent(msg)...)
		cmds = append(cmds, d.scheduleEventPoll())
		return d, batchCmds(cmds...)

	case tea.KeyMsg:
		if d.apiSettings.visible {
			d.apiSettings.handleKey(msg)
			cmds = append(cmds, d.consumeAPISettingsRequest())
			return d, batchCmds(cmds...)
		}
		if cmd, handled := d.handleGlobalKey(msg); handled {
			cmds = append(cmds, cmd)
		} else {
			cmds = append(cmds, d.routeToFocused(msg))
		}

	case tea.MouseMsg:
		if d.apiSettings.visible {
			return d, nil
		}
		if !d.mouseEnabled {
			return d, nil
		}
		if cmd, handled := d.handleLayoutMouse(msg); handled {
			cmds = append(cmds, cmd)
			return d, batchCmds(cmds...)
		}
		cmds = append(cmds, d.routeMouseToFocused(msg))

	case clipboardCopyDoneMsg:
		if msg.Error != "" {
			d.setDashboardStatus("Copy failed: " + msg.Error)
		} else if msg.Bytes > 0 {
			d.setDashboardStatus(fmt.Sprintf("Copied %s (%d bytes)", msg.Label, msg.Bytes))
		} else {
			d.setDashboardStatus("Nothing to copy")
		}

	case APISettingsLoadStartedMsg:
		d.apiSettings.busy = true
		d.apiSettings.status = "Loading API settings..."

	case APISettingsLoadDoneMsg:
		d.apiSettings.applyLoaded(msg.Settings, msg.Error)

	case APISettingsTestStartedMsg:
		d.apiSettings.busy = true
		d.apiSettings.status = "Testing provider..."

	case APISettingsTestDoneMsg:
		if msg.Error != "" {
			d.apiSettings.setStatus("Test failed: " + msg.Error)
		} else {
			d.apiSettings.setStatus("Provider test OK.")
		}

	case APISettingsApplyStartedMsg:
		d.apiSettings.busy = true
		d.apiSettings.status = "Applying provider settings..."

	case APISettingsApplyDoneMsg:
		if msg.Error != "" {
			d.apiSettings.setStatus("Apply failed: " + msg.Error)
		} else {
			d.apiSettings.setStatus(fmt.Sprintf("Saved and connected to %s.", msg.Provider))
			if msg.Session != nil {
				d.assistant = msg.Session
				d.attachAssistantBridge()
			}
		}

	case AuthCaptureDoneMsg:
		if msg.Session != nil && msg.Error == "" {
			d.authSession = msg.Session
			d.authCookies = append(d.authCookies[:0], msg.Session.Cookies...)
			core.SetDefaultCookies(d.authCookies)
			d.syncMCPContextFromConfig(d.currentConfig)
		}
		cmds = append(cmds, d.updatePanels(msg)...)

	case ScanStartedMsg:
		d.currentConfig = msg.Config
		d.workspace = FocusDiscovery
		if d.focus == FocusAgent {
			d.focus = FocusDiscovery
			d.updateFocus()
		}
		d.syncMCPContextFromConfig(msg.Config)
		cmds = append(cmds, d.updatePanels(msg)...)

	case ScanDoneMsg:
		d.workActive = false
		d.workCancel = nil
		if msg.Archive != nil {
			d.currentArchive = msg.Archive
		}
		if msg.ArchivePath != "" {
			d.currentArchivePath = msg.ArchivePath
		}
		cmds = append(cmds, d.updatePanels(msg)...)

	case RunLoadedMsg:
		cmds = append(cmds, d.updatePanels(msg)...)

	case archiveLoadedMsg:
		if msg.Error != "" {
			cmds = append(cmds, d.updatePanels(RunLoadedMsg{Path: msg.Path, Error: msg.Error})...)
		} else {
			d.applyArchive(msg.Archive, msg.Path)
			summary := ""
			if msg.Archive != nil {
				summary = msg.Archive.Summary
			}
			cmds = append(cmds, d.updatePanels(RunLoadedMsg{Path: msg.Path, Summary: summary})...)
		}

	case conversationLoadedMsg:
		if msg.Error != "" {
			cmds = append(cmds, d.updatePanels(AIChatErrorMsg{Error: msg.Error})...)
		} else {
			d.workspace = FocusAgent
			d.focus = FocusAgent
			d.updateFocus()
			d.agent.enterChatMode()
			d.agent.SetChatTranscript(msg.Transcript)
			if msg.Offline {
				d.agent.addChat("system", "Loaded saved conversation. Configure API settings to continue chatting.")
				d.agent.updateViewport()
			}
		}

	case conversationStartedMsg:
		if msg.Error != "" {
			cmds = append(cmds, d.updatePanels(AIChatErrorMsg{Error: msg.Error})...)
		} else {
			d.workspace = FocusAgent
			d.focus = FocusAgent
			d.updateFocus()
			d.agent.enterChatMode()
			d.agent.SetChatTranscript(nil)
			if msg.Offline {
				d.agent.addChat("system", "New chat started. Configure API settings to continue.")
				d.agent.updateViewport()
			}
			d.refreshAgentHistoryList()
		}

	default:
		cmds = append(cmds, d.updatePanels(msg)...)
	}

	cmds = append(cmds, d.consumeTargetRequest())
	cmds = append(cmds, d.consumeDiscoveryRequest())
	cmds = append(cmds, d.consumeAgentRequest())
	cmds = append(cmds, d.consumeAPISettingsRequest())

	return d, batchCmds(cmds...)
}

func (d *Dashboard) handleGlobalKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "ctrl+c", "ctrl+q":
		d.stopWork()
		return tea.Quit, true
	case "ctrl+b":
		d.showBanner = !d.showBanner
		d.layoutPanels()
	case "ctrl+m":
		d.mouseEnabled = !d.mouseEnabled
		d.dragMode = layoutDragNone
		if d.mouseEnabled {
			d.setDashboardStatus("Mouse resize enabled")
			return tea.EnableMouseCellMotion, true
		}
		d.setDashboardStatus("Mouse disabled - select/copy terminal text normally")
		return tea.DisableMouse, true
	case "ctrl+y":
		label, text := d.copyTextForFocus()
		return copyToClipboardCmd(label, text), true
	case "ctrl+x":
		d.stopWork()
	case "f5", "ctrl+o":
		d.apiSettings.open()
		return d.consumeAPISettingsRequest(), true
	case "ctrl+d":
		d.showDiscoveryWorkspace()
	case "ctrl+a":
		d.showAgentActivity()
	case "ctrl+p":
		d.toggleAgentChat()
	case "ctrl+g":
		d.toggleAgentHistory()
	case "tab":
		d.moveFocus(1)
	case "shift+tab":
		d.moveFocus(-1)
	default:
		return nil, false
	}
	return nil, true
}

func (d *Dashboard) updatePanels(msg tea.Msg) []tea.Cmd {
	cmds := make([]tea.Cmd, 0, 4)
	if model, cmd := d.target.Update(msg); true {
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
		if tp, ok := model.(*TargetPanel); ok {
			d.target = tp
		}
	}
	if model, cmd := d.discovery.Update(msg); true {
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
		if dp, ok := model.(*DiscoveryPanel); ok {
			d.discovery = dp
		}
	}
	if model, cmd := d.system.Update(msg); true {
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
		if sp, ok := model.(*SystemPanel); ok {
			d.system = sp
		}
	}
	if model, cmd := d.agent.Update(msg); true {
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
		if ap, ok := model.(*AgentPanel); ok {
			d.agent = ap
		}
	}
	return cmds
}

func (d *Dashboard) routeToFocused(msg tea.Msg) tea.Cmd {
	var model tea.Model
	var cmd tea.Cmd
	switch d.focus {
	case FocusTarget:
		model, cmd = d.target.Update(msg)
		if next, ok := model.(*TargetPanel); ok {
			d.target = next
		}
	case FocusDiscovery:
		d.workspace = FocusDiscovery
		model, cmd = d.discovery.Update(msg)
		if next, ok := model.(*DiscoveryPanel); ok {
			d.discovery = next
		}
	case FocusSystem:
		model, cmd = d.system.Update(msg)
		if next, ok := model.(*SystemPanel); ok {
			d.system = next
		}
	case FocusAgent:
		d.workspace = FocusAgent
		model, cmd = d.agent.Update(msg)
		if next, ok := model.(*AgentPanel); ok {
			d.agent = next
		}
	}
	return cmd
}

func (d *Dashboard) routeMouseToFocused(msg tea.MouseMsg) tea.Cmd {
	if d.width <= 0 || d.height <= 0 {
		return d.routeToFocused(msg)
	}
	leftW, topH := d.panelBounds()
	local := msg
	switch {
	case msg.X < leftW && msg.Y < topH:
		d.focus = FocusTarget
	case msg.X < leftW:
		d.focus = FocusSystem
		local.Y = max(0, msg.Y-topH)
	default:
		if d.workspace == FocusDiscovery {
			d.focus = FocusDiscovery
		} else {
			d.focus = FocusAgent
		}
		local.X = max(0, msg.X-leftW-d.panelGapWidth(leftW))
	}
	d.updateFocus()
	return d.routeToFocused(local)
}

func (d *Dashboard) handleLayoutMouse(msg tea.MouseMsg) (tea.Cmd, bool) {
	if d.width <= 0 || d.height <= 0 {
		return nil, false
	}
	leftW, topH := d.panelBounds()
	switch msg.Action {
	case tea.MouseActionPress:
		if msg.Button != tea.MouseButtonLeft {
			return nil, false
		}
		if d.onVerticalDivider(msg.X, leftW) {
			d.dragMode = layoutDragVertical
			d.applyVerticalSplit(msg.X)
			d.setDashboardStatus("Resizing dashboard columns")
			return nil, true
		}
		if d.onHorizontalDivider(msg.X, msg.Y, leftW, topH) {
			d.dragMode = layoutDragHorizontal
			d.applyHorizontalSplit(msg.Y)
			d.setDashboardStatus("Resizing target/system panels")
			return nil, true
		}
	case tea.MouseActionMotion:
		switch d.dragMode {
		case layoutDragVertical:
			d.applyVerticalSplit(msg.X)
			return nil, true
		case layoutDragHorizontal:
			d.applyHorizontalSplit(msg.Y)
			return nil, true
		}
	case tea.MouseActionRelease:
		if d.dragMode != layoutDragNone {
			d.dragMode = layoutDragNone
			d.setDashboardStatus("Dashboard layout ratio saved")
			return nil, true
		}
	}
	return nil, false
}

func (d *Dashboard) onVerticalDivider(x, leftW int) bool {
	gapW := d.panelGapWidth(leftW)
	return x >= leftW-1 && x <= leftW+max(0, gapW)
}

func (d *Dashboard) onHorizontalDivider(x, y, leftW, topH int) bool {
	return x < leftW && y >= topH-1 && y <= topH
}

func (d *Dashboard) applyVerticalSplit(x int) {
	minLeftW, minRightW := d.horizontalPanelLimits()
	leftW := min(max(x, minLeftW), max(minLeftW, d.width-1-minRightW))
	d.splitH = clampRatio(float64(leftW) / float64(max(1, d.width)))
	d.layoutPanels()
}

func (d *Dashboard) applyHorizontalSplit(y int) {
	bodyH := d.bodyHeight()
	minTargetH, minSystemH := d.verticalPanelLimits(bodyH)
	topH := min(max(y, minTargetH), max(minTargetH, bodyH-minSystemH))
	d.splitV = clampRatio(float64(topH) / float64(max(1, bodyH)))
	d.layoutPanels()
}

func (d *Dashboard) moveFocus(delta int) {
	right := d.workspace
	if right != FocusDiscovery {
		right = FocusAgent
	}
	order := []FocusMsg{FocusTarget, right, FocusSystem}
	idx := -1
	for i, focus := range order {
		if focus == d.focus {
			idx = i
			break
		}
	}
	if idx < 0 {
		if d.focus == FocusDiscovery || d.focus == FocusAgent {
			idx = 1
		} else {
			idx = 0
		}
	}
	d.focus = order[(idx+delta+len(order))%len(order)]
	d.updateFocus()
}

func (d *Dashboard) showDiscoveryWorkspace() {
	d.workspace = FocusDiscovery
	d.focus = FocusDiscovery
	d.updateFocus()
}

func (d *Dashboard) showAgentActivity() {
	d.workspace = FocusAgent
	d.focus = FocusAgent
	d.agent.enterActivityMode()
	d.updateFocus()
}

func (d *Dashboard) toggleAgentChat() {
	d.workspace = FocusAgent
	d.focus = FocusAgent
	if d.agent.mode == agentModeChat {
		d.agent.enterActivityMode()
	} else {
		d.agent.enterChatMode()
	}
	d.updateFocus()
}

func (d *Dashboard) toggleAgentHistory() {
	d.workspace = FocusAgent
	d.focus = FocusAgent
	d.agent.toggleHistoryMode()
	d.refreshAgentHistoryList()
	d.updateFocus()
}

func (d *Dashboard) stopWork() {
	if d.workCancel != nil {
		d.workCancel()
	}
	d.workActive = false
	if d.target != nil && d.target.scanning {
		d.target.status = "Stop requested..."
	}
}

func (d *Dashboard) updateFocus() {
	if d.target != nil {
		d.target.Focus(d.focus == FocusTarget)
	}
	if d.discovery != nil {
		d.discovery.Focus(d.focus == FocusDiscovery)
	}
	if d.system != nil {
		d.system.Focus(d.focus == FocusSystem)
	}
	if d.agent != nil {
		d.agent.Focus(d.focus == FocusAgent)
	}
}

func (d *Dashboard) setDashboardStatus(status string) {
	status = strings.TrimSpace(status)
	if status == "" || d.target == nil {
		return
	}
	d.target.status = status
}

func (d *Dashboard) consumeTargetRequest() tea.Cmd {
	if d.target == nil {
		return nil
	}
	cmds := make([]tea.Cmd, 0, 4)
	if d.target.ScanRequested {
		cfg := d.target.PendingConfig
		d.target.ScanRequested = false
		d.target.PendingConfig = ScanConfig{}
		cmds = append(cmds, d.launchScan(cfg))
	}
	if d.target.AuthCaptureRequested {
		targetURL := d.target.PendingAuthURL
		username := d.target.PendingAuthUsername
		password := d.target.PendingAuthPassword
		d.target.AuthCaptureRequested = false
		d.target.PendingAuthURL = ""
		d.target.PendingAuthUsername = ""
		d.target.PendingAuthPassword = ""
		cmds = append(cmds, d.captureAuthCmd(targetURL, username, password))
	}
	if d.target.SaveRunRequested {
		path := d.target.PendingRunPath
		d.target.SaveRunRequested = false
		d.target.PendingRunPath = ""
		cmds = append(cmds, d.saveRun(path))
	}
	if d.target.LoadRunRequested {
		path := d.target.PendingRunPath
		d.target.LoadRunRequested = false
		d.target.PendingRunPath = ""
		cmds = append(cmds, d.loadRun(path))
	}
	return batchCmds(cmds...)
}

func (d *Dashboard) consumeDiscoveryRequest() tea.Cmd {
	if d.discovery == nil || !d.discovery.CopyRequested {
		return nil
	}
	text := d.discovery.PendingCopyText
	d.discovery.CopyRequested = false
	d.discovery.PendingCopyText = ""
	return copyToClipboardCmd("discovery row", text)
}

func (d *Dashboard) launchScan(cfg ScanConfig) tea.Cmd {
	if strings.TrimSpace(cfg.Target) == "" {
		return messageCmd(ScanDoneMsg{Summary: "target is required", Error: fmt.Errorf("target is required")})
	}
	d.stopWork()
	ctx, cancel := context.WithCancel(context.Background())
	d.workCancel = cancel
	d.workActive = true
	cfg.AuthCookies = append([]string(nil), d.authCookies...)
	d.workConfig = cfg
	d.currentConfig = cfg
	d.syncMCPContextFromConfig(cfg)

	start := ScanStartedMsg{
		Target: cfg.Target,
		Intent: cfg.Intent,
		Config: cfg,
	}
	return tea.Batch(messageCmd(start), d.runScanCmd(ctx, cfg))
}

func (d *Dashboard) runScanCmd(ctx context.Context, cfg ScanConfig) tea.Cmd {
	services := d.services
	send := d.send
	archiveDir := strings.TrimSpace(services.ArchiveDir)
	return func() tea.Msg {
		if strings.TrimSpace(cfg.Proxy) != "" {
			if err := proxy.ConfigureProxy(cfg.Proxy, ""); err != nil {
				return ScanDoneMsg{
					Summary: "proxy configuration failed",
					Error:   fmt.Errorf("proxy configuration failed: %w", err),
				}
			}
		}
		if len(cfg.AuthCookies) > 0 {
			core.SetDefaultCookies(cfg.AuthCookies)
		}

		emitter := newScanEmitter(send)
		result, err := runDashboardIntentScan(ctx, services, cfg, emitter)

		cancelled := errors.Is(ctx.Err(), context.Canceled)
		if result == nil {
			result = &surface.FullSurfaceResult{
				Target:    cfg.Target,
				StartTime: time.Now(),
				EndTime:   time.Now(),
			}
		}

		done := scanDoneFromSurfaceResult(result, cfg.Intent, err, cancelled)
		done.Archive, done.ArchiveError = archiveFromSurface(cfg, result, nil)
		if done.Archive != nil && archiveDir != "" {
			if path, writeErr := writeArchiveToDir(archiveDir, cfg.Target, done.Archive); writeErr != nil {
				done.ArchiveError = writeErr.Error()
			} else {
				done.ArchivePath = path
			}
		}
		return done
	}
}

type scanEmitter struct {
	mu     sync.Mutex
	send   func(tea.Msg)
	latest ScanProgressMsg
}

func newScanEmitter(send func(tea.Msg)) *scanEmitter {
	return &scanEmitter{send: send}
}

func (e *scanEmitter) progress(stage string) {
	e.mu.Lock()
	e.latest.Phase = stage
	msg := e.latest
	e.mu.Unlock()
	e.emit(msg)
}

func (e *scanEmitter) port(port core.PortResult) {
	e.mu.Lock()
	e.latest.Ports++
	phase := e.latest.Phase
	msg := e.latest
	e.mu.Unlock()
	e.emit(DiscoveryItemMsg{Section: "Ports", Key: fmt.Sprintf("%d", port.Port), Item: formatPortResult(port), Phase: phase})
	e.emit(msg)
}

func (e *scanEmitter) crawl(f core.CrawlFinding) {
	e.mu.Lock()
	e.latest.URLs++
	phase := e.latest.Phase
	msg := e.latest
	e.mu.Unlock()
	e.emit(DiscoveryItemMsg{Section: "URLs", Key: f.URL, Item: formatCrawlFinding(f), Phase: phase})
	e.emit(msg)
}

func (e *scanEmitter) finding(f core.VulnFinding) {
	e.mu.Lock()
	e.latest.Findings++
	msg := e.latest
	e.mu.Unlock()
	e.emit(discoveryItemForFinding(f))
	e.emit(msg)
}

func (e *scanEmitter) param(name string, detail core.ParamDetail) {
	e.mu.Lock()
	e.latest.Params++
	phase := e.latest.Phase
	msg := e.latest
	e.mu.Unlock()
	e.emit(DiscoveryItemMsg{Section: "Params", Key: name, Item: formatParamDetail(name, detail), Phase: phase})
	e.emit(msg)
}

func (e *scanEmitter) apiParameter(param core.APIParameterFinding) {
	key, item := formatAPIParameter(param)
	e.mu.Lock()
	e.latest.Params++
	phase := e.latest.Phase
	msg := e.latest
	e.mu.Unlock()
	e.emit(DiscoveryItemMsg{Section: "Params", Key: key, Item: item, Phase: phase})
	e.emit(msg)
}

func (e *scanEmitter) js(pageURL string, js *core.JSAnalysisResult) {
	if js == nil {
		return
	}
	e.mu.Lock()
	e.latest.JSFiles += len(js.ScriptURLs)
	e.latest.Secrets += len(js.Secrets)
	e.latest.Params += len(js.HiddenParams)
	phase := e.latest.Phase
	msg := e.latest
	e.mu.Unlock()
	for _, scriptURL := range js.ScriptURLs {
		e.emit(DiscoveryItemMsg{Section: "JS Files", Key: scriptURL, Item: scriptURL, Phase: phase})
	}
	for _, secret := range js.Secrets {
		e.emit(DiscoveryItemMsg{Section: "Secrets", Key: secret.Value + secret.SourceURL, Item: formatSecretFinding(secret), Phase: phase})
	}
	for _, param := range js.HiddenParams {
		e.emit(DiscoveryItemMsg{Section: "Params", Key: param, Item: fmt.Sprintf("?%s= (js)", param), Phase: phase})
	}
	e.emit(msg)
}

func (e *scanEmitter) api(api *core.APISurfaceResult) {
	if api == nil {
		return
	}
	e.mu.Lock()
	e.latest.Endpoints += len(api.APIEndpoints) + len(api.APISpecs)
	phase := e.latest.Phase
	msg := e.latest
	e.mu.Unlock()
	for _, ep := range api.APIEndpoints {
		key, item := formatAPIEndpoint(ep)
		e.emit(DiscoveryItemMsg{Section: "Endpoints", Key: key, Item: item, Phase: phase})
	}
	for _, spec := range api.APISpecs {
		key, item := formatAPISpec(spec)
		e.emit(DiscoveryItemMsg{Section: "Endpoints", Key: key, Item: item, Phase: phase})
	}
	e.emit(msg)
}

func (e *scanEmitter) subdomain(sub core.SubdomainResult) {
	e.mu.Lock()
	e.latest.Subdomains++
	phase := e.latest.Phase
	msg := e.latest
	e.mu.Unlock()
	e.emit(DiscoveryItemMsg{Section: "Subdomains", Key: sub.Name, Item: formatSubdomainResult(sub), Phase: phase})
	e.emit(msg)
}

func (e *scanEmitter) emit(msg tea.Msg) {
	if e != nil && e.send != nil {
		e.send(msg)
	}
}

func (e *scanEmitter) callbacks() surface.Callbacks {
	return surface.Callbacks{
		Progress:     e.progress,
		Port:         e.port,
		CrawlFinding: e.crawl,
		Finding:      e.finding,
		Param:        e.param,
		JSAnalysis:   e.js,
		APIResult:    e.api,
		APIParameter: e.apiParameter,
		Subdomain:    e.subdomain,
	}
}

func runDashboardIntentScan(ctx context.Context, services DashboardServices, cfg ScanConfig, emitter *scanEmitter) (*surface.FullSurfaceResult, error) {
	intent := normalizeDashboardIntent(cfg.Intent)
	result := &surface.FullSurfaceResult{
		Target:    cfg.Target,
		StartTime: time.Now(),
		Config: map[string]interface{}{
			"target":     cfg.Target,
			"intent":     intent,
			"port_range": cfg.PortRange,
			"threads":    cfg.Threads,
			"timeout":    cfg.Timeout,
			"depth":      cfg.Depth,
		},
	}
	defer func() {
		result.EndTime = time.Now()
		result.Counts = surfaceResultCounts(result)
	}()

	checkCtx := func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	addErr := func(stage string, err error) {
		if err != nil {
			result.Errors = append(result.Errors, surface.StageError{Stage: stage, Error: err.Error()})
			// Surface the error in real-time via the phase display
			emitter.progress(fmt.Sprintf("%s error: %s", stage, err.Error()))
		}
	}

	runPortScan := func(stage string, ports []int) error {
		if services.Scanner == nil {
			return nil
		}
		emitter.progress(stage)
		scan, err := services.Scanner.Scan(ctx, core.ScanRequest{
			Host:           cfg.Target,
			Ports:          ports,
			Threads:        firstPositiveInt(cfg.Threads, 200),
			TimeoutMs:      firstPositiveInt(cfg.Timeout, 10) * 1000,
			Rate:           1000,
			Retries:        1,
			Randomize:      true,
			BannerGrab:     true,
			SuppressOutput: true,
		})
		if scan != nil {
			result.PortScan = scan
			for _, port := range scan.OpenPorts {
				emitter.port(port)
			}
		}
		addErr(stage, err)
		return checkCtx()
	}
	runCrawl := func(depth int) ([]string, error) {
		if services.Discoverer == nil {
			return nil, nil
		}
		emitter.progress("Crawling")
		seedURL := core.EnsureProtocol(cfg.Target)
		emitter.emit(DiscoveryItemMsg{Section: "URLs", Key: seedURL, Item: formatCrawlFinding(core.CrawlFinding{URL: seedURL, Title: "PENDING"}), Phase: "Crawling"})
		emitter.emit(emitter.latest)
		seen := make(map[string]struct{})
		var seenMu sync.Mutex
		emitFinding := func(finding core.CrawlFinding) {
			key := strings.TrimSpace(finding.URL)
			if key == "" {
				return
			}
			seenMu.Lock()
			if _, ok := seen[key]; ok {
				seenMu.Unlock()
				return
			}
			seen[key] = struct{}{}
			seenMu.Unlock()
			emitter.crawl(finding)
		}
		var findings []core.CrawlFinding
		var err error
		if live, ok := services.Discoverer.(interface {
			CrawlWithCallback(context.Context, string, int, func(core.CrawlFinding)) ([]core.CrawlFinding, error)
		}); ok {
			findings, err = live.CrawlWithCallback(ctx, cfg.Target, core.NormalizeCrawlDepth(depth), emitFinding)
		} else {
			findings, err = services.Discoverer.Crawl(ctx, cfg.Target, core.NormalizeCrawlDepth(depth))
			for _, finding := range findings {
				emitFinding(finding)
			}
		}
		result.CrawlFindings = append(result.CrawlFindings, findings...)
		urls := make([]string, 0, len(findings))
		for _, finding := range findings {
			if finding.URL != "" {
				urls = append(urls, finding.URL)
			}
		}
		addErr("Crawling", err)
		return urls, checkCtx()
	}
	runProbe := func(stage string, tags []string) error {
		if services.Prober == nil {
			return nil
		}
		emitter.progress(stage)
		findings, err := services.Prober.Probe(ctx, cfg.Target, core.ProbeConfig{
			Threads:      firstPositiveInt(cfg.Threads, 5),
			Timeout:      firstPositiveInt(cfg.Timeout, 10),
			UseTemplates: true,
			TemplateTags: tags,
		})
		result.VulnFindings = append(result.VulnFindings, findings...)
		for _, finding := range findings {
			emitter.finding(finding)
		}
		addErr(stage, err)
		return checkCtx()
	}
	addHiddenParam := func(name, source string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if result.Params == nil {
			result.Params = &core.ParamDiscoveryResult{Params: make(map[string]core.ParamDetail)}
		}
		if result.Params.Params == nil {
			result.Params.Params = make(map[string]core.ParamDetail)
		}
		detail := result.Params.Params[name]
		detail.Name = name
		detail.Sources = uniqueOrderedStrings(append(detail.Sources, source))
		result.Params.Params[name] = detail
		result.Params.TotalCount = len(result.Params.Params)
	}
	runJSAnalysis := func(stage string, pageURLs []string) error {
		if services.Discoverer == nil {
			return nil
		}
		emitter.progress(stage)
		for _, pageURL := range uniqueOrderedStrings(pageURLs) {
			if strings.TrimSpace(pageURL) == "" {
				continue
			}
			jsResult, err := services.Discoverer.AnalyzeJS(ctx, pageURL)
			if err != nil {
				addErr(stage, err)
			} else if jsResult != nil {
				result.JSAnalysis = append(result.JSAnalysis, surface.JSPageAnalysis{
					PageURL: pageURL,
					Result:  *jsResult,
				})
				result.Secrets = append(result.Secrets, jsResult.Secrets...)
				for _, param := range jsResult.HiddenParams {
					addHiddenParam(param, pageURL)
				}
				emitter.js(pageURL, jsResult)
			}
			if err := checkCtx(); err != nil {
				return err
			}
		}
		return nil
	}
	runAPI := func(stage string, discoveredURLs []string) error {
		if services.Discoverer == nil {
			return nil
		}
		emitter.progress(stage)
		hunt, err := services.Discoverer.HuntAPISurface(ctx, core.APIHuntRequest{
			StartURL:       cfg.Target,
			DiscoveredURLs: discoveredURLs,
			Mode:           "safe-active",
			AuthCookies:    append([]string(nil), cfg.AuthCookies...),
			MaxCandidates:  250,
			Threads:        firstPositiveInt(cfg.Threads, 10),
			Timeout:        firstPositiveInt(cfg.Timeout, 10),
		})
		if hunt != nil {
			result.APIEndpoints = append(result.APIEndpoints, hunt.APIEndpoints...)
			result.APISpecs = append(result.APISpecs, hunt.APISpecs...)
			result.APIParameters = append(result.APIParameters, hunt.Parameters...)
			for _, stageErr := range hunt.StageErrors {
				if strings.TrimSpace(stageErr) != "" {
					result.Errors = append(result.Errors, surface.StageError{Stage: stage, Error: stageErr})
				}
			}
			emitter.api(&core.APISurfaceResult{APIEndpoints: hunt.APIEndpoints, APISpecs: hunt.APISpecs})
			for _, param := range hunt.Parameters {
				emitter.apiParameter(param)
			}
		}
		addErr(stage, err)
		return checkCtx()
	}
	runSubdomains := func(stage string) error {
		if services.SubEnumerator == nil {
			return nil
		}
		domain := domainFromTarget(cfg.Target)
		if domain == "" {
			return nil
		}
		emitter.progress(stage)
		subdomains, err := services.SubEnumerator.Enumerate(ctx, domain, core.SubdomainConfig{
			Threads:    firstPositiveInt(cfg.Threads, 20),
			Timeout:    firstPositiveInt(cfg.Timeout, 10),
			UseCrtSh:   true,
			CheckAlive: true,
		})
		result.Subdomains = append(result.Subdomains, subdomains...)
		for _, subdomain := range subdomains {
			emitter.subdomain(subdomain)
		}
		addErr(stage, err)
		return checkCtx()
	}

	switch intent {
	case "full_surface_map":
		// ── Level 1: parallel independent operations ──────────
		var crawledURLs []string
		var crawlMu sync.Mutex
		g, gctx := errgroup.WithContext(ctx)

		g.Go(func() error {
			return runPortScan("Port scanning", parsePorts(cfg.PortRange))
		})
		g.Go(func() error {
			return runSubdomains("Enumerating subdomains")
		})
		g.Go(func() error {
			return runProbe("Checking headers and tech", []string{"headers", "misconfig", "tech", "detect"})
		})
		g.Go(func() error {
			if services.Discoverer == nil {
				return nil
			}
			emitter.progress("Crawling + mining parameters")
			findings, params, err := services.Discoverer.CrawlAndMine(
				gctx, cfg.Target, core.NormalizeCrawlDepth(cfg.Depth),
				core.MiningConfig{
					Depth:   core.NormalizeCrawlDepth(cfg.Depth),
					Threads: firstPositiveInt(cfg.Threads, 10),
					Timeout: firstPositiveInt(cfg.Timeout, 10),
					MineJS:  true, MineForms: true, MineJSON: true, MinePath: true,
				},
				func(f core.CrawlFinding) {
					emitter.crawl(f)
					if f.URL != "" {
						crawlMu.Lock()
						crawledURLs = append(crawledURLs, f.URL)
						crawlMu.Unlock()
					}
				},
			)
			if err != nil {
				addErr("Crawl+Mine", err)
			}
			if findings != nil {
				result.CrawlFindings = append(result.CrawlFindings, findings...)
			}
			if params != nil {
				result.Params = params
				for _, name := range sortedParamNames(params.Params) {
					emitter.param(name, params.Params[name])
				}
			}
			return nil
		})

		if err := g.Wait(); err != nil {
			return result, err
		}

		// ── Level 2: depends on crawled URLs ──────────────────
		jsTargets := uniqueOrderedStrings(append([]string{cfg.Target}, crawledURLs...))
		if err := runJSAnalysis("Analyzing JavaScript", jsTargets); err != nil {
			return result, err
		}
		if err := runAPI("Discovering API surface", crawledURLs); err != nil {
			return result, err
		}

	case "quick_recon":
		g, _ := errgroup.WithContext(ctx)
		g.Go(func() error {
			return runPortScan("Port scanning", parsePorts(cfg.PortRange))
		})
		g.Go(func() error {
			_, err := runCrawl(min(core.NormalizeCrawlDepth(cfg.Depth), 2))
			return err
		})
		g.Go(func() error {
			return runProbe("Checking headers and tech", []string{"headers", "misconfig", "tech", "detect"})
		})
		if err := g.Wait(); err != nil {
			return result, err
		}

	case "api_hunter":
		if services.Discoverer != nil {
			emitter.progress("API Hunter")
			hunt, err := services.Discoverer.HuntAPISurface(ctx, core.APIHuntRequest{
				StartURL:      cfg.Target,
				Mode:          "safe-active",
				AuthCookies:   append([]string(nil), cfg.AuthCookies...),
				MaxCandidates: 250,
				Threads:       firstPositiveInt(cfg.Threads, 10),
				Timeout:       firstPositiveInt(cfg.Timeout, 10),
			})
			if hunt != nil {
				result.APIEndpoints = append(result.APIEndpoints, hunt.APIEndpoints...)
				result.APISpecs = append(result.APISpecs, hunt.APISpecs...)
				result.APIParameters = append(result.APIParameters, hunt.Parameters...)
				emitter.api(&core.APISurfaceResult{APIEndpoints: hunt.APIEndpoints, APISpecs: hunt.APISpecs})
				for _, param := range hunt.Parameters {
					emitter.apiParameter(param)
				}
			}
			addErr("API Hunter", err)
			if err := checkCtx(); err != nil {
				return result, err
			}
		}

	case "sqli_hunt":
		// Use CrawlAndMine pipeline to avoid double-crawl
		if services.Discoverer != nil {
			emitter.progress("Crawling + mining parameters")
			findings, params, err := services.Discoverer.CrawlAndMine(
				ctx, cfg.Target, min(core.NormalizeCrawlDepth(cfg.Depth), 2),
				core.MiningConfig{
					Depth:   core.NormalizeCrawlDepth(cfg.Depth),
					Threads: firstPositiveInt(cfg.Threads, 10),
					Timeout: firstPositiveInt(cfg.Timeout, 10),
					MineJS:  true, MineForms: true, MineJSON: true, MinePath: true,
				},
				func(f core.CrawlFinding) { emitter.crawl(f) },
			)
			if err != nil {
				addErr("Crawl+Mine", err)
			}
			if findings != nil {
				for _, f := range findings {
					emitter.crawl(f)
				}
				result.CrawlFindings = append(result.CrawlFindings, findings...)
			}
			if params != nil {
				result.Params = params
				for _, name := range sortedParamNames(params.Params) {
					emitter.param(name, params.Params[name])
				}
			}
			if err := checkCtx(); err != nil {
				return result, err
			}
		}
		if err := runProbe("Hunting SQLi", []string{"sqli"}); err != nil {
			return result, err
		}

	case "vuln_assessment":
		if err := runProbe("Vulnerability assessment", nil); err != nil {
			return result, err
		}

	default:
		g, _ := errgroup.WithContext(ctx)
		g.Go(func() error {
			return runPortScan("Port scanning", parsePorts(cfg.PortRange))
		})
		g.Go(func() error {
			_, err := runCrawl(cfg.Depth)
			return err
		})
		g.Go(func() error {
			return runProbe("Checking headers and tech", []string{"headers", "misconfig"})
		})
		if err := g.Wait(); err != nil {
			return result, err
		}
	}

	return result, nil
}

func normalizeDashboardIntent(intent string) string {
	intent = strings.ToLower(strings.TrimSpace(intent))
	switch intent {
	case "full_surface_scan", "akemi_full_surface_scan", "akemi_full_surface_map", "surface_scan", "full_surface":
		return "full_surface_map"
	case "full_surface_map", "api_hunter", "sqli_hunt", "vuln_assessment", "quick_recon":
		return intent
	default:
		return "quick_recon"
	}
}

func (d *Dashboard) captureAuthCmd(targetURL, username, password string) tea.Cmd {
	return tea.Batch(
		messageCmd(AuthCaptureStartedMsg{TargetURL: targetURL, Username: username}),
		func() tea.Msg {
			session, err := dothound.CaptureLoginWithOptions(targetURL, username, password, dothound.StdinOptions{
				IncludeSecrets:      false,
				MaxBodyCaptureBytes: 64 * 1024,
			})
			if err != nil {
				return AuthCaptureDoneMsg{Error: err.Error()}
			}
			return AuthCaptureDoneMsg{Session: engagementAuthSessionFromDotHound(session, targetIDFromTarget(targetURL))}
		},
	)
}

func (d *Dashboard) consumeAgentRequest() tea.Cmd {
	if d.agent == nil {
		return nil
	}
	ap := d.agent
	cmds := make([]tea.Cmd, 0, 6)
	if ap.ConfigLoadRequested {
		ap.ConfigLoadRequested = false
		cmds = append(cmds, messageCmd(AIConfigLoadStartedMsg{}), d.loadAssistantFromConfigCmd())
	}
	if ap.SetupRequested {
		provider, key := ap.PendingSetupProvider, ap.PendingSetupAPIKey
		ap.SetupRequested = false
		ap.PendingSetupProvider = ""
		ap.PendingSetupAPIKey = ""
		cmds = append(cmds, messageCmd(AISetupStartedMsg{}), d.setupAssistantCmd(provider, key))
	}
	if ap.ChatSubmitRequested {
		text := ap.PendingChatInput
		ap.ChatSubmitRequested = false
		ap.PendingChatInput = ""
		cmds = append(cmds, messageCmd(AIChatStartedMsg{}), d.submitAIChatCmd(text))
	}
	if ap.ApproveRequested {
		ap.ApproveRequested = false
		cmds = append(cmds, d.approveAIToolCmd())
	}
	if ap.DenyRequested {
		ap.DenyRequested = false
		cmds = append(cmds, d.denyAIToolCmd())
	}
	if ap.ClearHistoryRequested {
		ap.ClearHistoryRequested = false
		if d.assistant != nil {
			_ = d.assistant.ClearHistory(context.Background())
			ap.SetChatTranscript(d.assistant.Transcript())
			d.refreshAgentHistoryList()
		}
	}
	if ap.HistoryLoadRequested {
		id := ap.PendingHistoryID
		ap.HistoryLoadRequested = false
		ap.PendingHistoryID = ""
		cmds = append(cmds, d.loadConversationCmd(id))
	}
	if ap.NewChatRequested {
		ap.NewChatRequested = false
		cmds = append(cmds, d.newConversationCmd())
	}
	return batchCmds(cmds...)
}

func (d *Dashboard) loadAssistantFromConfigCmd() tea.Cmd {
	return func() tea.Msg {
		if d.services.AssistantLoad == nil {
			return AIConfigLoadDoneMsg{Error: "assistant loader is not configured", NeedsSetup: true}
		}
		session, err := d.services.AssistantLoad()
		if err != nil {
			return AIConfigLoadDoneMsg{Error: err.Error(), NeedsSetup: assistantErrorNeedsSetup(err)}
		}
		tools := ""
		if session != nil {
			tools = session.ToolsSummary()
		}
		return AIConfigLoadDoneMsg{Session: session, ToolsSummary: tools}
	}
}

func (d *Dashboard) setupAssistantCmd(provider, apiKey string) tea.Cmd {
	return func() tea.Msg {
		if d.services.AssistantSetup == nil {
			return AISetupDoneMsg{Provider: provider, Error: "assistant setup is not configured"}
		}
		session, err := d.services.AssistantSetup(provider, apiKey)
		if err != nil {
			return AISetupDoneMsg{Provider: provider, Error: err.Error()}
		}
		tools := ""
		if session != nil {
			tools = session.ToolsSummary()
		}
		return AISetupDoneMsg{Provider: provider, Session: session, ToolsSummary: tools}
	}
}

func (d *Dashboard) submitAIChatCmd(text string) tea.Cmd {
	return func() tea.Msg {
		if d.assistant == nil || !d.assistant.Available() {
			return AIChatErrorMsg{Error: "assistant is not configured"}
		}
		ctx, cancel := context.WithTimeout(context.Background(), d.pendingAIToolTimeout())
		defer cancel()
		turn, err := d.assistant.Submit(ctx, text, d.assistantContext())
		return d.aiTurnMsg(turn, err)
	}
}

func (d *Dashboard) approveAIToolCmd() tea.Cmd {
	return func() tea.Msg {
		if d.assistant == nil {
			return AIChatErrorMsg{Error: "assistant is not configured"}
		}
		if run := d.assistant.PendingToolRun("running"); run != nil {
			d.send(AIToolRunMsg{ToolRun: run})
		}
		ctx, cancel := context.WithTimeout(context.Background(), d.pendingAIToolTimeout())
		defer cancel()
		turn, err := d.assistant.ApprovePending(ctx)
		return d.aiTurnMsg(turn, err)
	}
}

func (d *Dashboard) denyAIToolCmd() tea.Cmd {
	return func() tea.Msg {
		if d.assistant == nil {
			return AIChatErrorMsg{Error: "assistant is not configured"}
		}
		turn, err := d.assistant.DenyPending(context.Background())
		return d.aiTurnMsg(turn, err)
	}
}

func (d *Dashboard) loadConversationCmd(id string) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		if d.historyUsesAssistant && d.assistant != nil {
			if err := d.assistant.LoadConversation(ctx, id); err != nil {
				return conversationLoadedMsg{ID: id, Error: err.Error()}
			}
			return conversationLoadedMsg{
				ID:         id,
				Transcript: d.assistant.Transcript(),
			}
		}

		store := d.historyStore
		if store == nil {
			store, _, _ = d.diskHistoryList(ctx)
		}
		if store == nil {
			return conversationLoadedMsg{ID: id, Error: "assistant history file was not found"}
		}
		snapshot, err := store.LoadConversation(ctx, id)
		if err != nil {
			return conversationLoadedMsg{ID: id, Error: err.Error()}
		}
		if snapshot == nil {
			return conversationLoadedMsg{ID: id, Error: fmt.Sprintf("conversation %q not found", id)}
		}
		return conversationLoadedMsg{
			ID:         id,
			Title:      snapshot.Title,
			Transcript: append([]assistant.TranscriptEntry(nil), snapshot.Transcript...),
			Offline:    d.assistant == nil || !d.assistant.Available(),
		}
	}
}

func (d *Dashboard) newConversationCmd() tea.Cmd {
	return func() tea.Msg {
		if d.assistant == nil {
			return conversationStartedMsg{Offline: true}
		}
		if err := d.assistant.StartNewConversation(context.Background()); err != nil {
			return conversationStartedMsg{Error: err.Error()}
		}
		return conversationStartedMsg{}
	}
}

func (d *Dashboard) aiTurnMsg(turn *assistant.TurnResult, err error) tea.Msg {
	if err != nil {
		return AIChatErrorMsg{Error: err.Error()}
	}
	if turn == nil {
		return AIChatDoneMsg{}
	}
	if turn.PendingApproval != nil {
		return AIApprovalRequiredMsg{
			Pending:    turn.PendingApproval,
			ToolResult: turn.ToolResult,
			ToolRun:    turn.ToolRun,
			Response:   turn.Assistant,
		}
	}
	return AIChatDoneMsg{
		Response:   turn.Assistant,
		ToolResult: turn.ToolResult,
		ToolRun:    turn.ToolRun,
	}
}

func (d *Dashboard) consumeAPISettingsRequest() tea.Cmd {
	if d.apiSettings == nil {
		return nil
	}
	m := d.apiSettings
	cmds := make([]tea.Cmd, 0, 3)
	if m.LoadRequested {
		m.LoadRequested = false
		cmds = append(cmds, messageCmd(APISettingsLoadStartedMsg{}), d.loadAPISettingsCmd())
	}
	if m.TestRequested {
		settings := m.currentSettings()
		m.TestRequested = false
		cmds = append(cmds, messageCmd(APISettingsTestStartedMsg{}), d.testAPISettingsCmd(settings))
	}
	if m.ApplyRequested {
		settings := m.currentSettings()
		m.ApplyRequested = false
		cmds = append(cmds, messageCmd(APISettingsApplyStartedMsg{}), d.applyAPISettingsCmd(settings))
	}
	return batchCmds(cmds...)
}

func (d *Dashboard) loadAPISettingsCmd() tea.Cmd {
	return func() tea.Msg {
		if d.services.APISettingsLoad == nil {
			return APISettingsLoadDoneMsg{Settings: defaultAPISettings("deepseek")}
		}
		settings, err := d.services.APISettingsLoad()
		if err != nil {
			return APISettingsLoadDoneMsg{Error: err.Error()}
		}
		return APISettingsLoadDoneMsg{Settings: settings}
	}
}

func (d *Dashboard) testAPISettingsCmd(settings APISettings) tea.Cmd {
	return func() tea.Msg {
		if d.services.APISettingsTest == nil {
			return APISettingsTestDoneMsg{Error: "API settings test is not configured"}
		}
		if err := d.services.APISettingsTest(settings); err != nil {
			return APISettingsTestDoneMsg{Error: err.Error()}
		}
		return APISettingsTestDoneMsg{}
	}
}

func (d *Dashboard) applyAPISettingsCmd(settings APISettings) tea.Cmd {
	return func() tea.Msg {
		if d.services.APISettingsApply == nil {
			return APISettingsApplyDoneMsg{Provider: settings.Provider, Error: "API settings apply is not configured"}
		}
		session, err := d.services.APISettingsApply(settings)
		if err != nil {
			return APISettingsApplyDoneMsg{Provider: settings.Provider, Error: err.Error()}
		}
		tools := ""
		if session != nil {
			tools = session.ToolsSummary()
		}
		return APISettingsApplyDoneMsg{
			Provider:     settings.Provider,
			Session:      session,
			ToolsSummary: tools,
		}
	}
}

func (d *Dashboard) attachAssistantBridge() {
	if d.assistant == nil {
		d.agent.SetAssistantAvailable(false, "")
		return
	}
	d.assistant.SetToolEventSink(dashboardToolSink{send: d.send})
	d.agent.SetAssistantAvailable(d.assistant.Available(), d.assistant.ToolsSummary())
	d.agent.SetChatTranscript(d.assistant.Transcript())
	d.refreshAgentHistoryList()
}

func (d *Dashboard) refreshAgentHistoryList() {
	if d.assistant == nil || d.agent == nil {
		if d.agent == nil {
			return
		}
		store, path, entries := d.diskHistoryList(context.Background())
		d.historyStore = store
		d.historyPath = path
		d.historyUsesAssistant = false
		d.agent.SetHistoryEntries(entries)
		return
	}
	ctx := context.Background()
	entries := d.assistant.HistoryList(ctx)
	if len(entries) > 0 {
		d.historyStore = nil
		d.historyPath = ""
		d.historyUsesAssistant = true
		d.agent.SetHistoryEntries(entries)
		return
	}
	store, path, entries := d.diskHistoryList(ctx)
	d.historyStore = store
	d.historyPath = path
	d.historyUsesAssistant = false
	d.agent.SetHistoryEntries(entries)
}

func (d *Dashboard) diskHistoryList(ctx context.Context) (assistant.HistoryStore, string, []assistant.ConversationSummary) {
	for _, path := range d.historyCandidatePaths() {
		store := assistant.NewFileHistoryStore(path)
		entries, err := store.List(ctx)
		if err != nil || len(entries) == 0 {
			continue
		}
		return store, path, entries
	}
	return nil, "", nil
}

func (d *Dashboard) historyCandidatePaths() []string {
	seen := make(map[string]struct{})
	paths := make([]string, 0, 6)
	var addPath func(string)
	addDir := func(dir string) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			dir = "."
		}
		addPath(assistant.DefaultHistoryPath(expandHomePath(dir)))
	}
	addPath = func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		clean := filepath.Clean(expandHomePath(path))
		key := strings.ToLower(clean)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		paths = append(paths, clean)
	}

	addDir(d.services.ArchiveDir)
	addDir(".")
	addDir(filepath.Join("bin", "windows"))
	if cwd, err := os.Getwd(); err == nil {
		addDir(cwd)
		addDir(filepath.Join(cwd, "bin", "windows"))
	}
	if exe, err := os.Executable(); err == nil {
		addDir(filepath.Dir(exe))
	}
	return paths
}

func (d *Dashboard) assistantContext() string {
	var sb strings.Builder
	cfg := d.currentConfig
	if strings.TrimSpace(cfg.Target) == "" && d.target != nil {
		cfg = d.target.buildArchiveConfig()
	}
	if strings.TrimSpace(cfg.Target) != "" {
		sb.WriteString(fmt.Sprintf("Target: %s\n", cfg.Target))
	}
	if strings.TrimSpace(cfg.Intent) != "" {
		sb.WriteString(fmt.Sprintf("Intent: %s\n", cfg.Intent))
	}
	if d.discovery != nil {
		sb.WriteString("Discovery: ")
		sb.WriteString(d.discovery.Summary())
		sb.WriteString("\n")
	}
	if d.currentArchive != nil && d.currentArchive.Summary != "" {
		sb.WriteString("Last run: ")
		sb.WriteString(d.currentArchive.Summary)
		sb.WriteString("\n")
	}
	if d.authSession != nil {
		sb.WriteString(fmt.Sprintf("Auth session: %d cookies, success=%v\n", len(d.authSession.Cookies), d.authSession.AuthSuccess))
	}
	return strings.TrimSpace(sb.String())
}

func (d *Dashboard) pendingAIToolTimeout() time.Duration {
	return 5 * time.Hour
}

func (d *Dashboard) handleToolBridgeEvent(evt toolbridge.Event) []tea.Cmd {
	cmds := make([]tea.Cmd, 0, 4)
	phase := firstNonEmpty(evt.Phase, evt.NativeName, evt.ToolName)
	if evt.Target != nil {
		cmds = append(cmds, messageCmd(TargetConfigUpdatedMsg{Config: *evt.Target, Phase: phase}))
	}
	for _, item := range evt.Discoveries {
		cmds = append(cmds, messageCmd(DiscoveryItemMsg{
			Section: item.Section,
			Key:     item.Key,
			Item:    item.Item,
			Phase:   firstNonEmpty(item.Phase, phase),
		}))
	}
	if phase != "" {
		cmds = append(cmds, messageCmd(d.scanProgressForToolEvent(phase, evt.Discoveries)))
	}
	if strings.TrimSpace(evt.Error) != "" {
		cmds = append(cmds, messageCmd(AIToolResultMsg{Text: "tool event error: " + evt.Error}))
	}
	return cmds
}

func (d *Dashboard) scanProgressForToolEvent(phase string, items []toolbridge.DiscoveryItem) ScanProgressMsg {
	progress := ScanProgressMsg{Phase: phase}
	if d.discovery != nil {
		progress.Subdomains = d.discovery.totalSubdomains
		progress.Ports = d.discovery.totalPorts
		progress.URLs = d.discovery.totalURLs
		progress.Endpoints = d.discovery.totalEndpoints
		progress.Secrets = d.discovery.totalSecrets
		progress.Params = d.discovery.totalParams
		progress.JSFiles = d.discovery.totalJSFiles
		progress.Findings = d.discovery.totalFindings
	}

	seen := d.discoveryKeysBySection()
	for _, item := range items {
		section := strings.TrimSpace(item.Section)
		if section == "" {
			continue
		}
		key := strings.TrimSpace(item.Key)
		if key == "" {
			key = strings.TrimSpace(item.Item)
		}
		if key == "" {
			continue
		}
		if seen[section] == nil {
			seen[section] = make(map[string]struct{})
		}
		if _, ok := seen[section][key]; ok {
			continue
		}
		seen[section][key] = struct{}{}
		switch strings.ToLower(section) {
		case "subdomains":
			progress.Subdomains++
		case "ports":
			progress.Ports++
		case "urls":
			progress.URLs++
		case "endpoints":
			progress.Endpoints++
		case "secrets":
			progress.Secrets++
		case "params":
			progress.Params++
		case "js files":
			progress.JSFiles++
		case "findings":
			progress.Findings++
		}
	}
	return progress
}

func (d *Dashboard) discoveryKeysBySection() map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{})
	if d.discovery == nil {
		return out
	}
	for _, section := range d.discovery.sections {
		if section == nil {
			continue
		}
		keys := make(map[string]struct{})
		for key := range section.Keys {
			keys[key] = struct{}{}
		}
		out[section.Name] = keys
	}
	return out
}

func (d *Dashboard) saveRun(path string) tea.Cmd {
	target := ""
	if d.target != nil {
		target = d.target.buildArchiveConfig().Target
	}
	archive := d.archiveForCurrentRun()
	return func() tea.Msg {
		resolved, err := resolveManualSavePath(path, target)
		if err != nil {
			return RunSavedMsg{Error: err.Error()}
		}
		if archive == nil {
			return RunSavedMsg{Error: "nothing to save yet"}
		}
		if err := akemiarchive.WriteFile(resolved, archive); err != nil {
			return RunSavedMsg{Error: err.Error()}
		}
		return RunSavedMsg{Path: resolved}
	}
}

func (d *Dashboard) loadRun(path string) tea.Cmd {
	return func() tea.Msg {
		archivePath := strings.TrimSpace(path)
		if archivePath == "" {
			return archiveLoadedMsg{Error: ".akemi path is required"}
		}
		resolved := expandHomePath(archivePath)
		archive, err := akemiarchive.ReadFile(resolved)
		if err != nil {
			return archiveLoadedMsg{Path: resolved, Error: err.Error()}
		}
		return archiveLoadedMsg{Path: resolved, Archive: archive}
	}
}

func (d *Dashboard) archiveForCurrentRun() *akemiarchive.File {
	if d.currentArchive != nil {
		clone := *d.currentArchive
		clone.DiscoverySections = d.snapshotDiscoverySections()
		if ctx := d.snapshotMCPContext(); ctx != nil {
			clone.MCPContext = ctx
		}
		clone.Normalize()
		return &clone
	}
	cfg := archiveScanConfig(d.target.buildArchiveConfig())
	results := akemiarchive.Results{}
	archive := akemiarchive.New(cfg, "Manual dashboard save", results, d.snapshotDiscoverySections())
	if ctx := d.snapshotMCPContext(); ctx != nil {
		archive.MCPContext = ctx
	}
	return archive
}

func (d *Dashboard) applyArchive(file *akemiarchive.File, path string) {
	if file == nil {
		return
	}
	file.Normalize()
	cfg := file.Config
	if d.target != nil {
		d.target.fields[fieldTarget].value = cfg.Target
		d.target.fields[fieldAuthURL].value = cfg.AuthURL
		d.target.fields[fieldPorts].value = firstNonEmpty(cfg.PortRange, "top-1000")
		d.target.fields[fieldThreads].value = fmt.Sprintf("%d", firstPositiveInt(cfg.Threads, 200))
		d.target.fields[fieldProxy].value = cfg.Proxy
		d.target.fields[fieldIntent].value = firstNonEmpty(cfg.Intent, "quick_recon")
		d.target.fields[fieldDepth].value = fmt.Sprintf("%d", firstPositiveInt(cfg.Depth, 2))
		d.target.fields[fieldTimeout].value = fmt.Sprintf("%d", firstPositiveInt(cfg.Timeout, 10))
		if cfg.Target != "" {
			d.target.addRecentTarget(cfg.Target)
		}
		d.target.status = "Loaded .akemi"
		if file.Summary != "" {
			d.target.status = "Loaded .akemi: " + file.Summary
		}
	}
	if d.discovery != nil {
		d.discovery.reset()
		if len(file.DiscoverySections) > 0 {
			for _, section := range file.DiscoverySections {
				for _, item := range section.Items {
					d.discovery.AddItemWithKey(section.Name, item.Key, item.Item)
				}
			}
		} else {
			d.applyArchiveResultsToDiscovery(file.Results)
		}
		d.discovery.updateViewport()
	}
	d.currentConfig = ScanConfig{
		Target:    cfg.Target,
		AuthURL:   cfg.AuthURL,
		PortRange: firstNonEmpty(cfg.PortRange, "top-1000"),
		Threads:   firstPositiveInt(cfg.Threads, 200),
		Proxy:     cfg.Proxy,
		Intent:    firstNonEmpty(cfg.Intent, "quick_recon"),
		Depth:     firstPositiveInt(cfg.Depth, 2),
		Timeout:   firstPositiveInt(cfg.Timeout, 10),
	}
	d.currentArchive = file
	d.currentArchivePath = path
	if file.MCPContext != nil && d.services.MCPContext != nil {
		_ = d.services.MCPContext.Replace(context.Background(), *file.MCPContext)
	} else {
		d.syncMCPContextFromConfig(d.currentConfig)
	}
}

func (d *Dashboard) applyArchiveResultsToDiscovery(results akemiarchive.Results) {
	for _, port := range results.Ports {
		d.discovery.AddItemWithKey("Ports", fmt.Sprintf("%d", port.Port), formatPortResult(port))
	}
	for _, crawl := range results.CrawlFindings {
		d.discovery.AddItemWithKey("URLs", crawl.URL, formatCrawlFinding(crawl))
	}
	for _, u := range results.URLs {
		d.discovery.AddItemWithKey("URLs", u, u)
	}
	for _, sub := range results.Subdomains {
		d.discovery.AddItemWithKey("Subdomains", sub, sub)
	}
	for name, detail := range results.Params {
		d.discovery.AddItemWithKey("Params", name, formatParamDetail(name, detail))
	}
	for _, js := range results.JSAnalysis {
		for _, script := range js.Result.ScriptURLs {
			d.discovery.AddItemWithKey("JS Files", script, script)
		}
		for _, secret := range js.Result.Secrets {
			d.discovery.AddItemWithKey("Secrets", secret.Value+secret.SourceURL, formatSecretFinding(secret))
		}
	}
	for _, ep := range results.APIEndpoints {
		key, item := formatAPIEndpoint(ep)
		d.discovery.AddItemWithKey("Endpoints", key, item)
	}
	for _, spec := range results.APISpecs {
		key, item := formatAPISpec(spec)
		d.discovery.AddItemWithKey("Endpoints", key, item)
	}
	for _, param := range results.APIParameters {
		key, item := formatAPIParameter(param)
		d.discovery.AddItemWithKey("Params", key, item)
	}
	for _, finding := range results.Findings {
		item := discoveryItemForFinding(finding)
		d.discovery.AddItemWithKey(item.Section, item.Key, item.Item)
	}
}

func (d *Dashboard) snapshotMCPContext() *engagement.EngagementContext {
	if d.services.MCPContext == nil {
		return nil
	}
	snapshot, err := d.services.MCPContext.Snapshot(context.Background())
	if err != nil {
		return nil
	}
	return &snapshot
}

func (d *Dashboard) syncMCPContextFromConfig(cfg ScanConfig) {
	if d.services.MCPContext == nil || strings.TrimSpace(cfg.Target) == "" {
		return
	}
	ctx := context.Background()
	domain := domainFromTarget(cfg.Target)
	_ = d.services.MCPContext.SetTarget(ctx, engagement.TargetProfile{
		Name:    cfg.Target,
		BaseURL: cfg.Target,
		Domain:  domain,
		Hosts:   nonEmptyList(domain),
	})
	_ = d.services.MCPContext.SetDefaults(ctx, engagement.ScanDefaults{
		Ports:   cfg.PortRange,
		Threads: cfg.Threads,
		Timeout: cfg.Timeout,
		Depth:   cfg.Depth,
	})
	if d.authSession != nil {
		_ = d.services.MCPContext.SetAuthSession(ctx, *d.authSession)
	}
}

func emptyMCPDefaults() engagement.ScanDefaults {
	return engagement.ScanDefaults{}
}

func (d *Dashboard) snapshotDiscoverySections() []akemiarchive.DiscoverySection {
	if d.discovery == nil {
		return nil
	}
	sections := make([]akemiarchive.DiscoverySection, 0, len(d.discovery.sections))
	for _, section := range d.discovery.sections {
		out := akemiarchive.DiscoverySection{
			Name:  section.Name,
			Count: len(section.Items),
			Items: make([]akemiarchive.DiscoveryItem, 0, len(section.Items)),
		}
		for _, item := range section.Items {
			out.Items = append(out.Items, akemiarchive.DiscoveryItem{Key: item, Item: item})
		}
		sections = append(sections, out)
	}
	return sections
}

func (d *Dashboard) writeAkemiArchive(path string, archive *akemiarchive.File) error {
	if ctx := d.snapshotMCPContext(); ctx != nil {
		archive.MCPContext = ctx
	}
	return akemiarchive.WriteFile(path, archive)
}

func (d *Dashboard) send(msg tea.Msg) {
	select {
	case d.events <- msg:
	default:
		go func() { d.events <- msg }()
	}
}

func (d *Dashboard) scheduleEventPoll() tea.Cmd {
	if d.polling {
		return nil
	}
	d.polling = true
	return d.pollEvents()
}

func (d *Dashboard) pollEvents() tea.Cmd {
	return func() tea.Msg {
		select {
		case msg := <-d.events:
			return dashboardPolledMsg{Msg: msg}
		case <-time.After(150 * time.Millisecond):
			return dashboardPolledMsg{Msg: AgentTickMsg{}}
		}
	}
}

func (d *Dashboard) layoutPanels() {
	if d.width <= 0 || d.height <= 0 {
		return
	}
	leftW, topH := d.panelBounds()
	bodyH := d.bodyHeight()
	gapW := d.panelGapWidth(leftW)
	rightW := max(12, d.width-leftW-gapW)
	bottomH := max(6, bodyH-topH)

	d.target.SetSize(panelContentWidth(leftW), panelContentHeight(topH))
	d.system.SetSize(panelContentWidth(leftW), panelContentHeight(bottomH))
	d.discovery.SetSize(panelContentWidth(rightW), panelContentHeight(bodyH))
	d.agent.SetSize(panelContentWidth(rightW), panelContentHeight(bodyH))
}

func (d *Dashboard) panelBounds() (int, int) {
	leftW := int(float64(d.width) * d.splitH)
	minLeftW, minRightW := d.horizontalPanelLimits()
	if d.width > minLeftW+1+minRightW {
		leftW = min(max(leftW, minLeftW), d.width-1-minRightW)
	} else {
		leftW = max(12, d.width/2)
	}

	bodyH := d.bodyHeight()
	topH := int(float64(bodyH) * d.splitV)
	minTargetH, minSystemH := d.verticalPanelLimits(bodyH)
	if bodyH > minTargetH+minSystemH {
		topH = min(max(topH, minTargetH), bodyH-minSystemH)
	} else {
		topH = max(6, bodyH-minSystemH)
	}
	return leftW, topH
}

func (d *Dashboard) horizontalPanelLimits() (int, int) {
	return 28, 24
}

func (d *Dashboard) verticalPanelLimits(bodyH int) (int, int) {
	minTargetH := 10
	minSystemH := 6
	if bodyH < minTargetH+minSystemH {
		minTargetH = max(6, bodyH-minSystemH)
	}
	return minTargetH, minSystemH
}

func (d *Dashboard) bodyHeight() int {
	if d.showBanner {
		return max(1, d.height-1)
	}
	return max(1, d.height)
}

func (d *Dashboard) panelGapWidth(leftW int) int {
	if d.width-leftW > 24 {
		return 1
	}
	return 0
}

// View implements tea.Model.
func (d *Dashboard) View() string {
	if d.apiSettings != nil && d.apiSettings.visible {
		return d.apiSettings.view(d.width, d.height)
	}
	if !d.ready || d.width <= 0 || d.height <= 0 {
		return AccentText.Render("Loading Akemi dashboard...")
	}

	leftW, topH := d.panelBounds()
	bodyH := d.bodyHeight()
	gapW := d.panelGapWidth(leftW)
	rightW := max(12, d.width-leftW-gapW)
	bottomH := max(6, bodyH-topH)

	rightModel := tea.Model(d.agent)
	rightFocus := FocusAgent
	if d.workspace == FocusDiscovery {
		rightModel = d.discovery
		rightFocus = FocusDiscovery
	}

	targetPanel := d.renderPanel(d.target, leftW, topH, FocusTarget)
	systemPanel := d.renderPanel(d.system, leftW, bottomH, FocusSystem)
	rightPanel := d.renderPanel(rightModel, rightW, bodyH, rightFocus)
	leftColumn := lipgloss.JoinVertical(lipgloss.Top, targetPanel, systemPanel)
	parts := []string{leftColumn}
	if gapW > 0 {
		parts = append(parts, strings.Repeat(" ", gapW))
	}
	parts = append(parts, rightPanel)
	body := lipgloss.JoinHorizontal(lipgloss.Top, parts...)

	if d.showBanner {
		return lipgloss.JoinVertical(lipgloss.Top, body, d.renderBanner())
	}
	return body
}

func (d *Dashboard) renderPanel(model tea.Model, width, height int, focus FocusMsg) string {
	if width < 12 {
		width = 12
	}
	if height < 6 {
		height = 6
	}
	contentWidth := panelContentWidth(width)
	contentHeight := panelContentHeight(height)
	style := PanelStyle
	if d.focus == focus {
		style = PanelFocused
	}
	content := clipBlock(model.View(), contentWidth, contentHeight)
	return style.Render(content)
}

func panelContentWidth(width int) int {
	return max(1, width-6)
}

func panelContentHeight(height int) int {
	return max(1, height-4)
}

func clampRatio(value float64) float64 {
	if value < 0.05 {
		return 0.05
	}
	if value > 0.95 {
		return 0.95
	}
	return value
}

func clipBlock(value string, width, height int) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	lines := strings.Split(value, "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	for i, line := range lines {
		if ansi.StringWidth(line) > width {
			lines[i] = ansi.Truncate(line, width, "")
		}
		if pad := width - ansi.StringWidth(lines[i]); pad > 0 {
			lines[i] += strings.Repeat(" ", pad)
		}
	}
	for len(lines) < height {
		lines = append(lines, strings.Repeat(" ", width))
	}
	return strings.Join(lines, "\n")
}

func (d *Dashboard) renderBanner() string {
	tab := func(label string, active bool) string {
		if active {
			return HighlightRow.Render(" " + label + " ")
		}
		return DimText.Render(" " + label + " ")
	}

	activityActive := d.focus == FocusAgent && d.agent.mode == agentModeActivity
	chatActive := d.focus == FocusAgent && d.agent.mode == agentModeChat
	historyActive := d.focus == FocusAgent && d.agent.mode == agentModeHistory
	agentLabel := "CHAT"
	if historyActive {
		agentLabel = "HISTORY"
	}

	parts := []string{
		tab("TARGET", d.focus == FocusTarget),
		DimText.Render("|"),
		tab("DISCOVERY", d.focus == FocusDiscovery),
		DimText.Render("|"),
		tab("SYSTEM", d.focus == FocusSystem),
		DimText.Render("|"),
		tab("ACTIVITY", activityActive),
		DimText.Render("|"),
		tab(agentLabel, chatActive || historyActive),
		DimText.Render("|"),
		HelpText.Render(" Tab focus | Drag borders resize | Ctrl+Y copy | Ctrl+M mouse/select | Ctrl+D discovery | Ctrl+A activity | Ctrl+P chat | F5 settings | Ctrl+X stop | Ctrl+C quit "),
	}
	line := lipgloss.JoinHorizontal(lipgloss.Top, parts...)
	if d.width > 0 && lipgloss.Width(line) > d.width {
		return ansi.Truncate(line, d.width, "")
	}
	if lipgloss.Width(line) < d.width {
		line += strings.Repeat(" ", d.width-lipgloss.Width(line))
	}
	return line
}

func (d *Dashboard) copyTextForFocus() (string, string) {
	switch d.focus {
	case FocusDiscovery:
		if d.discovery != nil {
			if item := d.discovery.SelectedText(); strings.TrimSpace(item) != "" {
				return "discovery row", item
			}
			return "discovery panel", plainText(d.discovery.View())
		}
	case FocusSystem:
		if d.system != nil {
			return "system panel", plainText(d.system.View())
		}
	case FocusAgent:
		if d.agent != nil {
			return "agent panel", plainText(d.agent.View())
		}
	default:
		if d.target != nil {
			return "target panel", plainText(d.target.View())
		}
	}
	return "dashboard", plainText(d.View())
}

func copyToClipboardCmd(label, text string) tea.Cmd {
	text = strings.TrimSpace(plainText(text))
	return func() tea.Msg {
		if text == "" {
			return clipboardCopyDoneMsg{Label: label}
		}
		if err := copyToClipboard(text); err != nil {
			return clipboardCopyDoneMsg{Label: label, Error: err.Error()}
		}
		return clipboardCopyDoneMsg{Label: label, Bytes: len(text)}
	}
}

func copyToClipboard(text string) error {
	var commands [][]string
	switch runtime.GOOS {
	case "windows":
		commands = [][]string{
			{"clip"},
			{"powershell", "-NoProfile", "-Command", "Set-Clipboard -Value ([Console]::In.ReadToEnd())"},
		}
	case "darwin":
		commands = [][]string{{"pbcopy"}}
	default:
		commands = [][]string{
			{"wl-copy"},
			{"xclip", "-selection", "clipboard"},
			{"xsel", "--clipboard", "--input"},
		}
	}
	var lastErr error
	for _, spec := range commands {
		cmd := exec.Command(spec[0], spec[1:]...)
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no clipboard command configured")
	}
	return lastErr
}

func plainText(value string) string {
	return strings.TrimRight(ansi.Strip(value), "\n")
}

type dashboardToolSink struct {
	send func(tea.Msg)
}

func (s dashboardToolSink) Emit(ctx context.Context, event toolbridge.Event) {
	if s.send == nil {
		return
	}
	select {
	case <-ctx.Done():
		return
	default:
		s.send(event)
	}
}

func batchCmds(cmds ...tea.Cmd) tea.Cmd {
	filtered := make([]tea.Cmd, 0, len(cmds))
	for _, cmd := range cmds {
		if cmd != nil {
			filtered = append(filtered, cmd)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	if len(filtered) == 1 {
		return filtered[0]
	}
	return tea.Batch(filtered...)
}

func messageCmd(msg tea.Msg) tea.Cmd {
	return func() tea.Msg { return msg }
}

func assistantErrorNeedsSetup(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "api key") ||
		strings.Contains(text, "apikey") ||
		strings.Contains(text, "not configured") ||
		strings.Contains(text, "no usable")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstPositiveInt(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func nonEmptyList(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return out
}

func parsePorts(value string) []int {
	return surface.ParseDashboardPorts(value)
}

func domainFromTarget(target string) string {
	return surface.DomainFromTarget(target)
}

func targetIDFromTarget(target string) string {
	domain := domainFromTarget(target)
	if domain != "" {
		return strings.ToLower(strings.ReplaceAll(domain, ".", "-"))
	}
	target = strings.ToLower(strings.TrimSpace(target))
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.Trim(target, "/")
	target = strings.ReplaceAll(target, "/", "-")
	target = strings.ReplaceAll(target, ":", "-")
	return target
}

func engagementAuthSessionFromDotHound(session *dothound.AuthSession, targetID string) *engagement.AuthSession {
	if session == nil {
		return nil
	}
	return &engagement.AuthSession{
		TargetID:       targetID,
		TargetURL:      session.TargetURL,
		Source:         "dothound",
		AuthSuccess:    session.AuthSuccess,
		Cookies:        append([]string(nil), session.Cookies...),
		CSRFTokens:     append([]string(nil), session.CSRFTokens...),
		RedirectChain:  append([]string(nil), session.RedirectChain...),
		CapturedAt:     session.CapturedAt,
		WorkflowPath:   session.WorkflowPath,
		HTMLReportPath: session.HTMLReportPath,
	}
}

func scanDoneFromSurfaceResult(result *surface.FullSurfaceResult, intent string, err error, cancelled bool) ScanDoneMsg {
	ports := []core.PortResult(nil)
	if result.PortScan != nil {
		ports = append(ports, result.PortScan.OpenPorts...)
	}
	urls := make([]string, 0, len(result.CrawlFindings))
	for _, crawl := range result.CrawlFindings {
		if crawl.URL != "" {
			urls = append(urls, crawl.URL)
		}
	}
	subdomains := make([]string, 0, len(result.Subdomains))
	for _, sub := range result.Subdomains {
		if sub.Name != "" {
			subdomains = append(subdomains, sub.Name)
		}
	}
	counts := surfaceResultCounts(result)
	summary := dashboardScanSummary(intent, counts)
	if cancelled {
		summary = "cancelled - " + summary
		err = nil
	}
	return ScanDoneMsg{
		Findings:      append([]core.VulnFinding(nil), result.VulnFindings...),
		Ports:         ports,
		URLs:          urls,
		CrawlFindings: append([]core.CrawlFinding(nil), result.CrawlFindings...),
		Subdomains:    subdomains,
		APIEndpoints:  append([]core.APIEndpointFinding(nil), result.APIEndpoints...),
		APISpecs:      append([]core.APISpecFinding(nil), result.APISpecs...),
		APIParameters: append([]core.APIParameterFinding(nil), result.APIParameters...),
		Summary:       summary,
		Cancelled:     cancelled,
		Error:         err,
	}
}

func archiveFromSurface(cfg ScanConfig, result *surface.FullSurfaceResult, mcp *engagement.EngagementContext) (*akemiarchive.File, string) {
	if result == nil {
		return nil, ""
	}
	results := akemiarchive.Results{
		CrawlFindings: append([]core.CrawlFinding(nil), result.CrawlFindings...),
		Params:        cloneParamDetails(nil),
		APIEndpoints:  append([]core.APIEndpointFinding(nil), result.APIEndpoints...),
		APISpecs:      append([]core.APISpecFinding(nil), result.APISpecs...),
		APIParameters: append([]core.APIParameterFinding(nil), result.APIParameters...),
		Secrets:       append([]core.SecretFinding(nil), result.Secrets...),
		Findings:      append([]core.VulnFinding(nil), result.VulnFindings...),
	}
	if result.PortScan != nil {
		results.Ports = append([]core.PortResult(nil), result.PortScan.OpenPorts...)
	}
	results.URLs = make([]string, 0, len(result.CrawlFindings))
	for _, crawl := range result.CrawlFindings {
		if crawl.URL != "" {
			results.URLs = append(results.URLs, crawl.URL)
		}
	}
	results.Subdomains = make([]string, 0, len(result.Subdomains))
	for _, sub := range result.Subdomains {
		if sub.Name != "" {
			results.Subdomains = append(results.Subdomains, sub.Name)
		}
	}
	if result.Params != nil {
		results.Params = cloneParamDetails(result.Params.Params)
	}
	for _, js := range result.JSAnalysis {
		results.JSAnalysis = append(results.JSAnalysis, akemiarchive.JSAnalysisCapture{
			PageURL: js.PageURL,
			Result:  js.Result,
		})
	}
	summary := dashboardScanSummary(cfg.Intent, map[string]int{
		"ports":          len(results.Ports),
		"urls":           len(results.CrawlFindings),
		"params":         len(results.Params),
		"api_endpoints":  len(results.APIEndpoints),
		"api_specs":      len(results.APISpecs),
		"api_parameters": len(results.APIParameters),
		"subdomains":     len(results.Subdomains),
		"vuln_findings":  len(results.Findings),
		"secrets":        len(results.Secrets),
	})
	sections := archiveSectionsFromResults(results)
	archive := akemiarchive.New(archiveScanConfig(cfg), summary, results, sections)
	archive.MCPContext = mcp
	return archive, ""
}

func surfaceResultCounts(result *surface.FullSurfaceResult) map[string]int {
	counts := map[string]int{
		"ports":          0,
		"urls":           0,
		"params":         0,
		"js_analysis":    0,
		"api_endpoints":  0,
		"api_specs":      0,
		"api_parameters": 0,
		"subdomains":     0,
		"vuln_findings":  0,
		"secrets":        0,
		"stage_errors":   0,
	}
	if result == nil {
		return counts
	}
	for key, value := range result.Counts {
		counts[key] = value
	}
	if result.PortScan != nil {
		counts["ports"] = len(result.PortScan.OpenPorts)
	}
	counts["urls"] = len(result.CrawlFindings)
	if result.Params != nil {
		counts["params"] = len(result.Params.Params)
	}
	counts["js_analysis"] = len(result.JSAnalysis)
	counts["api_endpoints"] = len(result.APIEndpoints)
	counts["api_specs"] = len(result.APISpecs)
	counts["api_parameters"] = len(result.APIParameters)
	counts["subdomains"] = len(result.Subdomains)
	counts["vuln_findings"] = len(result.VulnFindings)
	counts["secrets"] = len(result.Secrets)
	counts["stage_errors"] = len(result.Errors)
	return counts
}

func dashboardScanSummary(intent string, counts map[string]int) string {
	label := intentLabel(normalizeDashboardIntent(intent))
	return fmt.Sprintf("%s: %d ports, %d URLs, %d params, %d API endpoints, %d subdomains, %d findings, %d secrets",
		label,
		counts["ports"],
		counts["urls"],
		counts["params"],
		counts["api_endpoints"],
		counts["subdomains"],
		counts["vuln_findings"],
		counts["secrets"],
	)
}

func intentLabel(intent string) string {
	switch intent {
	case "full_surface_map":
		return "Full surface map"
	case "api_hunter":
		return "API Hunter"
	case "sqli_hunt":
		return "SQLi hunt"
	case "vuln_assessment":
		return "Vulnerability assessment"
	default:
		return "Quick recon"
	}
}

func archiveScanConfig(cfg ScanConfig) akemiarchive.ScanConfig {
	return akemiarchive.ScanConfig{
		Target:    cfg.Target,
		AuthURL:   cfg.AuthURL,
		PortRange: cfg.PortRange,
		Threads:   cfg.Threads,
		Proxy:     cfg.Proxy,
		Intent:    cfg.Intent,
		Depth:     cfg.Depth,
		Timeout:   cfg.Timeout,
	}
}

func archiveSectionsFromResults(results akemiarchive.Results) []akemiarchive.DiscoverySection {
	buckets := map[string][]akemiarchive.DiscoveryItem{}
	add := func(section, key, item string) {
		if strings.TrimSpace(item) == "" {
			return
		}
		buckets[section] = append(buckets[section], akemiarchive.DiscoveryItem{Key: key, Item: item})
	}
	for _, port := range results.Ports {
		add("Ports", fmt.Sprintf("%d", port.Port), formatPortResult(port))
	}
	for _, crawl := range results.CrawlFindings {
		add("URLs", crawl.URL, formatCrawlFinding(crawl))
	}
	for _, sub := range results.Subdomains {
		add("Subdomains", sub, sub)
	}
	for name, detail := range results.Params {
		add("Params", name, formatParamDetail(name, detail))
	}
	for _, js := range results.JSAnalysis {
		for _, script := range js.Result.ScriptURLs {
			add("JS Files", script, script)
		}
		for _, secret := range js.Result.Secrets {
			add("Secrets", secret.Value+secret.SourceURL, formatSecretFinding(secret))
		}
	}
	for _, ep := range results.APIEndpoints {
		key, item := formatAPIEndpoint(ep)
		add("Endpoints", key, item)
	}
	for _, spec := range results.APISpecs {
		key, item := formatAPISpec(spec)
		add("Endpoints", key, item)
	}
	for _, param := range results.APIParameters {
		key, item := formatAPIParameter(param)
		add("Params", key, item)
	}
	for _, finding := range results.Findings {
		item := discoveryItemForFinding(finding)
		add(item.Section, item.Key, item.Item)
	}

	order := []string{"Subdomains", "Ports", "URLs", "Endpoints", "Secrets", "Params", "JS Files", "Findings"}
	sections := make([]akemiarchive.DiscoverySection, 0, len(order))
	for _, name := range order {
		items := buckets[name]
		if len(items) == 0 {
			continue
		}
		sections = append(sections, akemiarchive.DiscoverySection{Name: name, Count: len(items), Items: items})
	}
	return sections
}

func writeArchiveToDir(dir, target string, archive *akemiarchive.File) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, akemiarchive.DefaultFilename(target, time.Now()))
	if err := akemiarchive.WriteFile(path, archive); err != nil {
		return "", err
	}
	return path, nil
}

func resolveManualSavePath(path, target string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			home = "."
		}
		path = filepath.Join(home, akemiarchive.DefaultRunFilename(target))
	}
	path = expandHomePath(path)
	if strings.TrimSpace(filepath.Ext(path)) == "" {
		path += ".akemi"
	}
	return filepath.Clean(path), nil
}

func normalizeArchivePath(path string) string {
	return filepath.Clean(expandHomePath(path))
}

func expandHomePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "~" || strings.HasPrefix(path, "~"+string(os.PathSeparator)) || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			if path == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimLeft(path[1:], `/\`))
		}
	}
	return path
}

func paramCount(params *core.ParamDiscoveryResult) int {
	if params == nil {
		return 0
	}
	return len(params.Params)
}

func discoveryItemForFinding(f core.VulnFinding) DiscoveryItemMsg {
	item := fmt.Sprintf("[%s] %s", strings.ToUpper(firstNonEmpty(f.Severity, "info")), firstNonEmpty(f.Name, f.Description, f.Target))
	if strings.TrimSpace(f.Target) != "" {
		item += " -> " + f.Target
	}
	if strings.TrimSpace(f.Evidence) != "" {
		item += " | " + f.Evidence
	}
	key := firstNonEmpty(f.ID, strings.Join(nonEmptyList(f.Name, f.Target, f.Evidence), "|"), item)
	return DiscoveryItemMsg{Section: "Findings", Key: key, Item: item, Phase: "Finding"}
}

func formatPortResult(p core.PortResult) string {
	parts := []string{fmt.Sprintf("[PORT] %d/%s", p.Port, firstNonEmpty(p.State, "open"))}
	if p.Service != "" {
		parts = append(parts, p.Service)
	}
	if p.Version != "" {
		parts = append(parts, p.Version)
	}
	if len(p.Technology) > 0 {
		parts = append(parts, strings.Join(p.Technology, ","))
	}
	if p.TLS {
		parts = append(parts, "tls")
	}
	if p.Banner != "" {
		parts = append(parts, truncate(p.Banner, 100))
	}
	return strings.Join(parts, "  ")
}

func formatCrawlFinding(f core.CrawlFinding) string {
	status := "URL"
	if f.StatusCode > 0 {
		status = fmt.Sprintf("%d", f.StatusCode)
	}
	path := f.URL
	if parsed, err := url.Parse(f.URL); err == nil && parsed.Path != "" {
		path = parsed.Path
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
	}
	parts := []string{fmt.Sprintf("[%s] %s", status, path)}
	if f.Depth > 0 {
		parts = append(parts, fmt.Sprintf("depth=%d", f.Depth))
	}
	if f.Title != "" {
		parts = append(parts, truncate(f.Title, 80))
	}
	return strings.Join(parts, "  ")
}

func formatAPIEndpoint(ep core.APIEndpointFinding) (string, string) {
	key := firstNonEmpty(ep.URL, ep.Path, ep.Method)
	method := firstNonEmpty(ep.Method, "GET")
	path := firstNonEmpty(ep.Path, ep.URL)
	parts := []string{fmt.Sprintf("[%s] %s", strings.ToUpper(method), path)}
	if ep.StatusCode > 0 {
		parts = append(parts, fmt.Sprintf("%d", ep.StatusCode))
	}
	if ep.APIType != "" {
		parts = append(parts, ep.APIType)
	}
	if ep.AuthRequired {
		parts = append(parts, "auth")
	}
	if len(ep.Parameters) > 0 {
		parts = append(parts, fmt.Sprintf("%d params", len(ep.Parameters)))
	}
	return key, strings.Join(parts, "  ")
}

func formatAPISpec(spec core.APISpecFinding) (string, string) {
	key := firstNonEmpty(spec.URL, spec.Title, spec.APIType)
	parts := []string{"[SPEC]", firstNonEmpty(spec.Title, spec.URL)}
	if spec.APIType != "" {
		parts = append(parts, spec.APIType)
	}
	if spec.Format != "" {
		parts = append(parts, spec.Format)
	}
	if spec.EndpointCount > 0 {
		parts = append(parts, fmt.Sprintf("%d endpoints", spec.EndpointCount))
	}
	return key, strings.Join(parts, "  ")
}

func formatAPIParameter(param core.APIParameterFinding) (string, string) {
	key := firstNonEmpty(param.Name, strings.Join(param.Endpoints, ","))
	parts := []string{fmt.Sprintf("?%s=", firstNonEmpty(param.Name, "parameter"))}
	if param.In != "" {
		parts = append(parts, param.In)
	}
	if param.Type != "" {
		parts = append(parts, param.Type)
	}
	if param.Required {
		parts = append(parts, "required")
	}
	if len(param.Endpoints) > 0 {
		parts = append(parts, fmt.Sprintf("(%d endpoints)", len(param.Endpoints)))
	}
	if len(param.Sources) > 0 {
		parts = append(parts, fmt.Sprintf("(%d sources)", len(param.Sources)))
	}
	return key, strings.Join(parts, " ")
}

func formatParamDetail(name string, detail core.ParamDetail) string {
	parts := []string{fmt.Sprintf("?%s=", firstNonEmpty(name, detail.Name, "param"))}
	if len(detail.Sources) > 0 {
		parts = append(parts, fmt.Sprintf("(%d sources)", len(detail.Sources)))
	}
	if len(detail.Examples) > 0 {
		parts = append(parts, "ex: "+truncate(detail.Examples[0], 60))
	}
	return strings.Join(parts, " ")
}

func formatSecretFinding(secret core.SecretFinding) string {
	category := firstNonEmpty(secret.Category, "secret")
	source := firstNonEmpty(secret.SourceURL, secret.SourceKind)
	value := "<redacted>"
	if secret.Value != "" {
		value = truncate(secret.Value, 12) + "..."
	}
	if source == "" {
		return fmt.Sprintf("[%s] %s", category, value)
	}
	return fmt.Sprintf("[%s] %s from %s", category, value, source)
}

func formatSubdomainResult(sub core.SubdomainResult) string {
	parts := []string{sub.Name}
	if sub.Source != "" {
		parts = append(parts, "source="+sub.Source)
	}
	if len(sub.IPs) > 0 {
		parts = append(parts, strings.Join(sub.IPs, ","))
	}
	if sub.StatusCode > 0 {
		parts = append(parts, fmt.Sprintf("%d", sub.StatusCode))
	}
	if sub.IsAlive {
		parts = append(parts, "alive")
	}
	return strings.Join(parts, "  ")
}

func sortedParamNames(params map[string]core.ParamDetail) []string {
	names := make([]string, 0, len(params))
	for name := range params {
		if strings.TrimSpace(name) != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func uniqueOrderedStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func cloneParamDetails(params map[string]core.ParamDetail) map[string]core.ParamDetail {
	if len(params) == 0 {
		return nil
	}
	out := make(map[string]core.ParamDetail, len(params))
	for name, detail := range params {
		detail.Sources = append([]string(nil), detail.Sources...)
		detail.Examples = append([]string(nil), detail.Examples...)
		out[name] = detail
	}
	return out
}

// RunDashboard starts the Bubble Tea dashboard.
func RunDashboard(services DashboardServices) error {
	prevLogger := core.Logger()
	core.SetLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer core.SetLogger(prevLogger)
	prevStdLogOutput := log.Writer()
	prevStdLogFlags := log.Flags()
	prevStdLogPrefix := log.Prefix()
	log.SetOutput(io.Discard)
	defer func() {
		log.SetOutput(prevStdLogOutput)
		log.SetFlags(prevStdLogFlags)
		log.SetPrefix(prevStdLogPrefix)
	}()

	program := tea.NewProgram(
		NewDashboard(services),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	_, err := program.Run()
	return err
}
