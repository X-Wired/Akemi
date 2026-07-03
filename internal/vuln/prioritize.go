package vuln

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	core "Akemi/internal/core"
)

// =============================================================
// ── ADAPTIVE TEMPLATE PRIORITIZATION ENGINE ──────────────────
// =============================================================
//
// PrioritizeTemplates reorders probe templates based on the target
// context gathered during Phase 1 fingerprinting. The goal is to
// run the most relevant, highest-impact templates first so that:
//
// 1. Critical findings surface early (before scan timeout or rate limits).
// 2. Irrelevant templates (e.g. Java deserialization against PHP) are
//    pushed to the back rather than skipped entirely — the fingerprint
//    may be incomplete.
// 3. WAF-aware deprioritization avoids burning request budget on
//    templates likely to be filtered by the detected WAF.
//
// Scoring factors (weighted):
//   - Tech-stack match     → 40%  (template tags overlap with detected tech)
//   - Severity             → 30%  (critical > high > medium > low)
//   - Parameter-type match → 20%  (template tags overlap with param priority tags)
//   - CVE version match    → 50%  bonus if framework + CVE template align
//   - WAF penalty          → ×0.3 for historically-filtered template+WAF pairs

// templatePriority holds a scored template ready for sorting.
type templatePriority struct {
	tmpl      ProbeTemplate
	score     float64
	breakdown string // human-readable score breakdown for verbose output
}

// PrioritizeTemplates returns a reordered slice where the most relevant
// templates appear first. When targetCtx is nil or prioritization is
// disabled, the original order is preserved.
func PrioritizeTemplates(
	templates []ProbeTemplate,
	targetCtx *core.TargetContext,
	paramNames []string,
	verbose bool,
) []ProbeTemplate {
	if targetCtx == nil || len(templates) <= 1 {
		return templates
	}

	// Build parameter → priority-tags map once
	paramPriorityMap := buildParamPriorityMap(targetCtx.ParameterProfile, paramNames)

	// Score every template
	scored := make([]templatePriority, 0, len(templates))
	for _, tmpl := range templates {
		prio := scoreTemplate(tmpl, targetCtx, paramPriorityMap)
		scored = append(scored, prio)
	}

	// Stable sort by descending score (highest first)
	slices.SortStableFunc(scored, func(a, b templatePriority) int {
		return cmp.Compare(b.score, a.score)
	})

	if verbose {
		printPriorityBreakdown(scored, targetCtx.URL)
	}

	result := make([]ProbeTemplate, len(scored))
	for i, sp := range scored {
		result[i] = sp.tmpl
	}
	return result
}

// =============================================================
// ── SCORING ENGINE ───────────────────────────────────────────
// =============================================================

func scoreTemplate(
	tmpl ProbeTemplate,
	ctx *core.TargetContext,
	paramPriorityMap map[string]map[string]bool,
) templatePriority {
	sp := templatePriority{
		tmpl:  tmpl,
		score: 10.0, // base score so every template gets run
	}

	var parts []string

	// ── 1. Tech-stack match (weight: 40%) ────────────────
	techScore := scoreTechMatch(tmpl, ctx)
	sp.score += techScore * 40
	if techScore > 0 {
		parts = append(parts, fmtScore("tech", techScore, 40))
	}

	// ── 2. Severity weighting (weight: 30%) ──────────────
	sevScore := scoreSeverity(tmpl.Info.Severity)
	sp.score += sevScore * 30
	parts = append(parts, fmtScore("severity", sevScore, 30))

	// ── 3. Parameter-type match (weight: 20%) ────────────
	paramScore := scoreParamMatch(tmpl, paramPriorityMap)
	sp.score += paramScore * 20
	if paramScore > 0 {
		parts = append(parts, fmtScore("param", paramScore, 20))
	}

	// ── 4. CVE / version bonus ───────────────────────────
	if cveScore := scoreCVEMatch(tmpl, ctx); cveScore > 0 {
		sp.score += cveScore * 50
		parts = append(parts, fmtScore("cve", cveScore, 50))
	}

	// ── 5. WAF penalty ───────────────────────────────────
	if wafPenalty := scoreWAFPenalty(tmpl, ctx); wafPenalty > 0 {
		sp.score *= (1.0 - wafPenalty)
		parts = append(parts, fmtScore("waf_penalty", -wafPenalty, 0))
	}

	sp.breakdown = strings.Join(parts, " ")
	return sp
}

// ── Tech-stack overlap ──────────────────────────────────────

// langAliases maps framework/language names to canonical form for comparison.
var langAliases = map[string]string{
	"php":        "php",
	"python":     "python",
	"java":       "java",
	"javascript": "javascript",
	"js":         "javascript",
	"nodejs":     "javascript",
	"node":       "javascript",
	"ruby":       "ruby",
	"csharp":     "dotnet",
	"c#":         "dotnet",
	"dotnet":     "dotnet",
	".net":       "dotnet",
	"asp.net":    "dotnet",
	"go":         "go",
	"golang":     "go",
}

// frameworkAliases maps common template-tag framework names to recognized frameworks.
var frameworkAliases = map[string]string{
	"spring":     "Spring",
	"springboot": "Spring Boot",
	"django":     "Django",
	"rails":      "Rails",
	"laravel":    "Laravel",
	"express":    "Express",
	"flask":      "Flask",
	"wordpress":  "WordPress",
	"symfony":    "Symfony",
	"aspnet":     "ASP.NET",
	"asp.net":    "ASP.NET",
	"nextjs":     "Next.js",
	"next.js":    "Next.js",
	"gin":        "Gin / Go",
}

// tagToTech maps template tags to canonical tech identifiers.
var tagToTech = map[string][]string{
	"php":        {"php"},
	"python":     {"python"},
	"java":       {"java"},
	"jsp":        {"java"},
	"servlet":    {"java"},
	"dotnet":     {"dotnet"},
	"asp.net":    {"dotnet"},
	"csharp":     {"dotnet"},
	"nodejs":     {"javascript"},
	"node":       {"javascript"},
	"javascript": {"javascript"},
	"js":         {"javascript"},
	"ruby":       {"ruby"},
	"go":         {"go"},
	"golang":     {"go"},
	"spring":     {"java", "spring"},
	"springboot": {"java", "spring"},
	"spel":       {"java", "spring"},
	"ognl":       {"java"},
	"struts":     {"java"},
	"django":     {"python", "django"},
	"flask":      {"python"},
	"jinja2":     {"python"},
	"rails":      {"ruby"},
	"laravel":    {"php"},
	"symfony":    {"php"},
	"wordpress":  {"php"},
	"express":    {"javascript"},
	"nextjs":     {"javascript"},
	"next.js":    {"javascript"},
	"log4j":      {"java"},
	"jndi":       {"java"},
	"gadget":     {"java"},
	"pickle":     {"python"},
	"yaml":       {"python"},
	"xml":        {"java", "dotnet"},
	"xxe":        {"java", "dotnet", "php"},
}

func scoreTechMatch(tmpl ProbeTemplate, ctx *core.TargetContext) float64 {
	if ctx.Framework == "" && ctx.Language == "" {
		return 0
	}

	hits := 0

	// Normalize template tags to canonical tech identifiers
	for _, tag := range tmpl.Info.Tags {
		tagLower := strings.ToLower(strings.TrimSpace(tag))

		// Direct tech match via tagToTech lookup
		if techs, ok := tagToTech[tagLower]; ok {
			for _, tech := range techs {
				if techMatch(ctx, tech) {
					hits++
					break
				}
			}
		}

		// Framework name match via frameworkAliases
		if fw, ok := frameworkAliases[tagLower]; ok {
			if strings.EqualFold(ctx.Framework, fw) {
				hits += 2
			}
		}

		// Language alias match
		if alias, ok := langAliases[tagLower]; ok {
			ctxLang := langAliases[strings.ToLower(ctx.Language)]
			if ctxLang == alias && ctxLang != "" {
				hits++
			}
		}
	}

	// Clamp to [0, 1]
	switch {
	case hits >= 3:
		return 1.0
	case hits == 2:
		return 0.75
	case hits == 1:
		return 0.40
	default:
		return 0
	}
}

func techMatch(ctx *core.TargetContext, tech string) bool {
	techLower := strings.ToLower(tech)
	frameworkLower := strings.ToLower(ctx.Framework)
	languageLower := strings.ToLower(ctx.Language)

	// Check language
	if ctxLang, ok := langAliases[languageLower]; ok && ctxLang == techLower {
		return true
	}
	if languageLower == techLower {
		return true
	}

	// Check framework name
	if strings.Contains(frameworkLower, techLower) {
		return true
	}

	// Check tech stack entries
	for _, ts := range ctx.TechStack {
		if strings.Contains(strings.ToLower(ts), techLower) {
			return true
		}
	}

	return false
}

// ── Severity scoring ─────────────────────────────────────────

func scoreSeverity(severity string) float64 {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 1.0
	case "high":
		return 0.70
	case "medium":
		return 0.35
	case "low", "info":
		return 0.10
	default:
		return 0.35
	}
}

// ── Parameter-type match ────────────────────────────────────

func buildParamPriorityMap(profile *core.ParameterProfile, paramNames []string) map[string]map[string]bool {
	result := make(map[string]map[string]bool, len(paramNames))
	for _, name := range paramNames {
		result[name] = nil // params without profile get empty set (no boost)
	}

	if profile == nil {
		return result
	}

	for _, pc := range profile.Parameters {
		if _, exists := result[pc.Name]; !exists {
			continue
		}
		tagSet := make(map[string]bool, len(pc.PriorityTags))
		for _, tag := range pc.PriorityTags {
			tagSet[strings.ToLower(tag)] = true
		}
		if len(tagSet) > 0 {
			result[pc.Name] = tagSet
		}
	}

	return result
}

func scoreParamMatch(tmpl ProbeTemplate, paramPriorityMap map[string]map[string]bool) float64 {
	maxOverlap := 0
	for _, tagSet := range paramPriorityMap {
		if tagSet == nil {
			continue
		}
		overlap := 0
		for _, tag := range tmpl.Info.Tags {
			if tagSet[strings.ToLower(tag)] {
				overlap++
			}
		}
		if overlap > maxOverlap {
			maxOverlap = overlap
		}
	}

	switch {
	case maxOverlap >= 2:
		return 1.0
	case maxOverlap == 1:
		return 0.50
	default:
		return 0
	}
}

// ── CVE / version bonus ─────────────────────────────────────

// cveFrameworkMap maps CVE template IDs to the affected framework.
var cveFrameworkMap = map[string]string{
	"log4shell":    "Log4j",
	"log4j":        "Log4j",
	"spring4shell": "Spring",
	"spring4j":     "Spring",
}

func scoreCVEMatch(tmpl ProbeTemplate, ctx *core.TargetContext) float64 {
	affectedFramework := ""

	// Check by template ID
	if fw, ok := cveFrameworkMap[strings.ToLower(tmpl.ID)]; ok {
		affectedFramework = fw
	}

	// Check by tags: look for "cve" + framework tag
	isCVE := false
	for _, tag := range tmpl.Info.Tags {
		tagLower := strings.ToLower(tag)
		if tagLower == "cve" {
			isCVE = true
		}
		if fw, ok := cveFrameworkMap[tagLower]; ok {
			affectedFramework = fw
		}
	}

	if !isCVE || affectedFramework == "" {
		return 0
	}

	// Does the target context suggest this framework?
	frameworkLower := strings.ToLower(ctx.Framework)
	affectedLower := strings.ToLower(affectedFramework)

	if strings.Contains(frameworkLower, affectedLower) {
		return 1.0 // strong match
	}

	// Check tech stack for indirect evidence
	for _, ts := range ctx.TechStack {
		if strings.Contains(strings.ToLower(ts), affectedLower) {
			return 0.60
		}
	}

	return 0
}

// ── WAF penalty ──────────────────────────────────────────────

// historicallyFiltered defines template tag → WAF pairs known to have low
// success rates. The penalty reduces the priority score multiplier.
var historicallyFiltered = map[string]map[string]float64{
	"sqli": {
		"Cloudflare":          0.60,
		"AWS WAF":             0.55,
		"Imperva / Incapsula": 0.55,
		"ModSecurity":         0.65,
		"Fortinet FortiWeb":   0.55,
	},
	"xss": {
		"Cloudflare":          0.50,
		"AWS WAF":             0.40,
		"Imperva / Incapsula": 0.45,
	},
	"cmdi": {
		"Cloudflare":  0.45,
		"ModSecurity": 0.40,
	},
	"lfi": {
		"Cloudflare":          0.55,
		"ModSecurity":         0.55,
		"Imperva / Incapsula": 0.50,
	},
	"rfi": {
		"Cloudflare":  0.50,
		"ModSecurity": 0.50,
	},
	"xxe": {
		"Cloudflare": 0.45,
		"AWS WAF":    0.40,
	},
	"ssti": {
		"Cloudflare":  0.50,
		"ModSecurity": 0.50,
	},
	"jndi": {
		"Cloudflare": 0.60,
		"AWS WAF":    0.55,
	},
	"deserialization": {
		"Cloudflare":  0.35,
		"ModSecurity": 0.30,
	},
}

func scoreWAFPenalty(tmpl ProbeTemplate, ctx *core.TargetContext) float64 {
	if ctx.WAF == "" {
		return 0
	}

	maxPenalty := 0.0
	for _, tag := range tmpl.Info.Tags {
		tagLower := strings.ToLower(tag)
		if wafMap, ok := historicallyFiltered[tagLower]; ok {
			if penalty, ok2 := wafMap[ctx.WAF]; ok2 {
				if penalty > maxPenalty {
					maxPenalty = penalty
				}
			}
		}
	}

	return maxPenalty
}

// ── Display helpers ──────────────────────────────────────────

func fmtScore(label string, score float64, weight float64) string {
	return ""
}

func printPriorityBreakdown(scored []templatePriority, targetURL string) {
	fmtHead := "\n[*] ── Template Priority Queue ──\n"
	fmtHead += "[*] Templates ordered by relevance to target fingerprint.\n"
	fmtHead += "[*] Legend: critical=×1.0 high=×0.70 medium=×0.35 low=×0.10\n\n"
	fmtHead += "    %-4s %-8s %-25s %s\n"
	fmt.Printf(fmtHead, "Rank", "Score", "ID", "Signals")

	limit := len(scored)
	if limit > 20 {
		limit = 20
	}

	for i := 0; i < limit; i++ {
		sp := scored[i]
		tech := sp.tmpl.Info.Severity
		signals := collectPrioritySignals(sp.tmpl, scored[i].score)

		fmt.Printf("    %-4d %-8.0f %-25s %s\n",
			i+1, sp.score, sp.tmpl.ID,
			strings.Join(signals, " | "),
		)
		_ = tech
	}

	if len(scored) > limit {
		fmt.Printf("    ... +%d more (lower priority)\n", len(scored)-limit)
	}

	fmt.Printf("%s\n", strings.Repeat("-", 55))
}

func collectPrioritySignals(tmpl ProbeTemplate, score float64) []string {
	var signals []string

	sev := strings.ToUpper(strings.TrimSpace(tmpl.Info.Severity))
	signals = append(signals, sev)

	isCVE := false
	for _, tag := range tmpl.Info.Tags {
		tagLower := strings.ToLower(tag)
		if tagLower == "cve" {
			isCVE = true
			break
		}
	}
	if isCVE {
		signals = append(signals, "CVE")
	}

	_ = score
	return signals
}
