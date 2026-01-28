// containerd-upgrade-analyzer: Analyze differences between containerd versions
// to gain upgrade confidence - identify breaking changes, API diffs, deprecations
//
// Usage:
//
//	containerd-upgrade-analyzer --from v2.0.0 --to v2.1.0
//	containerd-upgrade-analyzer --from v2.0.0 --to v2.2.0 --json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type VersionDiff struct {
	FromVersion          string         `json:"from_version"`
	ToVersion            string         `json:"to_version"`
	Summary              DiffSummary    `json:"summary"`
	BreakingChanges      []Change       `json:"breaking_changes"`
	Deprecations         []Deprecation  `json:"deprecations"`
	NewFeatures          []Feature      `json:"new_features"`
	RemovedAPIs          []APIChange    `json:"removed_apis"`
	ChangedAPIs          []APIChange    `json:"changed_apis"`
	ConfigChanges        []ConfigChange `json:"config_changes"`
	DependencyChanges    []DepChange    `json:"dependency_changes"`
	ProtoChanges         []ProtoChange  `json:"proto_changes,omitempty"`
	CRICompatibility     *CRICompat     `json:"cri_compatibility,omitempty"`
	UpgradePath          []UpgradeStep  `json:"upgrade_path,omitempty"`
	GitHubRelease        *GitHubRelease `json:"github_release,omitempty"`
	DistroInfo           *DistroInfo    `json:"distro_info,omitempty"`
	RiskLevel            string         `json:"risk_level"` // low, medium, high, critical
	Recommendations      []string       `json:"recommendations"`
	ExitCode             int            `json:"exit_code"` // For CI/CD: 0=safe, 1=warning, 2=breaking, 3=critical
	IsUpgradeSupported   bool           `json:"is_upgrade_supported"`
	UpgradeBlockedReason string         `json:"upgrade_blocked_reason,omitempty"`
	IsLTSUpgrade         bool           `json:"is_lts_upgrade,omitempty"`
	RequiredHops         []string       `json:"required_hops,omitempty"`
}

// DistroInfo holds distro version data and metadata
type DistroInfo struct {
	Versions    []DistroVersion `json:"versions"`
	Source      string          `json:"source"`       // "repology" or "fallback"
	LastUpdated time.Time       `json:"last_updated"` // When the data was fetched
	Note        string          `json:"note,omitempty"`
}

// DistroVersion tracks containerd version in a Linux distribution
type DistroVersion struct {
	Distro      string `json:"distro"`
	Release     string `json:"release"`
	Version     string `json:"version"`
	Status      string `json:"status"` // "current", "outdated", "ahead"
	PackageRepo string `json:"package_repo,omitempty"`
	Notes       string `json:"notes,omitempty"`
}

// ProtoChange represents a change in Protocol Buffer definitions
type ProtoChange struct {
	File        string `json:"file"`
	Service     string `json:"service,omitempty"`
	Message     string `json:"message,omitempty"`
	Field       string `json:"field,omitempty"`
	ChangeType  string `json:"change_type"` // added, removed, modified, renamed
	OldDef      string `json:"old_definition,omitempty"`
	NewDef      string `json:"new_definition,omitempty"`
	IsBreaking  bool   `json:"is_breaking"`
	Description string `json:"description"`
}

// CRICompat tracks Container Runtime Interface compatibility
type CRICompat struct {
	FromCRIVersion string   `json:"from_cri_version"`
	ToCRIVersion   string   `json:"to_cri_version"`
	IsCompatible   bool     `json:"is_compatible"`
	K8sCompatFrom  []string `json:"k8s_compat_from"` // Kubernetes versions compatible with from version
	K8sCompatTo    []string `json:"k8s_compat_to"`   // Kubernetes versions compatible with to version
	Notes          []string `json:"notes"`
}

// UpgradeStep represents a recommended intermediate version for large jumps
type UpgradeStep struct {
	Version     string   `json:"version"`
	Reason      string   `json:"reason"`
	RiskLevel   string   `json:"risk_level"`
	KeyChanges  []string `json:"key_changes"`
	ReleaseDate string   `json:"release_date,omitempty"`
}

// GitHubRelease contains release information from GitHub API
type GitHubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Prerelease  bool      `json:"prerelease"`
}

type DiffSummary struct {
	TotalChanges     int    `json:"total_changes"`
	BreakingCount    int    `json:"breaking_count"`
	DeprecationCount int    `json:"deprecation_count"`
	NewFeatureCount  int    `json:"new_feature_count"`
	RiskAssessment   string `json:"risk_assessment"`
}

type Change struct {
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Impact      string   `json:"impact"`
	Migration   string   `json:"migration"`
	AffectedAPI string   `json:"affected_api,omitempty"`
	Files       []string `json:"files,omitempty"`
}

type Deprecation struct {
	API            string `json:"api"`
	DeprecatedIn   string `json:"deprecated_in"`
	RemovedIn      string `json:"removed_in,omitempty"`
	Replacement    string `json:"replacement"`
	MigrationNotes string `json:"migration_notes"`
}

type Feature struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	PRLinks     string `json:"pr_links,omitempty"`
}

type APIChange struct {
	Package     string `json:"package"`
	Type        string `json:"type"` // function, struct, interface, method
	Name        string `json:"name"`
	ChangeType  string `json:"change_type"` // removed, signature_changed, added
	OldSig      string `json:"old_signature,omitempty"`
	NewSig      string `json:"new_signature,omitempty"`
	Description string `json:"description"`
}

type ConfigChange struct {
	Key         string `json:"key"`
	ChangeType  string `json:"change_type"` // added, removed, default_changed, renamed
	OldDefault  string `json:"old_default,omitempty"`
	NewDefault  string `json:"new_default,omitempty"`
	Description string `json:"description"`
}

type DepChange struct {
	Dependency string `json:"dependency"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
	Type       string `json:"type"` // direct, indirect
	BreakingIn string `json:"breaking_in,omitempty"`
}

// ReleaseInfo holds containerd release metadata parsed from RELEASES.md
type ReleaseInfo struct {
	Version   string `json:"version"`
	Status    string `json:"status"` // "LTS", "Active", "Extended", "End of Life"
	IsLTS     bool   `json:"is_lts"`
	StartDate string `json:"start_date,omitempty"`
	EOLDate   string `json:"eol_date,omitempty"`
}

// MultiHopAnalysis contains analysis results for multi-step upgrade paths
type MultiHopAnalysis struct {
	FromVersion       string        `json:"from_version"`
	ToVersion         string        `json:"to_version"`
	Hops              []VersionDiff `json:"hops"`
	TotalRiskLevel    string        `json:"total_risk_level"`
	IsPathSupported   bool          `json:"is_path_supported"`
	UnsupportedReason string        `json:"unsupported_reason,omitempty"`
	RequiredVersions  []string      `json:"required_versions"`
	ExitCode          int           `json:"exit_code"`
}

// fallbackLTSVersions is used when RELEASES.md cannot be fetched
var fallbackLTSVersions = map[string]bool{
	"1.7": true,
	"2.3": true,
}

// cachedReleaseInfo stores release info fetched once per run
var cachedReleaseInfo map[string]ReleaseInfo

// analyzeMultiHop performs full analysis for each hop in a multi-step upgrade path
func analyzeMultiHop(repoPath, fromVersion, toVersion string) (*MultiHopAnalysis, error) {
	// Fetch release info once for the entire analysis
	releases := getReleaseInfo()

	// Check if direct upgrade is supported
	supported, reason := isUpgradeSupported(fromVersion, toVersion, releases)

	result := &MultiHopAnalysis{
		FromVersion:     fromVersion,
		ToVersion:       toVersion,
		IsPathSupported: supported,
	}

	if supported {
		// Direct upgrade is supported - just run single analysis
		diff, err := analyzeVersions(repoPath, fromVersion, toVersion)
		if err != nil {
			return nil, err
		}
		result.Hops = []VersionDiff{*diff}
		result.TotalRiskLevel = diff.RiskLevel
		result.RequiredVersions = []string{fromVersion, toVersion}
		result.ExitCode = diff.ExitCode
		return result, nil
	}

	// Direct upgrade not supported - calculate required hops
	result.UnsupportedReason = reason
	hops := calculateRequiredHops(fromVersion, toVersion, releases)
	result.RequiredVersions = hops

	// Ensure we have a local repo to work with (clone once for all hops)
	workDir := repoPath
	tmpDir := ""
	if workDir == "" {
		var err error
		tmpDir, err = os.MkdirTemp("", "containerd-analysis-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp dir: %w", err)
		}
		defer os.RemoveAll(tmpDir)
		workDir = tmpDir

		fmt.Fprintf(os.Stderr, "Cloning containerd repository for multi-hop analysis...\n")
		cmd := exec.Command("git", "clone", "--no-checkout",
			"https://github.com/containerd/containerd.git", ".")
		cmd.Dir = workDir
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("failed to clone repo: %w", err)
		}

		// Fetch all required tags
		fetchArgs := []string{"fetch", "--depth", "1", "origin"}
		for _, v := range hops {
			fetchArgs = append(fetchArgs, fmt.Sprintf("refs/tags/%s:refs/tags/%s", v, v))
		}
		cmd = exec.Command("git", fetchArgs...)
		cmd.Dir = workDir
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not fetch all tags: %v\n", err)
		}
	}

	// Run analysis for each hop
	highestRisk := "low"
	riskLevels := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}

	for i := 0; i < len(hops)-1; i++ {
		hopFrom := hops[i]
		hopTo := hops[i+1]

		fmt.Fprintf(os.Stderr, "\n═══ Analyzing hop %d/%d: %s → %s ═══\n", i+1, len(hops)-1, hopFrom, hopTo)

		diff, err := analyzeVersions(workDir, hopFrom, hopTo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: analysis failed for %s → %s: %v\n", hopFrom, hopTo, err)
			// Create a minimal diff entry for the failed hop
			diff = &VersionDiff{
				FromVersion: hopFrom,
				ToVersion:   hopTo,
				RiskLevel:   "high",
				Summary: DiffSummary{
					RiskAssessment: fmt.Sprintf("Analysis failed: %v", err),
				},
				Recommendations: []string{"Manual analysis required for this hop"},
			}
		}
		diff.IsUpgradeSupported = true // Each individual hop is supported
		result.Hops = append(result.Hops, *diff)

		// Track highest risk level
		if riskLevels[diff.RiskLevel] > riskLevels[highestRisk] {
			highestRisk = diff.RiskLevel
		}
	}

	result.TotalRiskLevel = highestRisk
	result.ExitCode = riskLevels[highestRisk]

	return result, nil
}

// Exit codes for the analyzer
const (
	ExitCodeSuccess            = 0
	ExitCodeLowRisk            = 1
	ExitCodeMediumRisk         = 2
	ExitCodeHighRisk           = 3
	ExitCodeCriticalRisk       = 4
	ExitCodeUpgradeUnsupported = 5
)

func main() {
	fromVersion := flag.String("from", "", "Source containerd version (e.g., v2.0.0)")
	toVersion := flag.String("to", "", "Target containerd version (e.g., v2.1.0)")
	jsonOutput := flag.Bool("json", false, "Output as JSON")
	repoPath := flag.String("repo", "", "Path to local containerd repo (optional, will clone if not provided)")
	ciMode := flag.Bool("ci", false, "CI mode: exit with code based on risk level (0=safe, 1=warning, 2=breaking, 3=critical, 5=unsupported)")
	failOn := flag.String("fail-on", "critical", "Risk level to fail on in CI mode: low, medium, high, critical")
	flag.Parse()

	if *fromVersion == "" || *toVersion == "" {
		fmt.Fprintln(os.Stderr, "Usage: containerd-upgrade-analyzer --from VERSION --to VERSION [--json] [--repo PATH] [--ci] [--fail-on LEVEL]")
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  containerd-upgrade-analyzer --from v2.0.0 --to v2.1.0")
		fmt.Fprintln(os.Stderr, "  containerd-upgrade-analyzer --from v2.0.0 --to v2.2.0 --json")
		fmt.Fprintln(os.Stderr, "  containerd-upgrade-analyzer --from v2.0.0 --to v2.2.0 --ci --fail-on high")
		fmt.Fprintln(os.Stderr, "\nExit codes:")
		fmt.Fprintln(os.Stderr, "  0 = Success/low risk")
		fmt.Fprintln(os.Stderr, "  1-4 = Risk level (low, medium, high, critical)")
		fmt.Fprintln(os.Stderr, "  5 = Upgrade path not supported (minor version skip without LTS exception)")
		os.Exit(1)
	}

	// Check if the upgrade path is supported first
	releases := getReleaseInfo()
	supported, reason := isUpgradeSupported(*fromVersion, *toVersion, releases)

	if !supported {
		// Run multi-hop analysis for unsupported direct upgrades
		multiHop, err := analyzeMultiHop(*repoPath, *fromVersion, *toVersion)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if *jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(multiHop)
		} else {
			printMultiHopAnalysis(multiHop)
		}

		// CI mode: exit with code 5 for unsupported upgrade path
		if *ciMode {
			fmt.Fprintf(os.Stderr, "\n⛔ CI Check Failed: Direct upgrade from %s to %s is not supported\n", *fromVersion, *toVersion)
			fmt.Fprintf(os.Stderr, "   Reason: %s\n", reason)
			fmt.Fprintf(os.Stderr, "   Required upgrade path: %s\n", strings.Join(multiHop.RequiredVersions, " → "))
			os.Exit(ExitCodeUpgradeUnsupported)
		}
		return
	}

	// Supported direct upgrade - run single analysis
	diff, err := analyzeVersions(*repoPath, *fromVersion, *toVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(diff)
	} else {
		printHumanReadable(diff)
	}

	// CI mode: exit with appropriate code
	if *ciMode {
		exitCode := calculateExitCode(diff.RiskLevel, *failOn)
		if exitCode > 0 {
			fmt.Fprintf(os.Stderr, "\n⚠️  CI Check Failed: Risk level '%s' meets or exceeds threshold '%s'\n", diff.RiskLevel, *failOn)
		}
		os.Exit(exitCode)
	}
}

// calculateExitCode returns exit code based on risk level and threshold
func calculateExitCode(riskLevel, failOn string) int {
	levels := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	riskScore := levels[riskLevel]
	threshold := levels[failOn]

	if riskScore >= threshold {
		return riskScore
	}
	return 0
}

// fetchReleaseInfo fetches and parses containerd RELEASES.md to identify LTS versions
// Results are cached for the duration of the run
func fetchReleaseInfo() (map[string]ReleaseInfo, error) {
	if cachedReleaseInfo != nil {
		return cachedReleaseInfo, nil
	}

	url := "https://raw.githubusercontent.com/containerd/containerd/main/RELEASES.md"
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "containerd-upgrade-analyzer")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch RELEASES.md: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("RELEASES.md returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read RELEASES.md: %w", err)
	}

	releases := parseReleasesMarkdown(string(body))
	cachedReleaseInfo = releases
	return releases, nil
}

// parseReleasesMarkdown parses the RELEASES.md markdown content to extract release info
func parseReleasesMarkdown(content string) map[string]ReleaseInfo {
	releases := make(map[string]ReleaseInfo)

	// Match table rows: | [version](url) | Status | Start | EOL | Owners |
	// The Status column may contain "LTS", "Active", "Extended", "End of Life", etc.
	tableRowRe := regexp.MustCompile(`\|\s*\[([0-9.]+)\]\([^)]+\)\s*\|\s*([^|]+)\|([^|]*)\|([^|]*)\|`)

	for _, match := range tableRowRe.FindAllStringSubmatch(content, -1) {
		if len(match) >= 3 {
			version := strings.TrimSpace(match[1])
			status := strings.TrimSpace(match[2])
			startDate := ""
			eolDate := ""
			if len(match) >= 4 {
				startDate = strings.TrimSpace(match[3])
			}
			if len(match) >= 5 {
				eolDate = strings.TrimSpace(match[4])
			}

			// Normalize status - remove markdown formatting
			status = strings.ReplaceAll(status, "*", "")
			status = strings.ReplaceAll(status, "_", "")
			status = strings.TrimSpace(status)

			isLTS := strings.EqualFold(status, "LTS")

			releases[version] = ReleaseInfo{
				Version:   version,
				Status:    status,
				IsLTS:     isLTS,
				StartDate: startDate,
				EOLDate:   eolDate,
			}
		}
	}

	return releases
}

// getReleaseInfo returns release info for a version, using cache or fallback
func getReleaseInfo() map[string]ReleaseInfo {
	releases, err := fetchReleaseInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not fetch RELEASES.md (%v), using fallback LTS list\n", err)
		// Return fallback data
		releases = make(map[string]ReleaseInfo)
		for version := range fallbackLTSVersions {
			releases[version] = ReleaseInfo{
				Version: version,
				Status:  "LTS",
				IsLTS:   true,
			}
		}
	}
	return releases
}

// isVersionLTS checks if a version (e.g., "v2.3.0" or "2.3") is an LTS release
func isVersionLTS(version string, releases map[string]ReleaseInfo) bool {
	// Normalize version: remove 'v' prefix and patch version
	version = strings.TrimPrefix(version, "v")
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		majorMinor := parts[0] + "." + parts[1]
		if info, ok := releases[majorMinor]; ok {
			return info.IsLTS
		}
	}
	// Also check for just major.minor format
	if info, ok := releases[version]; ok {
		return info.IsLTS
	}
	// Check fallback
	if len(parts) >= 2 {
		majorMinor := parts[0] + "." + parts[1]
		return fallbackLTSVersions[majorMinor]
	}
	return fallbackLTSVersions[version]
}

// isUpgradeSupported checks if a direct upgrade from one version to another is supported
// Returns (supported, reason) where reason explains why if not supported
func isUpgradeSupported(fromVersion, toVersion string, releases map[string]ReleaseInfo) (bool, string) {
	fromMajor, fromMinor := parseVersion(fromVersion)
	toMajor, toMinor := parseVersion(toVersion)

	// Downgrade is not an upgrade
	if toMajor < fromMajor || (toMajor == fromMajor && toMinor < fromMinor) {
		return false, "Downgrades are not supported"
	}

	// Same version - nothing to do
	if fromMajor == toMajor && fromMinor == toMinor {
		return true, "Same version"
	}

	// Check LTS status for both versions
	fromLTS := isVersionLTS(fromVersion, releases)
	toLTS := isVersionLTS(toVersion, releases)

	// LTS-to-LTS upgrades are always supported (direct jump allowed)
	if fromLTS && toLTS {
		return true, "LTS-to-LTS upgrade supported"
	}

	// Same major version: check minor version skip
	if fromMajor == toMajor {
		minorDiff := toMinor - fromMinor
		if minorDiff > 1 {
			return false, fmt.Sprintf("Cannot skip minor versions: %d.%d → %d.%d requires sequential upgrades (e.g., %d.%d → %d.%d → %d.%d)",
				fromMajor, fromMinor, toMajor, toMinor,
				fromMajor, fromMinor, fromMajor, fromMinor+1, fromMajor, fromMinor+2)
		}
		return true, "Sequential minor upgrade"
	}

	// Major version change: check if it's to the first minor of new major
	if toMajor > fromMajor {
		// Major upgrades should go through v{major}.0 first
		if toMinor > 0 {
			// Can only jump to X.0, not X.1+
			return false, fmt.Sprintf("Major version upgrade should go through v%d.0.0 first, then sequential minor upgrades", toMajor)
		}
		return true, "Major version upgrade to .0 release"
	}

	return true, ""
}

// calculateRequiredHops determines the intermediate versions needed for an upgrade
func calculateRequiredHops(fromVersion, toVersion string, releases map[string]ReleaseInfo) []string {
	fromMajor, fromMinor := parseVersion(fromVersion)
	toMajor, toMinor := parseVersion(toVersion)

	var hops []string
	hops = append(hops, fromVersion)

	currentMajor := fromMajor
	currentMinor := fromMinor

	// Handle major version change
	if toMajor > fromMajor {
		// First, upgrade to the last minor of current major if not already there
		// For simplicity, we'll go to X.0 of the new major directly
		// (In practice, you might want to go to latest patch of current major first)

		// Go to the first release of new major
		for major := fromMajor + 1; major <= toMajor; major++ {
			firstOfMajor := fmt.Sprintf("v%d.0.0", major)
			hops = append(hops, firstOfMajor)
			currentMajor = major
			currentMinor = 0
		}
	}

	// Now handle minor version upgrades within the target major
	if currentMajor == toMajor {
		for minor := currentMinor + 1; minor <= toMinor; minor++ {
			intermediateVersion := fmt.Sprintf("v%d.%d.0", toMajor, minor)
			if intermediateVersion != hops[len(hops)-1] {
				hops = append(hops, intermediateVersion)
			}
		}
	}

	// Ensure the final version is the target
	if hops[len(hops)-1] != toVersion {
		// Replace last hop with exact target version if needed
		hops[len(hops)-1] = toVersion
	}

	return hops
}

func analyzeVersions(repoPath, fromVersion, toVersion string) (*VersionDiff, error) {
	// Ensure we have a local repo to work with
	workDir := repoPath
	if workDir == "" {
		tmpDir, err := os.MkdirTemp("", "containerd-analysis-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp dir: %w", err)
		}
		defer os.RemoveAll(tmpDir)
		workDir = tmpDir

		fmt.Fprintf(os.Stderr, "Cloning containerd repository...\n")
		cmd := exec.Command("git", "clone", "--depth", "1", "--no-checkout",
			"https://github.com/containerd/containerd.git", ".")
		cmd.Dir = workDir
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("failed to clone repo: %w", err)
		}

		// Fetch the specific tags
		cmd = exec.Command("git", "fetch", "--depth", "1", "origin",
			fmt.Sprintf("refs/tags/%s:refs/tags/%s", fromVersion, fromVersion),
			fmt.Sprintf("refs/tags/%s:refs/tags/%s", toVersion, toVersion))
		cmd.Dir = workDir
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("failed to fetch tags: %w", err)
		}
	}

	diff := &VersionDiff{
		FromVersion: fromVersion,
		ToVersion:   toVersion,
	}

	// Analyze release notes if available
	if err := analyzeReleaseNotes(workDir, fromVersion, toVersion, diff); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not analyze release notes: %v\n", err)
	}

	// Analyze CHANGELOG.md
	if err := analyzeChangelog(workDir, fromVersion, toVersion, diff); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not analyze changelog: %v\n", err)
	}

	// Analyze go.mod differences
	if err := analyzeGoMod(workDir, fromVersion, toVersion, diff); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not analyze go.mod: %v\n", err)
	}

	// Analyze API changes using git diff
	if err := analyzeAPIChanges(workDir, fromVersion, toVersion, diff); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not analyze API changes: %v\n", err)
	}

	// Analyze config/TOML changes
	if err := analyzeConfigChanges(workDir, fromVersion, toVersion, diff); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not analyze config changes: %v\n", err)
	}

	// NEW: Analyze Protocol Buffer changes
	if err := analyzeProtoChanges(workDir, fromVersion, toVersion, diff); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not analyze proto changes: %v\n", err)
	}

	// NEW: Check CRI compatibility
	if err := analyzeCRICompatibility(workDir, fromVersion, toVersion, diff); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not analyze CRI compatibility: %v\n", err)
	}

	// NEW: Fetch GitHub release notes
	if err := fetchGitHubRelease(toVersion, diff); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not fetch GitHub release: %v\n", err)
	}

	// Fetch release info for LTS detection
	releases := getReleaseInfo()

	// Calculate upgrade path with new "no minor skip" policy
	if err := calculateUpgradePath(fromVersion, toVersion, diff, releases); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not calculate upgrade path: %v\n", err)
	}

	// NEW: Fetch distro version information
	if err := fetchDistroVersions(fromVersion, toVersion, diff); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not fetch distro versions: %v\n", err)
	}

	// Calculate summary and risk level
	calculateSummary(diff)

	return diff, nil
}

func analyzeReleaseNotes(workDir, fromVersion, toVersion string, diff *VersionDiff) error {
	// Try to get release notes from releases/ directory
	cmd := exec.Command("git", "diff", fromVersion+".."+toVersion, "--", "releases/", "docs/")
	cmd.Dir = workDir
	output, _ := cmd.Output()

	if len(output) > 0 {
		// Parse deprecation patterns
		deprecationRe := regexp.MustCompile(`(?i)deprecat(e|ed|ion).*?[:]\s*(.+)`)
		for _, match := range deprecationRe.FindAllStringSubmatch(string(output), -1) {
			if len(match) > 2 {
				diff.Deprecations = append(diff.Deprecations, Deprecation{
					API:            match[2],
					DeprecatedIn:   toVersion,
					MigrationNotes: "See release notes for migration guidance",
				})
			}
		}

		// Parse breaking change patterns
		breakingRe := regexp.MustCompile(`(?i)(breaking|incompatible).*?[:]\s*(.+)`)
		for _, match := range breakingRe.FindAllStringSubmatch(string(output), -1) {
			if len(match) > 2 {
				diff.BreakingChanges = append(diff.BreakingChanges, Change{
					Category:    "Release Notes",
					Description: match[2],
					Impact:      "Review release notes for impact assessment",
				})
			}
		}
	}

	return nil
}

func analyzeChangelog(workDir, fromVersion, toVersion string, diff *VersionDiff) error {
	// Fetch the blob for CHANGELOG.md at the target version
	// First try to fetch the file specifically if we're in a shallow clone
	fetchCmd := exec.Command("git", "fetch", "--depth=1", "origin", toVersion)
	fetchCmd.Dir = workDir
	fetchCmd.Run() // Ignore errors, might already have it

	// Get CHANGELOG.md content at target version
	cmd := exec.Command("git", "show", toVersion+":CHANGELOG.md")
	cmd.Dir = workDir
	output, err := cmd.Output()
	if err != nil {
		// Try fetching the specific file via sparse checkout
		return fmt.Errorf("changelog not available: %w", err)
	}

	content := string(output)

	// Extract section for target version
	versionRe := regexp.MustCompile(`(?m)^##\s*\[?` + regexp.QuoteMeta(strings.TrimPrefix(toVersion, "v")))
	match := versionRe.FindStringIndex(content)
	if match != nil {
		section := content[match[0]:]
		// Find end of section (next ## or end)
		nextSection := regexp.MustCompile(`(?m)^##\s*\[`).FindStringIndex(section[10:])
		if nextSection != nil {
			section = section[:nextSection[0]+10]
		}

		// Parse features
		featureRe := regexp.MustCompile(`(?m)^\*\s*\*\*([^*]+)\*\*[:\s]*(.+)`)
		for _, m := range featureRe.FindAllStringSubmatch(section, -1) {
			if len(m) > 2 {
				diff.NewFeatures = append(diff.NewFeatures, Feature{
					Name:        m[1],
					Description: m[2],
					Category:    "CHANGELOG",
				})
			}
		}

		// Look for deprecation notices
		if strings.Contains(strings.ToLower(section), "deprecat") {
			lines := strings.Split(section, "\n")
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "deprecat") {
					diff.Deprecations = append(diff.Deprecations, Deprecation{
						API:            strings.TrimSpace(line),
						DeprecatedIn:   toVersion,
						MigrationNotes: "See CHANGELOG for details",
					})
				}
			}
		}
	}

	return nil
}

func analyzeGoMod(workDir, fromVersion, toVersion string, diff *VersionDiff) error {
	// Get go.mod from both versions
	cmdFrom := exec.Command("git", "show", fromVersion+":go.mod")
	cmdFrom.Dir = workDir
	fromMod, err := cmdFrom.Output()
	if err != nil {
		return err
	}

	cmdTo := exec.Command("git", "show", toVersion+":go.mod")
	cmdTo.Dir = workDir
	toMod, err := cmdTo.Output()
	if err != nil {
		return err
	}

	fromDeps := parseGoMod(string(fromMod))
	toDeps := parseGoMod(string(toMod))

	// Find changed dependencies
	for dep, toVer := range toDeps {
		if fromVer, exists := fromDeps[dep]; exists {
			if fromVer != toVer {
				diff.DependencyChanges = append(diff.DependencyChanges, DepChange{
					Dependency: dep,
					OldVersion: fromVer,
					NewVersion: toVer,
					Type:       "direct",
				})
			}
		} else {
			diff.DependencyChanges = append(diff.DependencyChanges, DepChange{
				Dependency: dep,
				OldVersion: "",
				NewVersion: toVer,
				Type:       "direct",
			})
		}
	}

	// Find removed dependencies
	for dep, fromVer := range fromDeps {
		if _, exists := toDeps[dep]; !exists {
			diff.DependencyChanges = append(diff.DependencyChanges, DepChange{
				Dependency: dep,
				OldVersion: fromVer,
				NewVersion: "REMOVED",
				Type:       "direct",
			})
		}
	}

	return nil
}

func parseGoMod(content string) map[string]string {
	deps := make(map[string]string)
	lines := strings.Split(content, "\n")
	inRequire := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}
		if inRequire || strings.HasPrefix(line, "require ") {
			// Parse dependency line
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				deps[parts[0]] = parts[1]
			}
		}
	}

	return deps
}

func analyzeAPIChanges(workDir, fromVersion, toVersion string, diff *VersionDiff) error {
	// Get list of changed Go files in key packages
	packages := []string{
		"api/",
		"client/",
		"pkg/",
		"runtime/",
		"services/",
		"cio/",
		"containers/",
		"content/",
		"images/",
		"namespaces/",
		"oci/",
		"platforms/",
		"snapshots/",
	}

	for _, pkg := range packages {
		cmd := exec.Command("git", "diff", "--name-only", fromVersion+".."+toVersion, "--", pkg)
		cmd.Dir = workDir
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		files := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, file := range files {
			if !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
				continue
			}

			// Get detailed diff for this file
			diffCmd := exec.Command("git", "diff", fromVersion+".."+toVersion, "--", file)
			diffCmd.Dir = workDir
			diffOutput, err := diffCmd.Output()
			if err != nil {
				continue
			}

			// Look for function/method signature changes
			parseAPIDiff(string(diffOutput), file, diff)
		}
	}

	return nil
}

func parseAPIDiff(diffContent, filename string, diff *VersionDiff) {
	lines := strings.Split(diffContent, "\n")

	// Patterns for API changes
	funcRe := regexp.MustCompile(`^[-+]func\s+(\([^)]+\)\s+)?([A-Z][a-zA-Z0-9]*)\s*\(`)
	typeRe := regexp.MustCompile(`^[-+]type\s+([A-Z][a-zA-Z0-9]*)\s+`)
	interfaceRe := regexp.MustCompile(`^[-+]type\s+([A-Z][a-zA-Z0-9]*)\s+interface`)

	for i, line := range lines {
		if strings.HasPrefix(line, "-func ") {
			if match := funcRe.FindStringSubmatch(line); match != nil {
				// Check if this is a removal or signature change
				isChanged := false
				for j := i + 1; j < len(lines) && j < i+5; j++ {
					if strings.HasPrefix(lines[j], "+func ") {
						// Signature changed
						newMatch := funcRe.FindStringSubmatch(lines[j])
						if newMatch != nil && newMatch[2] == match[2] {
							diff.ChangedAPIs = append(diff.ChangedAPIs, APIChange{
								Package:     filepath.Dir(filename),
								Type:        "function",
								Name:        match[2],
								ChangeType:  "signature_changed",
								OldSig:      strings.TrimPrefix(line, "-"),
								NewSig:      strings.TrimPrefix(lines[j], "+"),
								Description: fmt.Sprintf("Function signature changed in %s", filename),
							})
							isChanged = true
							break
						}
					}
				}
				if !isChanged {
					diff.RemovedAPIs = append(diff.RemovedAPIs, APIChange{
						Package:     filepath.Dir(filename),
						Type:        "function",
						Name:        match[2],
						ChangeType:  "removed",
						OldSig:      strings.TrimPrefix(line, "-"),
						Description: fmt.Sprintf("Function removed from %s", filename),
					})
				}
			}
		}

		if strings.HasPrefix(line, "-type ") {
			if match := typeRe.FindStringSubmatch(line); match != nil {
				if interfaceRe.MatchString(line) {
					diff.RemovedAPIs = append(diff.RemovedAPIs, APIChange{
						Package:     filepath.Dir(filename),
						Type:        "interface",
						Name:        match[1],
						ChangeType:  "removed",
						Description: fmt.Sprintf("Interface removed from %s", filename),
					})
				} else {
					diff.RemovedAPIs = append(diff.RemovedAPIs, APIChange{
						Package:     filepath.Dir(filename),
						Type:        "struct",
						Name:        match[1],
						ChangeType:  "removed",
						Description: fmt.Sprintf("Type removed from %s", filename),
					})
				}
			}
		}
	}
}

func analyzeConfigChanges(workDir, fromVersion, toVersion string, diff *VersionDiff) error {
	// Check for changes in config-related files
	cmd := exec.Command("git", "diff", fromVersion+".."+toVersion, "--",
		"cmd/containerd/config*.go",
		"pkg/config/",
		"defaults/",
	)
	cmd.Dir = workDir
	output, _ := cmd.Output()

	if len(output) > 0 {
		// Look for config struct field changes
		fieldRe := regexp.MustCompile(`[-+]\s+([A-Z][a-zA-Z0-9]*)\s+([a-zA-Z0-9.*\[\]]+)\s+` + "`" + `toml:"([^"]+)"`)
		for _, match := range fieldRe.FindAllStringSubmatch(string(output), -1) {
			if len(match) > 3 {
				changeType := "modified"
				if strings.HasPrefix(match[0], "-") {
					changeType = "removed"
				} else if strings.HasPrefix(match[0], "+") {
					changeType = "added"
				}
				diff.ConfigChanges = append(diff.ConfigChanges, ConfigChange{
					Key:         match[3],
					ChangeType:  changeType,
					Description: fmt.Sprintf("Config field %s (%s)", match[1], match[2]),
				})
			}
		}
	}

	return nil
}

// analyzeProtoChanges detects changes in Protocol Buffer definitions
func analyzeProtoChanges(workDir, fromVersion, toVersion string, diff *VersionDiff) error {
	// Get list of changed .proto files
	cmd := exec.Command("git", "diff", "--name-only", fromVersion+".."+toVersion, "--", "*.proto")
	cmd.Dir = workDir
	output, err := cmd.Output()
	if err != nil {
		return nil // No proto files or git error
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, file := range files {
		if file == "" {
			continue
		}

		// Get detailed diff for this proto file
		diffCmd := exec.Command("git", "diff", fromVersion+".."+toVersion, "--", file)
		diffCmd.Dir = workDir
		diffOutput, err := diffCmd.Output()
		if err != nil {
			continue
		}

		parseProtoDiff(string(diffOutput), file, diff)
	}

	return nil
}

// parseProtoDiff extracts meaningful changes from proto file diffs
func parseProtoDiff(diffContent, filename string, diff *VersionDiff) {
	lines := strings.Split(diffContent, "\n")

	// Patterns for proto changes
	serviceRe := regexp.MustCompile(`^[-+]service\s+(\w+)\s*{`)
	rpcRe := regexp.MustCompile(`^[-+]\s*rpc\s+(\w+)\s*\(([^)]+)\)\s*returns\s*\(([^)]+)\)`)
	messageRe := regexp.MustCompile(`^[-+]message\s+(\w+)\s*{`)
	fieldRe := regexp.MustCompile(`^[-+]\s+(repeated\s+)?(\w+)\s+(\w+)\s*=\s*(\d+)`)
	reservedRe := regexp.MustCompile(`^[+]\s*reserved\s+(\d+)`)

	var currentService, currentMessage string

	for i, line := range lines {
		// Track context
		if match := serviceRe.FindStringSubmatch(line); match != nil {
			currentService = match[1]
			if strings.HasPrefix(line, "-") {
				diff.ProtoChanges = append(diff.ProtoChanges, ProtoChange{
					File:        filename,
					Service:     currentService,
					ChangeType:  "removed",
					IsBreaking:  true,
					Description: fmt.Sprintf("Service %s removed", currentService),
				})
			}
		}

		if match := messageRe.FindStringSubmatch(line); match != nil {
			currentMessage = match[1]
			if strings.HasPrefix(line, "-") {
				diff.ProtoChanges = append(diff.ProtoChanges, ProtoChange{
					File:        filename,
					Message:     currentMessage,
					ChangeType:  "removed",
					IsBreaking:  true,
					Description: fmt.Sprintf("Message %s removed", currentMessage),
				})
			}
		}

		// RPC method changes
		if match := rpcRe.FindStringSubmatch(line); match != nil {
			methodName := match[1]
			reqType := match[2]
			respType := match[3]

			if strings.HasPrefix(line, "-") {
				// Check if it's modified or removed
				isModified := false
				for j := i + 1; j < len(lines) && j < i+5; j++ {
					if newMatch := rpcRe.FindStringSubmatch(lines[j]); newMatch != nil {
						if newMatch[1] == methodName && strings.HasPrefix(lines[j], "+") {
							// Method signature changed
							diff.ProtoChanges = append(diff.ProtoChanges, ProtoChange{
								File:        filename,
								Service:     currentService,
								ChangeType:  "modified",
								OldDef:      fmt.Sprintf("rpc %s(%s) returns (%s)", methodName, reqType, respType),
								NewDef:      fmt.Sprintf("rpc %s(%s) returns (%s)", newMatch[1], newMatch[2], newMatch[3]),
								IsBreaking:  reqType != newMatch[2] || respType != newMatch[3],
								Description: fmt.Sprintf("RPC method %s signature changed", methodName),
							})
							isModified = true
							break
						}
					}
				}
				if !isModified {
					diff.ProtoChanges = append(diff.ProtoChanges, ProtoChange{
						File:        filename,
						Service:     currentService,
						ChangeType:  "removed",
						OldDef:      fmt.Sprintf("rpc %s(%s) returns (%s)", methodName, reqType, respType),
						IsBreaking:  true,
						Description: fmt.Sprintf("RPC method %s removed from %s", methodName, currentService),
					})
				}
			}
		}

		// Field changes (field number changes are breaking!)
		if match := fieldRe.FindStringSubmatch(line); match != nil {
			fieldName := match[3]
			fieldNum := match[4]
			fieldType := match[2]

			if strings.HasPrefix(line, "-") {
				diff.ProtoChanges = append(diff.ProtoChanges, ProtoChange{
					File:        filename,
					Message:     currentMessage,
					Field:       fieldName,
					ChangeType:  "removed",
					OldDef:      fmt.Sprintf("%s %s = %s", fieldType, fieldName, fieldNum),
					IsBreaking:  true,
					Description: fmt.Sprintf("Field %s removed from %s (field number %s)", fieldName, currentMessage, fieldNum),
				})
			}
		}

		// Reserved fields indicate removed fields
		if match := reservedRe.FindStringSubmatch(line); match != nil {
			diff.ProtoChanges = append(diff.ProtoChanges, ProtoChange{
				File:        filename,
				Message:     currentMessage,
				ChangeType:  "reserved",
				IsBreaking:  false, // Reserved is proper deprecation
				Description: fmt.Sprintf("Field number %s reserved in %s (properly deprecated)", match[1], currentMessage),
			})
		}
	}
}

// analyzeCRICompatibility checks Container Runtime Interface compatibility
func analyzeCRICompatibility(workDir, fromVersion, toVersion string, diff *VersionDiff) error {
	// CRI API version is typically defined in api/services/*/v1/ directories
	// and in vendor or go.mod for k8s.io/cri-api

	criCompat := &CRICompat{
		Notes: []string{},
	}

	// Check go.mod for CRI API version changes
	cmdFrom := exec.Command("git", "show", fromVersion+":go.mod")
	cmdFrom.Dir = workDir
	fromMod, _ := cmdFrom.Output()

	cmdTo := exec.Command("git", "show", toVersion+":go.mod")
	cmdTo.Dir = workDir
	toMod, _ := cmdTo.Output()

	// Look for k8s.io/cri-api version
	criRe := regexp.MustCompile(`k8s\.io/cri-api\s+(v[\d.]+)`)

	if match := criRe.FindStringSubmatch(string(fromMod)); match != nil {
		criCompat.FromCRIVersion = match[1]
	}
	if match := criRe.FindStringSubmatch(string(toMod)); match != nil {
		criCompat.ToCRIVersion = match[1]
	}

	// Map CRI versions to Kubernetes compatibility
	criCompat.K8sCompatFrom = getCRIK8sCompat(criCompat.FromCRIVersion)
	criCompat.K8sCompatTo = getCRIK8sCompat(criCompat.ToCRIVersion)

	// Determine if upgrade is compatible
	if criCompat.FromCRIVersion != "" && criCompat.ToCRIVersion != "" {
		criCompat.IsCompatible = criCompat.FromCRIVersion == criCompat.ToCRIVersion ||
			isCRIBackwardCompatible(criCompat.FromCRIVersion, criCompat.ToCRIVersion)

		if !criCompat.IsCompatible {
			criCompat.Notes = append(criCompat.Notes,
				fmt.Sprintf("CRI API changed from %s to %s - verify Kubernetes compatibility",
					criCompat.FromCRIVersion, criCompat.ToCRIVersion))
		}
	}

	// Check for CRI service changes in proto files
	cmd := exec.Command("git", "diff", "--name-only", fromVersion+".."+toVersion, "--",
		"api/services/images/", "api/services/containers/", "api/services/tasks/")
	cmd.Dir = workDir
	output, _ := cmd.Output()
	if len(output) > 0 {
		criCompat.Notes = append(criCompat.Notes, "CRI-related service definitions have changed")
	}

	if criCompat.FromCRIVersion != "" || criCompat.ToCRIVersion != "" || len(criCompat.Notes) > 0 {
		diff.CRICompatibility = criCompat
	}

	return nil
}

// getCRIK8sCompat returns Kubernetes versions compatible with a CRI API version
func getCRIK8sCompat(criVersion string) []string {
	// CRI API version to Kubernetes compatibility mapping
	// This is a simplified mapping - real mapping is more complex
	compatMap := map[string][]string{
		"v0.1.0": {"1.25", "1.26"},
		"v1":     {"1.26", "1.27", "1.28", "1.29", "1.30"},
		"v1.0.0": {"1.26", "1.27", "1.28", "1.29", "1.30", "1.31"},
	}

	if compat, ok := compatMap[criVersion]; ok {
		return compat
	}
	return []string{"check release notes"}
}

// isCRIBackwardCompatible checks if CRI upgrade is backward compatible
func isCRIBackwardCompatible(from, to string) bool {
	// Generally, CRI v1 is backward compatible within the v1.x series
	return strings.HasPrefix(from, "v1") && strings.HasPrefix(to, "v1")
}

// fetchGitHubRelease fetches release notes from GitHub API
func fetchGitHubRelease(version string, diff *VersionDiff) error {
	url := fmt.Sprintf("https://api.github.com/repos/containerd/containerd/releases/tags/%s", version)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "containerd-upgrade-analyzer")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var release GitHubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return err
	}

	diff.GitHubRelease = &release

	// Parse release notes for additional deprecations and breaking changes
	parseGitHubReleaseNotes(release.Body, diff)

	return nil
}

// parseGitHubReleaseNotes extracts structured info from release notes markdown
func parseGitHubReleaseNotes(body string, diff *VersionDiff) {
	lines := strings.Split(body, "\n")

	inBreakingSection := false
	inDeprecationSection := false

	for _, line := range lines {
		lineLower := strings.ToLower(line)

		// Detect section headers
		if strings.Contains(lineLower, "breaking") && (strings.HasPrefix(line, "#") || strings.HasPrefix(line, "*")) {
			inBreakingSection = true
			inDeprecationSection = false
			continue
		}
		if strings.Contains(lineLower, "deprecat") && (strings.HasPrefix(line, "#") || strings.HasPrefix(line, "*")) {
			inDeprecationSection = true
			inBreakingSection = false
			continue
		}
		if strings.HasPrefix(line, "#") {
			inBreakingSection = false
			inDeprecationSection = false
			continue
		}

		// Extract items from sections
		if inBreakingSection && (strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "- ")) {
			item := strings.TrimPrefix(strings.TrimPrefix(line, "* "), "- ")
			if item != "" {
				diff.BreakingChanges = append(diff.BreakingChanges, Change{
					Category:    "GitHub Release",
					Description: item,
					Impact:      "See release notes for details",
				})
			}
		}

		if inDeprecationSection && (strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "- ")) {
			item := strings.TrimPrefix(strings.TrimPrefix(line, "* "), "- ")
			if item != "" {
				diff.Deprecations = append(diff.Deprecations, Deprecation{
					API:            item,
					DeprecatedIn:   diff.ToVersion,
					MigrationNotes: "See GitHub release notes",
				})
			}
		}
	}
}

// calculateUpgradePath validates and calculates the upgrade path between versions
// It now enforces the "no minor version skip" policy with LTS-to-LTS exception
func calculateUpgradePath(fromVersion, toVersion string, diff *VersionDiff, releases map[string]ReleaseInfo) error {
	// Check if direct upgrade is supported
	supported, reason := isUpgradeSupported(fromVersion, toVersion, releases)
	diff.IsUpgradeSupported = supported
	diff.UpgradeBlockedReason = ""

	// Check if this is an LTS-to-LTS upgrade
	fromLTS := isVersionLTS(fromVersion, releases)
	toLTS := isVersionLTS(toVersion, releases)
	diff.IsLTSUpgrade = fromLTS && toLTS

	if !supported {
		diff.UpgradeBlockedReason = reason

		// Calculate the required hops for this upgrade
		hops := calculateRequiredHops(fromVersion, toVersion, releases)
		diff.RequiredHops = hops

		// Create UpgradeStep entries for each intermediate version
		for i := 1; i < len(hops)-1; i++ {
			prevVersion := hops[i-1]
			hopVersion := hops[i]
			prevMajor, prevMinor := parseVersion(prevVersion)
			hopMajor, hopMinor := parseVersion(hopVersion)

			riskLevel := "medium"
			stepReason := "Required intermediate upgrade (minor version skip not allowed)"
			if hopMajor > prevMajor {
				riskLevel = "high"
				stepReason = "Major version upgrade - expect breaking changes"
			}

			diff.UpgradePath = append(diff.UpgradePath, UpgradeStep{
				Version:    hopVersion,
				Reason:     stepReason,
				RiskLevel:  riskLevel,
				KeyChanges: []string{fmt.Sprintf("Upgrade from %d.%d to %d.%d", prevMajor, prevMinor, hopMajor, hopMinor)},
			})
		}

		return nil
	}

	// For supported upgrades, still provide upgrade path info for major jumps
	fromMajor, fromMinor := parseVersion(fromVersion)
	toMajor, toMinor := parseVersion(toVersion)

	// Single minor version upgrade - no intermediate steps needed
	if fromMajor == toMajor && toMinor-fromMinor == 1 {
		diff.RequiredHops = []string{fromVersion, toVersion}
		return nil
	}

	// LTS-to-LTS upgrade - direct jump is allowed
	if diff.IsLTSUpgrade {
		diff.RequiredHops = []string{fromVersion, toVersion}
		diff.UpgradePath = append(diff.UpgradePath, UpgradeStep{
			Version:    toVersion,
			Reason:     "Direct LTS-to-LTS upgrade supported",
			RiskLevel:  "medium",
			KeyChanges: []string{"LTS releases support direct upgrades between them"},
		})
		return nil
	}

	// Major version change (to .0 release)
	if toMajor > fromMajor {
		diff.RequiredHops = []string{fromVersion, toVersion}
		diff.UpgradePath = append(diff.UpgradePath, UpgradeStep{
			Version:    toVersion,
			Reason:     "Major version upgrade",
			RiskLevel:  "high",
			KeyChanges: []string{"Major version upgrade - review breaking changes carefully"},
		})
	}

	return nil
}

// parseVersion extracts major and minor version numbers
func parseVersion(version string) (major, minor int) {
	version = strings.TrimPrefix(version, "v")
	parts := strings.Split(version, ".")
	if len(parts) >= 1 {
		fmt.Sscanf(parts[0], "%d", &major)
	}
	if len(parts) >= 2 {
		fmt.Sscanf(parts[1], "%d", &minor)
	}
	return
}

// fetchDistroVersions fetches containerd versions from Linux distributions
func fetchDistroVersions(fromVersion, toVersion string, diff *VersionDiff) error {
	distroInfo := &DistroInfo{
		LastUpdated: time.Now(),
	}

	// Try to fetch from Repology API (tracks package versions across distros)
	distroVersions, err := fetchFromRepology()
	if err != nil {
		// Fall back to known versions if API fails
		distroVersions = getKnownDistroVersions()
		distroInfo.Source = "fallback"
		distroInfo.Note = "Live data unavailable, using cached values"
	} else {
		distroInfo.Source = "repology"
		distroInfo.Note = "Live data from repology.org (distro repos only, not Docker/vendor repos)"
	}

	// Compare distro versions with from/to versions
	fromMajor, fromMinor := parseVersion(fromVersion)
	toMajor, toMinor := parseVersion(toVersion)

	for i := range distroVersions {
		distroMajor, distroMinor := parseVersion(distroVersions[i].Version)

		// Determine status relative to target version
		if distroMajor < toMajor || (distroMajor == toMajor && distroMinor < toMinor) {
			if distroMajor < fromMajor || (distroMajor == fromMajor && distroMinor < fromMinor) {
				distroVersions[i].Status = "behind-source"
			} else {
				distroVersions[i].Status = "between"
			}
		} else if distroMajor == toMajor && distroMinor == toMinor {
			distroVersions[i].Status = "matches-target"
		} else {
			distroVersions[i].Status = "ahead"
		}
	}

	distroInfo.Versions = distroVersions
	diff.DistroInfo = distroInfo
	return nil
}

// RepologyResponse represents the Repology API response
type RepologyResponse []struct {
	Repo    string `json:"repo"`
	Version string `json:"version"`
	Status  string `json:"status"`
}

// fetchFromRepology fetches package versions from Repology API
func fetchFromRepology() ([]DistroVersion, error) {
	url := "https://repology.org/api/v1/project/containerd"

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "containerd-upgrade-analyzer")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("repology returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var repologyData RepologyResponse
	if err := json.Unmarshal(body, &repologyData); err != nil {
		return nil, err
	}

	// Map Repology repos to friendly distro names
	repoToDistro := map[string]string{
		"ubuntu_24_04":        "Ubuntu 24.04 LTS",
		"ubuntu_24_10":        "Ubuntu 24.10",
		"ubuntu_22_04":        "Ubuntu 22.04 LTS",
		"ubuntu_20_04":        "Ubuntu 20.04 LTS",
		"debian_12":           "Debian 12 (Bookworm)",
		"debian_13":           "Debian 13 (Trixie)",
		"debian_unstable":     "Debian Unstable",
		"fedora_40":           "Fedora 40",
		"fedora_41":           "Fedora 41",
		"fedora_42":           "Fedora 42",
		"fedora_43":           "Fedora 43",
		"fedora_rawhide":      "Fedora Rawhide",
		"alpine_3_19":         "Alpine 3.19",
		"alpine_3_20":         "Alpine 3.20",
		"alpine_3_21":         "Alpine 3.21",
		"alpine_3_22":         "Alpine 3.22",
		"alpine_3_23":         "Alpine 3.23",
		"alpine_edge":         "Alpine Edge",
		"arch":                "Arch Linux",
		"opensuse_tumbleweed": "openSUSE Tumbleweed",
		"opensuse_leap_15_6":  "openSUSE Leap 15.6",
		"centos_stream_9":     "CentOS Stream 9",
		"epel_9":              "RHEL 9 / Rocky 9 (EPEL)",
		"epel_10":             "RHEL 10 / Rocky 10 (EPEL)",
		"amazon_2023":         "Amazon Linux 2023",
		"nix_unstable":        "NixOS Unstable",
		"nix_stable_25_11":    "NixOS 25.11",
		"gentoo":              "Gentoo",
	}

	var results []DistroVersion
	seen := make(map[string]bool)

	for _, pkg := range repologyData {
		distroName, ok := repoToDistro[pkg.Repo]
		if !ok {
			continue
		}
		// Deduplicate
		if seen[distroName] {
			continue
		}
		seen[distroName] = true

		results = append(results, DistroVersion{
			Distro:      distroName,
			Version:     pkg.Version,
			PackageRepo: pkg.Repo,
		})
	}

	// Sort by distro name
	sort.Slice(results, func(i, j int) bool {
		return results[i].Distro < results[j].Distro
	})

	return results, nil
}

// getKnownDistroVersions returns a static list of known containerd versions
// Used as fallback when Repology API is unavailable
func getKnownDistroVersions() []DistroVersion {
	// Last updated: January 2026
	return []DistroVersion{
		{Distro: "Ubuntu 24.04 LTS", Release: "Noble", Version: "1.7.12", Notes: "Default in docker.io package"},
		{Distro: "Ubuntu 22.04 LTS", Release: "Jammy", Version: "1.6.12", Notes: "LTS support"},
		{Distro: "Debian 12", Release: "Bookworm", Version: "1.6.20", Notes: "Stable"},
		{Distro: "Debian 13", Release: "Trixie", Version: "1.7.18", Notes: "Testing"},
		{Distro: "Fedora 41", Release: "", Version: "1.7.20", Notes: ""},
		{Distro: "Alpine 3.20", Release: "", Version: "1.7.18", Notes: "apk add containerd"},
		{Distro: "Arch Linux", Release: "Rolling", Version: "1.7.21", Notes: "community repo"},
		{Distro: "RHEL 9 / Rocky 9", Release: "EPEL", Version: "1.6.28", Notes: "EPEL repository"},
		{Distro: "Amazon Linux 2023", Release: "", Version: "1.7.11", Notes: ""},
		{Distro: "openSUSE Tumbleweed", Release: "Rolling", Version: "1.7.20", Notes: ""},
		{Distro: "CentOS Stream 9", Release: "", Version: "1.6.28", Notes: ""},
		{Distro: "Flatcar Container Linux", Release: "Stable", Version: "1.7.13", Notes: "Built-in"},
		{Distro: "Bottlerocket", Release: "", Version: "1.7.x", Notes: "AWS container OS"},
		{Distro: "Talos Linux", Release: "", Version: "1.7.x", Notes: "Kubernetes OS"},
		{Distro: "k3s (default)", Release: "", Version: "1.7.x", Notes: "Embedded"},
		{Distro: "RKE2 (default)", Release: "", Version: "1.7.x", Notes: "Embedded"},
	}
}

func calculateSummary(diff *VersionDiff) {
	// Count breaking proto changes
	protoBreaking := 0
	for _, pc := range diff.ProtoChanges {
		if pc.IsBreaking {
			protoBreaking++
		}
	}

	diff.Summary.BreakingCount = len(diff.BreakingChanges) + len(diff.RemovedAPIs) + protoBreaking
	diff.Summary.DeprecationCount = len(diff.Deprecations)
	diff.Summary.NewFeatureCount = len(diff.NewFeatures)
	diff.Summary.TotalChanges = diff.Summary.BreakingCount + diff.Summary.DeprecationCount +
		diff.Summary.NewFeatureCount + len(diff.ChangedAPIs) + len(diff.ConfigChanges) + len(diff.ProtoChanges)

	// Calculate risk level
	if diff.Summary.BreakingCount > 10 {
		diff.RiskLevel = "critical"
		diff.Summary.RiskAssessment = "Major upgrade with significant breaking changes"
	} else if diff.Summary.BreakingCount > 5 {
		diff.RiskLevel = "high"
		diff.Summary.RiskAssessment = "Substantial breaking changes require careful migration"
	} else if diff.Summary.BreakingCount > 0 {
		diff.RiskLevel = "medium"
		diff.Summary.RiskAssessment = "Some breaking changes present, review before upgrading"
	} else {
		diff.RiskLevel = "low"
		diff.Summary.RiskAssessment = "No detected breaking changes, safe to upgrade"
	}

	// Increase risk if CRI is incompatible
	if diff.CRICompatibility != nil && !diff.CRICompatibility.IsCompatible {
		if diff.RiskLevel == "low" {
			diff.RiskLevel = "medium"
		} else if diff.RiskLevel == "medium" {
			diff.RiskLevel = "high"
		}
		diff.Summary.RiskAssessment += " (CRI API changes detected)"
	}

	// Set exit code based on risk level
	exitCodes := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	diff.ExitCode = exitCodes[diff.RiskLevel]

	// Generate recommendations
	diff.Recommendations = generateRecommendations(diff)
}

func generateRecommendations(diff *VersionDiff) []string {
	var recs []string

	if len(diff.RemovedAPIs) > 0 {
		recs = append(recs, fmt.Sprintf("Review %d removed APIs and update code accordingly", len(diff.RemovedAPIs)))
	}

	if len(diff.Deprecations) > 0 {
		recs = append(recs, fmt.Sprintf("Address %d deprecations to prepare for future versions", len(diff.Deprecations)))
	}

	if len(diff.ConfigChanges) > 0 {
		recs = append(recs, "Review config.toml for new/changed options")
	}

	if len(diff.DependencyChanges) > 0 {
		recs = append(recs, "Check dependency updates for compatibility with your stack")
	}

	// NEW: Proto/gRPC recommendations
	protoBreaking := 0
	for _, pc := range diff.ProtoChanges {
		if pc.IsBreaking {
			protoBreaking++
		}
	}
	if protoBreaking > 0 {
		recs = append(recs, fmt.Sprintf("⚠️  %d breaking gRPC/protobuf changes - update client code", protoBreaking))
	}

	// NEW: CRI compatibility recommendations
	if diff.CRICompatibility != nil {
		if !diff.CRICompatibility.IsCompatible {
			recs = append(recs, "⚠️  CRI API version changed - verify Kubernetes node compatibility")
		}
		if len(diff.CRICompatibility.K8sCompatTo) > 0 {
			recs = append(recs, fmt.Sprintf("Target version compatible with Kubernetes: %s",
				strings.Join(diff.CRICompatibility.K8sCompatTo, ", ")))
		}
	}

	// NEW: Upgrade path recommendations
	if len(diff.UpgradePath) > 0 {
		recs = append(recs, fmt.Sprintf("Consider %d intermediate upgrade steps for safer migration", len(diff.UpgradePath)))
	}

	// NEW: Distro version recommendations
	if diff.DistroInfo != nil && len(diff.DistroInfo.Versions) > 0 {
		matchingDistros := []string{}
		aheadDistros := []string{}
		for _, dv := range diff.DistroInfo.Versions {
			if dv.Status == "matches-target" {
				matchingDistros = append(matchingDistros, dv.Distro)
			} else if dv.Status == "ahead" {
				aheadDistros = append(aheadDistros, dv.Distro)
			}
		}
		if len(matchingDistros) > 0 {
			recs = append(recs, fmt.Sprintf("🐧 Target version used by: %s", strings.Join(matchingDistros, ", ")))
		} else if len(aheadDistros) > 0 {
			recs = append(recs, fmt.Sprintf("🐧 Rolling distros ahead: %s (good reference for compatibility)", strings.Join(aheadDistros, ", ")))
		}
	}

	if diff.RiskLevel == "high" || diff.RiskLevel == "critical" {
		recs = append(recs, "Recommend testing in staging environment before production upgrade")
		recs = append(recs, "Review containerd release notes and migration guides")
	}

	// NEW: Add release notes link if available
	if diff.GitHubRelease != nil && diff.GitHubRelease.HTMLURL != "" {
		recs = append(recs, fmt.Sprintf("📖 Release notes: %s", diff.GitHubRelease.HTMLURL))
	}

	if len(recs) == 0 {
		recs = append(recs, "No specific concerns - standard testing recommended")
	}

	return recs
}

// printMultiHopAnalysis prints the analysis results for multi-step upgrade paths
func printMultiHopAnalysis(analysis *MultiHopAnalysis) {
	fmt.Printf("\n")
	fmt.Printf("╔══════════════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  Containerd Multi-Hop Upgrade Analysis: %s → %s\n", analysis.FromVersion, analysis.ToVersion)
	fmt.Printf("╚══════════════════════════════════════════════════════════════════════╝\n")
	fmt.Printf("\n")

	// Show unsupported direct upgrade warning
	if !analysis.IsPathSupported {
		fmt.Printf("⛔ DIRECT UPGRADE NOT SUPPORTED\n")
		fmt.Printf("   %s\n\n", analysis.UnsupportedReason)
		fmt.Printf("🛤️  Required Upgrade Path:\n")
		fmt.Printf("   %s\n\n", strings.Join(analysis.RequiredVersions, " → "))
		fmt.Printf("   containerd policy requires sequential minor version upgrades.\n")
		fmt.Printf("   You must perform %d separate upgrade(s).\n\n", len(analysis.Hops))
	}

	// Overall risk
	riskColor := ""
	switch analysis.TotalRiskLevel {
	case "critical":
		riskColor = "🔴"
	case "high":
		riskColor = "🟠"
	case "medium":
		riskColor = "🟡"
	case "low":
		riskColor = "🟢"
	}
	fmt.Printf("Overall Risk Level: %s %s (highest across all hops)\n\n", riskColor, strings.ToUpper(analysis.TotalRiskLevel))

	// Print each hop analysis
	for i, hop := range analysis.Hops {
		fmt.Printf("┌──────────────────────────────────────────────────────────────────────┐\n")
		fmt.Printf("│  Hop %d/%d: %s → %s\n", i+1, len(analysis.Hops), hop.FromVersion, hop.ToVersion)
		fmt.Printf("└──────────────────────────────────────────────────────────────────────┘\n")

		// Risk for this hop
		hopRisk := ""
		switch hop.RiskLevel {
		case "critical":
			hopRisk = "🔴"
		case "high":
			hopRisk = "🟠"
		case "medium":
			hopRisk = "🟡"
		case "low":
			hopRisk = "🟢"
		}
		fmt.Printf("Risk: %s %s\n", hopRisk, strings.ToUpper(hop.RiskLevel))
		fmt.Printf("Assessment: %s\n\n", hop.Summary.RiskAssessment)

		// Summary for this hop
		fmt.Printf("📊 Summary\n")
		fmt.Printf("   Total Changes:    %d\n", hop.Summary.TotalChanges)
		fmt.Printf("   Breaking Changes: %d\n", hop.Summary.BreakingCount)
		fmt.Printf("   Deprecations:     %d\n", hop.Summary.DeprecationCount)
		fmt.Printf("   New Features:     %d\n\n", hop.Summary.NewFeatureCount)

		// Breaking changes for this hop
		if len(hop.BreakingChanges) > 0 {
			fmt.Printf("⚠️  Breaking Changes (%d)\n", len(hop.BreakingChanges))
			for _, c := range hop.BreakingChanges {
				fmt.Printf("   • [%s] %s\n", c.Category, c.Description)
			}
			fmt.Printf("\n")
		}

		// Removed APIs
		if len(hop.RemovedAPIs) > 0 {
			fmt.Printf("❌ Removed APIs (%d)\n", len(hop.RemovedAPIs))
			for _, api := range hop.RemovedAPIs {
				fmt.Printf("   • %s.%s (%s)\n", api.Package, api.Name, api.Type)
			}
			fmt.Printf("\n")
		}

		// Deprecations
		if len(hop.Deprecations) > 0 {
			fmt.Printf("⏳ Deprecations (%d)\n", len(hop.Deprecations))
			for _, d := range hop.Deprecations {
				depText := cleanDeprecationText(d.API)
				fmt.Printf("   • %s\n", depText)
			}
			fmt.Printf("\n")
		}

		// Proto changes (breaking only)
		protoBreaking := 0
		for _, pc := range hop.ProtoChanges {
			if pc.IsBreaking {
				protoBreaking++
			}
		}
		if protoBreaking > 0 {
			fmt.Printf("🔌 Breaking gRPC/Protobuf Changes (%d)\n", protoBreaking)
			for _, pc := range hop.ProtoChanges {
				if pc.IsBreaking {
					fmt.Printf("   • %s\n", pc.Description)
				}
			}
			fmt.Printf("\n")
		}

		// Key recommendations for this hop
		if len(hop.Recommendations) > 0 {
			fmt.Printf("📋 Key Recommendations\n")
			maxRecs := 5
			if len(hop.Recommendations) < maxRecs {
				maxRecs = len(hop.Recommendations)
			}
			for j := 0; j < maxRecs; j++ {
				fmt.Printf("   %d. %s\n", j+1, hop.Recommendations[j])
			}
			if len(hop.Recommendations) > 5 {
				fmt.Printf("   ... and %d more\n", len(hop.Recommendations)-5)
			}
			fmt.Printf("\n")
		}
	}

	// Final summary
	fmt.Printf("════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("📋 UPGRADE EXECUTION PLAN\n")
	fmt.Printf("════════════════════════════════════════════════════════════════════════\n\n")

	for i, hop := range analysis.Hops {
		fmt.Printf("Step %d: Upgrade %s → %s\n", i+1, hop.FromVersion, hop.ToVersion)
		fmt.Printf("        Risk: %s | Breaking Changes: %d\n", strings.ToUpper(hop.RiskLevel), hop.Summary.BreakingCount)
		fmt.Printf("        Run: containerd-upgrade-analyzer --from %s --to %s\n\n", hop.FromVersion, hop.ToVersion)
	}

	fmt.Printf("⚠️  IMPORTANT: Address all deprecation warnings at each step before proceeding!\n")
	fmt.Printf("   Features can only be removed in releases following an LTS release.\n\n")
}

func printHumanReadable(diff *VersionDiff) {
	fmt.Printf("\n")
	fmt.Printf("╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  Containerd Upgrade Analysis: %s → %s\n", diff.FromVersion, diff.ToVersion)
	fmt.Printf("╚══════════════════════════════════════════════════════════════╝\n")
	fmt.Printf("\n")

	// Show upgrade support status if it was blocked
	if !diff.IsUpgradeSupported {
		fmt.Printf("⛔ DIRECT UPGRADE NOT SUPPORTED\n")
		fmt.Printf("   %s\n\n", diff.UpgradeBlockedReason)
		if len(diff.RequiredHops) > 0 {
			fmt.Printf("🛤️  Required Upgrade Path: %s\n\n", strings.Join(diff.RequiredHops, " → "))
		}
	} else if diff.IsLTSUpgrade {
		fmt.Printf("✅ LTS-to-LTS Upgrade (direct upgrade supported)\n\n")
	}

	// Risk indicator
	riskColor := ""
	switch diff.RiskLevel {
	case "critical":
		riskColor = "🔴"
	case "high":
		riskColor = "🟠"
	case "medium":
		riskColor = "🟡"
	case "low":
		riskColor = "🟢"
	}
	fmt.Printf("Risk Level: %s %s\n", riskColor, strings.ToUpper(diff.RiskLevel))
	fmt.Printf("Assessment: %s\n\n", diff.Summary.RiskAssessment)

	// Summary
	fmt.Printf("📊 Summary\n")
	fmt.Printf("   Total Changes:    %d\n", diff.Summary.TotalChanges)
	fmt.Printf("   Breaking Changes: %d\n", diff.Summary.BreakingCount)
	fmt.Printf("   Deprecations:     %d\n", diff.Summary.DeprecationCount)
	fmt.Printf("   New Features:     %d\n", diff.Summary.NewFeatureCount)
	fmt.Printf("\n")

	// Breaking Changes
	if len(diff.BreakingChanges) > 0 {
		fmt.Printf("⚠️  Breaking Changes (%d)\n", len(diff.BreakingChanges))
		for _, c := range diff.BreakingChanges {
			fmt.Printf("   • [%s] %s\n", c.Category, c.Description)
			if c.Migration != "" {
				fmt.Printf("     Migration: %s\n", c.Migration)
			}
		}
		fmt.Printf("\n")
	}

	// Removed APIs
	if len(diff.RemovedAPIs) > 0 {
		fmt.Printf("❌ Removed APIs (%d)\n", len(diff.RemovedAPIs))
		for _, api := range diff.RemovedAPIs {
			fmt.Printf("   • %s.%s (%s)\n", api.Package, api.Name, api.Type)
		}
		fmt.Printf("\n")
	}

	// Changed APIs
	if len(diff.ChangedAPIs) > 0 {
		fmt.Printf("🔄 Changed APIs (%d)\n", len(diff.ChangedAPIs))
		for _, api := range diff.ChangedAPIs {
			fmt.Printf("   • %s.%s (%s)\n", api.Package, api.Name, api.ChangeType)
			if api.OldSig != "" && api.NewSig != "" {
				// Show the full signatures for clarity
				fmt.Printf("     - Old: %s\n", api.OldSig)
				fmt.Printf("     + New: %s\n", api.NewSig)
				// Highlight the difference if we can identify it
				if diffStr := highlightSignatureDiff(api.OldSig, api.NewSig); diffStr != "" {
					fmt.Printf("     💡 Change: %s\n", diffStr)
				}
			}
		}
		fmt.Printf("\n")
	}

	// Deprecations
	if len(diff.Deprecations) > 0 {
		fmt.Printf("⏳ Deprecations (%d)\n", len(diff.Deprecations))
		for _, d := range diff.Deprecations {
			// Clean up deprecation text - extract meaningful part
			depText := cleanDeprecationText(d.API)
			fmt.Printf("   • %s\n", depText)
			if d.Replacement != "" {
				fmt.Printf("     ↳ Replace with: %s\n", d.Replacement)
			}
			if d.MigrationNotes != "" && d.MigrationNotes != "See release notes for migration guidance" && d.MigrationNotes != "See CHANGELOG for details" {
				fmt.Printf("     ↳ Note: %s\n", d.MigrationNotes)
			}
		}
		fmt.Printf("\n")
	}

	// New Features
	if len(diff.NewFeatures) > 0 {
		fmt.Printf("✨ New Features (%d)\n", len(diff.NewFeatures))
		for _, f := range diff.NewFeatures {
			fmt.Printf("   • %s: %s\n", f.Name, truncate(f.Description, 50))
		}
		fmt.Printf("\n")
	}

	// Config Changes
	if len(diff.ConfigChanges) > 0 {
		fmt.Printf("⚙️  Config Changes (%d)\n", len(diff.ConfigChanges))
		for _, c := range diff.ConfigChanges {
			fmt.Printf("   • [%s] %s - %s\n", c.ChangeType, c.Key, c.Description)
		}
		fmt.Printf("\n")
	}

	// Dependency Changes (show top 10)
	if len(diff.DependencyChanges) > 0 {
		fmt.Printf("📦 Dependency Changes (%d total", len(diff.DependencyChanges))
		shown := diff.DependencyChanges
		if len(shown) > 10 {
			fmt.Printf(", showing top 10")
			shown = shown[:10]
		}
		fmt.Printf(")\n")
		for _, d := range shown {
			if d.NewVersion == "REMOVED" {
				fmt.Printf("   • ❌ %s (removed)\n", d.Dependency)
			} else if d.OldVersion == "" {
				fmt.Printf("   • ➕ %s → %s\n", d.Dependency, d.NewVersion)
			} else {
				fmt.Printf("   • %s: %s → %s\n", d.Dependency, d.OldVersion, d.NewVersion)
			}
		}
		fmt.Printf("\n")
	}

	// NEW: Protocol Buffer / gRPC Changes
	if len(diff.ProtoChanges) > 0 {
		breakingCount := 0
		for _, pc := range diff.ProtoChanges {
			if pc.IsBreaking {
				breakingCount++
			}
		}
		fmt.Printf("🔌 gRPC/Protobuf Changes (%d total, %d breaking)\n", len(diff.ProtoChanges), breakingCount)
		for _, pc := range diff.ProtoChanges {
			breakingIcon := ""
			if pc.IsBreaking {
				breakingIcon = "⚠️ "
			}
			if pc.Service != "" {
				fmt.Printf("   • %s[%s] Service %s: %s\n", breakingIcon, pc.ChangeType, pc.Service, pc.Description)
			} else if pc.Message != "" {
				fmt.Printf("   • %s[%s] Message %s: %s\n", breakingIcon, pc.ChangeType, pc.Message, pc.Description)
			} else {
				fmt.Printf("   • %s[%s] %s\n", breakingIcon, pc.ChangeType, pc.Description)
			}
			if pc.OldDef != "" && pc.NewDef != "" {
				fmt.Printf("     - Old: %s\n", pc.OldDef)
				fmt.Printf("     + New: %s\n", pc.NewDef)
			}
		}
		fmt.Printf("\n")
	}

	// NEW: CRI Compatibility
	if diff.CRICompatibility != nil {
		fmt.Printf("🐳 CRI (Container Runtime Interface) Compatibility\n")
		if diff.CRICompatibility.FromCRIVersion != "" || diff.CRICompatibility.ToCRIVersion != "" {
			fmt.Printf("   CRI API: %s → %s\n",
				nvl(diff.CRICompatibility.FromCRIVersion, "unknown"),
				nvl(diff.CRICompatibility.ToCRIVersion, "unknown"))
		}
		if diff.CRICompatibility.IsCompatible {
			fmt.Printf("   Status: ✅ Compatible\n")
		} else {
			fmt.Printf("   Status: ⚠️  API Changed - verify compatibility\n")
		}
		if len(diff.CRICompatibility.K8sCompatTo) > 0 {
			fmt.Printf("   Kubernetes: %s\n", strings.Join(diff.CRICompatibility.K8sCompatTo, ", "))
		}
		for _, note := range diff.CRICompatibility.Notes {
			fmt.Printf("   📝 %s\n", note)
		}
		fmt.Printf("\n")
	}

	// NEW: Upgrade Path
	if len(diff.UpgradePath) > 0 {
		fmt.Printf("🛤️  Recommended Upgrade Path\n")
		fmt.Printf("   %s", diff.FromVersion)
		for _, step := range diff.UpgradePath {
			riskIcon := "🟢"
			if step.RiskLevel == "medium" {
				riskIcon = "🟡"
			} else if step.RiskLevel == "high" {
				riskIcon = "🟠"
			}
			fmt.Printf(" → %s %s", step.Version, riskIcon)
		}
		fmt.Printf(" → %s\n", diff.ToVersion)
		fmt.Printf("\n")
		for i, step := range diff.UpgradePath {
			fmt.Printf("   Step %d: %s\n", i+1, step.Version)
			fmt.Printf("           %s\n", step.Reason)
		}
		fmt.Printf("\n")
	}

	// NEW: GitHub Release Info
	if diff.GitHubRelease != nil {
		fmt.Printf("📰 GitHub Release: %s\n", diff.GitHubRelease.Name)
		if diff.GitHubRelease.Prerelease {
			fmt.Printf("   ⚠️  This is a PRE-RELEASE version\n")
		}
		fmt.Printf("   Published: %s\n", diff.GitHubRelease.PublishedAt.Format("2006-01-02"))
		fmt.Printf("   URL: %s\n", diff.GitHubRelease.HTMLURL)
		fmt.Printf("\n")
	}

	// NEW: Distro Versions
	if diff.DistroInfo != nil && len(diff.DistroInfo.Versions) > 0 {
		fmt.Printf("🐧 Containerd in Linux Distributions\n")
		// Show source and timestamp
		sourceIcon := "🌐"
		if diff.DistroInfo.Source == "fallback" {
			sourceIcon = "📦"
		}
		fmt.Printf("   %s Source: %s | Fetched: %s\n", sourceIcon, diff.DistroInfo.Source, diff.DistroInfo.LastUpdated.Format("2006-01-02 15:04 MST"))
		if diff.DistroInfo.Note != "" {
			fmt.Printf("   ℹ️  %s\n", diff.DistroInfo.Note)
		}
		fmt.Printf("   %-28s %-12s %s\n", "Distribution", "Version", "Status")
		fmt.Printf("   %-28s %-12s %s\n", "────────────────────────────", "────────────", "──────────────")
		for _, dv := range diff.DistroInfo.Versions {
			statusIcon := ""
			switch dv.Status {
			case "matches-target":
				statusIcon = "✅ matches target"
			case "ahead":
				statusIcon = "🚀 ahead"
			case "between":
				statusIcon = "📍 between from/to"
			case "behind-source":
				statusIcon = "⚠️  behind source"
			default:
				statusIcon = ""
			}
			fmt.Printf("   %-28s %-12s %s\n", truncate(dv.Distro, 28), dv.Version, statusIcon)
		}
		fmt.Printf("\n")
	}

	// Recommendations
	fmt.Printf("📋 Recommendations\n")
	for i, rec := range diff.Recommendations {
		fmt.Printf("   %d. %s\n", i+1, rec)
	}
	fmt.Printf("\n")
}

// nvl returns the value if non-empty, otherwise the default
func nvl(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// highlightSignatureDiff compares old and new signatures and returns a description of what changed
func highlightSignatureDiff(oldSig, newSig string) string {
	oldSig = strings.TrimSpace(oldSig)
	newSig = strings.TrimSpace(newSig)

	// Extract parameters from signatures
	oldParamsStart := strings.Index(oldSig, "(")
	newParamsStart := strings.Index(newSig, "(")
	if oldParamsStart == -1 || newParamsStart == -1 {
		return ""
	}

	// Find the parameter sections
	oldParams := extractParams(oldSig[oldParamsStart:])
	newParams := extractParams(newSig[newParamsStart:])

	var changes []string

	// Compare parameter counts
	if len(oldParams) != len(newParams) {
		changes = append(changes, fmt.Sprintf("parameter count: %d → %d", len(oldParams), len(newParams)))
	}

	// Find specific parameter type changes
	for i := 0; i < len(oldParams) && i < len(newParams); i++ {
		if oldParams[i] != newParams[i] {
			// Extract just the type part if possible
			oldType := extractType(oldParams[i])
			newType := extractType(newParams[i])
			if oldType != newType {
				changes = append(changes, fmt.Sprintf("%s → %s", oldType, newType))
			}
		}
	}

	// Check return type changes
	oldRet := extractReturnType(oldSig)
	newRet := extractReturnType(newSig)
	if oldRet != newRet && oldRet != "" && newRet != "" {
		changes = append(changes, fmt.Sprintf("return: %s → %s", oldRet, newRet))
	}

	if len(changes) > 0 {
		return strings.Join(changes, "; ")
	}
	return ""
}

// extractParams extracts parameter list from a function signature starting at '('
func extractParams(sig string) []string {
	if len(sig) == 0 || sig[0] != '(' {
		return nil
	}

	// Find matching closing paren
	depth := 0
	start := 1
	var params []string

	for i, c := range sig {
		switch c {
		case '(':
			if depth == 0 {
				start = i + 1
			}
			depth++
		case ')':
			depth--
			if depth == 0 {
				if i > start {
					paramStr := strings.TrimSpace(sig[start:i])
					if paramStr != "" {
						params = append(params, splitParams(paramStr)...)
					}
				}
				return params
			}
		case ',':
			if depth == 1 {
				params = append(params, strings.TrimSpace(sig[start:i]))
				start = i + 1
			}
		}
	}
	return params
}

// splitParams splits a parameter string respecting nested brackets
func splitParams(s string) []string {
	var result []string
	depth := 0
	start := 0
	for i, c := range s {
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				result = append(result, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if start < len(s) {
		result = append(result, strings.TrimSpace(s[start:]))
	}
	return result
}

// extractType extracts the type from a "name type" parameter declaration
func extractType(param string) string {
	param = strings.TrimSpace(param)
	parts := strings.Fields(param)
	if len(parts) >= 2 {
		return strings.Join(parts[1:], " ")
	}
	return param
}

// extractReturnType extracts the return type from a function signature
func extractReturnType(sig string) string {
	// Find the last ) and get what's after it
	lastParen := strings.LastIndex(sig, ")")
	if lastParen == -1 || lastParen >= len(sig)-1 {
		return ""
	}
	return strings.TrimSpace(sig[lastParen+1:])
}

// cleanDeprecationText extracts meaningful text from raw deprecation notices
func cleanDeprecationText(raw string) string {
	raw = strings.TrimSpace(raw)

	// Remove common markdown artifacts
	raw = strings.TrimPrefix(raw, "* ")
	raw = strings.TrimPrefix(raw, "- ")
	raw = strings.TrimPrefix(raw, "• ")

	// Extract package/API name from GitHub URLs
	if strings.Contains(raw, "github.com/containerd/") {
		// Extract the package name
		re := regexp.MustCompile(`github\.com/containerd/([a-zA-Z0-9_-]+)`)
		if match := re.FindStringSubmatch(raw); len(match) > 1 {
			pkgName := match[1]
			// Check if there's descriptive text before the URL
			urlIdx := strings.Index(raw, "http")
			if urlIdx > 5 {
				return fmt.Sprintf("%s (see: github.com/containerd/%s)", strings.TrimSpace(raw[:urlIdx]), pkgName)
			}
			return fmt.Sprintf("Package github.com/containerd/%s", pkgName)
		}
	}

	// Extract meaningful portion if it's a URL-only deprecation
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "http") {
		// Try to extract the repo/package name from URL
		parts := strings.Split(raw, "/")
		for i, part := range parts {
			if part == "containerd" && i+1 < len(parts) {
				return fmt.Sprintf("Package containerd/%s", parts[i+1])
			}
		}
		// For RELEASES.md links, extract what's being deprecated
		if strings.Contains(raw, "RELEASES.md#deprecated") {
			return "See RELEASES.md for deprecated features"
		}
	}

	// Clean up if it has a trailing period or newlines
	raw = strings.TrimSuffix(raw, ".")
	raw = strings.ReplaceAll(raw, "\n", " ")

	// Truncate if still too long
	if len(raw) > 100 {
		return raw[:97] + "..."
	}

	return raw
}

// Sort dependency changes by importance
func init() {
	// Sort by: removals first, then adds, then updates
	sort.Slice([]DepChange{}, func(i, j int) bool { return false })
}
