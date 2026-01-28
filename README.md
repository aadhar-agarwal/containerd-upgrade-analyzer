# Containerd Upgrade Analyzer

A Go-based CLI tool to analyze differences between containerd versions, helping you gain upgrade confidence by identifying breaking changes, API diffs, deprecations, and compatibility risks.

## Features

- **API Change Detection** - Identifies removed, changed, and added public APIs
- **Deprecation Tracking** - Extracts deprecation notices from release notes and CHANGELOG
- **Dependency Analysis** - Compares go.mod dependencies between versions
- **Config Changes** - Detects changes to containerd configuration options
- **gRPC/Protobuf Analysis** - Detects breaking changes in `.proto` files and gRPC services
- **CRI Compatibility** - Checks Container Runtime Interface compatibility with Kubernetes
- **GitHub Release Integration** - Fetches release notes directly from GitHub API
- **Distro Version Tracking** - Shows containerd versions in major Linux distributions
- **Upgrade Path Validation** - Enforces containerd's sequential minor version upgrade policy
- **Multi-Hop Analysis** - Runs full analysis for each required upgrade step
- **LTS Support** - Detects LTS releases from RELEASES.md; allows direct LTS-to-LTS upgrades
- **Risk Assessment** - Calculates upgrade risk level (low/medium/high/critical)
- **CI/CD Integration** - Exit codes and flags for pipeline integration
- **Recommendations** - Provides actionable upgrade guidance

## Installation

```bash
cd containerd-upgrade-analyzer
go build -o containerd-upgrade-analyzer .

# Optionally install to PATH
go install .
```

## Usage

### Basic Usage

```bash
# Analyze upgrade from v2.0.0 to v2.1.0
containerd-upgrade-analyzer --from v2.0.0 --to v2.1.0

# Use a local containerd repo (faster, avoids cloning)
containerd-upgrade-analyzer --from v2.0.0 --to v2.1.0 --repo ~/repos/containerd

# Output as JSON for programmatic consumption
containerd-upgrade-analyzer --from v2.0.0 --to v2.1.0 --json
```

### Upgrade Path Validation

The analyzer enforces containerd's **sequential minor version upgrade policy** (see [PR #12830](https://github.com/containerd/containerd/pull/12830)):

- ✅ **Supported**: `v2.0.0 → v2.1.0` (sequential minor)
- ✅ **Supported**: `v1.7.x → v2.3.x` (LTS-to-LTS direct upgrade)
- ❌ **Not Supported**: `v2.0.0 → v2.2.0` (skipping minor version)

When you attempt an unsupported upgrade path, the analyzer automatically:
1. Calculates the required intermediate versions
2. Runs full analysis for each hop
3. Shows a combined report with cumulative risk

```bash
# Attempting to skip minor versions triggers multi-hop analysis
containerd-upgrade-analyzer --from v2.0.0 --to v2.2.0
```

### CI/CD Integration

```bash
# CI mode - exits with code based on risk level
containerd-upgrade-analyzer --from v2.0.0 --to v2.2.0 --ci

# Fail only on high or critical risk
containerd-upgrade-analyzer --from v2.0.0 --to v2.2.0 --ci --fail-on high

# Combine with JSON for machine-readable output
containerd-upgrade-analyzer --from v2.0.0 --to v2.2.0 --json --ci --fail-on medium
```

**Exit Codes:**
| Code | Meaning |
|------|---------|
| 0 | Safe to upgrade (or below threshold) |
| 1 | Low risk |
| 2 | Medium risk - some breaking changes |
| 3 | High risk - substantial breaking changes |
| 4 | Critical risk - major breaking changes |
| 5 | **Upgrade path not supported** (minor version skip without LTS exception) |

### Sample Output (Multi-Hop Analysis)

```
╔══════════════════════════════════════════════════════════════════════╗
║  Containerd Multi-Hop Upgrade Analysis: v2.0.0 → v2.2.0
╚══════════════════════════════════════════════════════════════════════╝

⛔ DIRECT UPGRADE NOT SUPPORTED
   Cannot skip minor versions: 2.0 → 2.2 requires sequential upgrades

🛤️  Required Upgrade Path:
   v2.0.0 → v2.1.0 → v2.2.0

Overall Risk Level: 🟠 HIGH (highest across all hops)

┌──────────────────────────────────────────────────────────────────────┐
│  Hop 1/2: v2.0.0 → v2.1.0
└──────────────────────────────────────────────────────────────────────┘
Risk: 🟠 HIGH | Breaking Changes: 4 | Deprecations: 3

┌──────────────────────────────────────────────────────────────────────┐
│  Hop 2/2: v2.1.0 → v2.2.0
└──────────────────────────────────────────────────────────────────────┘
Risk: 🟠 HIGH | Breaking Changes: 4 | Deprecations: 0

════════════════════════════════════════════════════════════════════════
📋 UPGRADE EXECUTION PLAN
════════════════════════════════════════════════════════════════════════
Step 1: containerd-upgrade-analyzer --from v2.0.0 --to v2.1.0
Step 2: containerd-upgrade-analyzer --from v2.1.0 --to v2.2.0

⚠️  IMPORTANT: Address all deprecation warnings at each step before proceeding!
```

### Sample Output (Single Hop)

```
╔══════════════════════════════════════════════════════════════╗
║  Containerd Upgrade Analysis: v2.0.0 → v2.2.0
╚══════════════════════════════════════════════════════════════╝

Risk Level: 🟠 HIGH
Assessment: Substantial breaking changes require careful migration (CRI API changes detected)

📊 Summary
   Total Changes:    17
   Breaking Changes: 7
   Deprecations:     2
   New Features:     0

❌ Removed APIs (3)
   • client.WithSchema1Conversion (function)
   • pkg/archive.AsCimContainerLayer (function)
   • pkg/oci.WithCDIDevices (function)

🔄 Changed APIs (4)
   • pkg/oom/v1.New (signature_changed)
     - Old: func New(publisher shim.Publisher) (oom.Watcher, error) {
     + New: func New(publisher events.Publisher) (oom.Watcher, error) {
     💡 Change: shim.Publisher → events.Publisher

🔌 gRPC/Protobuf Changes (4 total, 4 breaking)
   • ⚠️ [removed] Message WindowsCpuGroupAffinity: Field removed (field number 2)

🐳 CRI (Container Runtime Interface) Compatibility
   CRI API: v0.31.2 → v0.34.1
   Status: ⚠️  API Changed - verify compatibility
   Kubernetes: check release notes

📰 GitHub Release: containerd 2.2.0
   Published: 2025-11-06
   URL: https://github.com/containerd/containerd/releases/tag/v2.2.0

� Containerd in Linux Distributions
   Distribution                 Version      Status
   ──────────────────────────── ──────────── ──────────────
   Alpine Edge                  2.2.1        ✅ matches target
   Arch Linux                   2.2.1        ✅ matches target
   Debian 12 (Bookworm)         1.6.20       ⚠️  behind source
   Fedora Rawhide               2.2.0        ✅ matches target
   RHEL 9 / Rocky 9 (EPEL)      2.2.0        ✅ matches target
   Ubuntu 24.04 LTS             1.6.24       ⚠️  behind source

📋 Recommendations
   1. Review 3 removed APIs and update code accordingly
   2. ⚠️  4 breaking gRPC/protobuf changes - update client code
   3. ⚠️  CRI API version changed - verify Kubernetes node compatibility
   4. 🐧 Target version used by: Alpine Edge, Arch Linux, Fedora Rawhide, RHEL 9
   5. 📖 Release notes: https://github.com/containerd/containerd/releases/tag/v2.2.0
```

## How It Works

1. **Repository Analysis**: Clones containerd repo (or uses local copy)
2. **Git Diff Parsing**: Compares files between version tags
3. **API Extraction**: Uses regex to identify public Go functions, types, interfaces
4. **go.mod Comparison**: Parses and diffs dependency versions
5. **Proto Analysis**: Scans `.proto` files for service/message/field changes
6. **CRI Detection**: Checks `k8s.io/cri-api` version in go.mod
7. **Distro Versions**: Fetches from [Repology API](https://repology.org/) (with fallback)
8. **GitHub API**: Fetches release notes for additional context
9. **Release Notes**: Scans for deprecation and breaking change notices
10. **Risk Calculation**: Scores changes and generates recommendations

## Analyzed Components

| Component | Source | Detection Method |
|-----------|--------|------------------|
| Removed APIs | Git diff | Regex on `-func`, `-type` lines |
| Changed APIs | Git diff | Adjacent `-`/`+` function signatures |
| Deprecations | releases/, docs/, GitHub | Keyword patterns |
| Dependencies | go.mod diff | Version comparison |
| Config changes | pkg/config/, defaults/ | TOML struct field changes |
| Proto/gRPC | *.proto files | Service, message, field changes |
| CRI Compat | go.mod | k8s.io/cri-api version tracking |
| Distro Versions | Repology API | Live package versions |

## Risk Levels

| Level | Criteria | Recommendation |
|-------|----------|----------------|
| 🟢 Low | No breaking changes | Safe to upgrade |
| 🟡 Medium | 1-5 breaking changes | Review before upgrading |
| 🟠 High | 6-10 breaking changes or CRI changes | Test in staging first |
| 🔴 Critical | 10+ breaking changes | Careful migration required |

## JSON Output Schema

```json
{
  "from_version": "v2.0.0",
  "to_version": "v2.2.0",
  "summary": {
    "total_changes": 17,
    "breaking_count": 7,
    "deprecation_count": 2,
    "new_feature_count": 0,
    "risk_assessment": "Substantial breaking changes require careful migration"
  },
  "breaking_changes": [...],
  "deprecations": [...],
  "removed_apis": [...],
  "changed_apis": [...],
  "config_changes": [...],
  "dependency_changes": [...],
  "proto_changes": [...],
  "cri_compatibility": {
    "from_cri_version": "v0.31.2",
    "to_cri_version": "v0.34.1",
    "is_compatible": false,
    "k8s_compat_to": ["check release notes"],
    "notes": ["CRI API changed - verify Kubernetes compatibility"]
  },
  "upgrade_path": [...],
  "github_release": {
    "tag_name": "v2.2.0",
    "name": "containerd 2.2.0",
    "html_url": "https://github.com/containerd/containerd/releases/tag/v2.2.0",
    "published_at": "2025-11-06T00:00:00Z"
  },
  "distro_versions": [
    {"distro": "Alpine Edge", "version": "2.2.1", "status": "matches-target"},
    {"distro": "Arch Linux", "version": "2.2.1", "status": "matches-target"},
    {"distro": "Ubuntu 24.04 LTS", "version": "1.6.24", "status": "behind-source"}
  ],
  "risk_level": "high",
  "exit_code": 3,
  "recommendations": [...]
}
```

## Supported Distributions

The tool fetches live containerd package versions from [Repology](https://repology.org/), covering:

- **Ubuntu** (20.04, 22.04, 24.04, 24.10)
- **Debian** (Bookworm, Trixie, Unstable)
- **Fedora** (40, 41, Rawhide)
- **Alpine** (3.19, 3.20, Edge)
- **Arch Linux**
- **openSUSE** (Leap, Tumbleweed)
- **RHEL/CentOS/Rocky** (via EPEL)
- **Amazon Linux 2023**
- **Gentoo**
- **NixOS**

Status indicators:
- ✅ **matches-target** - Distro has the target version
- 🚀 **ahead** - Distro has a newer version
- 📍 **between** - Version is between source and target
- ⚠️ **behind-source** - Distro is behind your current version

## Limitations

- Focuses on public API changes (exported functions/types)
- May miss some subtle breaking changes in behavior
- Deprecation detection depends on documentation consistency
- CRI-to-Kubernetes mapping is approximate
- Best used alongside official release notes

## Contributing

Contributions are welcome! Areas for improvement:

- Expand CRI-to-Kubernetes version mapping
- Add support for analyzing plugin interface changes
- Improve proto field renumbering detection
- Add NRI (Node Resource Interface) compatibility checks
