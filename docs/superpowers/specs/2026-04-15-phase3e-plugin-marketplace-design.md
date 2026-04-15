# Phase 3E: Plugin Marketplace Design

**Date:** 2026-04-15
**Status:** Draft
**Scope:** v1 CLI-only; v1.1 web marketplace UI

## Overview

A plugin marketplace for OpenTools that enables discovery, installation, sharing, and updating of community-contributed security skills, recipes, and tool container definitions. Plugins are unified bundles that ship skills, recipes, and Docker Compose fragments as a single installable unit, with individually installable pieces underneath.

### Goals

- **Discover** plugins via a curated, signed registry with faceted search
- **Install** plugins with transactional safety, full audit trail, and rollback support
- **Sandbox** plugin containers with defense-in-depth: network isolation, capability restrictions, egress control
- **Share** plugins across teams via lockfiles, plugin sets, and portable archives
- **Author** plugins with low friction: scaffold, link, validate, sign, submit

### Non-goals (v1)

- Web dashboard marketplace UI (deferred to v1.1)
- Self-hosted package registry API (migration path from Git registry, not v1)
- Plugin ratings, download counts, or usage analytics
- Paid/licensed plugins

## Architecture

### Approach: Shared `plugin-core` library

A new `packages/plugin-core/` package contains all marketplace logic. Both the CLI (`packages/cli`) and the web backend (`packages/web`, in v1.1) import from it. The CLI adds Typer commands, the web backend adds FastAPI routes — both thin wrappers around the core.

### Package structure

```
packages/plugin-core/
├── pyproject.toml
└── src/opentools_plugin_core/
    ├── __init__.py
    ├── models.py          # Pydantic v2 manifest & catalog models
    ├── registry.py        # Fetch signed catalog, ETag caching, multi-registry
    ├── resolver.py        # Dependency tree resolution + conflict detection
    ├── installer.py       # Transactional install: clone → verify → audit → stage → promote
    ├── sandbox.py         # Container policy, compose validation, mount blocklist
    ├── enforcement.py     # Recipe command parsing (shlex), execution scoping
    ├── content_advisor.py # Skill red-flag scanning (advisory, not enforcement)
    ├── compose.py         # Generate per-plugin compose project on isolated network
    ├── index.py           # SQLite installed-plugin tracking + integrity hashes
    ├── updater.py         # Version check, update flow, rollback
    ├── verify.py          # Sigstore signature verification
    ├── cache.py           # Content-addressable download cache
    └── errors.py          # PluginError hierarchy with user-facing messages + hints
```

### Storage layout

All plugin content lives in `~/.opentools/`, never inside the repo.

```
~/.opentools/
├── plugins/
│   └── wifi-hacking/
│       ├── .active                    # text file: "1.0.0" (active version pointer)
│       ├── 1.0.0/
│       │   ├── manifest.yaml          # copy of opentools-plugin.yaml
│       │   ├── skills/
│       │   │   └── wifi-pentest/
│       │   │       └── SKILL.md
│       │   ├── recipes/
│       │   │   ├── wpa-crack.json
│       │   │   └── deauth-survey.json
│       │   └── compose/
│       │       └── docker-compose.yaml
│       └── 0.9.0/                     # previous version (for rollback)
├── staging/                           # temp dir during installs (cleaned on failure)
├── cache/                             # content-addressed tarballs (SHA256)
│   └── ab3f...tar.gz
├── plugins.db                         # SQLite index
├── install.lock                       # filelock for concurrent install protection
└── registry-cache/
    └── catalog.json                   # cached registry catalog + ETag
```

### Loader integration

The existing skill loader, recipe loader, and `discover_plugin_dir()` gain an extended search path:

```python
def skill_search_paths() -> list[Path]:
    return [
        discover_plugin_dir() / "skills",                  # built-in
        Path.home() / ".opentools" / "plugins",            # marketplace (scan */active_version/skills/)
    ]
```

The loader reads each plugin's `.active` file to resolve the active version directory, then scans `skills/` and `recipes/` within it.

## Plugin Manifest

**File:** `opentools-plugin.yaml` at the root of a plugin repository.

```yaml
name: wifi-hacking
version: 1.0.0
description: "WiFi security assessment — WPA/WPA2 cracking, deauth, rogue AP"
author:
  name: someone
  url: https://github.com/someone
license: MIT
min_opentools_version: "0.3.0"
tags: [wifi, wireless, wpa, wpa2, deauth, aircrack]
domain: pentest                        # faceted search: pentest|re|forensics|cloud|mobile|hardware
changelog: CHANGELOG.md               # path relative to plugin root

provides:
  skills:
    - path: skills/wifi-pentest/SKILL.md
  recipes:
    - path: recipes/wpa-crack.json
    - path: recipes/deauth-survey.json
  containers:
    - name: aircrack-mcp
      compose_fragment: containers/aircrack-mcp.yaml
      image: ghcr.io/someone/aircrack-mcp:1.2.0
      profile: pentest

requires:
  containers: [nmap-mcp]
  tools: [tshark]
  plugins:
    - name: network-utils
      version: ">=0.2.0, <1.0.0"

sandbox:
  capabilities: [NET_RAW, NET_ADMIN]
  network_mode: host
  egress: false                        # default: no internet access
  # egress_domains: [api.example.com]  # v2: allowlist alternative
  volumes:
    - /dev/wifi0:/dev/wifi0
```

**Validation:** Pydantic v2 models with strict validation. JSON Schema auto-generated from models and published in the registry repo for IDE validation.

## Registry & Discovery

### Registry structure

Primary registry: `Emperiusm/opentools-registry` on GitHub.

```
opentools-registry/
├── plugins/
│   ├── wifi-hacking.yaml          # per-plugin metadata
│   └── cloud-recon.yaml
├── dist/
│   ├── catalog.json               # auto-generated static index
│   ├── catalog.json.sigstore.bundle  # signed catalog
│   └── provides-index.json        # reverse lookup: container/skill → plugin
├── schema/
│   └── plugin-entry.schema.json   # JSON Schema (from Pydantic models)
├── profiles/
│   └── seccomp/                   # pre-built seccomp profiles per capability
├── .github/
│   ├── workflows/
│   │   ├── build-catalog.yaml     # on merge: aggregate → catalog.json, sign with sigstore
│   │   └── validate-pr.yaml      # on PR: manifest consistency, compose analysis, image check, signature, duplicates
│   └── PULL_REQUEST_TEMPLATE.md
├── SECURITY.md                    # review checklist for submissions
└── README.md
```

### Per-plugin registry entry

```yaml
name: wifi-hacking
domain: pentest
description: "WiFi security assessment — WPA/WPA2 cracking, deauth, rogue AP"
author:
  name: someone
  github: someone
  sigstore_identity: someone@users.noreply.github.com
  trust_tier: verified             # unverified|verified|trusted|official
repo: https://github.com/someone/opentools-wifi-hacking
license: MIT
tags: [wifi, wireless, wpa, wpa2, deauth, aircrack]
min_opentools_version: "0.3.0"
provides:
  skills: [wifi-pentest]
  recipes: [wpa-crack, deauth-survey]
  containers: [aircrack-mcp]
requires:
  containers: [nmap-mcp]
  tools: [tshark]
versions:
  - version: 1.0.0
    ref: v1.0.0
    sha256: ab3f...
    yanked: false
  - version: 1.1.0-beta.1
    ref: v1.1.0-beta.1
    sha256: d8e2...
    prerelease: true
  - version: 0.9.0
    ref: v0.9.0
    sha256: c7d1...
    yanked: true
    yank_reason: "Compose fragment exposed Docker socket without declaration"
```

### Trust tiers

| Tier | Requirements | Privileges |
|---|---|---|
| unverified | Anyone | PR reviewed by maintainer before merge |
| verified | Signed releases, 3+ accepted plugins, no yanks | Own-plugin updates auto-merge after CI |
| trusted | Verified + maintainer endorsement | Can review other contributors' PRs |
| official | Maintained by Emperiusm | Featured in search, pre-installed |

### Static catalog

Built by GitHub Actions on every merge to `main`. Published as GitHub Release assets for CDN-backed delivery.

```json
{
  "generated_at": "2026-04-15T12:00:00Z",
  "schema_version": "1.0.0",
  "plugins": [
    {
      "name": "wifi-hacking",
      "description": "...",
      "author": "someone",
      "trust_tier": "verified",
      "domain": "pentest",
      "tags": ["wifi", "wireless", "wpa", "wpa2", "deauth", "aircrack"],
      "latest_version": "1.0.0",
      "repo": "https://github.com/someone/opentools-wifi-hacking",
      "min_opentools_version": "0.3.0",
      "provides": {"skills": ["wifi-pentest"], "recipes": ["wpa-crack", "deauth-survey"], "containers": ["aircrack-mcp"]},
      "requires": {"containers": ["nmap-mcp"], "tools": ["tshark"]},
      "yanked_versions": ["0.9.0"]
    }
  ]
}
```

**Provides index** (`dist/provides-index.json`): reverse lookup for dependency resolution and conflict detection.

```json
{
  "containers": {
    "aircrack-mcp": ["wifi-hacking", "wireless-audit"],
    "responder-mcp": ["ad-pentest"]
  },
  "skills": {
    "wifi-pentest": ["wifi-hacking"]
  },
  "recipes": {
    "wpa-crack": ["wifi-hacking"]
  }
}
```

**Pre-computed search index:** CI generates an inverted index (tokens → plugin names with TF weights) published alongside the catalog for ranked client-side search.

### Catalog delivery

- **URL:** `https://github.com/Emperiusm/opentools-registry/releases/latest/download/catalog.json`
- **Caching:** ETag-based conditional fetch with `httpx`. Local cache at `~/.opentools/registry-cache/catalog.json` with configurable TTL (default 1 hour).
- **Signing:** Catalog signed with sigstore using the registry repo's GitHub Actions OIDC identity. CLI verifies bundle before trusting.
- **Offline:** stale cache used with warning. Local path registries (`path:` in config) always work.

### Multi-registry support

```yaml
# Plugin config section in existing config
plugin:
  registries:
    - name: official
      url: https://github.com/Emperiusm/opentools-registry/releases/latest/download/catalog.json
      priority: 1
    - name: team-internal
      url: https://github.com/AcmeRedTeam/opentools-plugins/releases/latest/download/catalog.json
      priority: 2
      sigstore_identity: acme-bot@users.noreply.github.com
    - name: local
      path: /opt/opentools-plugins/catalog.json
      priority: 3
```

Resolution: search all registries, merge results, flag source. `--registry <name>` pins to a specific source.

### Registry CI validation (`validate-pr.yaml`)

1. **Manifest-registry consistency** — clone plugin repo at declared ref, verify `opentools-plugin.yaml` matches the registry entry
2. **Compose fragment static analysis** — parse and flag: `privileged`, `network_mode: host`, Docker socket mounts, undeclared `cap_add`
3. **Image existence check** — verify declared container image is pullable
4. **Signature verification** — verify plugin repo's tagged release is signed by declared sigstore identity
5. **Duplicate detection** — no existing plugin provides the same container/skill/recipe name
6. **Schema validation** — registry entry validates against published JSON Schema

## Install / Uninstall Flow

### Install pipeline

```
Resolve → Fetch (parallel, sparse git) → Verify (sigstore + SHA256)
  → Audit (risk tiers, y/N) → Stage (build version directory)
  → Validate (compose lint, skill parse, recipe schema)
  → Promote (atomic pointer write) → Register (SQLite) → Report
```

Failure at any point: delete staging directory. One cleanup action.

**1. Resolve.** Fetch catalog (ETag cache). Look up plugin. Build dependency tree (recursive). Check conflicts: does any installed plugin provide a container, skill, or recipe with the same name?

**2. Fetch.** Shallow clone at exact Git tag with sparse checkout (only declared paths):

```bash
git clone --depth 1 --branch v1.0.0 --filter=blob:none --sparse <repo>
cd <repo> && git sparse-checkout set skills/ recipes/ containers/ opentools-plugin.yaml CHANGELOG.md
```

Wrapped in `asyncio.create_subprocess_exec()` for parallel clones during bulk install. Content-addressed tarball stored in `~/.opentools/cache/`.

**3. Verify.** Sigstore signature verification against declared author identity. SHA256 tree hash against catalog's `sha256` field. Failure = abort, no `--force` override.

**4. Audit.** Parse manifest and compose fragment. Classify risks:

| Tier | Examples | Handling |
|---|---|---|
| Info | Adds N skills, N recipes | Shown always |
| Low (green) | New container on bridge network | Included in summary |
| Medium (yellow) | `network_mode: host`, `cap_add: [NET_RAW]` | Explicit in summary |
| Red | Docker socket mount, `privileged`, `/` volume, `SYS_ADMIN` | Per-item confirmation unless `--yes` |

Example output:

```
Plugin: wifi-hacking v1.0.0 by someone (verified)
Source: https://github.com/someone/opentools-wifi-hacking

  Adds:
    skill   wifi-pentest
    recipe  wpa-crack
    recipe  deauth-survey

  Containers:
    aircrack-mcp (ghcr.io/someone/aircrack-mcp:1.2.0)
      ⚠ cap_add: NET_RAW, NET_ADMIN
      ⚠ network_mode: host
      ✗ device mount: /dev/wifi0:/dev/wifi0

  Requires (already available):
    ✓ nmap-mcp (mcp-security-hub)
    ✓ tshark (system PATH)

Proceed? [y/N]
```

**5. Stage.** Build the version directory in `~/.opentools/staging/wifi-hacking/1.0.0/`. Copy skills, recipes, manifest. Generate compose project with sandbox hardening injected.

**6. Validate.** Lint the generated compose file. Parse skill markdown. Validate recipe JSON against schema. Verify compose doesn't exceed manifest sandbox (enforcement.py).

**7. Promote.** Move staging directory to `~/.opentools/plugins/wifi-hacking/1.0.0/`. Write `.active` file with `os.replace()` (atomic on both Linux and Windows).

**8. Register.** Write to `plugins.db`:

```sql
INSERT INTO installed_plugins (name, version, repo, registry, installed_at, signature_verified, last_update_check)
VALUES ('wifi-hacking', '1.0.0', 'https://...', 'official', '2026-04-15T...', true, null);
```

Record SHA256 hashes of all placed files in `plugin_integrity` table.

**9. Report.** Print summary and next steps.

### Docker-optional install

If Docker is unavailable at install time, install skills and recipes only. Skip compose generation. Warn:

```
⚠ Docker not available. Skills and recipes installed.
  Container aircrack-mcp will be set up when Docker is available.
  Run: opentools plugin setup wifi-hacking
```

### Uninstall

1. Stop plugin compose project: `docker compose down`
2. Optionally remove container images (ask unless `--yes` or `--keep-images`)
3. Check if other installed plugins depend on this one — warn if so, require `--force`
4. `shutil.rmtree(~/.opentools/plugins/wifi-hacking/)` (all versions)
5. `DELETE FROM installed_plugins WHERE name = 'wifi-hacking'`
6. Keep cache tarball unless `--purge`

### Concurrent install protection

```python
from filelock import FileLock

lock = FileLock(Path.home() / ".opentools" / "install.lock", timeout=30)
with lock:
    # entire install pipeline
```

### Orphan cleanup

On CLI startup, scan for directories in `~/.opentools/staging/`. If any exist, a prior install was interrupted. Clean them up with a warning.

## Sandboxing & Security

Defense in depth across three layers: container runtime, recipe execution, skill content.

### Layer 1: Container sandbox

**Default security profile** (injected into every plugin container):

```yaml
security_opt:
  - no-new-privileges:true
read_only: true
tmpfs:
  - /tmp:size=256m
mem_limit: 2g
cpus: 2.0
pids_limit: 256
labels:
  com.opentools.plugin: ${PLUGIN_NAME}
  com.opentools.version: ${PLUGIN_VERSION}
  com.opentools.sandbox: "enforced"
```

**Capability escalation** requires declaration in the manifest's `sandbox` section. The installer validates the compose fragment doesn't exceed declared permissions. Undeclared capabilities, volumes, or network modes in the compose fragment cause install abort.

**Mount blocklist** (never allowed, not overridable):

| Path | Reason |
|---|---|
| `/var/run/docker.sock` | Container escape |
| `/` (root) | Full host filesystem |
| `/etc/shadow`, `/etc/passwd` | Credential theft |
| `/proc`, `/sys` | Kernel interface |
| `~/.opentools/plugins.db` | Index tampering |
| `~/.ssh/` | Key theft |

**Per-capability seccomp profiles.** Declared capabilities map to pre-built seccomp profiles shipped with `plugin-core`:

```python
CAPABILITY_SECCOMP_MAP = {
    "NET_RAW": "profiles/net-raw.json",
    "NET_ADMIN": "profiles/net-admin.json",
    "SYS_PTRACE": "profiles/ptrace.json",
}
```

Plugin authors declare capabilities; the system derives the minimal seccomp profile.

### Network isolation

Each plugin gets its own Docker network: `opentools-plugin-<name>`. Containers within a plugin communicate on that network. Bridges to `mcp-security-hub_default` are only created for containers listed in `requires.containers`.

Two plugins' containers cannot communicate unless one explicitly depends on the other.

**Note:** `network_mode: host` overrides Docker network isolation entirely — the per-plugin network segment has no effect when host networking is active. This is why `network_mode: host` is classified as a yellow/red risk in the install audit. Org policies can block it entirely via `blocked_network_modes: [host]`.

**Generated compose:**

```yaml
networks:
  plugin-net:
    name: opentools-plugin-wifi-hacking
  hub:
    name: mcp-security-hub_default
    external: true

services:
  aircrack-mcp:
    image: ghcr.io/someone/aircrack-mcp:1.2.0
    networks:
      - plugin-net
      - hub
    # sandbox defaults injected...
```

**Network fallback.** If `mcp-security-hub_default` doesn't exist, create `opentools-plugins` network as fallback. Bridge when hub starts.

### Egress control

Default: no internet egress. Plugin containers are on internal networks with no gateway.

Plugins requiring internet declare `egress: true` in the manifest sandbox section. Flagged as yellow risk at install time. v2 adds `egress_domains` allowlist with DNS proxy enforcement.

### Layer 2: Recipe execution sandbox

**Scoped execution:** Recipes from a plugin can only `docker exec` into:
1. Containers provided by that plugin
2. Containers listed in the plugin's `requires.containers`
3. Built-in `mcp-security-hub` containers

**Structural command validation** via `shlex.split()`:

```python
SHELL_OPERATORS = {";", "&&", "||", "|", ">", ">>", "<", "$(", "`"}

def validate(command: str, allowed_containers: set[str]) -> list[Violation]:
    # Reject shell metacharacters entirely for marketplace recipes
    for op in SHELL_OPERATORS:
        if op in command:
            return [Violation(severity="red", message=f"Shell operator '{op}' not allowed")]

    tokens = shlex.split(command)
    if tokens[0:2] != ["docker", "exec"]:
        return [Violation(severity="red", message="Must use 'docker exec <container>' format")]

    container = extract_container_name(tokens[2:])
    if container not in allowed_containers:
        return [Violation(severity="red", message=f"Undeclared container: {container}")]
    return []
```

Shell operators are flatly rejected for marketplace recipes. Built-in recipes (in `packages/plugin/recipes.json`) are trusted.

### Layer 3: Skill content (advisory)

Static regex scan for red flags at install time: pipe-to-shell, encoded payload execution, privilege escalation patterns. These are **warnings shown during audit**, not hard blocks — legitimate security skills contain offensive commands. The real enforcement boundary for skills is Claude's authorization gates + the container sandbox.

### Org-level policy overrides

```yaml
# sandbox-policy.yaml
enforced_by: "Acme Red Team SOPs"

container_defaults:
  mem_limit: 4g
  registry_mirror: registry.acme.internal

blocked_capabilities: [SYS_ADMIN, SYS_PTRACE]
blocked_network_modes: [host]
require_egress_allowlist: true
max_volume_mounts: 3
```

Loaded by `sandbox.py` as a final layer. Plugin manifest says `cap_add: [SYS_PTRACE]`, org policy blocks it — install fails with a clear message pointing to the policy file.

### Runtime integrity

SHA256 hashes of all placed files recorded at install time in `plugin_integrity` table. Verified before `docker compose up` and on-demand via `opentools plugin verify`. Tampering flagged in `plugin list`.

### Supply chain summary

```
Registry PR review (human) + CI validation
  → Signed catalog (sigstore, repo OIDC)
    → Plugin signature verification (sigstore, author identity)
      → Compose ⊆ manifest sandbox check
        → Blocklist enforcement
          → Risk-tiered user audit
            → Runtime: container sandbox + network isolation + egress control
              → Runtime: recipe scoped execution
                → Runtime: integrity verification on launch
```

## CLI Commands

All commands under `opentools plugin`. Supports `--json` for structured output. Uses `rich` for terminal output (tables, styled text, progress bars). Tab completion via Typer completers.

### Command reference

| Command | Purpose | Network | Modifies state |
|---|---|---|---|
| `search <query>` | Search registry catalog | cache-first | no |
| `info <name>` | Show plugin details | cache-first | no |
| `install <name...>` | Install from registry | yes (clone) | yes |
| `uninstall <name>` | Remove plugin | no | yes |
| `list` | Show installed plugins | no | no |
| `update <name>` | Update to new version | yes (clone) | yes |
| `up <name>` | Start containers | no | Docker |
| `down <name>` | Stop containers | no | Docker |
| `logs <name>` | View container logs | no | no |
| `exec <name> <ctr> <cmd>` | Exec into container (container-scoped, no shell-op restriction) | no | Docker |
| `pull <name>` | Pull container images | yes (Docker) | Docker |
| `verify <name>` | Check file integrity | no | no |
| `validate .` | Validate local plugin (author tool) | no | no |
| `init <name>` | Scaffold new plugin project | no | filesystem |
| `link <path>` | Symlink local dev plugin | no | symlink |
| `unlink <name>` | Remove dev symlink | no | symlink |
| `setup <name>` | Re-run container setup | no | filesystem |
| `export <name>` | Export to .otp archive | no | filesystem |
| `import <archive>` | Install from archive | no | yes |
| `freeze` | Generate lockfile from current state | no | filesystem |
| `sync` | Sync to lockfile or plugin set | conditional | yes |
| `rollback <name>` | Repoint to previous version | no | pointer + Docker |
| `prune` | Delete old version directories | no | filesystem |

### Key flags

- `--yes` — skip audit confirmation (all modifying commands)
- `--json` — structured output (all commands)
- `--registry <name>` — pin to specific registry (search, info, install)
- `--domain <name>` — filter by domain (search, list)
- `--pre` — include pre-release versions (search, install, update)
- `--all` — bulk operations (up, down, pull, update, export)
- `--pull` — eagerly pull images (install, up)
- `--keep-images` — don't remove images on uninstall
- `--purge` — remove cache on uninstall
- `--refresh` — force catalog re-fetch (search)
- `--check-updates` — check for available updates (list)
- `--verify` — run integrity checks (list)
- `--version <ver>` — pin version (install, update, info)
- `--strict` — treat warnings as errors (validate)
- `--accept` — re-record hashes for modified files (verify)

### Performance design

- `list` reads only from `plugins.db` by default — instant. `--check-updates` and `--verify` are opt-in.
- `search` uses local catalog cache — instant unless `--refresh`. Stale cache shown immediately with age note.
- Update check hook runs at most once per hour, non-blocking, when a plugin skill/recipe is invoked. One-line notification.
- Bulk install: single catalog fetch, parallel git clones via `asyncio.gather()`, combined audit, sequential promote.

### Offline behavior

| Scenario | Behavior |
|---|---|
| No internet, cache exists | Use stale cache, warn with age |
| No internet, no cache | Clear error: add local registry or connect |
| Registry unreachable, cache exists | Use stale cache, warn |
| Rate limited | Back off, use stale cache |

### Error handling

```python
class PluginError(Exception):
    def __init__(self, message: str, detail: str = "", hint: str = ""):
        self.message = message    # one-line summary
        self.detail = detail      # technical detail (--verbose)
        self.hint = hint          # exact command to fix
```

Every fixable error includes a `hint` with the exact command. No dead ends.

### Existing CLI integration

- `opentools containers status` shows both built-in and plugin containers, distinguished by source
- `opentools recipe list` scans marketplace plugin recipe directories alongside built-in recipes
- `opentools preflight --skill <name>` checks plugin container availability

## Update Lifecycle

### Version resolution

- `install wifi-hacking` — latest non-yanked
- `install wifi-hacking@1.0.0` — exact pin
- `update wifi-hacking` — latest non-yanked
- `update wifi-hacking@1.1.0` — specific version (allows downgrade)
- `install wifi-hacking --pre` — latest including pre-releases

Installed plugins are pinned to exact versions. Semver ranges exist only in `requires.plugins` for inter-plugin dependencies.

### Update flow

1. Fetch new version to staging (same as install pipeline)
2. Diff against installed: new/removed/modified files, sandbox changes
3. Show changelog between installed and target version
4. If user modified installed files: per-file diff, choice to overwrite/keep
5. User confirms
6. Stop containers
7. Promote new version directory, update `.active` pointer (atomic)
8. Rebuild compose if fragment changed
9. Restart containers
10. Update `plugins.db`

### Rollback

Instant — repoint `.active` to previous version directory:

```
$ opentools plugin rollback wifi-hacking
Available versions: 1.1.0 (active), 1.0.0
Roll back to 1.0.0? [Y/n]
```

No file copying. Previous version directory is intact. Auto-prune keeps active + N previous versions (default: 1, configurable).

### Yanked versions

- Install blocked unless `--allow-yanked`
- Already-installed yanked: `list` shows `⚠ yanked`, notifies on every CLI invocation
- Yank reason displayed prominently

### Pre-release versions

Hidden by default. `--pre` flag enables visibility and installation. Plugin sets can opt in via semver pre-release ranges.

## Team Workflows

### Lockfile

`opentools plugin freeze > plugin-lock.yaml` captures exact environment state:

```yaml
generated_at: "2026-04-15T14:30:00Z"
opentools_version: "0.3.0"
plugins:
  wifi-hacking:
    version: "1.0.0"
    registry: official
    repo: https://github.com/someone/opentools-wifi-hacking
    ref: v1.0.0
    sha256: ab3f...
    signature_identity: someone@users.noreply.github.com
```

`opentools plugin sync --lockfile plugin-lock.yaml` reproduces the exact environment. Check lockfile into engagement repo for reproducibility.

### Plugin sets

Declarative team toolkit:

```yaml
# team-toolkit.yaml
name: "Acme Red Team Standard Kit v2"
min_opentools_version: "0.3.0"
registries: [official, team-internal]
plugins:
  wifi-hacking: ">=1.0.0, <2.0.0"
  ad-pentest: "1.2.0"
  cloud-recon: "latest"
sandbox_policy: ./acme-sandbox-policy.yaml
```

`opentools plugin sync --set team-toolkit.yaml` resolves ranges to specific versions, installs/updates/removes to match.

`opentools plugin sync --set team-toolkit.yaml --freeze plugin-lock.yaml` resolves + generates pinned lockfile.

### Portable archives

`opentools plugin export wifi-hacking` produces `wifi-hacking-1.0.0.otp` (gzipped tarball + sigstore bundle). `opentools plugin import wifi-hacking-1.0.0.otp` installs from archive with signature verification. Air-gap story: download online, carry on USB, import in lab.

## Plugin Authoring

### Development workflow

```
1. opentools plugin init my-scanner        # scaffold project
2. cd my-scanner && edit files             # develop
3. opentools plugin link .                 # live dev mode
4. opentools plugin up my-scanner          # test containers
5. opentools plugin validate .             # check everything
6. git tag v1.0.0 && git push --tags      # publish (Actions auto-signs)
7. Submit PR to registry repo              # CI validates, maintainer reviews
```

### Scaffold (`plugin init`)

Generates: manifest template, skill template, empty recipes/containers dirs, GitHub Actions signing workflow, README.

### Link mode

Symlink to `~/.opentools/plugins/`. Changes reflected immediately. Skips integrity checks and signature verification. Shown as `linked` in `plugin list`.

### Validate (`plugin validate .`)

Runs all install-time checks locally: manifest schema, file existence, compose syntax, sandbox compliance, recipe command structure, skill content advisory scan.

## Configuration

Plugin config is a section within the existing `ConfigLoader` system:

```yaml
# Existing config file
plugin:
  registries:
    - name: official
      url: https://github.com/Emperiusm/opentools-registry/releases/latest/download/catalog.json
      priority: 1
  catalog_ttl: 3600
  max_cache_size: 10g
  keep_versions: 1
  update_check_frequency: 3600
  sandbox_policy_file: null
  network_primary: mcp-security-hub_default
  network_fallback: opentools-plugins
```

### Database schema

```sql
CREATE TABLE installed_plugins (
    name TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    repo TEXT NOT NULL,
    registry TEXT NOT NULL,
    installed_at TEXT NOT NULL,
    signature_verified BOOLEAN NOT NULL,
    last_update_check TEXT,
    mode TEXT NOT NULL DEFAULT 'registry'  -- registry|linked|imported
);

CREATE TABLE plugin_integrity (
    plugin_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (plugin_name, file_path)
);

CREATE INDEX idx_integrity_plugin ON plugin_integrity(plugin_name);
```

## Testing Strategy

### Unit tests (pytest, no Docker)

| Module | Key test areas |
|---|---|
| `models.py` | Valid/invalid manifests, Pydantic validation errors, unknown fields ignored |
| `registry.py` | ETag caching, multi-registry merge, offline fallback, rate limit handling |
| `resolver.py` | Linear/diamond/circular deps, conflict detection, version range satisfaction |
| `compose.py` | Single/multi container, network config, sandbox defaults, org policy |
| `sandbox.py` | Undeclared capabilities, blocklist, seccomp mapping |
| `enforcement.py` | Shell operator rejection, container scoping, shlex parsing |
| `verify.py` | Valid/invalid signatures, wrong identity |
| `index.py` | CRUD, integrity hashes, concurrent access |

### Property-based tests (hypothesis)

- Manifest parsing: random dicts never crash, always raise `ValidationError`
- Resolver: random dependency graphs always terminate, cycles detected, resolution consistent

### Integration tests (Docker required)

- Full install from local path → verify files placed, compose valid, DB entry
- Install with dependencies → parallel resolution
- Uninstall with running containers → cleanup
- Update with compose change → old stopped, new started
- Network isolation → plugin containers can't reach other plugins
- Sandbox enforcement → blocked mounts rejected
- Export/import round-trip → signature preserved

### Performance benchmarks

| Benchmark | Target |
|---|---|
| Catalog parse (1000 plugins) | <50ms |
| Search inverted index | <10ms |
| Dependency resolution (depth 10) | <100ms |
| Install from local fixture | <2s |
| Integrity check (50 plugins) | <500ms |

### Test fixtures

```
tests/fixtures/
├── valid-plugin/        # complete plugin with all artifact types
├── minimal-plugin/      # manifest + one recipe, no containers
├── malicious-plugin/    # docker socket mount, shell ops, red flags
├── signed-plugin/       # includes sigstore bundle
└── catalog.json         # sample registry catalog
```

## Key Dependencies

| Library | Purpose |
|---|---|
| `pydantic` v2 | Manifest & catalog model validation |
| `httpx` | Async HTTP with ETag caching for catalog fetch |
| `sigstore` | Keyless signature verification (author + catalog) |
| `rich` | Terminal output: tables, styled text, progress |
| `filelock` | Cross-platform concurrent install protection |
| `shlex` | Recipe command structural parsing (stdlib) |
| `hypothesis` | Property-based fuzz testing |

## v1.1: Web Marketplace (deferred)

FastAPI routes in `packages/web/backend/app/routes/plugins.py` wrapping `opentools_plugin_core`. Vue frontend with:
- Browse/search catalog with faceted filters
- Plugin detail pages with README, changelog, sandbox summary
- Install/uninstall/update from the UI
- Installed plugin management dashboard

The `plugin-core` library means all business logic is shared — the web layer is purely presentation.

## Migration path: Git registry → self-hosted

When community scale exceeds PR review capacity (~500+ plugins):
1. Stand up a lightweight API (FastAPI service or GitHub App)
2. API replaces the static catalog — serves search, handles submissions, stores metadata
3. CLI's `registry.py` already supports URL-based registries — point to the new API
4. Plugin manifest format, signing, sandboxing, install flow remain unchanged
5. The Git registry becomes the "official curated" tier; the API handles the long tail
