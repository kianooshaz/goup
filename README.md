# goup

`goup` is an interactive terminal UI for inspecting and updating Go module dependencies, with an integrated security check.

It discovers available updates, classifies them as patch, minor, major, or unknown, shows which installed versions have known vulnerabilities, lets you select which dependencies to upgrade, and runs `go mod tidy` after the updates.

## Requirements

- Go 1.27 or later
- A Go module containing a `go.mod` file
- Normal Go module/network access for discovering and downloading updates

## Installation

Install the latest version with:

```sh
go install github.com/kianooshaz/goup/cmd/goup@latest
```

Alternatively, build from a checkout:

```sh
go build -o goup ./cmd/goup
```

## Usage

Run `goup` from the directory containing your Go module:

```sh
goup
```

The command discovers direct dependency updates and opens the interactive interface when updates are available.

```text
goup — interactive Go dependency updater

Usage:
  goup [flags]

Flags:
  --indirect      Include indirect dependencies
  --security      Show only dependencies with security issues
  --no-security   Skip the vulnerability check
  --dir string    Go module directory (default: current directory)
  --version       Show version
  -h, --help      Show help
```

Examples:

```sh
# Update dependencies in the current module
goup

# Include indirect dependencies
goup --indirect

# Focus on dependencies with known vulnerabilities
goup --security

# Skip the vulnerability check entirely
goup --no-security

# Operate on another Go module
goup --dir /path/to/module

# Show the installed version
goup --version
```

The selected directory must contain a `go.mod` file. If no updates are available, `goup` exits without starting the TUI. Interactive operation requires a terminal attached to standard input.

## Interactive controls

| Key | Action |
| --- | --- |
| `↑` / `↓`, `j` / `k` | Navigate dependencies |
| `Space` | Toggle the current dependency |
| `a` | Select all dependencies |
| `n` | Select no dependencies |
| `/` | Search dependencies by module path |
| `d` | Show security details for the current dependency |
| `Enter` | Continue to review or start upgrades |
| `q` / `Esc` | Quit, clear search, or return from the detail view |
| `Ctrl+C` | Quit |

After confirmation, `goup` runs `go get` for each selected dependency and then runs `go mod tidy`. Upgrade failures are reported individually while processing continues for the remaining selections.

## Search

Press `/` on the dependency list to filter by module path. Matching is case-insensitive substring matching against module paths and updates live as you type — entirely in memory, with no network or re-discovery.

### Example session

Start with the full update list:

```text
  8 updates available

  ◯ github.com/gin-gonic/gin     v1.9.1  → v1.10.0   direct    ✓
  ◯ github.com/google/uuid       v1.6.0  → v1.7.0    direct    ✓
  ◯ golang.org/x/net             v0.24.0 → v0.30.0   direct    🔴 HIGH
  ◯ golang.org/x/sync            v0.6.0  → v0.8.0    direct    ✓
  ◯ golang.org/x/text            v0.9.0  → v0.10.0   direct    ✓

  ↑/↓ Navigate  Space Select  / Search  d Details  Enter Upgrade  q Quit
```

Press `/` and type `golang.org/x` — the list narrows on every keystroke:

```text
Search: golang.org/x█

  ◯ golang.org/x/net             v0.24.0 → v0.30.0   direct    🔴 HIGH  ✓ fixed by upgrade
  ◯ golang.org/x/sync            v0.6.0  → v0.8.0    direct    ✓
  ◯ golang.org/x/text            v0.9.0  → v0.10.0   direct    ✓

  3 of 8 dependencies match

  Type Search  ↑/↓ Navigate  Space Select  Enter Apply  Esc Clear
```

Search finds what you meant without the full path — `redis` matches
`github.com/redis/go-redis/v9`, `x/sync` matches `golang.org/x/sync`,
and `GOLANG.ORG/X` matches all three `golang.org/x/*` modules. Paths
whose segment starts with the query rank first:

```text
Search: redis█

  ◯ github.com/redis/go-redis/v9   v9.5.1 → v9.7.0   indirect   ✓
  ◯ github.com/foo/redis-wrapper   v1.0.2 → v1.1.0   direct     ✓

  2 of 8 dependencies match
```

Press `Enter` to keep the filter applied while you work, or `Esc` to
clear it and restore the full list:

```text
  Search cleared.

  8 updates available

  ◯ github.com/gin-gonic/gin     v1.9.1  → v1.10.0   direct    ✓
  ...
```

### Search + security + selection

Security badges and direct/indirect labels stay on filtered rows, and
selections belong to the dependency — not to its position — so they
survive filtering. Select while filtered, clear, and everything you
ticked is still ticked:

```text
Search: golang.org/x█

  ◯ golang.org/x/net             v0.24.0 → v0.30.0   direct    🔴 HIGH
  ◉ golang.org/x/sync            v0.6.0  → v0.8.0    direct    ✓
  ◯ golang.org/x/text            v0.9.0  → v0.10.0   direct    ✓

  3 of 8 dependencies match
  ● 1 selected
```

With `--security`, search narrows the already-filtered vulnerable list;
with `--indirect`, both direct and indirect matches appear.

## Security check

When updates are listed, `goup` checks each installed version against the official Go vulnerability data served through the OSV ecosystem API (`api.osv.dev`). The list shows a severity badge per dependency:

```text
  ◯ github.com/foo/bar   v1.4.2 → v1.4.5   direct    🟠 HIGH (1)  ✓ fixed by upgrade
  ◯ github.com/foo/baz   v1.2.0 → v1.3.0   direct    ✓
```

- Dependencies with vulnerabilities are sorted to the top; the rest keep the normal order.
- The header summarizes how many updates contain security fixes, by severity.
- Nothing is ever pre-selected — the user stays in control.
- Pressing `d` on a dependency opens a detail view listing every vulnerability with its ID, severity, fixed version, and whether the available upgrade resolves it. The tool compares against the concrete fixed version, so it can also warn when the latest version is still affected or when no fixed version exists.
- If the vulnerability database cannot be reached, affected rows show `⚠ security check failed` instead of a clean bill of health. A failed check is never presented as "no known issues".
- Vulnerabilities found at the module level are labeled *known vulnerabilities*: the lightweight scan does not analyze reachability. A future deep scan (govulncheck-style call graph analysis) will distinguish code that is actually called by your application.
- Checks touch public modules only by module path and version — no source code or project contents are sent anywhere. Modules that cannot be hosted publicly (dotless first path element) are skipped and shown as `private module: not checked`.
- Results are cached on disk for 24 hours (`~/Library/Caches/goup` / `~/.cache/goup` on Linux) so repeated runs stay fast.

The severity badge vocabulary is `🔴 CRITICAL`, `🟠 HIGH`, `🟡 MEDIUM`, `🔵 LOW`, `⚪ UNKNOWN` (severity not provided by the database — never guessed), and `✓` for no known issues.

## Development

Clone the repository and run the application directly:

```sh
git clone https://github.com/kianooshaz/goup.git
cd goup
go run ./cmd/goup
```

Run the test suite:

```sh
go test ./...
```

Run additional checks:

```sh
go vet ./...
go build ./cmd/goup
```

## Versioned builds

Development builds report `dev` by default. A release version can be embedded at build time with Go linker flags:

```sh
go build \
  -ldflags "-X github.com/kianooshaz/goup/internal/cli.Version=v1.0.0" \
  -o goup \
  ./cmd/goup
```

## How it works

1. Runs `go list -m -u -json all` for the selected module.
2. Filters out the main module, dependencies without available updates, and indirect dependencies unless `--indirect` is used.
3. Sorts direct dependencies before indirect dependencies.
4. Checks each installed version for known vulnerabilities (unless `--no-security`).
5. Presents available updates in the terminal UI, with vulnerable dependencies first.
6. Runs `go get <module>@<version>` for each confirmed selection.
7. Runs `go mod tidy` to clean up module files.
