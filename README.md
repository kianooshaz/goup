# goup

`goup` is an interactive terminal UI for inspecting and updating Go module dependencies.

It discovers available updates, classifies them as patch, minor, major, or unknown, lets you select which dependencies to upgrade, and runs `go mod tidy` after the updates.

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
  --indirect    Include indirect dependencies
  --dir string  Go module directory (default: current directory)
  --version     Show version
  -h, --help    Show help
```

Examples:

```sh
# Update dependencies in the current module
goup

# Include indirect dependencies
goup --indirect

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
| `Enter` | Continue to review or start upgrades |
| `q` / `Esc` | Quit or cancel |
| `Ctrl+C` | Quit |

After confirmation, `goup` runs `go get` for each selected dependency and then runs `go mod tidy`. Upgrade failures are reported individually while processing continues for the remaining selections.

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
4. Presents available updates in the terminal UI.
5. Runs `go get <module>@<version>` for each confirmed selection.
6. Runs `go mod tidy` to clean up module files.
