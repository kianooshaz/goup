#!/usr/bin/env bash
# Drives the goup TUI inside a pseudo-terminal so it can be scripted:
# the keystrokes below are typed at the UI in order.
#
#   Usage: demo.sh <goup-binary> [goup flags...]
#
# The pty is required because goup refuses to start without a terminal.
set -uo pipefail

GOUP="${1:?usage: demo.sh <goup-binary> [flags...]}"
shift

# The key sequence: wait for discovery, press "d" to open the security
# detail for the first row, read it, then quit.
KEYS='sleep 14; printf "d"; sleep 4; printf "q"; sleep 1; printf "q"'

# script(1) provides the pty; the timing/keys are piped into its stdin.
eval "$KEYS" | script -q /dev/null "$GOUP" "$@" 2>&1
