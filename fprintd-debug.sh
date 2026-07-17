#!/usr/bin/env bash
# Run fprintd in the foreground with full debug logging and capture output.
# Usage: ./fprintd-debug.sh [logfile]
#   logfile defaults to docs/fprintd-$(date +%Y%m%d-%H%M%S).log
set -euo pipefail

REPO_DIR="$(dirname "$(realpath "$0")")"
LOGDIR="$REPO_DIR/docs"
LOGFILE="${1:-$LOGDIR/fprintd-$(date +%Y%m%d-%H%M%S).log}"

# Arch: /usr/lib/fprintd ; some distros use /usr/libexec/fprintd
FPRINTD_BIN="${FPRINTD_BIN:-}"
if [[ -z "$FPRINTD_BIN" ]]; then
  for candidate in /usr/lib/fprintd /usr/libexec/fprintd; do
    if [[ -x "$candidate" ]]; then
      FPRINTD_BIN="$candidate"
      break
    fi
  done
fi
if [[ -z "${FPRINTD_BIN:-}" ]]; then
  echo "error: fprintd binary not found (tried /usr/lib/fprintd, /usr/libexec/fprintd)" >&2
  exit 1
fi

mkdir -p "$LOGDIR"

echo "==> Stopping fprintd service..."
sudo systemctl stop fprintd 2>/dev/null || true

echo "==> Starting $FPRINTD_BIN with debug logging (Ctrl-C to stop)"
echo "==> Log: $LOGFILE"
echo ""

sudo G_MESSAGES_DEBUG=all "$FPRINTD_BIN" -t 2>&1 | tee "$LOGFILE"
