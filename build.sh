#!/usr/bin/env bash
# Build the microarray driver into a local libfprint tree.
# By default does NOT install over the system library (safe for Arch).
#
# Usage:
#   ./build.sh              # build + copy .so into ./build/
#   INSTALL=1 ./build.sh    # also install to system libdir (with backup)
#
# Override paths:
#   LIBFPRINT_SRC=~/libfprint LIBDIR=/usr/lib INSTALL=1 ./build.sh
set -euo pipefail

DRIVER_SRC="$(dirname "$(realpath "$0")")/src/microarray.c"
REPO_DIR="$(dirname "$(realpath "$0")")"
LIBFPRINT_SRC="${LIBFPRINT_SRC:-$HOME/libfprint}"
DEST="$LIBFPRINT_SRC/libfprint/drivers/microarray/microarray.c"
BUILD="$LIBFPRINT_SRC/build"
SO_NAME="libfprint-2.so.2.0.0"

if [[ ! -f "$DRIVER_SRC" ]]; then
  echo "error: driver source not found: $DRIVER_SRC" >&2
  exit 1
fi
if [[ ! -d "$LIBFPRINT_SRC/libfprint" ]]; then
  echo "error: libfprint source tree not found at $LIBFPRINT_SRC" >&2
  echo "  Clone libfprint and set LIBFPRINT_SRC if needed." >&2
  exit 1
fi

# Arch packages libfprint under /usr/lib. /usr/lib64 may exist as the same
# inode or a separate copy — prefer the pacman path unless LIBDIR is set.
if [[ -z "${LIBDIR:-}" ]]; then
  if [[ -e /usr/lib/$SO_NAME ]]; then
    LIBDIR=/usr/lib
  elif [[ -e /usr/lib64/$SO_NAME ]]; then
    LIBDIR=/usr/lib64
  else
    LIBDIR=/usr/lib
  fi
fi
TARGET="$LIBDIR/$SO_NAME"

echo "==> Copying driver source..."
mkdir -p "$(dirname "$DEST")"
cp "$DRIVER_SRC" "$DEST"

echo "==> Building..."
if [[ ! -d "$BUILD" ]]; then
  echo "error: build directory missing: $BUILD (run meson setup first)" >&2
  exit 1
fi
ninja -C "$BUILD" "libfprint/$SO_NAME"

echo "==> Saving build output to repo..."
mkdir -p "$REPO_DIR/build"
cp "$BUILD/libfprint/$SO_NAME" "$REPO_DIR/build/$SO_NAME"

if [[ "${INSTALL:-0}" != "1" ]]; then
  echo "==> Skipping system install (built artifact: $REPO_DIR/build/$SO_NAME)"
  echo "    To install on Arch: INSTALL=1 ./build.sh"
  echo "    Target would be: $TARGET"
  exit 0
fi

echo "==> Installing to $TARGET (requires sudo)..."
if [[ ! -e "$TARGET" ]]; then
  echo "error: existing library not found at $TARGET" >&2
  exit 1
fi
BACKUP="$TARGET.bak.$(date +%Y%m%d%H%M%S)"
sudo cp -a "$TARGET" "$BACKUP"
echo "    Backup: $BACKUP"
sudo systemctl stop fprintd 2>/dev/null || true
sudo cp "$BUILD/libfprint/$SO_NAME" "$TARGET"
echo "==> Done. Start fprintd when ready (e.g. systemctl start fprintd)."
