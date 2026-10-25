#!/bin/sh
# pktforge installer for macOS / Linux / WSL / Git-Bash.
#   curl -fsSL https://raw.githubusercontent.com/Cosmos-0118/pktforge/main/install.sh | sh
#   ... | sh -s -- --with-skill     also installs the Claude skill (~/.claude/skills/pktforge)
#   ... | sh -s -- --uninstall
# Env: PKTFORGE_REPO (owner/name), PKTFORGE_REF (branch/tag), PKTFORGE_HOME, PKTFORGE_BIN,
#      PKTFORGE_SRC (local folder, .tar.gz or URL to install from instead of GitHub)
# Needs Python 3.10+ and curl or wget. No pip, no root, nothing else is touched.
set -eu

REPO="${PKTFORGE_REPO:-Cosmos-0118/pktforge}"
REF="${PKTFORGE_REF:-main}"
HOME_DIR="${PKTFORGE_HOME:-$HOME/.pktforge}"
BIN_DIR="${PKTFORGE_BIN:-$HOME/.local/bin}"
WITH_SKILL="${PKTFORGE_SKILL:-0}"
UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --with-skill) WITH_SKILL=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,9p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
die() { printf 'pktforge install: %s\n' "$*" >&2; exit 1; }

if [ "$UNINSTALL" = 1 ]; then
  rm -rf "$HOME_DIR" "$BIN_DIR/pktforge" "$HOME/.claude/skills/pktforge"
  say "pktforge removed."
  exit 0
fi

# ---- python >= 3.10
PY=""
for c in python3 python py; do
  if command -v "$c" >/dev/null 2>&1 &&
     "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
    PY="$(command -v "$c")"; break
  fi
done
[ -n "$PY" ] || die "Python 3.10+ not found. Install it (macOS: brew install python; Debian/Ubuntu: sudo apt install python3) and re-run."

# ---- fetch
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
SRC_DIR="$TMP/src"; mkdir -p "$SRC_DIR"
fetch() { # url dest
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else die "need curl or wget"; fi
}
SRC="${PKTFORGE_SRC:-}"
if [ -n "$SRC" ] && [ -d "$SRC" ]; then
  say "Installing from folder $SRC"
  cp -R "$SRC/." "$SRC_DIR/"
else
  if [ -n "$SRC" ]; then URL="$SRC"; else URL="https://github.com/$REPO/archive/refs/heads/$REF.tar.gz"; fi
  say "Downloading $URL"
  case "$URL" in
    http://*|https://*|ftp://*) fetch "$URL" "$TMP/pktforge.tgz" ;;
    *) cp "$URL" "$TMP/pktforge.tgz" ;;
  esac
  tar -xzf "$TMP/pktforge.tgz" -C "$SRC_DIR" --strip-components=1 || die "could not unpack the archive"
fi
[ -f "$SRC_DIR/pktforge/__init__.py" ] || die "archive does not contain the pktforge package"

# ---- install
rm -rf "$HOME_DIR/src"
mkdir -p "$HOME_DIR" "$BIN_DIR"
cp -R "$SRC_DIR" "$HOME_DIR/src"
find "$HOME_DIR/src" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true

cat > "$BIN_DIR/pktforge" <<EOF
#!/bin/sh
PYTHONPATH="$HOME_DIR/src\${PYTHONPATH:+:\$PYTHONPATH}" exec "$PY" -m pktforge "\$@"
EOF
chmod +x "$BIN_DIR/pktforge"

if [ "$WITH_SKILL" = 1 ]; then
  mkdir -p "$HOME/.claude/skills/pktforge"
  cp "$HOME_DIR/src/SKILL.md" "$HOME/.claude/skills/pktforge/SKILL.md"
  say "Claude skill installed: ~/.claude/skills/pktforge"
fi

"$BIN_DIR/pktforge" doctor || die "installed, but the self-test failed (run: $BIN_DIR/pktforge doctor)"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say ""; say "Add pktforge to your PATH:"; say "  export PATH=\"$BIN_DIR:\$PATH\"   # put this in ~/.bashrc or ~/.zshrc" ;;
esac
say ""
say "Done. Try:  pktforge guide"
