#!/bin/bash
set -e

# ─── OpenClaw Security Monitor — Installer ──────────────────────────────────
# Clones the repository into the OpenClaw skills directory.
# Does NOT auto-execute scans, remediation, or IOC updates.
# Does NOT install cron jobs or LaunchAgents.
#
# Usage:
#   git clone https://github.com/adibirzu/openclaw-security-monitor.git && cd openclaw-security-monitor && ./install.sh
#
# What this script does:
#   1. Checks prerequisites (bash, curl, node, git)
#   2. Copies/clones the skill into ~/.openclaw/workspace/skills/
#   3. Makes scripts executable
#   That's it. No auto-updates, no background services, no system modifications.

REPO="https://github.com/adibirzu/openclaw-security-monitor.git"
OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
SKILLS_DIR="$OPENCLAW_HOME/workspace/skills"
SKILL_NAME="openclaw-security-monitor"
INSTALL_DIR="$SKILLS_DIR/$SKILL_NAME"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       OpenClaw Security Monitor — Installer v5.1.1         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Check prerequisites ────────────────────────────────────────────────────
missing=""
for cmd in bash curl node git; do
  if ! command -v "$cmd" &>/dev/null; then
    missing="$missing $cmd"
  fi
done
if [ -n "$missing" ]; then
  echo "ERROR: Missing required tools:$missing"
  echo "Please install them and re-run this script."
  exit 1
fi

# ─── Detect OpenClaw installation ───────────────────────────────────────────
if [ ! -d "$OPENCLAW_HOME" ]; then
  echo "WARNING: OpenClaw home not found at $OPENCLAW_HOME"
  echo "The security monitor will be installed but some checks may not apply."
  echo ""
fi

# ─── Install or update ─────────────────────────────────────────────────────
mkdir -p "$SKILLS_DIR"

if [ -d "$INSTALL_DIR/.git" ]; then
  echo "→ Existing installation found. Updating..."
  cd "$INSTALL_DIR"
  git pull --ff-only origin main 2>/dev/null || {
    echo "  Could not fast-forward. Backing up and reinstalling..."
    mv "$INSTALL_DIR" "${INSTALL_DIR}.bak.$(date +%s)"
    git clone "$REPO" "$INSTALL_DIR"
  }
else
  if [ -d "$INSTALL_DIR" ]; then
    echo "→ Non-git installation found. Backing up and reinstalling..."
    mv "$INSTALL_DIR" "${INSTALL_DIR}.bak.$(date +%s)"
  fi
  echo "→ Cloning from GitHub..."
  git clone "$REPO" "$INSTALL_DIR"
fi

# ─── Make scripts executable ───────────────────────────────────────────────
chmod +x "$INSTALL_DIR/scripts/"*.sh
chmod +x "$INSTALL_DIR/scripts/remediate/"*.sh 2>/dev/null || true

# ─── Summary ──────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  Installation Complete!                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Installed to: $INSTALL_DIR"
echo ""
echo "  Next steps:"
echo "    # Run a 41-point security scan (read-only, no system changes)"
echo "    $INSTALL_DIR/scripts/scan.sh"
echo ""
echo "    # Preview what remediation would do (dry-run, no changes)"
echo "    $INSTALL_DIR/scripts/remediate.sh --dry-run"
echo ""
echo "    # Start the web dashboard (read-only, localhost:18800)"
echo "    node $INSTALL_DIR/dashboard/server.js"
echo ""
echo "    # Update IOC database (fetches from this project's GitHub)"
echo "    $INSTALL_DIR/scripts/update-ioc.sh"
echo ""
echo "  Optional (manual, requires explicit user action):"
echo "    # Scan installed ClawHub skills"
echo "    $INSTALL_DIR/scripts/clawhub-scan.sh"
echo ""
echo "    # Set up Telegram alerts"
echo "    $INSTALL_DIR/scripts/telegram-setup.sh"
echo ""
echo "  NOTE: No cron jobs, LaunchAgents, or background services"
echo "  were installed. See README.md for optional persistence setup."
echo ""
