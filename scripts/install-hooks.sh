#!/bin/bash

# Install git hooks for the project
# This ensures commit messages don't contain prohibited attribution terms

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
HOOKS_DIR="${PROJECT_ROOT}/.github/hooks"
GIT_HOOKS_DIR="${PROJECT_ROOT}/.git/hooks"

echo "Installing git hooks..."

# Ensure git hooks directory exists
if [ ! -d "$GIT_HOOKS_DIR" ]; then
    echo "Error: Not a git repository or .git/hooks directory not found"
    exit 1
fi

# Install commit-msg hook
if [ -f "${HOOKS_DIR}/commit-msg" ]; then
    cp "${HOOKS_DIR}/commit-msg" "${GIT_HOOKS_DIR}/commit-msg"
    chmod +x "${GIT_HOOKS_DIR}/commit-msg"
    echo "✓ Installed commit-msg hook"
else
    echo "⚠ commit-msg hook not found in ${HOOKS_DIR}"
fi

echo ""
echo "Git hooks installed successfully!"
echo "These hooks will:"
echo "  - Prevent commits with AI tool attribution"
echo "  - Clean up any accidental attribution trailers"
echo ""
echo "To bypass hooks in emergency (not recommended):"
echo "  git commit --no-verify"