#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────
# Pipeline Sentinel – Secure Installer
# ──────────────────────────────────────────────

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

NON_INTERACTIVE=false

print_header() {
    echo -e "${GREEN}🛡️  Pipeline Sentinel – Quick Install${RESET}"
    echo -e "${GREEN}------------------------------------${RESET}"
}

info() { echo -e "${BOLD}→${RESET} $*"; }
warn() { echo -e "${YELLOW}⚠️  $*${RESET}"; }
error() { echo -e "${RED}❌ $*${RESET}"; exit 1; }

# ──────────────────────────────────────────────
# 1. Check prerequisites
# ──────────────────────────────────────────────
check_prereqs() {
    info "Checking system requirements..."

    if ! command -v python3 &> /dev/null; then
        error "Python3 is not installed. Please install Python 3.10 or later."
    fi

    python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    major=$(echo "$python_version" | cut -d. -f1)
    minor=$(echo "$python_version" | cut -d. -f2)

    if (( major < 3 )) || { (( major == 3 )) && (( minor < 10 )); }; then
        error "Python 3.10+ is required. Found: $python_version"
    fi

    info "Python $python_version detected."
}

# ──────────────────────────────────────────────
# 2. Install Pipeline Sentinel
# ──────────────────────────────────────────────
install_sentinel() {
    if python3 -c "import devsecops_radar" &> /dev/null; then
        info "Pipeline Sentinel is already installed."
    else
        info "Installing devsecops-radar..."
        python3 -m pip install --user devsecops-radar
    fi
}

# ──────────────────────────────────────────────
# 3. Optional AI setup (Ollama) – skipped if non‑interactive or offline
# ──────────────────────────────────────────────
setup_ai() {
    if $NON_INTERACTIVE; then
        info "Skipping AI setup (non‑interactive mode). You can run 'ollama pull llama3.2:latest' later."
        return
    fi

    if command -v ollama &> /dev/null; then
        info "Ollama is available. Pulling recommended AI model (llama3.2)..."
        ollama pull llama3.2:latest || warn "Could not pull AI model. You can do it later with: ollama pull llama3.2:latest"
    else
        warn "Ollama not found. AI analysis will not be available."
        echo -e "  To enable AI features:"
        echo -e "    • Install Ollama from https://ollama.com/download"
        echo -e "    • Then run: ollama pull llama3.2:latest"
        echo -e "  You can also use cloud-based LLMs with --llm-backend litellm (requires internet)."
    fi
}

# ──────────────────────────────────────────────
# 4. Run first-time wizard (optional)
# ──────────────────────────────────────────────
run_wizard() {
    if $NON_INTERACTIVE; then
        info "Skipping interactive wizard (non‑interactive mode)."
        return
    fi

    if command -v devsecops-radar &> /dev/null; then
        echo ""
        info "You can now run the interactive setup wizard:"
        echo -e "     ${BOLD}devsecops-radar --wizard${RESET}"
        echo ""
        if [ -t 0 ]; then
            read -p "Would you like to run it now? [y/N]: " answer
            if [[ "$answer" =~ ^[Yy]$ ]]; then
                devsecops-radar --wizard
            fi
        fi
    fi
}

# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
main() {
    # Parse optional --non-interactive flag
    for arg in "$@"; do
        if [[ "$arg" == "--non-interactive" ]]; then
            NON_INTERACTIVE=true
        fi
    done

    print_header
    check_prereqs
    install_sentinel
    setup_ai
    run_wizard
    echo -e "${GREEN}✅ Installation complete.${RESET}"
}

main "$@"