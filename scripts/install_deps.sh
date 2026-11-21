#!/usr/bin/env bash
# ==============================================================================
# Ether Universal Dependency & Security Tool Installer
# ==============================================================================
# Automatically detects Linux distributions and package managers to install
# security CLI tools supervised by Ether:
#   - nmap         (Network discovery and port scanner)
#   - gobuster     (URI and DNS brute-forcer)
#   - nikto        (Web vulnerability scanner + Perl XML writer)
#   - whois        (Domain and IP registration lookup)
#   - subfinder    (Fast passive subdomain enumeration)
#   - ffuf         (Fast web fuzzer and directory discovery)
#   - nuclei       (Fast and customizable vulnerability scanner)
#   - searchsploit (Offline exploit search engine for Exploit-DB)
#   - sqlmap       (Automatic SQL injection tool)
# ==============================================================================

set -eo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m"

log_info() { echo -e "${BLUE}${BOLD}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}${BOLD}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}${BOLD}[!]${NC} $1"; }
log_error() { echo -e "${RED}${BOLD}[-]${NC} $1" >&2; }

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_LIKE=${ID_LIKE:-""}
    else
        DISTRO="unknown"
    fi
    echo "$DISTRO"
}

DISTRO=$(detect_distro)
log_info "Detected operating system: ${BOLD}$DISTRO${NC}"

case "$DISTRO" in
    arch|manjaro|endeavouros)
        log_info "Installing security tools via pacman..."
        sudo pacman -S --needed --noconfirm nmap whois nikto sqlmap perl-xml-writer || true
        ;;
    ubuntu|debian|kali|pop)
        log_info "Installing security tools via apt..."
        sudo apt-get update -y
        sudo apt-get install -y --no-install-recommends nmap gobuster whois nikto ffuf sqlmap libxml-writer-perl || true
        ;;
    fedora|rhel|centos)
        log_info "Installing security tools via dnf..."
        sudo dnf install -y nmap whois nikto sqlmap perl-XML-Writer || true
        ;;
    *)
        log_warn "Distribution $DISTRO not natively automated. Please install nmap, ffuf, nuclei manually."
        ;;
esac

log_success "Ether dependency check complete."
