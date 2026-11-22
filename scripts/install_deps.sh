#!/usr/bin/env bash
# ==============================================================================
# Ether Universal Dependency & Security Tool Installer
# ==============================================================================
# Automatically detects Linux distributions, BSD/macOS environments, and
# package managers to install required security CLI tools and dependencies:
#   - nmap         (Network discovery and port scanner)
#   - gobuster     (URI and DNS brute-forcer)
#   - nikto        (Web vulnerability scanner + Perl XML writer)
#   - whois        (Domain and IP registration lookup)
#   - subfinder    (Fast passive subdomain enumeration)
#   - ffuf         (Fast web fuzzer and directory discovery)
#   - nuclei       (Fast and customizable vulnerability scanner)
#   - searchsploit (Offline exploit search engine for Exploit-DB)
#   - sqlmap       (Automatic SQL injection tool)
#   - dnspython    (Pure-Python DNS resolver and zone transfer engine)
#   - httpx        (HTTP client for coroutine probe adapter)
# ==============================================================================

set -eo pipefail

# ANSI Color Codes
BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
RESET="\033[0m"

log_info()    { echo -e "${BLUE}[*]${RESET} $1"; }
log_success() { echo -e "${GREEN}[+]${RESET} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
log_error()   { echo -e "${RED}[-]${RESET} $1"; }
log_header()  { echo -e "${BOLD}${CYAN}$1${RESET}"; }

SUBFINDER_VERSION="2.6.6"
FFUF_VERSION="2.1.0"
NUCLEI_VERSION="3.3.7"
INSTALL_USER_ONLY=false
CHECK_ONLY=false

usage() {
    cat <<EOF
Usage: ./scripts/install_deps.sh [OPTIONS]

Options:
  -c, --check       Verify installed tools and dependencies without modifying system.
  -u, --user        Install standalone binaries into \$HOME/.local/bin (no root/sudo needed).
  -h, --help        Show this help message.

Supported Environments:
  • Debian / Ubuntu / Kali / Parrot / Pop!_OS / Linux Mint (apt)
  • Arch Linux / Manjaro / EndeavourOS / BlackArch (pacman)
  • Fedora / RHEL / CentOS / Rocky / AlmaLinux (dnf / yum)
  • openSUSE Tumbleweed & Leap (zypper)
  • Alpine Linux (apk)
  • Void Linux (xbps)
  • macOS (Homebrew)
EOF
    exit 0
}

# Parse Command-Line Arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--check)
            CHECK_ONLY=true
            shift
            ;;
        -u|--user)
            INSTALL_USER_ONLY=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

echo -e "${BOLD}======================================================${RESET}"
echo -e "${BOLD}${CYAN}   Ether System Dependency & Security Tool Installer${RESET}"
echo -e "${BOLD}======================================================${RESET}"

# Architecture & Platform Detection
UNAME_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
UNAME_ARCH="$(uname -m)"

case "$UNAME_ARCH" in
    x86_64|amd64)   ARCH="amd64" ;;
    aarch64|arm64)  ARCH="arm64" ;;
    armv7*|armhf)   ARCH="armv7" ;;
    i386|i686)      ARCH="386" ;;
    *)              ARCH="amd64" ;;
esac

# Privilege Detection
SUDO=""
if [ "$INSTALL_USER_ONLY" = false ]; then
    if [ "$EUID" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            SUDO="sudo"
        else
            log_warn "Neither root nor sudo detected. Falling back to user-space binary installs."
            INSTALL_USER_ONLY=true
        fi
    fi
fi

# Destination directory for binaries
if [ "$INSTALL_USER_ONLY" = true ]; then
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
else
    BIN_DIR="/usr/local/bin"
fi

verify_tools() {
    echo ""
    log_header "--- Installed Security Tools Status ---"
    local all_good=true
    local tools=("nmap" "gobuster" "nikto" "whois" "subfinder" "ffuf" "nuclei" "searchsploit" "sqlmap")

    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            local path
            path="$(command -v "$tool")"
            log_success "${BOLD}$tool${RESET} -> $path"
        else
            log_error "${BOLD}$tool${RESET} -> NOT FOUND"
            all_good=false
        fi
    done

    # Check NetExec / nxc
    if command -v nxc >/dev/null 2>&1; then
        local nxc_path
        nxc_path="$(command -v nxc)"
        log_success "${BOLD}netexec (nxc)${RESET} -> $nxc_path"
    elif command -v netexec >/dev/null 2>&1; then
        local netexec_path
        netexec_path="$(command -v netexec)"
        log_success "${BOLD}netexec${RESET} -> $netexec_path"
    else
        log_warn "${BOLD}netexec (nxc)${RESET} -> NOT FOUND (install via 'pipx install netexec')"
    fi

    # Check Pure-Python coroutine dependencies
    if python3 -c "import dns.resolver" >/dev/null 2>&1; then
        log_success "${BOLD}dnspython${RESET} -> python3 module available"
    else
        log_warn "${BOLD}dnspython${RESET} -> NOT FOUND (install via 'pip install dnspython')"
        all_good=false
    fi

    if python3 -c "import httpx" >/dev/null 2>&1; then
        log_success "${BOLD}httpx (http_probe)${RESET} -> python3 module available"
    else
        log_warn "${BOLD}httpx${RESET} -> NOT FOUND (install via 'pip install httpx')"
        all_good=false
    fi

    echo ""
    if [ "$all_good" = true ]; then
        log_success "All core security tools and adapters are installed and ready!"
        log_info "Run ${BOLD}ether tool list${RESET} to inspect discovered adapters."
    else
        log_warn "Some tools are missing. Run ${BOLD}./scripts/install_deps.sh${RESET} to install them."
    fi
}

if [ "$CHECK_ONLY" = true ]; then
    verify_tools
    exit 0
fi

download_file() {
    local url="$1"
    local output="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$output"
    else
        log_warn "curl or wget is required to download standalone binaries."
        return 1
    fi
}

install_subfinder_release() {
    if command -v subfinder >/dev/null 2>&1; then
        return 0
    fi
    log_info "Installing subfinder v${SUBFINDER_VERSION} binary for ${UNAME_OS}/${ARCH}..."
    local url="https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_${UNAME_OS}_${ARCH}.zip"
    local tmp_dir
    tmp_dir="$(mktemp -d)"

    if download_file "$url" "$tmp_dir/subfinder.zip"; then
        if command -v unzip >/dev/null 2>&1; then
            unzip -q "$tmp_dir/subfinder.zip" -d "$tmp_dir"
            if [ "$INSTALL_USER_ONLY" = true ]; then
                mv "$tmp_dir/subfinder" "$BIN_DIR/subfinder"
                chmod +x "$BIN_DIR/subfinder"
            else
                $SUDO mv "$tmp_dir/subfinder" "$BIN_DIR/subfinder"
                $SUDO chmod +x "$BIN_DIR/subfinder"
            fi
            log_success "subfinder installed successfully to $BIN_DIR/subfinder"
        else
            log_warn "unzip is required to extract subfinder."
        fi
    fi
    rm -rf "$tmp_dir"
}

install_nuclei_release() {
    if command -v nuclei >/dev/null 2>&1; then
        return 0
    fi
    log_info "Installing nuclei v${NUCLEI_VERSION} binary for ${UNAME_OS}/${ARCH}..."
    local url="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${UNAME_OS}_${ARCH}.zip"
    local tmp_dir
    tmp_dir="$(mktemp -d)"

    if download_file "$url" "$tmp_dir/nuclei.zip"; then
        if command -v unzip >/dev/null 2>&1; then
            unzip -q "$tmp_dir/nuclei.zip" -d "$tmp_dir"
            if [ "$INSTALL_USER_ONLY" = true ]; then
                mv "$tmp_dir/nuclei" "$BIN_DIR/nuclei"
                chmod +x "$BIN_DIR/nuclei"
            else
                $SUDO mv "$tmp_dir/nuclei" "$BIN_DIR/nuclei"
                $SUDO chmod +x "$BIN_DIR/nuclei"
            fi
            log_success "nuclei installed successfully to $BIN_DIR/nuclei"
        else
            log_warn "unzip is required to extract nuclei."
        fi
    fi
    rm -rf "$tmp_dir"
}

install_nikto_source() {
    if command -v nikto >/dev/null 2>&1; then
        return 0
    fi
    log_info "Installing Nikto from source..."
    local target_dir="/opt/nikto"
    if [ "$INSTALL_USER_ONLY" = true ]; then
        target_dir="$HOME/.local/share/nikto"
    fi
    if command -v git >/dev/null 2>&1; then
        if [ "$INSTALL_USER_ONLY" = true ]; then
            git clone --depth 1 https://github.com/sullo/nikto.git "$target_dir" 2>/dev/null || true
            ln -sf "$target_dir/program/nikto.pl" "$BIN_DIR/nikto"
        else
            $SUDO git clone --depth 1 https://github.com/sullo/nikto.git "$target_dir" 2>/dev/null || true
            $SUDO ln -sf "$target_dir/program/nikto.pl" "$BIN_DIR/nikto"
        fi
        log_success "Nikto installed to $BIN_DIR/nikto"
    fi
}

install_searchsploit_source() {
    if command -v searchsploit >/dev/null 2>&1; then
        return 0
    fi
    log_info "Installing searchsploit (Exploit-DB) from repository..."
    local target_dir="/opt/exploitdb"
    if [ "$INSTALL_USER_ONLY" = true ]; then
        target_dir="$HOME/.local/share/exploitdb"
    fi
    if command -v git >/dev/null 2>&1; then
        if [ "$INSTALL_USER_ONLY" = true ]; then
            git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git "$target_dir" 2>/dev/null || true
            ln -sf "$target_dir/searchsploit" "$BIN_DIR/searchsploit"
        else
            $SUDO git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git "$target_dir" 2>/dev/null || true
            $SUDO ln -sf "$target_dir/searchsploit" "$BIN_DIR/searchsploit"
        fi
        log_success "searchsploit installed to $BIN_DIR/searchsploit"
    fi
}

# Distro Detection and Installation
if [ "$UNAME_OS" = "darwin" ]; then
    log_header "--- macOS Detected (Homebrew) ---"
    if command -v brew >/dev/null 2>&1; then
        brew install nmap gobuster whois ffuf sqlmap nikto
    else
        log_error "Homebrew not found. Please install Homebrew from https://brew.sh/"
    fi
elif [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        ubuntu|debian|kali|parrot|pop|mint)
            log_header "--- Debian/Ubuntu/Kali Detected (apt) ---"
            $SUDO apt-get update
            $SUDO apt-get install -y --no-install-recommends \
                nmap gobuster whois ffuf sqlmap perl libxml-writer-perl ca-certificates curl unzip git tar
            install_nikto_source
            install_searchsploit_source
            install_subfinder_release
            install_nuclei_release
            ;;
        arch|manjaro|endeavouros|blackarch)
            log_header "--- Arch Linux Detected (pacman) ---"
            $SUDO pacman -Sy --needed --noconfirm \
                nmap gobuster whois ffuf sqlmap perl perl-xml-writer subfinder nuclei exploitdb
            ;;
        fedora|rhel|centos|rocky|almalinux)
            log_header "--- Red Hat / Fedora Detected (dnf/yum) ---"
            PM="dnf"
            command -v dnf >/dev/null 2>&1 || PM="yum"
            $SUDO $PM install -y nmap whois perl perl-XML-Writer curl unzip git tar
            install_nikto_source
            install_searchsploit_source
            install_subfinder_release
            install_nuclei_release
            ;;
        opensuse*|suse)
            log_header "--- openSUSE Detected (zypper) ---"
            $SUDO zypper --non-interactive install \
                nmap whois perl-XML-Writer curl unzip git tar
            install_nikto_source
            install_searchsploit_source
            install_subfinder_release
            install_nuclei_release
            ;;
        alpine)
            log_header "--- Alpine Linux Detected (apk) ---"
            $SUDO apk add --no-cache \
                nmap whois perl perl-xml-writer curl unzip git tar
            install_nikto_source
            install_searchsploit_source
            install_subfinder_release
            install_nuclei_release
            ;;
        void)
            log_header "--- Void Linux Detected (xbps) ---"
            $SUDO xbps-install -Sy \
                nmap whois perl perl-XML-Writer curl unzip git tar
            install_nikto_source
            install_searchsploit_source
            install_subfinder_release
            install_nuclei_release
            ;;
        *)
            log_warn "Unrecognized Linux distribution: $ID. Attempting standalone binary installs."
            install_subfinder_release
            install_nuclei_release
            ;;
    esac
fi

chmod +x "$BIN_DIR"/* 2>/dev/null || true
verify_tools
