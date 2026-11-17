# Required and Optional Tools Setup

Before a full engagement, run
`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/bootstrap.py" --strict`. The bootstrap
installs and verifies the managed toolchain. For a narrower recon task, use
`--require-tool dig --require-tool nmap` (plus any Go tools the selected flow
needs); a nonzero result means the dependent checks must wait until the tools
are available. Manual install commands below remain useful when no supported
package manager is present.

## Required (Python - no install needed)
The core scripts use only Python 3 standard library. No pip install required.

## Optional Go Tools (Recommended for Performance)

These tools dramatically speed up scanning. Install any/all:

### subfinder - Fast passive subdomain enumeration
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### httpx - Fast HTTP probing
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### puredns - Fast DNS brute-force with massdns
```bash
go install github.com/d3mondev/puredns/v2@latest
```

### naabu - Fast port scanner
```bash
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

### amass - Comprehensive subdomain enumeration

This tool is intentionally not installed by bootstrap and is not in `GO_TOOLS`.
The wrapper uses the v4-style `amass enum -passive` interface and parses JSON
from stdout. In v5, `enum` moved to a local-database model and dropped its
one-shot `-o`/`-json` output. Oct 2025 docs pointed to
`amass subs -names/-ip/-summary` for plain-text readback, but that CLI surface
was later reported removed in a subsequent v5.x point release. An Apr 2026
issue against v5.1.1/`develop` also reports `-brute`/`-w` wordlists accepted
into config but unused by the engine; this remains an open maintainer question,
not an acknowledged or fixed bug ([upstream issue #1122](https://github.com/owasp-amass/amass/issues/1122)).
The v5 output change is discussed in [upstream issue #1115](https://github.com/owasp-amass/amass/issues/1115).
The v5 CLI has moved between minor versions, so articles are not a source of truth.

Re-evaluate only against the version actually installed: inspect
`amass --help` and `amass enum --help`, prove wordlist brute-force visibly
produces guesses on an owned-domain fixture, and prove a reliable structured
output path exists. Until all three checks pass, use the built-in
subfinder/Wayback sources and leave Amass unmanaged.

## System Tools
- `dig` - DNS queries (pre-installed on macOS/Linux)
- `whois` - WHOIS lookups (pre-installed on macOS/Linux)
- `nmap` - Port scanning (install via package manager)

### Install nmap
```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt install nmap

# Arch
sudo pacman -S nmap
```
