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

This tool is intentionally not installed by bootstrap yet. The recon wrapper
uses the v4-style `amass enum -passive` interface and parses JSON from stdout;
the upstream project's current installation docs describe v5. Verify that the
installed CLI still accepts this invocation and emits the expected JSON before
manually enabling it; until then, use the built-in subfinder/Wayback sources.

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
