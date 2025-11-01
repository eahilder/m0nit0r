# M0nit0r - Attack Surface Management Tool

A comprehensive CLI-based ASM tool written in Go. Monitor your external attack surface, detect changes, and track credential breaches.

## Features

- **Multi-client Management** - Organize assets by client/organization with primary domain tracking
- **Asset Types** - Domains, subdomains, IPs (with CIDR expansion on import)
- **Subdomain Enumeration** - BBOT integration for passive DNS reconnaissance
- **Port Scanning** - Native Go concurrent scanner (top 250 ports) with banner grabbing and service detection
- **Credential Breach Monitoring** - Query breach intelligence databases (DeHashed, OathNet) for compromised credentials
- **Technology Detection** - HTTP header and HTML analysis to identify tech stacks
- **Change Detection** - Automatic comparison with previous scans to detect attack surface changes
- **Baseline Tracking** - First scan establishes baseline, subsequent scans detect deltas
- **History Review** - View and export historical scan data with built-in comparison tools
- **JSON Output** - Structured change logs for external processing
- **Single Binary** - No CGO dependency, cross-compiles cleanly for Linux/macOS

## Requirements

- **Go 1.25.3+** (for building from source)
- **BBOT** (for subdomain enumeration): `pip install bbot`
- **API Keys** (optional, for credential scanning):
  - DeHashed API key
  - OathNet API key

## Installation

### Build from Source

```bash
# Clone repository
git clone https://github.com/errorixlab/m0nit0r.git
cd m0nit0r

# Build for current platform
go build -o m0nit0r cmd/m0nit0r/*.go

# Cross-compile for Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o m0nit0r-linux cmd/m0nit0r/*.go

# Install system-wide (optional)
sudo mv m0nit0r /usr/local/bin/
```

### First-Time Setup

```bash
# Initialize configuration and API keys
./m0nit0r setup

# Or manually create ~/.m0nit0r/config.json:
{
  "dehashed_api_key": "your-dehashed-key-here",
  "oathnet_api_key": "your-oathnet-key-here"
}
```

## Quick Start

```bash
# 1. Create a client with primary domain
./m0nit0r client add --name "acmecorp" --primary-domain acmecorp.com

# 2. (Optional) Import additional assets
./m0nit0r asset import --client-id 1 --file targets.txt

# 3. Run comprehensive baseline scan
./m0nit0r scan all --client-id 1 --verbose

# 4. View results
./m0nit0r changes list --client-id 1
./m0nit0r history client --client-id 1
```

## Usage

### Client Management

```bash
# Add client with primary domain
./m0nit0r client add --name "MyCompany" --primary-domain example.com

# Add client with targets file
./m0nit0r client add --name "MyCompany" --primary-domain example.com --targets targets.txt

# List clients
./m0nit0r client list

# Delete client
./m0nit0r client delete --client-id 1
```

### Asset Management

```bash
# Add single asset
./m0nit0r asset add --client-id 1 --type domain --value example.com
./m0nit0r asset add --client-id 1 --type ip --value 192.168.1.0/24

# Import from file (one target per line)
./m0nit0r asset import --client-id 1 --file assets.txt

# List assets
./m0nit0r asset list --client-id 1

# Delete asset
./m0nit0r asset delete --asset-id 5
```

**Asset file format** (`assets.txt`):
```
app.example.com
api.example.com
192.168.1.100
10.0.0.0/24
```

### Scanning

```bash
# Run all scan types (subdomains, ports, credentials, tech)
./m0nit0r scan all --client-id 1

# Run with verbose output
./m0nit0r scan all --client-id 1 --verbose

# Run specific scan types
./m0nit0r scan subdomains --client-id 1
./m0nit0r scan ports --client-id 1
./m0nit0r scan credentials --client-id 1
./m0nit0r scan tech --client-id 1
```

**What gets scanned:**
- **Subdomains**: BBOT-powered enumeration using certificate transparency, DNS, and OSINT sources
- **Ports**: Concurrent TCP scanning of top 250 most common ports with banner grabbing
- **Credentials**: Query breach databases for compromised emails/passwords associated with domain
- **Technology**: HTTP fingerprinting to detect web frameworks, servers, and libraries

### Viewing Changes

```bash
# List all changes for a client
./m0nit0r changes list --client-id 1

# List changes for specific asset
./m0nit0r changes list --client-id 1 --asset-id 5

# Export changes as JSON
./m0nit0r changes list --client-id 1 --json
```

### History Review

```bash
# View scan history summaries for entire client
./m0nit0r history client --client-id 1
./m0nit0r history client --client-id 1 --limit 20
./m0nit0r history client --client-id 1 --export

# View detailed scan history for specific asset
./m0nit0r history list --asset-id 5
./m0nit0r history list --asset-id 5 --type port --limit 10
./m0nit0r history list --asset-id 5 --export

# Compare last two scans
./m0nit0r history compare --asset-id 5 --type port
./m0nit0r history compare --asset-id 5 --type subdomain
./m0nit0r history compare --asset-id 5 --type port --export
```

### Output Files

All results are saved to `~/.m0nit0r/output/<client_name>/`:

- `YYYYMMDD_HHMMSS_changes.json` - Structured change log with all discoveries and deltas
- `YYYYMMDD_HHMMSS_scan_summary.txt` - Human-readable summary of scan results

**JSON Structure:**
```json
{
  "client": "acmecorp",
  "client_id": 1,
  "timestamp": "2025-11-01T16:19:20Z",
  "is_baseline": true,
  "summary": {
    "total_assets": 15,
    "domains": 1,
    "subdomains_found": 5,
    "ports_discovered": 23,
    "total_breached_emails": 407,
    "total_breached_passwords": 156,
    "total_breached_hashes": 89
  },
  "changes": [...]
}
```

## Baseline vs Delta Scans

### First Scan (Baseline)
The first time you scan a client, everything is recorded as a baseline. All discovered assets, ports, and subdomains get logged with a `baseline_*` prefix in the change type. The JSON output will have `"is_baseline": true`.

### Subsequent Scans (Delta Detection)
After the baseline, scans only record actual changes:
- `new_subdomain` - New subdomain discovered
- `new_port` - New open port detected
- `closed_port` - Previously open port now closed
- `breached_email` - New credential breach detected

The JSON output will have `"is_baseline": false`.

## Automation

### Cron Scheduling

```bash
# Scan twice weekly (Monday and Thursday at 2 AM)
0 2 * * 1,4 /usr/local/bin/m0nit0r scan all --client-id 1

# Multiple clients
0 2 * * 1,4 /usr/local/bin/m0nit0r scan all --client-id 1
0 3 * * 1,4 /usr/local/bin/m0nit0r scan all --client-id 2
```

## Architecture

- **Language:** Go 1.25.3
- **Database:** SQLite with pure Go driver (glebarez/sqlite, no CGO)
- **ORM:** GORM for database operations
- **CLI Framework:** Cobra for command structure
- **Subdomain Enumeration:** BBOT (external Python tool)
- **Port Scanner:** Native Go with concurrent workers and banner grabbing
- **Credential Scanning:** Pure Go HTTP clients for DeHashed and OathNet APIs
- **Technology Detection:** HTTP header and HTML analysis

## Configuration

### Config File Location
`~/.m0nit0r/config.json`

### Example Configuration
```json
{
  "dehashed_api_key": "your-dehashed-api-key-here",
  "oathnet_api_key": "your-oathnet-api-key-here"
}
```

### Database Location
`~/.m0nit0r/m0nit0r.db`

## Future Enhancements

The following features have database models defined but aren't implemented yet:

- **Webhooks** - Direct notification support for Slack, Discord, Teams
- **Built-in Scheduler** - Daemon mode with internal job scheduling (currently recommend using system cron)
- **Technology Change Detection** - Track changes in tech stacks over time
