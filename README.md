# Ultimate Automated Recon + Leak Detection Framework

A comprehensive, modular Python automation framework for passive reconnaissance, archived JavaScript leak discovery, environment file exposure detection, Git repository exposure detection, and CORS misconfiguration testing.

## 🚀 Features

### Core Capabilities
- **Subdomain Enumeration** - Using subfinder for comprehensive subdomain discovery
- **Live Host Detection** - HTTP-based alive host checking with httpx
- **URL Collection** - Multi-tool URL gathering (gau, katana, waybackurls)
- **JavaScript Filtering** - Intelligent JS/JSON/Source map file identification
- **Deduplication** - Advanced URL and content deduplication
- **Dead Link Analysis** - Identification of 404, timeout, and connection errors
- **Archive Analysis** - Wayback Machine CDX querying and snapshot fetching
- **Secret Detection** - Comprehensive secret scanning with false positive filtering
- **Environment File Scanning** - .env file exposure detection
- **Git Repository Scanning** - Exposed .git repository detection
- **CORS Testing** - Misconfiguration vulnerability testing
- **Discord Notifications** - Real-time alerts via webhooks
- **Automatic Cleanup** - Temporary file management

### Security & Ethics
- **Passive Only** - No active exploitation or bypass attempts
- **Rate Limiting** - Built-in rate limiting and respectful scanning
- **Error Handling** - Comprehensive error handling and failsafe mechanisms
- **Production Ready** - Clean, commented, modular code structure

## 📋 Requirements

### Python Dependencies
```bash
pip install -r requirements.txt
```

### External Tools (Required)
Install these Go-based tools before running:

```bash
# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/waybackurls@latest

# Add to PATH (add to ~/.bashrc or ~/.zshrc)
export PATH=$PATH:~/go/bin
```

### System Requirements
- Python 3.8+
- Go 1.19+
- Internet connection
- 2GB+ RAM recommended

## 🛠️ Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd bbp_workflow
```

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

3. **Install external tools:**
```bash
# See External Tools section above
```

4. **Configure Discord webhooks (optional):**
```bash
export DISCORD_WEBHOOK_JS="https://discord.com/api/webhooks/..."
export DISCORD_WEBHOOK_ENV="https://discord.com/api/webhooks/..."
export DISCORD_WEBHOOK_GIT="https://discord.com/api/webhooks/..."
export DISCORD_WEBHOOK_CORS="https://discord.com/api/webhooks/..."
```

## 🚀 Usage

### Basic Usage

**Single target:**
```bash
python main.py example.com
```

**Multiple targets from file:**
```bash
python main.py -l targets.txt
```

### Advanced Options

**Custom threading and delay:**
```bash
python main.py example.com --threads 5 --delay 3 8
```

**Custom output file:**
```bash
python main.py example.com --output my_results.json
```

**Verbose logging:**
```bash
python main.py example.com --log-level DEBUG
```

### Utility Commands

**Test Discord webhooks:**
```bash
python main.py --test-webhooks
```

**Cleanup temporary files:**
```bash
python main.py --cleanup-only
```

## 📁 Project Structure

```
bbp_workflow/
├── main.py                 # Main orchestrator
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── config/
│   └── config.py          # Configuration settings
├── core/                  # Core functionality (empty for now)
├── modules/
│   ├── subdomain_enum.py   # Subdomain enumeration
│   ├── live_check.py       # Live host checking
│   ├── url_collector.py    # URL collection
│   ├── js_filter.py        # JavaScript filtering
│   ├── deduper.py          # Deduplication
│   ├── deadlink_checker.py # Dead link checking
│   ├── cdx_query.py        # Wayback CDX querying
│   ├── timestamp_picker.py # Timestamp selection
│   ├── archive_fetcher.py  # Archive fetching
│   ├── secret_scanner.py   # Secret scanning
│   ├── env_scanner.py      # Environment file scanning
│   ├── git_scanner.py      # Git repository scanning
│   ├── cors_scanner.py     # CORS testing
│   ├── logger.py           # Result logging
│   ├── notifier.py         # Discord notifications
│   └── cleanup.py          # Cleanup management
├── utils/
│   ├── __init__.py
│   ├── logger.py           # Logging utilities
│   ├── rate_limiter.py     # Rate limiting
│   └── helpers.py          # Helper functions
├── output/
│   └── results.json        # Scan results (auto-generated)
└── tmp/                   # Temporary files (auto-cleaned)
```

## 🔧 Configuration

### Environment Variables
```bash
# Discord Webhooks (optional)
DISCORD_WEBHOOK_JS="https://discord.com/api/webhooks/..."
DISCORD_WEBHOOK_ENV="https://discord.com/api/webhooks/..."
DISCORD_WEBHOOK_GIT="https://discord.com/api/webhooks/..."
DISCORD_WEBHOOK_CORS="https://discord.com/api/webhooks/..."
```

### Configuration File
Edit `config/config.py` to customize:
- Rate limiting settings
- User agent rotation
- Secret detection patterns
- File paths and timeouts
- External tool paths

## 📊 Output Format

Results are saved in `output/results.json` with the following structure:

```json
[
  {
    "target": "example.com",
    "module": "Secret Scanner",
    "url": "https://example.com/app.js",
    "timestamp": "2024-01-01T12:00:00",
    "vulnerability_type": "API Key",
    "severity": "HIGH",
    "evidence": "api_key: 'sk-1234567890abcdef'"
  }
]
```

### Severity Levels
- **CRITICAL** - Immediate attention required
- **HIGH** - Important security issues
- **MEDIUM** - Potential security concerns
- **LOW** - Minor issues or informational

## 🔍 Scanning Pipeline

1. **Subdomain Enumeration** - Discover all subdomains using subfinder
2. **Live Host Check** - Identify responsive hosts with httpx
3. **URL Collection** - Gather URLs from multiple sources (gau, katana, waybackurls)
4. **JavaScript Filtering** - Filter for JS/JSON/Source map files
5. **Deduplication** - Remove duplicates with smart normalization
6. **Dead Link Analysis** - Find 404/timeout errors for archive analysis
7. **Wayback CDX Query** - Query archive.org for historical snapshots
8. **Timestamp Selection** - Choose optimal timestamps (oldest, newest, random)
9. **Archive Fetching** - Retrieve historical snapshots with rate limiting
10. **Secret Scanning** - Comprehensive secret detection with false positive filtering
11. **Environment Scanning** - Check for exposed .env files
12. **Git Repository Scanning** - Detect exposed .git repositories
13. **CORS Testing** - Test for CORS misconfigurations
14. **Result Logging** - Save structured findings to JSON
15. **Discord Notifications** - Send real-time alerts
16. **Cleanup** - Remove temporary files

## 🛡️ False Positive Prevention

The framework includes multiple layers of false positive prevention:

### Secret Detection
- Pattern-based filtering with context awareness
- High entropy string analysis
- Common false positive pattern detection
- Confidence scoring system

### Environment Files
- Real content validation (not examples/dummies)
- Actual secret detection in .env files
- File size and content analysis

### Git Repositories
- HEAD file validation
- Content verification
- Secret extraction from git files

### CORS Testing
- Origin reflection validation
- Credential combination checking
- Pattern-based false positive filtering

## 📈 Performance & Rate Limiting

### Built-in Protections
- **Concurrent Request Limiting** - Configurable thread pool
- **Random Delays** - 2-5 second delays between requests
- **User Agent Rotation** - 5 different user agents
- **Exponential Backoff** - Smart retry logic
- **Request Queuing** - Organized request management
- **Response Caching** - Avoid duplicate requests

### Recommended Settings
- **Production**: 3 threads, 3-8 second delays
- **Testing**: 1 thread, 5-10 second delays
- **Research**: 5 threads, 2-5 second delays

## 🐛 Troubleshooting

### Common Issues

**External tools not found:**
```bash
# Check if tools are in PATH
which subfinder httpx gau katana waybackurls

# Install Go tools if missing
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

**Permission errors:**
```bash
# Fix permissions
chmod +x main.py
sudo chown -R $USER:$USER output/ tmp/
```

**Rate limiting issues:**
```bash
# Increase delays
python main.py example.com --delay 5 10

# Reduce threads
python main.py example.com --threads 1
```

**Discord webhooks not working:**
```bash
# Test webhook configuration
python main.py --test-webhooks
```

### Debug Mode
```bash
python main.py example.com --log-level DEBUG
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
pytest

# Code formatting
black .
flake8 .
mypy .
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any targets. The authors are not responsible for any misuse of this software.

### Ethical Usage Guidelines
- Only scan targets you own or have explicit permission to test
- Respect rate limits and terms of service of target websites
- Do not use for malicious purposes
- Follow responsible disclosure practices for any vulnerabilities found

## 📞 Support

For issues, questions, or contributions:
- Create an issue on GitHub
- Check the troubleshooting section
- Review the debug logs with `--log-level DEBUG`

## 🔄 Changelog

### v1.0.0
- Initial release with full scanning pipeline
- Discord webhook integration
- Comprehensive false positive prevention
- Production-ready rate limiting
- Modular architecture

---

**Happy Hunting! 🎯**
