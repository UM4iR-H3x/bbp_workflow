"""
Configuration settings for the Ultimate Automated Recon + Leak Detection Framework
"""

import os
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
CORE_DIR = PROJECT_ROOT / "core"
MODULES_DIR = PROJECT_ROOT / "modules"
UTILS_DIR = PROJECT_ROOT / "utils"
CONFIG_DIR = PROJECT_ROOT / "config"
OUTPUT_DIR = PROJECT_ROOT / "output"
TMP_DIR = PROJECT_ROOT / "tmp"

# Rate limiting settings
DEFAULT_DELAY = (2, 5)  # Random delay between 2-5 seconds
MAX_CONCURRENT_REQUESTS = 3
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
BACKOFF_FACTOR = 2

# User agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# Secret detection patterns
SECRET_PATTERNS = {
    "api_key": [
        r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]",
        r"(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]",
        r"(?i)(access[_-]?key|accesskey)\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]"
    ],
    "jwt_token": [
        r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"
    ],
    "private_key": [
        r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----"
    ],
    "email": [
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ],
    "password": [
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^\s'\"]{6,})['\"]"
    ],
    "aws_key": [
        r"AKIA[0-9A-Z]{16}"
    ],
    "github_token": [
        r"ghp_[a-zA-Z0-9]{36}"
    ],
    "slack_token": [
        r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}"
    ],
    "high_entropy": {
        "threshold": 4.5,
        "min_length": 20
    }
}

# Environment file paths to check
ENV_PATHS = [
    "/.env",
    "/.env.backup",
    "/.env.old",
    "/.env.dev",
    "/.env.production",
    "/api/.env",
    "/config/.env"
]

# CORS test origins
CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null"
]

# Important JS file keywords for live scanning
IMPORTANT_JS_KEYWORDS = [
    "main",
    "app", 
    "bundle",
    "vendor",
    "config",
    "env",
    "prod",
    "build",
    "init",
    "core",
    "index",
    "api",
    "client",
    "server",
    "auth",
    "dashboard",
    "admin"
]

# Discord webhook configuration - YOUR WEBHOOKS CONFIGURED
DISCORD_WEBHOOKS = {
    "js_leaks": "https://discord.com/api/webhooks/1442479921724264559/WujffNyMbxBPdq0GlGaFwyRz4Rk9zeQBh5FyB2pbDUF4ErO2z-jFJyAWEG3w8VmMTZcU",
    "env_exposure": "https://discord.com/api/webhooks/1442480810312859750/8KLFkVUUkaAF8WdOeKrqGi1Wvz5JVCQ8WJVvVtAYvwtUwAeBP4U4VqDHYjIcqCOGXP6L",
    "git_exposure": "https://discord.com/api/webhooks/1442480810312859750/8KLFkVUUkaAF8WdOeKrqGi1Wvz5JVCQ8WJVvVtAYvwtUwAeBP4U4VqDHYjIcqCOGXP6L",
    "cors": "https://discord.com/api/webhooks/1442480607258218496/-NuD8z5N1KkFpjEl_V4CwjKSTHua8yNV85GK2yafd4HJim02TZlxaHG4j_NaDZJb8JnG"
}

# Severity levels
SEVERITY_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}

# Output configuration
RESULTS_FILE = OUTPUT_DIR / "results.json"
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB max file size

# Archive.org settings
WAYBACK_CDX_URL = "http://web.archive.org/cdx/search/cdx"
WAYBACK_SNAPSHOT_URL = "https://web.archive.org/web/{timestamp}/{url}"
MAX_TIMESTAMPS = 3

# Tool paths (assumed to be in PATH)
EXTERNAL_TOOLS = {
    "subfinder": "subfinder",
    "httpx": "httpx",
    "gau": "gau",
    "katana": "katana",
    "waybackurls": "waybackurls"
}
