"""
JavaScript File Scanner Module
Comprehensive JS file analysis with secret detection, endpoint finding, and vulnerability scanning
"""

import asyncio
import aiohttp
import re
import json
import math
import time
import random
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass
from datetime import datetime
import logging

from config.config import (
    IMPORTANT_JS_KEYWORDS, SECRET_PATTERNS, DISCORD_WEBHOOKS,
    SEVERITY_LEVELS, OUTPUT_DIR, USER_AGENTS, DEFAULT_DELAY,
    MAX_CONCURRENT_REQUESTS, REQUEST_TIMEOUT, MAX_RETRIES,
    WAYBACK_CDX_URL, WAYBACK_SNAPSHOT_URL, MAX_TIMESTAMPS
)


@dataclass
class JSFinding:
    url: str
    type: str
    severity: str
    matched_string: str
    line_number: Optional[int] = None
    context: Optional[str] = None


@dataclass
class JSScanResult:
    url: str
    status: str
    findings: List[JSFinding]
    file_size: int
    scan_time: float


class JSFilter:
    """Phase 1: JavaScript URL filtering"""
    
    @staticmethod
    def is_js_file(url: str) -> bool:
        """Check if URL ends with .js (case insensitive, ignoring query strings)"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        return path.endswith('.js')
    
    @staticmethod
    def filter_js_urls(urls: List[str]) -> List[str]:
        """Filter and deduplicate JS URLs"""
        seen = set()
        js_urls = []
        
        for url in urls:
            if not JSFilter.is_js_file(url):
                continue
                
            # Remove query string for deduplication
            parsed = urlparse(url)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            if clean_url not in seen:
                seen.add(clean_url)
                js_urls.append(url)
        
        return js_urls


class JSPriorityDetector:
    """Phase 2: Priority detection for JS files"""
    
    def __init__(self, keywords: List[str] = None):
        self.keywords = keywords or IMPORTANT_JS_KEYWORDS
    
    def get_priority(self, url: str) -> str:
        """Determine if JS file is high or low priority"""
        filename = Path(urlparse(url).path).name.lower()
        
        for keyword in self.keywords:
            if keyword.lower() in filename:
                return "HIGH"
        
        return "LOW"


class JSFetcher:
    """Phase 3: HTTP status checking and content fetching"""
    
    def __init__(self, timeout: int = REQUEST_TIMEOUT, max_retries: int = MAX_RETRIES):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.session = None
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_REQUESTS)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers={'User-Agent': random.choice(USER_AGENTS)}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def fetch_js_content(self, url: str) -> Tuple[int, str, int]:
        """Fetch JS content with retry logic"""
        for attempt in range(self.max_retries):
            try:
                async with self.session.get(url) as response:
                    content = await response.text()
                    return response.status, content, len(content.encode())
            
            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    return 0, "", 0  # timeout
                await asyncio.sleep(2 ** attempt)
            
            except Exception as e:
                if attempt == self.max_retries - 1:
                    return 0, "", 0  # error
                await asyncio.sleep(1)
        
        return 0, "", 0


class Soft404Detector:
    """Phase 4: Soft 404 detection"""
    
    SOFT_404_PATTERNS = [
        r'not found',
        r'error',
        r'page missing',
        r'404',
        r'does not exist',
        r'file not found'
    ]
    
    @staticmethod
    def is_soft_404(content: str) -> bool:
        """Check if content indicates soft 404"""
        content_lower = content.lower()
        
        for pattern in Soft404Detector.SOFT_404_PATTERNS:
            if re.search(pattern, content_lower):
                return True
        
        return False


class FileSizeFilter:
    """Phase 5: File size filtering"""
    
    def __init__(self, max_size: int = 1024 * 1024):  # 1MB default
        self.max_size = max_size
    
    def should_scan(self, file_size: int) -> bool:
        """Check if file should be scanned based on size"""
        return file_size <= self.max_size


class JSSecretDetector:
    """Phase 6.1: Secret detection in JS content"""
    
    def __init__(self):
        self.patterns = SECRET_PATTERNS
    
    def detect_secrets(self, content: str, url: str) -> List[JSFinding]:
        """Detect secrets in JS content and report immediately"""
        findings = []
        lines = content.split('\n')
        
        for secret_type, patterns in self.patterns.items():
            if secret_type == "high_entropy":
                continue  # Handle separately
            
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        severity = self._get_secret_severity(secret_type)
                        finding = JSFinding(
                            url=url,
                            type=f"secret_{secret_type}",
                            severity=severity,
                            matched_string=match.group(0),
                            line_number=line_num,
                            context=line.strip()
                        )
                        findings.append(finding)
                        
                        # Report secret immediately
                        asyncio.create_task(self._report_secret_immediately(finding))
        
        return findings
    
    async def _report_secret_immediately(self, finding: JSFinding):
        """Report secret immediately via Discord"""
        if finding.severity not in ['HIGH', 'CRITICAL']:
            return
        
        webhook_url = DISCORD_WEBHOOKS.get('js_leaks')
        if not webhook_url:
            return
        
        try:
            async with aiohttp.ClientSession() as session:
                embed = {
                    "title": f"🚨 IMMEDIATE SECRET DETECTED - {finding.severity}",
                    "description": f"**URL:** {finding.url}\n"
                                 f"**Type:** {finding.type}\n"
                                 f"**Severity:** {finding.severity}\n"
                                 f"**Secret:** `{finding.matched_string}`",
                    "color": 0xFF0000 if finding.severity == "CRITICAL" else 0xFF6600,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                if finding.context:
                    embed["description"] += f"\n**Context:** ```{finding.context}```"
                
                payload = {"embeds": [embed]}
                
                async with session.post(webhook_url, json=payload) as response:
                    if response.status != 204:
                        print(f"Failed to send immediate alert: {response.status}")
        
        except Exception as e:
            print(f"Error sending immediate alert: {e}")
    
    def _get_secret_severity(self, secret_type: str) -> str:
        """Determine severity based on secret type"""
        critical_types = ["private_key"]
        high_types = ["api_key", "jwt_token", "aws_key", "github_token", "slack_token"]
        medium_types = ["password"]
        low_types = ["email"]
        
        if secret_type in critical_types:
            return "CRITICAL"
        elif secret_type in high_types:
            return "HIGH"
        elif secret_type in medium_types:
            return "MEDIUM"
        else:
            return "LOW"


class JSEndpointDetector:
    """Phase 6.2: Endpoint detection in JS content"""
    
    ENDPOINT_PATTERNS = [
        r'["\']([^"\']*(?:api|endpoint|route|service|server)[^"\']*)["\']',
        r'["\']([^"\']*/(v\d+|api|admin|user|auth|data|config)[^"\']*)["\']',
        r'url\s*[:=]\s*["\']([^"\']+)["\']',
        r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'\.get\s*\(\s*["\']([^"\']+)["\']',
        r'\.post\s*\(\s*["\']([^"\']+)["\']'
    ]
    
    def detect_endpoints(self, content: str, url: str) -> List[JSFinding]:
        """Extract endpoints from JS content"""
        findings = []
        lines = content.split('\n')
        
        for pattern in self.ENDPOINT_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    endpoint = match.group(1)
                    if self._is_valid_endpoint(endpoint):
                        findings.append(JSFinding(
                            url=url,
                            type="endpoint",
                            severity="MEDIUM",
                            matched_string=endpoint,
                            line_number=line_num,
                            context=line.strip()
                        ))
        
        return findings
    
    def _is_valid_endpoint(self, endpoint: str) -> bool:
        """Validate if string is actually an endpoint"""
        # Skip obvious non-endpoints
        skip_patterns = [
            r'^http[s]?://',  # Full URLs are handled elsewhere
            r'^\w+$',  # Single words
            r'^\d+$',  # Numbers only
            r'^[{}()\[\]]+$'  # Just brackets
        ]
        
        for pattern in skip_patterns:
            if re.match(pattern, endpoint):
                return False
        
        # Should contain path-like structure
        return '/' in endpoint or '.' in endpoint


class JSSensitiveKeywordDetector:
    """Phase 6.3: Sensitive keyword detection"""
    
    SENSITIVE_KEYWORDS = [
        'secret', 'token', 'auth', 'password', 'key', 'internal',
        'admin', 'private', 'confidential', 'sensitive', 'credential'
    ]
    
    def detect_keywords(self, content: str, url: str) -> List[JSFinding]:
        """Detect sensitive keywords in JS content"""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for keyword in self.SENSITIVE_KEYWORDS:
                if keyword.lower() in line.lower():
                    findings.append(JSFinding(
                        url=url,
                        type="sensitive_keyword",
                        severity="LOW",
                        matched_string=keyword,
                        line_number=line_num,
                        context=line.strip()
                    ))
        
        return findings


class JSEntropyDetector:
    """Phase 6.4: High entropy string detection"""
    
    def __init__(self, threshold: float = 4.5, min_length: int = 20):
        self.threshold = threshold
        self.min_length = min_length
    
    def detect_high_entropy(self, content: str, url: str) -> List[JSFinding]:
        """Detect high entropy strings (possible hidden secrets)"""
        findings = []
        lines = content.split('\n')
        
        # Extract quoted strings
        string_pattern = r'["\']([^"\']{20,})["\']'
        
        for line_num, line in enumerate(lines, 1):
            matches = re.finditer(string_pattern, line)
            for match in matches:
                candidate = match.group(1)
                if self._calculate_entropy(candidate) >= self.threshold:
                    findings.append(JSFinding(
                        url=url,
                        type="high_entropy",
                        severity="MEDIUM",
                        matched_string=candidate[:50] + "..." if len(candidate) > 50 else candidate,
                        line_number=line_num,
                        context=line.strip()
                    ))
        
        return findings
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        # Count character frequencies
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        string_len = len(string)
        
        for count in char_counts.values():
            probability = count / string_len
            entropy -= probability * math.log2(probability)
        
        return entropy


class ArchiveHandler:
    """Archive.org handler for dead URLs"""
    
    def __init__(self):
        self.session = None
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_REQUESTS)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            headers={'User-Agent': random.choice(USER_AGENTS)}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def get_available_timestamps(self, url: str) -> List[str]:
        """Phase 2: Query Archive Index (CDX API)"""
        try:
            cdx_url = f"{WAYBACK_CDX_URL}?url={url}&output=json"
            
            async with self.session.get(cdx_url) as response:
                if response.status != 200:
                    return []
                
                data = await response.json()
                if len(data) < 2:
                    return []
                
                # Extract timestamps (skip header row)
                timestamps = [row[1] for row in data[1:] if len(row) > 1]
                return timestamps
        
        except Exception:
            return []
    
    def select_random_timestamps(self, timestamps: List[str], count: int = None) -> List[str]:
        """Phase 3: Random Timestamp Selection"""
        if not timestamps:
            return []
        
        count = count or MAX_TIMESTAMPS
        count = min(count, len(timestamps))
        
        # Pick random timestamps to avoid rate limiting
        return random.sample(timestamps, count)
    
    async def fetch_archived_content(self, url: str, timestamp: str) -> Tuple[int, str]:
        """Phase 4: Fetch Archived JS"""
        archive_url = WAYBACK_SNAPSHOT_URL.format(timestamp=timestamp, url=url)
        
        try:
            async with self.session.get(archive_url) as response:
                content = await response.text()
                return response.status, content
        
        except Exception:
            return 0, ""
    
    def validate_archived_content(self, content: str) -> bool:
        """Phase 5: Validate Content"""
        if not content or len(content.strip()) < 50:
            return False
        
        # Skip HTML pages
        if content.strip().startswith('<!DOCTYPE') or content.strip().startswith('<html'):
            return False
        
        # Skip error pages
        error_indicators = ['404 not found', 'error', 'page not found', 'wayback machine']
        content_lower = content.lower()
        if any(indicator in content_lower for indicator in error_indicators):
            return False
        
        # Should look like JavaScript
        js_indicators = ['var ', 'function', 'const ', 'let ', '=>', '{', '}', ';']
        if any(indicator in content for indicator in js_indicators):
            return True
        
        return False


class JSScanner:
    """Main JS scanner orchestrating all phases"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.filter = JSFilter()
        self.priority_detector = JSPriorityDetector(
            self.config.get('keywords', IMPORTANT_JS_KEYWORDS)
        )
        self.size_filter = FileSizeFilter(
            self.config.get('max_size', 1024 * 1024)
        )
        self.secret_detector = JSSecretDetector()
        self.endpoint_detector = JSEndpointDetector()
        self.keyword_detector = JSSensitiveKeywordDetector()
        self.entropy_detector = JSEntropyDetector()
        
        # Setup logging
        self.logger = self._setup_logger()
        
        # Create output directories
        dirs = ['js', 'js/live', 'js/archive', 'logs']
        for dir_name in dirs:
            (OUTPUT_DIR / dir_name).mkdir(exist_ok=True)
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('js_scanner')
        logger.setLevel(logging.INFO)
        
        # Create file handler
        log_file = OUTPUT_DIR / 'logs' / 'js_scanner.log'
        log_file.parent.mkdir(exist_ok=True)
        
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    async def scan_urls(self, urls: List[str]) -> List[JSScanResult]:
        """Main scanning function"""
        # Phase 1: Filter JS URLs
        js_urls = self.filter.filter_js_urls(urls)
        self.logger.info(f"Filtered {len(js_urls)} JS URLs from {len(urls)} total URLs")
        
        # Phase 2: Prioritize URLs
        high_priority_urls = []
        low_priority_urls = []
        
        for url in js_urls:
            priority = self.priority_detector.get_priority(url)
            if priority == "HIGH":
                high_priority_urls.append(url)
            else:
                low_priority_urls.append(url)
                self.logger.info(f"skipped: not important js - {url}")
        
        # Scan high priority URLs
        results = await self._scan_url_list(high_priority_urls, "HIGH")
        
        # Scan low priority if config allows
        if self.config.get('scan_low_priority', False):
            results.extend(await self._scan_url_list(low_priority_urls, "LOW"))
        
        # Process archive queue for dead URLs
        archive_results = await self._process_archive_queue(results)
        results.extend(archive_results)
        
        return results
    
    async def _scan_url_list(self, urls: List[str], priority: str) -> List[JSScanResult]:
        """Scan a list of URLs with concurrency control"""
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        
        async def scan_with_semaphore(url: str):
            async with semaphore:
                return await self._scan_single_url(url, priority)
        
        # Add delay between requests
        tasks = []
        for url in urls:
            tasks.append(scan_with_semaphore(url))
            # Random delay
            delay = random.uniform(*DEFAULT_DELAY)
            await asyncio.sleep(delay)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and log errors
        valid_results = []
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Error during scanning: {result}")
            else:
                valid_results.append(result)
        
        return valid_results
    
    async def _process_archive_queue(self, results: List[JSScanResult]) -> List[JSScanResult]:
        """Process dead URLs through archive.org"""
        archive_urls = [r.url for r in results if r.status in ["ARCHIVE_QUEUED", "SOFT_404"]]
        
        if not archive_urls:
            return []
        
        self.logger.info(f"Processing {len(archive_urls)} URLs through archive.org")
        
        async with ArchiveHandler() as archive:
            archive_results = []
            
            for url in archive_urls:
                try:
                    # Phase 2: Query Archive Index
                    timestamps = await archive.get_available_timestamps(url)
                    
                    if not timestamps:
                        self.logger.info(f"archive: no snapshots found - {url}")
                        archive_results.append(JSScanResult(url, "ARCHIVE_NOT_FOUND", [], 0, 0))
                        continue
                    
                    # Phase 3: Random Timestamp Selection
                    selected_timestamps = archive.select_random_timestamps(timestamps)
                    
                    # Phase 4-6: Fetch and scan archived versions
                    for timestamp in selected_timestamps:
                        status, content = await archive.fetch_archived_content(url, timestamp)
                        
                        if status != 200:
                            continue
                        
                        # Phase 5: Validate Content
                        if not archive.validate_archived_content(content):
                            continue
                        
                        # Phase 6: Scan Archived JS
                        findings = []
                        findings.extend(self.secret_detector.detect_secrets(content, url))
                        findings.extend(self.endpoint_detector.detect_endpoints(content, url))
                        findings.extend(self.keyword_detector.detect_keywords(content, url))
                        findings.extend(self.entropy_detector.detect_high_entropy(content, url))
                        
                        # Add archive info to findings
                        for finding in findings:
                            finding.matched_string = f"[{timestamp}] {finding.matched_string}"
                        
                        if findings:
                            self.logger.info(f"archive: scanned {url} - {len(findings)} findings")
                            await self._send_discord_alerts(findings)
                        
                        archive_results.append(JSScanResult(
                            url, "ARCHIVE_SCANNED", findings, 
                            len(content.encode()), 0
                        ))
                        
                        # Small delay between archive requests
                        await asyncio.sleep(random.uniform(1, 2))
                
                except Exception as e:
                    self.logger.error(f"archive error for {url}: {e}")
                    archive_results.append(JSScanResult(url, "ARCHIVE_ERROR", [], 0, 0))
            
            return archive_results
    
    async def _scan_single_url(self, url: str, priority: str) -> JSScanResult:
        """Scan a single URL through all phases"""
        start_time = time.time()
        
        try:
            async with JSFetcher() as fetcher:
                # Phase 3: HTTP status check
                status, content, file_size = await fetcher.fetch_js_content(url)
                
                if status == 200:
                    # Phase 4: Soft 404 detection
                    if Soft404Detector.is_soft_404(content):
                        self.logger.info(f"queued: archive scan (soft 404) - {url}")
                        return JSScanResult(url, "SOFT_404", [], file_size, time.time() - start_time)
                    
                    # Phase 5: File size filter
                    if not self.size_filter.should_scan(file_size):
                        self.logger.info(f"skipped: size too large ({file_size} bytes) - {url}")
                        return JSScanResult(url, "SIZE_EXCEEDED", [], file_size, time.time() - start_time)
                    
                    # Phase 6: Content scanning
                    findings = []
                    findings.extend(self.secret_detector.detect_secrets(content, url))
                    findings.extend(self.endpoint_detector.detect_endpoints(content, url))
                    findings.extend(self.keyword_detector.detect_keywords(content, url))
                    findings.extend(self.entropy_detector.detect_high_entropy(content, url))
                    
                    # Phase 7: Result classification (done in detectors)
                    self.logger.info(f"scanned: {priority.lower()} priority js - {url} - {len(findings)} findings")
                    
                    # Phase 9: Discord alerts for high severity
                    await self._send_discord_alerts(findings)
                    
                    return JSScanResult(url, "SCANNED", findings, file_size, time.time() - start_time)
                
                elif status == 404:
                    self.logger.info(f"queued: archive scan (404) - {url}")
                    return JSScanResult(url, "ARCHIVE_QUEUED", [], file_size, time.time() - start_time)
                
                elif status == 403:
                    self.logger.info(f"skipped: 403 forbidden - {url}")
                    return JSScanResult(url, "FORBIDDEN", [], file_size, time.time() - start_time)
                
                elif status >= 500:
                    self.logger.info(f"skipped: server error {status} - {url}")
                    return JSScanResult(url, "SERVER_ERROR", [], file_size, time.time() - start_time)
                
                else:
                    self.logger.info(f"skipped: status {status} - {url}")
                    return JSScanResult(url, f"STATUS_{status}", [], file_size, time.time() - start_time)
        
        except Exception as e:
            self.logger.error(f"Error scanning {url}: {e}")
            return JSScanResult(url, "ERROR", [], 0, time.time() - start_time)
    
    async def _send_discord_alerts(self, findings: List[JSFinding]):
        """Send Discord webhook alerts for high severity findings"""
        webhook_url = self.config.get('discord_webhook') or DISCORD_WEBHOOKS.get('js_leaks')
        
        if not webhook_url:
            return
        
        high_severity_findings = [f for f in findings if f.severity in ['HIGH', 'CRITICAL']]
        
        if not high_severity_findings:
            return
        
        try:
            async with aiohttp.ClientSession() as session:
                for finding in high_severity_findings:
                    embed = {
                        "title": f"🚨 JS Security Finding - {finding.severity}",
                        "description": f"**URL:** {finding.url}\n"
                                     f"**Type:** {finding.type}\n"
                                     f"**Severity:** {finding.severity}\n"
                                     f"**Match:** `{finding.matched_string}`",
                        "color": self._get_discord_color(finding.severity),
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    
                    if finding.context:
                        embed["description"] += f"\n**Context:** ```{finding.context}```"
                    
                    payload = {"embeds": [embed]}
                    
                    async with session.post(webhook_url, json=payload) as response:
                        if response.status != 204:
                            self.logger.error(f"Failed to send Discord alert: {response.status}")
        
        except Exception as e:
            self.logger.error(f"Error sending Discord alert: {e}")
    
    def _get_discord_color(self, severity: str) -> int:
        """Get Discord embed color based on severity"""
        colors = {
            "CRITICAL": 0xFF0000,  # Red
            "HIGH": 0xFF6600,      # Orange
            "MEDIUM": 0xFFFF00,    # Yellow
            "LOW": 0x00FF00        # Green
        }
        return colors.get(severity, 0x808080)  # Gray default
    
    def save_results(self, results: List[JSScanResult]):
        """Phase 8: Save results to files"""
        # Prepare data
        findings_data = []
        scanned_urls = []
        skipped_urls = []
        errors = []
        
        for result in results:
            if result.status == "SCANNED":
                scanned_urls.append(result.url)
                for finding in result.findings:
                    findings_data.append({
                        "url": finding.url,
                        "type": finding.type,
                        "severity": finding.severity,
                        "matched_string": finding.matched_string,
                        "line_number": finding.line_number,
                        "context": finding.context,
                        "timestamp": datetime.utcnow().isoformat()
                    })
            elif result.status in ["ARCHIVE_QUEUED", "SOFT_404", "ARCHIVE_SCANNED", "ARCHIVE_NOT_FOUND", "ARCHIVE_ERROR"]:
                # Archive results are handled separately
                pass
            elif result.status in ["ERROR", "FORBIDDEN", "SERVER_ERROR", "SIZE_EXCEEDED"]:
                errors.append(f"{result.url} - {result.status}")
            else:
                skipped_urls.append(f"{result.url} - {result.status}")
        
        # Save findings
        findings_file = OUTPUT_DIR / 'js' / 'findings.json'
        with open(findings_file, 'w') as f:
            json.dump(findings_data, f, indent=2)
        
        # Save scanned URLs
        scanned_file = OUTPUT_DIR / 'js' / 'scanned.txt'
        with open(scanned_file, 'w') as f:
            f.write('\n'.join(scanned_urls))
        
        # Save skipped URLs
        skipped_file = OUTPUT_DIR / 'js' / 'skipped.txt'
        with open(skipped_file, 'w') as f:
            f.write('\n'.join(skipped_urls))
        
        # Save errors
        errors_file = OUTPUT_DIR / 'js' / 'errors.txt'
        with open(errors_file, 'w') as f:
            f.write('\n'.join(errors))
        
        self.logger.info(f"Results saved: {len(findings_data)} findings, {len(scanned_urls)} scanned, {len(skipped_urls)} skipped, {len(errors)} errors")


# Main execution function
async def main():
    """Example usage of the JS scanner"""
    # Sample configuration
    config = {
        'keywords': IMPORTANT_JS_KEYWORDS,
        'max_size': 1024 * 1024,  # 1MB
        'scan_low_priority': False,
        'discord_webhook': DISCORD_WEBHOOKS.get('js_leaks'),
        'threads': MAX_CONCURRENT_REQUESTS,
        'timeout': REQUEST_TIMEOUT,
        'delay': DEFAULT_DELAY
    }
    
    # Sample URLs to test
    test_urls = [
        "https://example.com/main.js",
        "https://example.com/app.min.js",
        "https://example.com/style.css",  # Should be filtered out
        "https://example.com/config.prod.js",
        "https://example.com/bundle.js"
    ]
    
    scanner = JSScanner(config)
    results = await scanner.scan_urls(test_urls)
    scanner.save_results(results)
    
    print(f"Scanning complete. Processed {len(results)} URLs.")


if __name__ == "__main__":
    asyncio.run(main())
