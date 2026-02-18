"""
Environment file scanner module for detecting exposed .env files
"""

import asyncio
import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.rate_limiter import get_rate_limiter
from config.config import ENV_PATHS, MAX_CONCURRENT_REQUESTS

class EnvScanner:
    """
    Scan for exposed .env files and environment variables.
    Only reports valid findings: 200 response + real .env content + extracted secrets (no examples/fakes).
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.rate_limiter = get_rate_limiter()
        self.env_paths = ENV_PATHS
        
        # Patterns for actual secrets in .env files
        self.secret_patterns = {
            "database": [
                r"(?i)(db_|database_)(password|pass|pwd)\s*=\s*[^\s\n]{8,}",
                r"(?i)(db_|database_)(user|username)\s*=\s*[^\s\n]{3,}",
                r"(?i)(db_|database_)(host|server|url)\s*=\s*[^\s\n]{5,}",
                r"(?i)(mongodb|mysql|postgres|redis)://[^\s\n]{10,}"
            ],
            "api_keys": [
                r"(?i)(api_|access_)(key|token|secret)\s*=\s*[^\s\n]{16,}",
                r"(?i)(secret_|private_)(key|token)\s*=\s*[^\s\n]{16,}"
            ],
            "auth": [
                r"(?i)(jwt_|auth_)(secret|key|token)\s*=\s*[^\s\n]{16,}",
                r"(?i)(session|csrf)_secret\s*=\s*[^\s\n]{16,}",
                r"(?i)(password|passwd|pwd)\s*=\s*[^\s\n]{8,}"
            ],
            "cloud": [
                r"(?i)(aws_|amazon_)(access|secret)_key\s*=\s*[A-Za-z0-9/+=]{16,}",
                r"(?i)(google_|gcp_)(api|private)_key\s*=\s*[^\s\n]{20,}",
                r"(?i)(azure_|microsoft_)(key|secret|token)\s*=\s*[^\s\n]{16,}"
            ],
            "external_services": [
                r"(?i)(stripe|paypal|twilio|sendgrid)_key\s*=\s*[^\s\n]{16,}",
                r"(?i)(github_|gitlab_|bitbucket_)(token|key|secret)\s*=\s*[^\s\n]{16,}",
                r"(?i)(slack_|discord_)_(webhook|token|key)\s*=\s*[^\s\n]{16,}"
            ],
            "encryption": [
                r"(?i)(encrypt|decrypt)_key\s*=\s*[^\s\n]{16,}",
                r"(?i)(salt|pepper)\s*=\s*[^\s\n]{8,}",
                r"(?i)(hash|cipher)_key\s*=\s*[^\s\n]{16,}"
            ]
        }
        
        # Patterns that indicate real .env content (not examples)
        self.real_content_patterns = [
            r"(?i)production|prod|live",
            r"(?i)database|db_host|db_user|db_pass",
            r"(?i)api_key|secret_key|access_token",
            r"(?i)aws_|google_|azure_|stripe_",
            r"\.amazonaws\.com",
            r"\.googleapis\.com",
            r"mongodb://|mysql://|postgres://"
        ]
        
        # Patterns that indicate fake/example content
        self.fake_content_patterns = [
            r"(?i)example|dummy|test|fake|sample",
            r"(?i)xxx|yyy|zzz|123|abc",
            r"(?i)localhost|127\.0\.0\.1|0\.0\.0\.0",
            r"(?i)your_.*_here",
            r"(?i)replace_with_.*",
            r"(?i)change_this"
        ]
        
        # Additional paths to check
        self.additional_env_paths = [
            "/.env.local",
            "/.env.development", 
            "/.env.staging",
            "/.env.backup",
            "/.env.old",
            "/.env.sample",
            "/config/.env",
            "/api/.env",
            "/admin/.env",
            "/backend/.env",
            "/app/.env",
            "/src/.env",
            "/public/.env"
        ]
    
    async def scan_base_url(self, base_url: str) -> List[Dict[str, Any]]:
        """
        Scan a base URL for exposed .env files
        
        Args:
            base_url: Base URL to scan
            
        Returns:
            List of findings
        """
        log_module_start(self.logger, "ENV Scanner", base_url)
        
        if not base_url:
            return []
        
        try:
            # Ensure base URL has proper format
            if not base_url.startswith(('http://', 'https://')):
                base_url = 'https://' + base_url
            
            # Remove trailing slash
            if base_url.endswith('/'):
                base_url = base_url[:-1]
            
            # Build all possible .env URLs
            env_urls = []
            all_paths = self.env_paths + self.additional_env_paths
            for path in all_paths:
                env_url = urljoin(base_url + '/', path.lstrip('/'))
                env_urls.append(env_url)
            
            # Check all URLs concurrently
            findings = await self._check_env_urls(env_urls, base_url)
            
            log_module_complete(self.logger, "ENV Scanner", base_url, len(findings))
            
            if findings:
                self.logger.warning(f"Found {len(findings)} exposed .env files on {base_url}")
            
            return findings
            
        except Exception as e:
            log_error(self.logger, "ENV Scanner", base_url, str(e))
            return []
    
    async def _check_env_urls(self, env_urls: List[str], base_url: str) -> List[Dict[str, Any]]:
        """
        Check multiple .env URLs for exposure
        
        Args:
            env_urls: List of .env URLs to check
            base_url: Base URL for context
            
        Returns:
            List of findings
        """
        findings = []
        
        # Use semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        
        async def check_single_env_url(env_url: str) -> Optional[Dict[str, Any]]:
            async with semaphore:
                try:
                    # Make request
                    response = await self.rate_limiter.get(env_url, timeout=10)
                    
                    if response is None or response.status != 200:
                        return None
                    
                    # Get content
                    content = await response.text()
                    
                    # Check if it's actually an .env file with real secrets
                    if not self._is_real_env_file(content):
                        return None
                    
                    # Extract secrets from content
                    secrets = self._extract_secrets(content)
                    
                    if not secrets:
                        return None
                    
                    return {
                        "url": env_url,
                        "base_url": base_url,
                        "status_code": response.status,
                        "content_length": len(content),
                        "secrets": secrets,
                        "severity": "CRITICAL" if len(secrets) > 5 else "HIGH",
                        "content_preview": content[:500] + "..." if len(content) > 500 else content
                    }
                    
                except Exception as e:
                    self.logger.debug(f"Error checking {env_url}: {e}")
                    return None
        
        # Check all URLs concurrently
        tasks = [check_single_env_url(url) for url in env_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and None results
        for result in results:
            if isinstance(result, Exception):
                continue
            if result is not None:
                findings.append(result)
        
        return findings
    
    def _is_real_env_file(self, content: str) -> bool:
        """
        Check if content is from a real .env file (not example/fake)
        
        Args:
            content: Content to check
            
        Returns:
            True if real .env file
        """
        if not content or len(content.strip()) < 20:
            return False
        
        # Check for real content patterns
        real_matches = 0
        for pattern in self.real_content_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                real_matches += 1
        
        # Check for fake content patterns
        fake_matches = 0
        for pattern in self.fake_content_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                fake_matches += 1
        
        # Only report valid .env: must have real content and at most one fake indicator
        return real_matches >= 1 and fake_matches <= 1
    
    def _extract_secrets(self, content: str) -> List[Dict[str, Any]]:
        """
        Extract secrets from .env file content
        
        Args:
            content: .env file content
            
        Returns:
            List of secrets found
        """
        secrets = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Check each secret pattern
            for category, patterns in self.secret_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    
                    for match in matches:
                        # Extract the secret value
                        if '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            
                            # Remove quotes if present
                            if (value.startswith('"') and value.endswith('"')) or \
                               (value.startswith("'") and value.endswith("'")):
                                value = value[1:-1]
                            
                            # Skip if value is too short or looks fake
                            if len(value) < 6 or self._is_fake_secret(value):
                                continue
                            
                            secret = {
                                "category": category,
                                "key": key,
                                "value": value,  # Include full value for analysis
                                "line_number": line_num,
                                "line": line,
                                "confidence": self._calculate_env_confidence(category, value),
                                "masked_value": self._mask_secret(value)
                            }
                            
                            secrets.append(secret)
        
        return secrets
    
    def _is_fake_secret(self, value: str) -> bool:
        """
        Check if a secret value is fake/example
        
        Args:
            value: Secret value to check
            
        Returns:
            True if fake
        """
        value_lower = value.lower()
        
        fake_indicators = [
            "example", "dummy", "test", "fake", "sample",
            "xxx", "yyy", "zzz", "123", "abc",
            "your_", "replace_", "change_", "enter_",
            "localhost", "127.0.0.1", "0.0.0.0"
        ]
        
        for indicator in fake_indicators:
            if indicator in value_lower:
                return True
        
        return False
    
    def _calculate_env_confidence(self, category: str, value: str) -> str:
        """
        Calculate confidence level for .env secret
        
        Args:
            category: Secret category
            value: Secret value
            
        Returns:
            Confidence level
        """
        high_confidence_categories = {"database", "cloud", "api_keys"}
        medium_confidence_categories = {"auth", "external_services"}
        
        if category in high_confidence_categories:
            return "high"
        elif category in medium_confidence_categories:
            return "medium"
        else:
            return "low"
    
    def _mask_secret(self, value: str, visible_chars: int = 4) -> str:
        """
        Mask a secret value for logging
        
        Args:
            value: Secret value to mask
            visible_chars: Number of characters to show at start/end
            
        Returns:
            Masked value
        """
        if len(value) <= visible_chars * 2:
            return "*" * len(value)
        
        return value[:visible_chars] + "*" * (len(value) - visible_chars * 2) + value[-visible_chars:]
    
    async def scan_multiple_targets(self, base_urls: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan multiple base URLs for exposed .env files
        
        Args:
            base_urls: List of base URLs to scan
            
        Returns:
            Dictionary mapping URLs to findings
        """
        log_module_start(self.logger, "ENV Scanner", f"{len(base_urls)} targets")
        
        results = {}
        total_findings = 0
        
        # Use semaphore to limit concurrent scans
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        
        async def scan_single_target(base_url: str) -> tuple:
            async with semaphore:
                findings = await self.scan_base_url(base_url)
                return base_url, findings
        
        # Create tasks for all targets
        tasks = [scan_single_target(url) for url in base_urls]
        completed_tasks = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for task_result in completed_tasks:
            if isinstance(task_result, Exception):
                continue
            
            base_url, findings = task_result
            results[base_url] = findings
            total_findings += len(findings)
        
        log_module_complete(self.logger, "ENV Scanner", f"{len(base_urls)} targets", total_findings)
        
        if total_findings > 0:
            self.logger.warning(f"Found {total_findings} exposed .env files across all targets")
        
        return results
    
    def get_scan_statistics(self, results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Get statistics about .env scan results
        
        Args:
            results: Scan results
            
        Returns:
            Statistics dictionary
        """
        total_targets = len(results)
        targets_with_findings = sum(1 for findings in results.values() if findings)
        total_env_files = sum(len(findings) for findings in results.values())
        total_secrets = sum(
            len(finding.get("secrets", [])) 
            for findings in results.values() 
            for finding in findings
        )
        
        # Count by category
        category_counts = {}
        for findings in results.values():
            for finding in findings:
                for secret in finding.get("secrets", []):
                    category = secret.get("category", "unknown")
                    category_counts[category] = category_counts.get(category, 0) + 1
        
        return {
            "total_targets_scanned": total_targets,
            "targets_with_exposed_env": targets_with_findings,
            "total_env_files_found": total_env_files,
            "total_secrets_found": total_secrets,
            "secrets_by_category": category_counts,
            "average_secrets_per_env": total_secrets / total_env_files if total_env_files > 0 else 0
        }

# Singleton instance
_env_scanner = None

def get_env_scanner() -> EnvScanner:
    """Get the ENV scanner instance"""
    global _env_scanner
    if _env_scanner is None:
        _env_scanner = EnvScanner()
    return _env_scanner
