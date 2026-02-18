"""
Git repository exposure scanner module
"""

import asyncio
import re
import tempfile
import zipfile
import base64
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.rate_limiter import get_rate_limiter
from utils.helpers import calculate_entropy, is_high_entropy_string
from config.config import MAX_CONCURRENT_REQUESTS

class GitScanner:
    """
    Scan for exposed .git repositories and extract sensitive information
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.rate_limiter = get_rate_limiter()
        
        # Common .git files and directories to check
        self.git_paths = [
            "/.git/HEAD",
            "/.git/config",
            "/.git/description",
            "/.git/info/exclude",
            "/.git/objects/info/packs",
            "/.git/packed-refs",
            "/.git/refs/heads/master",
            "/.git/refs/heads/main",
            "/.git/refs/remotes/origin/HEAD",
            "/.git/index",
            "/.git/logs/HEAD",
            "/.git/logs/refs/heads/master",
            "/.git/logs/refs/heads/main"
        ]
        
        # Patterns for sensitive information in git files
        self.secret_patterns = {
            "api_keys": [
                r"(?i)(api|access|secret|private)_key\s*[:=]\s*['\"]?[A-Za-z0-9+/]{16,}['\"]?",
                r"(?i)password\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?"
            ],
            "database": [
                r"(?i)(mongodb|mysql|postgres)://[^\s'\"]{10,}",
                r"(?i)(db_|database_)(host|user|pass|password)\s*[:=]\s*['\"]?[^\s'\"]{5,}['\"]?"
            ],
            "cloud_tokens": [
                r"(?i)(aws_|amazon_)(access|secret)_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,}['\"]?",
                r"(?i)(google_|gcp_)(api|private)_key\s*[:=]\s*['\"]?[^\s'\"]{20,}['\"]?"
            ],
            "private_keys": [
                r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[^-]+-----END (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"
            ],
            "tokens": [
                r"(?i)(jwt|auth|session|csrf)_token\s*[:=]\s*['\"]?[A-Za-z0-9._-]{20,}['\"]?",
                r"(?i)github_token\s*[:=]\s*['\"]?[A-Za-z0-9]{36,}['\"]?"
            ]
        }
        
        # File extensions that might contain sensitive data
        self.sensitive_extensions = [
            ".env", ".config", ".key", ".pem", ".p12", ".pfx",
            ".sql", ".db", ".sqlite", ".json", ".xml", ".yml", ".yaml"
        ]
    
    async def scan_base_url(self, base_url: str) -> List[Dict[str, Any]]:
        """
        Scan a base URL for exposed .git repository
        
        Args:
            base_url: Base URL to scan
            
        Returns:
            List of findings
        """
        log_module_start(self.logger, "Git Scanner", base_url)
        
        if not base_url:
            return []
        
        try:
            # Ensure base URL has proper format
            if not base_url.startswith(('http://', 'https://')):
                base_url = 'https://' + base_url
            
            # Remove trailing slash
            if base_url.endswith('/'):
                base_url = base_url[:-1]
            
            # First check if .git/HEAD is accessible
            head_url = urljoin(base_url + '/', '.git/HEAD')
            
            # Try multiple approaches
            if await self._check_git_head(head_url):
                pass  # Standard .git/HEAD works
            elif await self._check_git_head_alternative(base_url):
                pass  # Alternative method works
            else:
                return []
            
            # .git repository is exposed, gather more information
            git_info = await self._gather_git_info(base_url)
            
            if git_info:
                finding = {
                    "url": base_url,
                    "head_url": head_url,
                    "severity": "CRITICAL",
                    "git_info": git_info,
                    "evidence": f"Exposed .git repository at {base_url}/.git/"
                }
                
                log_module_complete(self.logger, "Git Scanner", base_url, 1)
                self.logger.warning(f"Exposed .git repository found at {base_url}")
                
                return [finding]
            
            return []
            
        except Exception as e:
            log_error(self.logger, "Git Scanner", base_url, str(e))
            return []
    
    async def _check_git_head(self, head_url: str) -> bool:
        """
        Check if .git/HEAD is accessible
        
        Args:
            head_url: URL to .git/HEAD
            
        Returns:
            True if accessible
        """
        try:
            response = await self.rate_limiter.get(head_url, timeout=10)
            
            if response and response.status == 200:
                content = await response.text()
                # Check if it looks like a valid git HEAD file
                return "ref:" in content or content.strip().startswith("ref:")
            
            return False
            
        except Exception:
            return False
    
    async def _check_git_head_alternative(self, base_url: str) -> bool:
        """
        Alternative method to check for .git exposure
        
        Args:
            base_url: Base URL to check
            
        Returns:
            True if .git repository is exposed
        """
        try:
            # Try checking other git files that might be accessible
            test_files = [
                "/.git/config",
                "/.git/description", 
                "/.git/index"
            ]
            
            for file_path in test_files:
                file_url = urljoin(base_url + '/', file_path.lstrip('/'))
                response = await self.rate_limiter.get(file_url, timeout=5)
                
                if response and response.status == 200:
                    content = await response.text()
                    
                    # Check if it looks like valid git content
                    if "config" in file_path and ("[core]" in content or "[remote" in content):
                        return True
                    elif "description" in file_path and len(content.strip()) > 0:
                        return True
                    elif "index" in file_path and len(content) > 10:  # Index files are binary-ish
                        return True
            
            return False
            
        except Exception:
            return False
    
    async def _gather_git_info(self, base_url: str) -> Optional[Dict[str, Any]]:
        """
        Gather information about the exposed git repository
        
        Args:
            base_url: Base URL
            
        Returns:
            Git information dictionary
        """
        try:
            git_info = {
                "accessible_files": [],
                "branches": [],
                "remotes": [],
                "config_info": None,
                "secrets_found": []
            }
            
            # Check various git files
            for path in self.git_paths:
                file_url = urljoin(base_url + '/', path.lstrip('/'))
                
                try:
                    response = await self.rate_limiter.get(file_url, timeout=5)
                    
                    if response and response.status == 200:
                        content = await response.text()
                        
                        file_info = {
                            "path": path,
                            "url": file_url,
                            "size": len(content),
                            "content_preview": content[:200] + "..." if len(content) > 200 else content
                        }
                        
                        git_info["accessible_files"].append(file_info)
                        
                        # Extract specific information based on file type
                        if "HEAD" in path:
                            git_info["head_content"] = content.strip()
                        elif "config" in path:
                            git_info["config_info"] = self._parse_git_config(content)
                        elif "refs/heads" in path:
                            branch_name = path.split('/')[-1]
                            git_info["branches"].append(branch_name)
                        elif "refs/remotes" in path:
                            remote_name = path.split('/')[-1]
                            git_info["remotes"].append(remote_name)
                        
                        # Scan for secrets in the content
                        secrets = self._scan_content_for_secrets(content, file_url)
                        git_info["secrets_found"].extend(secrets)
                        
                except Exception as e:
                    self.logger.debug(f"Error checking {file_url}: {e}")
                    continue
            
            return git_info if git_info["accessible_files"] else None
            
        except Exception as e:
            self.logger.error(f"Error gathering git info for {base_url}: {e}")
            return None
    
    def _parse_git_config(self, content: str) -> Dict[str, Any]:
        """
        Parse git config file for useful information
        
        Args:
            content: Git config file content
            
        Returns:
            Parsed config information
        """
        config_info = {
            "remote_urls": [],
            "user_info": {},
            "core_info": {}
        }
        
        try:
            lines = content.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Extract remote URLs
                if "url =" in line.lower():
                    url = line.split('=')[-1].strip()
                    config_info["remote_urls"].append(url)
                
                # Extract user information
                elif "name =" in line.lower():
                    name = line.split('=')[-1].strip()
                    config_info["user_info"]["name"] = name
                elif "email =" in line.lower():
                    email = line.split('=')[-1].strip()
                    config_info["user_info"]["email"] = email
                
                # Extract core settings
                elif "bare =" in line.lower():
                    bare = line.split('=')[-1].strip()
                    config_info["core_info"]["bare"] = bare
            
        except Exception as e:
            self.logger.warning(f"Error parsing git config: {e}")
        
        return config_info
    
    def _scan_content_for_secrets(self, content: str, source_url: str) -> List[Dict[str, Any]]:
        """
        Scan git file content for secrets
        
        Args:
            content: Content to scan
            source_url: Source URL
            
        Returns:
            List of secrets found
        """
        secrets = []
        
        try:
            for secret_type, patterns in self.secret_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    
                    for match in matches:
                        secret_value = match.group(0)
                        
                        # Skip if it looks like a false positive
                        if self._is_false_positive(secret_value):
                            continue
                        
                        secret = {
                            "type": secret_type,
                            "value": secret_value,
                            "source_file": source_url,
                            "line_number": content[:match.start()].count('\n') + 1,
                            "confidence": "high" if secret_type in ["private_keys", "cloud_tokens"] else "medium"
                        }
                        
                        secrets.append(secret)
            
            # Also check for high entropy strings
            words = re.findall(r'\b[A-Za-z0-9+/]{20,}\b', content)
            for word in words:
                if is_high_entropy_string(word, 4.0) and not self._is_false_positive(word):
                    secret = {
                        "type": "high_entropy",
                        "value": word,
                        "source_file": source_url,
                        "confidence": "low"
                    }
                    secrets.append(secret)
        
        except Exception as e:
            self.logger.warning(f"Error scanning content for secrets: {e}")
        
        return secrets
    
    def _is_false_positive(self, text: str) -> bool:
        """
        Check if text is likely a false positive
        
        Args:
            text: Text to check
            
        Returns:
            True if false positive
        """
        text_lower = text.lower()
        
        false_positive_indicators = [
            "example", "dummy", "test", "fake", "sample",
            "xxx", "yyy", "zzz", "123", "abc",
            "localhost", "127.0.0.1", "0.0.0.0",
            "your_", "replace_", "change_"
        ]
        
        for indicator in false_positive_indicators:
            if indicator in text_lower:
                return True
        
        return False
    
    async def scan_multiple_targets(self, base_urls: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan multiple base URLs for exposed .git repositories
        
        Args:
            base_urls: List of base URLs to scan
            
        Returns:
            Dictionary mapping URLs to findings
        """
        log_module_start(self.logger, "Git Scanner", f"{len(base_urls)} targets")
        
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
        
        log_module_complete(self.logger, "Git Scanner", f"{len(base_urls)} targets", total_findings)
        
        if total_findings > 0:
            self.logger.warning(f"Found {total_findings} exposed .git repositories")
        
        return results
    
    def get_scan_statistics(self, results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Get statistics about git scan results
        
        Args:
            results: Scan results
            
        Returns:
            Statistics dictionary
        """
        total_targets = len(results)
        targets_with_git = sum(1 for findings in results.values() if findings)
        total_git_repos = sum(len(findings) for findings in results.values())
        
        # Count accessible files and secrets
        total_accessible_files = 0
        total_secrets = 0
        secret_types = {}
        
        for findings in results.values():
            for finding in findings:
                git_info = finding.get("git_info", {})
                total_accessible_files += len(git_info.get("accessible_files", []))
                
                secrets = git_info.get("secrets_found", [])
                total_secrets += len(secrets)
                
                for secret in secrets:
                    secret_type = secret.get("type", "unknown")
                    secret_types[secret_type] = secret_types.get(secret_type, 0) + 1
        
        return {
            "total_targets_scanned": total_targets,
            "targets_with_exposed_git": targets_with_git,
            "total_git_repos_found": total_git_repos,
            "total_accessible_files": total_accessible_files,
            "total_secrets_found": total_secrets,
            "secrets_by_type": secret_types,
            "average_files_per_repo": total_accessible_files / total_git_repos if total_git_repos > 0 else 0
        }

# Singleton instance
_git_scanner = None

def get_git_scanner() -> GitScanner:
    """Get the git scanner instance"""
    global _git_scanner
    if _git_scanner is None:
        _git_scanner = GitScanner()
    return _git_scanner
