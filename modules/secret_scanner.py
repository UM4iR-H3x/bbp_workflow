"""
Secret scanner module for finding sensitive information in JavaScript files
"""

import re
import base64
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.helpers import calculate_entropy, is_high_entropy_string, decode_base64_safe, is_base64_string
from config.config import SECRET_PATTERNS

class SecretScanner:
    """
    Scan JavaScript files for secrets and sensitive information
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.patterns = SECRET_PATTERNS
        
        # Additional patterns for common secrets
        self.extended_patterns = {
            "database_url": [
                r"(?i)(mongodb|mysql|postgres|redis)://[^\s'\"]{20,}",
                r"(?i)(database|db)_url\s*[:=]\s*['\"]([^\s'\"]{20,})['\"]"
            ],
            "internal_endpoint": [
                r"(?i)(api|endpoint|url)\s*[:=]\s*['\"](https?://[^/]*\.(internal|local|dev|staging|test)[^\s'\"]*)['\"]",
                r"(?i)(internal|private|admin)_api\s*[:=]\s*['\"]([^\s'\"]{20,})['\"]"
            ],
            "auth_header": [
                r"(?i)(authorization|auth)\s*[:=]\s*['\"](bearer [^\s'\"]{20,})['\"]",
                r"(?i)(x-api-key|x-auth-token)\s*[:=]\s*['\"]([^\s'\"]{20,})['\"]"
            ],
            "certificate": [
                r"-----BEGIN (CERTIFICATE|PUBLIC KEY)-----[^-]+-----END (CERTIFICATE|PUBLIC KEY)-----"
            ],
            "ssh_key": [
                r"ssh-(rsa|dsa|ecdsa|ed25519)\s+[A-Za-z0-9+/]+[=]{0,3}\s+\S+"
            ],
            "webhook": [
                r"(?i)(webhook|callback)\s*[:=]\s*['\"](https?://[^\s'\"]{20,})['\"]"
            ]
        }
        
        # Combine all patterns
        self.all_patterns = {**self.patterns, **self.extended_patterns}
        
        # False positive patterns
        self.false_positive_patterns = [
            r"example\.(com|org|net)",
            r"test\.(com|org|net)",
            r"dummy\.(com|org|net)",
            r"localhost",
            r"127\.0\.0\.1",
            r"0\.0\.0\.0",
            r"::1",
            r"\.example",
            r"\.test",
            r"\.local",
            r"\.dev",
            r"xxx",
            r"yyy",
            r"zzz",
            r"abc123",
            r"password123",
            r"secret123",
            r"key123",
            r"token123"
        ]
    
    def scan_content(self, content: str, source_url: str = "") -> List[Dict[str, Any]]:
        """
        Scan content for secrets and sensitive information
        
        Args:
            content: Content to scan
            source_url: Source URL for context
            
        Returns:
            List of findings
        """
        if not content:
            return []
        
        findings = []
        
        try:
            # Scan for each pattern type
            for pattern_type, patterns in self.all_patterns.items():
                if isinstance(patterns, dict) and pattern_type == "high_entropy":
                    # Handle high entropy strings separately
                    entropy_findings = self._scan_high_entropy(content, pattern_type, source_url)
                    findings.extend(entropy_findings)
                else:
                    # Handle regex patterns
                    for pattern in patterns:
                        matches = self._find_pattern_matches(content, pattern, pattern_type, source_url)
                        findings.extend(matches)
            
            # Remove duplicates and false positives
            findings = self._filter_findings(findings)
            
            self.logger.debug(f"Found {len(findings)} potential secrets in {source_url}")
            return findings
            
        except Exception as e:
            log_error(self.logger, "Secret Scanner", source_url, str(e))
            return []
    
    def _find_pattern_matches(
        self,
        content: str,
        pattern: str,
        pattern_type: str,
        source_url: str
    ) -> List[Dict[str, Any]]:
        """
        Find matches for a specific pattern
        
        Args:
            content: Content to search
            pattern: Regex pattern
            pattern_type: Type of pattern
            source_url: Source URL
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                # Get the matched text
                matched_text = match.group(0)
                
                # For patterns with capture groups, get the specific secret
                if match.groups():
                    secret = match.groups()[-1]  # Get the last group (usually the secret)
                else:
                    secret = matched_text
                
                # Skip if it's a false positive
                if self._is_false_positive(secret):
                    continue
                
                # Get line number and context
                line_number = content[:match.start()].count('\n') + 1
                lines = content.split('\n')
                context_line = lines[line_number - 1] if line_number <= len(lines) else ""
                
                finding = {
                    "type": pattern_type,
                    "secret": secret,
                    "matched_text": matched_text,
                    "line_number": line_number,
                    "context": context_line.strip(),
                    "source_url": source_url,
                    "confidence": self._calculate_confidence(pattern_type, secret),
                    "severity": self._get_severity(pattern_type)
                }
                
                findings.append(finding)
                
        except Exception as e:
            self.logger.warning(f"Error scanning pattern {pattern_type}: {e}")
        
        return findings
    
    def _scan_high_entropy(self, content: str, pattern_type: str, source_url: str) -> List[Dict[str, Any]]:
        """
        Scan for high entropy strings
        
        Args:
            content: Content to scan
            pattern_type: Pattern type (high_entropy)
            source_url: Source URL
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Extract potential base64 strings
            base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            matches = re.finditer(base64_pattern, content)
            
            for match in matches:
                candidate = match.group(0)
                
                # Check if it's valid base64
                if not is_base64_string(candidate):
                    continue
                
                # Check entropy
                if is_high_entropy_string(candidate, self.all_patterns[pattern_type]["threshold"]):
                    # Try to decode to see if it contains meaningful data
                    decoded = decode_base64_safe(candidate)
                    
                    # Skip if decode reveals false positive patterns
                    if decoded and self._is_false_positive(decoded):
                        continue
                    
                    line_number = content[:match.start()].count('\n') + 1
                    lines = content.split('\n')
                    context_line = lines[line_number - 1] if line_number <= len(lines) else ""
                    
                    finding = {
                        "type": "high_entropy_base64",
                        "secret": candidate,
                        "matched_text": candidate,
                        "line_number": line_number,
                        "context": context_line.strip(),
                        "source_url": source_url,
                        "confidence": "medium",
                        "severity": "medium",
                        "decoded": decoded[:100] if decoded else None
                    }
                    
                    findings.append(finding)
            
            # Also scan for high entropy strings in quotes
            quoted_pattern = r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']'
            matches = re.finditer(quoted_pattern, content)
            
            for match in matches:
                candidate = match.group(1)
                
                if is_high_entropy_string(candidate, self.all_patterns[pattern_type]["threshold"]):
                    line_number = content[:match.start()].count('\n') + 1
                    lines = content.split('\n')
                    context_line = lines[line_number - 1] if line_number <= len(lines) else ""
                    
                    finding = {
                        "type": "high_entropy_string",
                        "secret": candidate,
                        "matched_text": match.group(0),
                        "line_number": line_number,
                        "context": context_line.strip(),
                        "source_url": source_url,
                        "confidence": "low",
                        "severity": "low"
                    }
                    
                    findings.append(finding)
                    
        except Exception as e:
            self.logger.warning(f"Error scanning high entropy strings: {e}")
        
        return findings
    
    def _is_false_positive(self, text: str) -> bool:
        """
        Check if text matches false positive patterns
        
        Args:
            text: Text to check
            
        Returns:
            True if false positive
        """
        text_lower = text.lower()
        
        for pattern in self.false_positive_patterns:
            if re.search(pattern, text_lower):
                return True
        
        return False
    
    def _calculate_confidence(self, pattern_type: str, secret: str) -> str:
        """
        Calculate confidence level for a finding
        
        Args:
            pattern_type: Type of pattern
            secret: The secret found
            
        Returns:
            Confidence level (high, medium, low)
        """
        high_confidence_types = {
            "aws_key", "github_token", "slack_token", "jwt_token", "private_key"
        }
        
        medium_confidence_types = {
            "api_key", "database_url", "auth_header", "certificate", "ssh_key"
        }
        
        if pattern_type in high_confidence_types:
            return "high"
        elif pattern_type in medium_confidence_types:
            return "medium"
        else:
            return "low"
    
    def _get_severity(self, pattern_type: str) -> str:
        """
        Get severity level for a pattern type
        
        Args:
            pattern_type: Type of pattern
            
        Returns:
            Severity level
        """
        severity_mapping = {
            "aws_key": "CRITICAL",
            "github_token": "CRITICAL",
            "slack_token": "HIGH",
            "jwt_token": "HIGH",
            "private_key": "CRITICAL",
            "api_key": "HIGH",
            "database_url": "CRITICAL",
            "auth_header": "HIGH",
            "certificate": "MEDIUM",
            "ssh_key": "CRITICAL",
            "webhook": "MEDIUM",
            "internal_endpoint": "MEDIUM",
            "email": "LOW",
            "password": "HIGH",
            "high_entropy_base64": "MEDIUM",
            "high_entropy_string": "LOW"
        }
        
        return severity_mapping.get(pattern_type, "LOW")
    
    def _filter_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter findings to remove duplicates and low-confidence items
        
        Args:
            findings: List of findings
            
        Returns:
            Filtered list
        """
        if not findings:
            return []
        
        # Remove duplicates based on secret and type
        seen = set()
        filtered = []
        
        for finding in findings:
            # Create a unique key
            key = (finding["type"], finding["secret"])
            
            if key not in seen:
                seen.add(key)
                filtered.append(finding)
        
        # Sort by severity and confidence
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        confidence_order = {"high": 0, "medium": 1, "low": 2}
        
        filtered.sort(key=lambda x: (
            severity_order.get(x["severity"], 3),
            confidence_order.get(x["confidence"], 2)
        ))
        
        return filtered
    
    def scan_multiple_files(self, file_contents: List[Tuple[str, str]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan multiple files for secrets
        
        Args:
            file_contents: List of (url, content) tuples
            
        Returns:
            Dictionary mapping URLs to their findings
        """
        log_module_start(self.logger, "Secret Scanner", f"{len(file_contents)} files")
        
        results = {}
        total_findings = 0
        
        for url, content in file_contents:
            try:
                findings = self.scan_content(content, url)
                results[url] = findings
                total_findings += len(findings)
                
                if findings:
                    self.logger.info(f"Found {len(findings)} secrets in {url}")
                    
            except Exception as e:
                log_error(self.logger, "Secret Scanner", url, str(e))
                results[url] = []
        
        log_module_complete(self.logger, "Secret Scanner", f"{len(file_contents)} files", total_findings)
        self.logger.info(f"Total secrets found: {total_findings}")
        
        return results
    
    def get_scan_statistics(self, results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Get statistics about scan results
        
        Args:
            results: Scan results dictionary
            
        Returns:
            Statistics dictionary
        """
        total_files = len(results)
        total_findings = sum(len(findings) for findings in results.values())
        files_with_findings = sum(1 for findings in results.values() if findings)
        
        # Count by type and severity
        type_counts = {}
        severity_counts = {}
        
        for findings in results.values():
            for finding in findings:
                ftype = finding.get("type", "unknown")
                severity = finding.get("severity", "LOW")
                
                type_counts[ftype] = type_counts.get(ftype, 0) + 1
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "total_files_scanned": total_files,
            "files_with_findings": files_with_findings,
            "total_findings": total_findings,
            "findings_by_type": type_counts,
            "findings_by_severity": severity_counts,
            "average_findings_per_file": total_findings / total_files if total_files > 0 else 0
        }

# Singleton instance
_secret_scanner = None

def get_secret_scanner() -> SecretScanner:
    """Get the secret scanner instance"""
    global _secret_scanner
    if _secret_scanner is None:
        _secret_scanner = SecretScanner()
    return _secret_scanner
