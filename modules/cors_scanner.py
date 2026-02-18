"""
CORS misconfiguration scanner module
"""

import asyncio
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.rate_limiter import get_rate_limiter
from config.config import CORS_TEST_ORIGINS, MAX_CONCURRENT_REQUESTS

class CORSScanner:
    """
    Scan for CORS misconfigurations
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.rate_limiter = get_rate_limiter()
        self.test_origins = CORS_TEST_ORIGINS
        
        # CORS headers to check
        self.cors_headers = [
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-max-age",
            "access-control-expose-headers"
        ]
    
    async def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan a single URL for CORS misconfigurations
        
        Args:
            url: URL to scan
            
        Returns:
            List of findings
        """
        log_module_start(self.logger, "CORS Scanner", url)
        
        if not url:
            return []
        
        try:
            # Ensure URL has proper format
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            findings = []
            
            # Test each origin
            for origin in self.test_origins:
                finding = await self._test_cors_origin(url, origin)
                if finding:
                    findings.append(finding)
            
            log_module_complete(self.logger, "CORS Scanner", url, len(findings))
            
            if findings:
                self.logger.warning(f"Found {len(findings)} CORS misconfigurations at {url}")
            
            return findings
            
        except Exception as e:
            log_error(self.logger, "CORS Scanner", url, str(e))
            return []
    
    async def _test_cors_origin(self, url: str, origin: str) -> Optional[Dict[str, Any]]:
        """
        Test CORS with a specific origin
        
        Args:
            url: URL to test
            origin: Origin to test with
            
        Returns:
            Finding dictionary or None
        """
        try:
            # Prepare headers with Origin
            headers = {
                "Origin": origin,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            
            # Make request
            response = await self.rate_limiter.get(url, headers=headers, timeout=10)
            
            if response is None:
                return None
            
            # Extract CORS headers
            cors_headers = {}
            for header_name in self.cors_headers:
                value = response.headers.get(header_name)
                if value:
                    cors_headers[header_name] = value
            
            if not cors_headers:
                return None
            
            # Check for misconfigurations
            misconfig = self._analyze_cors_response(origin, cors_headers, response.status)
            
            if misconfig:
                return {
                    "url": url,
                    "test_origin": origin,
                    "response_status": response.status,
                    "cors_headers": cors_headers,
                    "misconfiguration_type": misconfig["type"],
                    "severity": misconfig["severity"],
                    "description": misconfig["description"],
                    "evidence": misconfig["evidence"]
                }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing CORS origin {origin} for {url}: {e}")
            return None
    
    def _analyze_cors_response(
        self,
        origin: str,
        cors_headers: Dict[str, str],
        status_code: int
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze CORS response for misconfigurations
        
        Args:
            origin: Tested origin
            cors_headers: CORS headers from response
            status_code: HTTP status code
            
        Returns:
            Misconfiguration details or None
        """
        # Get the relevant headers
        allow_origin = cors_headers.get("access-control-allow-origin", "").lower()
        allow_credentials = cors_headers.get("access-control-allow-credentials", "").lower()
        
        # Check for wildcard origin
        if allow_origin == "*":
            if allow_credentials == "true":
                return {
                    "type": "wildcard_with_credentials",
                    "severity": "CRITICAL",
                    "description": "CORS allows any origin with credentials enabled",
                    "evidence": f"Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true"
                }
            else:
                return {
                    "type": "wildcard_origin",
                    "severity": "MEDIUM",
                    "description": "CORS allows any origin",
                    "evidence": f"Access-Control-Allow-Origin: *"
                }
        
        # Check for origin reflection
        if allow_origin == origin.lower():
            if allow_credentials == "true":
                return {
                    "type": "origin_reflection_with_credentials",
                    "severity": "CRITICAL",
                    "description": f"CORS reflects origin '{origin}' with credentials enabled",
                    "evidence": f"Access-Control-Allow-Origin: {origin}, Access-Control-Allow-Credentials: true"
                }
            else:
                return {
                    "type": "origin_reflection",
                    "severity": "HIGH",
                    "description": f"CORS reflects origin '{origin}'",
                    "evidence": f"Access-Control-Allow-Origin: {origin}"
                }
        
        # Check for null origin acceptance
        if origin == "null" and allow_origin == "null":
            if allow_credentials == "true":
                return {
                    "type": "null_origin_with_credentials",
                    "severity": "HIGH",
                    "description": "CORS accepts null origin with credentials enabled",
                    "evidence": "Access-Control-Allow-Origin: null, Access-Control-Allow-Credentials: true"
                }
            else:
                return {
                    "type": "null_origin",
                    "severity": "MEDIUM",
                    "description": "CORS accepts null origin",
                    "evidence": "Access-Control-Allow-Origin: null"
                }
        
        # Check for overly permissive subdomain patterns
        if self._is_overly_permissive_pattern(allow_origin, origin):
            return {
                "type": "overly_permissive_pattern",
                "severity": "MEDIUM",
                "description": f"CORS uses overly permissive pattern: {allow_origin}",
                "evidence": f"Access-Control-Allow-Origin: {allow_origin}"
            }
        
        return None
    
    def _is_overly_permissive_pattern(self, allow_origin: str, test_origin: str) -> bool:
        """
        Check if the allowed origin pattern is overly permissive
        
        Args:
            allow_origin: The allowed origin from response
            test_origin: The origin that was tested
            
        Returns:
            True if pattern is overly permissive
        """
        # Check for wildcard subdomains
        if "*.com" in allow_origin or "*.org" in allow_origin or "*.net" in allow_origin:
            return True
        
        # Check for patterns that would match many origins
        if allow_origin.startswith("*.") and len(allow_origin) < 15:
            return True
        
        # Check if it accepts our malicious origin
        if test_origin in ["https://evil.com", "https://attacker.com"] and test_origin in allow_origin:
            return True
        
        return False
    
    async def scan_multiple_urls(self, urls: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan multiple URLs for CORS misconfigurations
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            Dictionary mapping URLs to findings
        """
        log_module_start(self.logger, "CORS Scanner", f"{len(urls)} URLs")
        
        if not urls:
            return {}
        
        try:
            # Use semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
            
            async def scan_single_url(url: str) -> tuple:
                async with semaphore:
                    findings = await self.scan_url(url)
                    return url, findings
            
            # Create tasks for all URLs
            tasks = [scan_single_url(url) for url in urls]
            completed_tasks = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            results = {}
            total_findings = 0
            
            for task_result in completed_tasks:
                if isinstance(task_result, Exception):
                    continue
                
                url, findings = task_result
                results[url] = findings
                total_findings += len(findings)
            
            log_module_complete(self.logger, "CORS Scanner", f"{len(urls)} URLs", total_findings)
            
            if total_findings > 0:
                self.logger.warning(f"Found {total_findings} CORS misconfigurations across all URLs")
            
            return results
            
        except Exception as e:
            log_error(self.logger, "CORS Scanner", "multiple", str(e))
            return {}
    
    def get_scan_statistics(self, results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Get statistics about CORS scan results
        
        Args:
            results: Scan results
            
        Returns:
            Statistics dictionary
        """
        total_urls = len(results)
        urls_with_findings = sum(1 for findings in results.values() if findings)
        total_findings = sum(len(findings) for findings in results.values())
        
        # Count by misconfiguration type and severity
        type_counts = {}
        severity_counts = {}
        
        for findings in results.values():
            for finding in findings:
                misconfig_type = finding.get("misconfiguration_type", "unknown")
                severity = finding.get("severity", "LOW")
                
                type_counts[misconfig_type] = type_counts.get(misconfig_type, 0) + 1
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count vulnerable origins
        vulnerable_origins = set()
        for findings in results.values():
            for finding in findings:
                origin = finding.get("test_origin", "")
                if origin:
                    vulnerable_origins.add(origin)
        
        return {
            "total_urls_scanned": total_urls,
            "urls_with_misconfigurations": urls_with_findings,
            "total_misconfigurations": total_findings,
            "misconfigurations_by_type": type_counts,
            "misconfigurations_by_severity": severity_counts,
            "vulnerable_origins": list(vulnerable_origins),
            "critical_findings": severity_counts.get("CRITICAL", 0),
            "high_findings": severity_counts.get("HIGH", 0)
        }
    
    def generate_test_report(self, results: Dict[str, List[Dict[str, Any]]]) -> str:
        """
        Generate a human-readable test report
        
        Args:
            results: Scan results
            
        Returns:
            Formatted report string
        """
        if not results:
            return "No CORS misconfigurations found."
        
        report = []
        report.append("=== CORS Misconfiguration Report ===\n")
        
        for url, findings in results.items():
            if findings:
                report.append(f"URL: {url}")
                report.append("-" * len(f"URL: {url}"))
                
                for finding in findings:
                    report.append(f"  Origin: {finding.get('test_origin', 'N/A')}")
                    report.append(f"  Type: {finding.get('misconfiguration_type', 'N/A')}")
                    report.append(f"  Severity: {finding.get('severity', 'N/A')}")
                    report.append(f"  Description: {finding.get('description', 'N/A')}")
                    report.append(f"  Evidence: {finding.get('evidence', 'N/A')}")
                    report.append("")
                
                report.append("")
        
        return "\n".join(report)

# Singleton instance
_cors_scanner = None

def get_cors_scanner() -> CORSScanner:
    """Get the CORS scanner instance"""
    global _cors_scanner
    if _cors_scanner is None:
        _cors_scanner = CORSScanner()
    return _cors_scanner
