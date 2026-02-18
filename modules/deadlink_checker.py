"""
Dead link checker module for finding 404, timeout, and connection errors
"""

import asyncio
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.rate_limiter import get_rate_limiter
from config.config import MAX_CONCURRENT_REQUESTS, REQUEST_TIMEOUT

class DeadLinkChecker:
    """
    Check for dead links (404, timeout, connection errors)
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.rate_limiter = get_rate_limiter()
        
        # Status codes that indicate a dead link (expanded for better detection)
        self.dead_status_codes = {
            400,  # Bad Request
            401,  # Unauthorized
            403,  # Forbidden
            404,  # Not Found
            405,  # Method Not Allowed
            406,  # Not Acceptable
            408,  # Request Timeout
            410,  # Gone
            422,  # Unprocessable Entity
            429,  # Too Many Requests
            500,  # Internal Server Error
            502,  # Bad Gateway
            503,  # Service Unavailable
            504,  # Gateway Timeout
            520,  # Unknown Error (Cloudflare)
            521,  # Web Server Is Down (Cloudflare)
            522,  # Connection Timed Out (Cloudflare)
            523,  # Origin Is Unreachable (Cloudflare)
            524,  # A Timeout Occurred (Cloudflare)
        }
    
    async def check_url_status(self, url: str) -> Tuple[bool, int, str]:
        """
        Check the status of a single URL
        
        Args:
            url: URL to check
            
        Returns:
            Tuple of (is_dead, status_code, error_message)
        """
        try:
            # Make HEAD request first (faster)
            response = await self.rate_limiter.head(url, allow_redirects=True, timeout=REQUEST_TIMEOUT)
            
            if response is None:
                return True, 0, "Connection failed"
            
            status_code = response.status
            
            # Check if status code indicates a dead link
            is_dead = status_code in self.dead_status_codes
            
            # Additional check for some edge cases
            if not is_dead and status_code == 200:
                # Check content length to detect empty responses
                content_length = response.headers.get('content-length', '0')
                if content_length == '0':
                    return True, status_code, "Empty response"
            
            return is_dead, status_code, ""
            
        except asyncio.TimeoutError:
            return True, 0, "Request timeout"
        except Exception as e:
            # Connection errors, DNS errors, etc.
            error_msg = str(e).lower()
            if any(err in error_msg for err in ['connection', 'dns', 'resolve', 'network']):
                return True, 0, f"Connection error: {str(e)}"
            else:
                # Other errors might not indicate a dead link
                return False, 0, f"Other error: {str(e)}"
    
    async def check_urls_dead(self, urls: List[str]) -> List[Dict[str, any]]:
        """
        Check multiple URLs for dead status
        
        Args:
            urls: List of URLs to check
            
        Returns:
            List of dictionaries with URL and status information
        """
        log_module_start(self.logger, "Dead Link Check", f"{len(urls)} URLs")
        
        if not urls:
            return []
        
        try:
            # Use semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
            
            async def check_single_url(url: str) -> Optional[Dict[str, any]]:
                async with semaphore:
                    is_dead, status_code, error_msg = await self.check_url_status(url)
                    
                    return {
                        "url": url,
                        "is_dead": is_dead,
                        "status_code": status_code,
                        "error_message": error_msg
                    }
            
            # Create tasks for all URLs
            tasks = [check_single_url(url) for url in urls]
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and None results
            valid_results = []
            for result in results:
                if isinstance(result, Exception):
                    self.logger.warning(f"Error checking URL: {result}")
                    continue
                if result is not None:
                    valid_results.append(result)
            
            # Separate dead and live URLs
            dead_urls = [result for result in valid_results if result["is_dead"]]
            live_urls = [result for result in valid_results if not result["is_dead"]]
            
            log_module_complete(self.logger, "Dead Link Check", f"{len(urls)} URLs", len(dead_urls))
            self.logger.info(f"Found {len(dead_urls)} dead URLs and {len(live_urls)} live URLs")
            
            return dead_urls
            
        except Exception as e:
            log_error(self.logger, "Dead Link Check", "checking", str(e))
            return []
    
    async def get_dead_urls_only(self, urls: List[str]) -> List[str]:
        """
        Get only the dead URLs from a list
        
        Args:
            urls: List of URLs to check
            
        Returns:
            List of dead URLs
        """
        dead_results = await self.check_urls_dead(urls)
        return [result["url"] for result in dead_results]
    
    async def check_url_with_get(self, url: str) -> Tuple[bool, int, str, Optional[str]]:
        """
        Check URL status with GET request (for cases where HEAD doesn't work)
        
        Args:
            url: URL to check
            
        Returns:
            Tuple of (is_dead, status_code, error_message, content_preview)
        """
        try:
            response = await self.rate_limiter.get(url, allow_redirects=True, timeout=REQUEST_TIMEOUT)
            
            if response is None:
                return True, 0, "Connection failed", None
            
            status_code = response.status
            is_dead = status_code in self.dead_status_codes
            
            # Get small content preview for debugging
            content_preview = None
            try:
                content = await response.text()
                content_preview = content[:200] if content else None
            except:
                pass
            
            return is_dead, status_code, "", content_preview
            
        except asyncio.TimeoutError:
            return True, 0, "Request timeout", None
        except Exception as e:
            error_msg = str(e).lower()
            if any(err in error_msg for err in ['connection', 'dns', 'resolve', 'network']):
                return True, 0, f"Connection error: {str(e)}", None
            else:
                return False, 0, f"Other error: {str(e)}", None
    
    def get_dead_link_statistics(self, results: List[Dict[str, any]]) -> Dict[str, any]:
        """
        Get statistics about dead link check results
        
        Args:
            results: List of dead link check results
            
        Returns:
            Statistics dictionary
        """
        if not results:
            return {
                "total_checked": 0,
                "dead_count": 0,
                "dead_percentage": 0,
                "status_code_distribution": {},
                "error_distribution": {}
            }
        
        # Count status codes
        status_codes = {}
        error_types = {}
        
        for result in results:
            status_code = result.get("status_code", 0)
            error_msg = result.get("error_message", "")
            
            # Count status codes
            status_codes[status_code] = status_codes.get(status_code, 0) + 1
            
            # Count error types
            if error_msg:
                if "timeout" in error_msg.lower():
                    error_types["timeout"] = error_types.get("timeout", 0) + 1
                elif "connection" in error_msg.lower():
                    error_types["connection"] = error_types.get("connection", 0) + 1
                elif "dns" in error_msg.lower():
                    error_types["dns"] = error_types.get("dns", 0) + 1
                else:
                    error_types["other"] = error_types.get("other", 0) + 1
        
        return {
            "total_checked": len(results),
            "dead_count": len(results),
            "dead_percentage": 100.0,  # All results are dead URLs
            "status_code_distribution": status_codes,
            "error_distribution": error_types
        }
    
    async def verify_dead_url(self, url: str) -> bool:
        """
        Verify that a URL is actually dead with multiple checks
        
        Args:
            url: URL to verify
            
        Returns:
            True if URL is confirmed dead
        """
        try:
            # First check with HEAD
            is_dead_1, status_1, error_1 = await self.check_url_status(url)
            
            if is_dead_1:
                # Second check with GET to confirm
                is_dead_2, status_2, error_2, _ = await self.check_url_with_get(url)
                return is_dead_2
            
            return False
            
        except Exception:
            return True  # Assume dead if we can't check
    
    def is_dead_status_code(self, status_code: int) -> bool:
        """
        Check if a status code indicates a dead link
        
        Args:
            status_code: HTTP status code
            
        Returns:
            True if status code indicates dead link
        """
        return status_code in self.dead_status_codes

# Singleton instance
_dead_link_checker = None

def get_dead_link_checker() -> DeadLinkChecker:
    """Get the dead link checker instance"""
    global _dead_link_checker
    if _dead_link_checker is None:
        _dead_link_checker = DeadLinkChecker()
    return _dead_link_checker
