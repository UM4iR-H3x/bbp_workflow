"""
Archive fetcher module for retrieving Wayback Machine snapshots
"""

import asyncio
from typing import List, Dict, Optional, Any
from urllib.parse import quote

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.rate_limiter import get_rate_limiter
from config.config import WAYBACK_SNAPSHOT_URL, MAX_CONCURRENT_REQUESTS

class ArchiveFetcher:
    """
    Fetch snapshots from Wayback Machine
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.rate_limiter = get_rate_limiter()
        self.snapshot_url_template = WAYBACK_SNAPSHOT_URL
    
    def build_snapshot_url(self, original_url: str, timestamp: str) -> str:
        """
        Build Wayback Machine snapshot URL
        
        Args:
            original_url: Original URL
            timestamp: Timestamp from CDX entry
            
        Returns:
            Wayback Machine snapshot URL
        """
        return self.snapshot_url_template.format(timestamp=timestamp, url=original_url)
    
    async def fetch_snapshot(
        self,
        original_url: str,
        timestamp: str,
        timeout: int = 30
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch a single snapshot from Wayback Machine
        
        Args:
            original_url: Original URL
            timestamp: Timestamp to fetch
            timeout: Request timeout in seconds
            
        Returns:
            Dictionary with snapshot data or None if failed
        """
        try:
            snapshot_url = self.build_snapshot_url(original_url, timestamp)
            
            self.logger.debug(f"Fetching snapshot: {snapshot_url}")
            
            # Make request
            response = await self.rate_limiter.get(snapshot_url, timeout=timeout)
            
            if response is None:
                self.logger.warning(f"No response for snapshot: {snapshot_url}")
                return None
            
            if response.status != 200:
                self.logger.warning(f"Snapshot returned status {response.status}: {snapshot_url}")
                return None
            
            # Get content
            content = await response.text()
            
            # Get content type
            content_type = response.headers.get('content-type', 'unknown')
            
            # Get content length
            content_length = response.headers.get('content-length', len(content))
            
            return {
                "original_url": original_url,
                "timestamp": timestamp,
                "snapshot_url": snapshot_url,
                "status_code": response.status,
                "content_type": content_type,
                "content_length": content_length,
                "content": content,
                "headers": dict(response.headers)
            }
            
        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout fetching snapshot for {original_url} at {timestamp}")
            return None
        except Exception as e:
            log_error(self.logger, "Archive Fetcher", f"{original_url}@{timestamp}", str(e))
            return None
    
    async def fetch_multiple_snapshots(
        self,
        url_timestamp_pairs: List[tuple],
        timeout: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Fetch multiple snapshots concurrently
        
        Args:
            url_timestamp_pairs: List of (url, timestamp) tuples
            timeout: Request timeout in seconds
            
        Returns:
            List of snapshot data
        """
        log_module_start(self.logger, "Archive Fetcher", f"{len(url_timestamp_pairs)} snapshots")
        
        if not url_timestamp_pairs:
            return []
        
        try:
            # Use semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
            
            async def fetch_single_snapshot(url_timestamp: tuple) -> Optional[Dict[str, Any]]:
                async with semaphore:
                    url, timestamp = url_timestamp
                    return await self.fetch_snapshot(url, timestamp, timeout)
            
            # Create tasks for all snapshots
            tasks = [fetch_single_snapshot(pair) for pair in url_timestamp_pairs]
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and None results
            valid_snapshots = []
            for result in results:
                if isinstance(result, Exception):
                    self.logger.warning(f"Error fetching snapshot: {result}")
                    continue
                if result is not None:
                    valid_snapshots.append(result)
            
            log_module_complete(self.logger, "Archive Fetcher", f"{len(url_timestamp_pairs)} snapshots", len(valid_snapshots))
            self.logger.info(f"Successfully fetched {len(valid_snapshots)} snapshots")
            
            return valid_snapshots
            
        except Exception as e:
            log_error(self.logger, "Archive Fetcher", "multiple", str(e))
            return []
    
    async def fetch_snapshots_for_url(
        self,
        original_url: str,
        timestamps: List[str],
        timeout: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Fetch all snapshots for a single URL
        
        Args:
            original_url: Original URL
            timestamps: List of timestamps to fetch
            timeout: Request timeout in seconds
            
        Returns:
            List of snapshot data
        """
        url_timestamp_pairs = [(original_url, timestamp) for timestamp in timestamps]
        return await self.fetch_multiple_snapshots(url_timestamp_pairs, timeout)
    
    def filter_js_snapshots(self, snapshots: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter snapshots to keep only JavaScript content
        
        Args:
            snapshots: List of snapshot data
            
        Returns:
            Filtered list of JavaScript snapshots
        """
        if not snapshots:
            return []
        
        js_snapshots = []
        
        for snapshot in snapshots:
            content_type = snapshot.get('content_type', '').lower()
            
            # Check for JavaScript content types
            js_types = [
                'application/javascript',
                'application/x-javascript',
                'text/javascript',
                'application/json',
                'text/json'
            ]
            
            # Also check file extension in URL
            url = snapshot.get('original_url', '').lower()
            
            if any(js_type in content_type for js_type in js_types):
                js_snapshots.append(snapshot)
            elif any(url.endswith(ext) for ext in ['.js', '.json', '.map']):
                js_snapshots.append(snapshot)
        
        return js_snapshots
    
    def get_snapshot_statistics(self, snapshots: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get statistics about fetched snapshots
        
        Args:
            snapshots: List of snapshot data
            
        Returns:
            Statistics dictionary
        """
        if not snapshots:
            return {
                "total_snapshots": 0,
                "total_size": 0,
                "content_type_distribution": {},
                "status_code_distribution": {}
            }
        
        total_size = 0
        content_types = {}
        status_codes = {}
        
        for snapshot in snapshots:
            # Count content size
            content_length = snapshot.get('content_length', '0')
            try:
                total_size += int(content_length)
            except (ValueError, TypeError):
                pass
            
            # Count content types
            content_type = snapshot.get('content_type', 'unknown')
            content_types[content_type] = content_types.get(content_type, 0) + 1
            
            # Count status codes
            status_code = snapshot.get('status_code', 0)
            status_codes[status_code] = status_codes.get(status_code, 0) + 1
        
        return {
            "total_snapshots": len(snapshots),
            "total_size": total_size,
            "average_size": total_size // len(snapshots) if snapshots else 0,
            "content_type_distribution": content_types,
            "status_code_distribution": status_codes
        }
    
    async def verify_snapshot_availability(
        self,
        original_url: str,
        timestamp: str
    ) -> bool:
        """
        Verify if a snapshot is available without downloading full content
        
        Args:
            original_url: Original URL
            timestamp: Timestamp to check
            
        Returns:
            True if snapshot is available
        """
        try:
            snapshot_url = self.build_snapshot_url(original_url, timestamp)
            
            # Make HEAD request
            response = await self.rate_limiter.head(snapshot_url, timeout=10)
            
            return response is not None and response.status == 200
            
        except Exception:
            return False
    
    def extract_js_content(self, snapshot: Dict[str, Any]) -> Optional[str]:
        """
        Extract JavaScript content from snapshot
        
        Args:
            snapshot: Snapshot data
            
        Returns:
            JavaScript content or None if not JS
        """
        content = snapshot.get('content', '')
        content_type = snapshot.get('content_type', '').lower()
        
        # Check if it's JavaScript content
        js_types = [
            'application/javascript',
            'application/x-javascript',
            'text/javascript'
        ]
        
        if any(js_type in content_type for js_type in js_types):
            return content
        
        # Check file extension
        url = snapshot.get('original_url', '').lower()
        if url.endswith('.js'):
            return content
        
        return None

# Singleton instance
_archive_fetcher = None

def get_archive_fetcher() -> ArchiveFetcher:
    """Get the archive fetcher instance"""
    global _archive_fetcher
    if _archive_fetcher is None:
        _archive_fetcher = ArchiveFetcher()
    return _archive_fetcher
