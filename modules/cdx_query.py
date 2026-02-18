"""
Wayback CDX query module for finding archived versions of URLs
"""

import asyncio
import json
from typing import List, Dict, Optional, Any
from urllib.parse import quote

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.rate_limiter import get_rate_limiter
from config.config import WAYBACK_CDX_URL, MAX_CONCURRENT_REQUESTS

class CDXQuery:
    """
    Query Wayback Machine CDX API for archived URL versions
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.rate_limiter = get_rate_limiter()
        self.cdx_url = WAYBACK_CDX_URL
    
    async def query_cdx(self, url: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query Wayback CDX API for archived versions of a URL
        
        Args:
            url: URL to query
            limit: Maximum number of results to return
            
        Returns:
            List of CDX entries
        """
        try:
            # Encode URL for query
            encoded_url = quote(url, safe='')
            
            # Build CDX query URL
            query_url = f"{self.cdx_url}?url={encoded_url}&output=json&limit={limit}"
            
            self.logger.debug(f"Querying CDX for URL: {url}")
            
            # Make request
            response = await self.rate_limiter.get(query_url)
            
            if response is None:
                self.logger.warning(f"No response from CDX API for URL: {url}")
                return []
            
            if response.status != 200:
                self.logger.warning(f"CDX API returned status {response.status} for URL: {url}")
                return []
            
            # Parse JSON response
            content = await response.text()
            
            if not content.strip():
                return []
            
            try:
                data = json.loads(content)
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse CDX response for URL {url}: {e}")
                return []
            
            # CDX API returns array where first row is headers
            if len(data) < 2:
                return []
            
            headers = data[0]
            entries = []
            
            for row in data[1:]:
                if len(row) >= len(headers):
                    entry = dict(zip(headers, row))
                    entries.append(entry)
            
            self.logger.debug(f"Found {len(entries)} CDX entries for URL: {url}")
            return entries
            
        except Exception as e:
            log_error(self.logger, "CDX Query", url, str(e))
            return []
    
    async def query_multiple_urls(self, urls: List[str], limit: int = 100) -> Dict[str, List[Dict[str, Any]]]:
        """
        Query CDX API for multiple URLs
        
        Args:
            urls: List of URLs to query
            limit: Maximum results per URL
            
        Returns:
            Dictionary mapping URLs to their CDX entries
        """
        log_module_start(self.logger, "CDX Query", f"{len(urls)} URLs")
        
        if not urls:
            return {}
        
        try:
            # Use semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
            
            async def query_single_url(url: str) -> tuple:
                async with semaphore:
                    entries = await self.query_cdx(url, limit)
                    return url, entries
            
            # Create tasks for all URLs
            tasks = [query_single_url(url) for url in urls]
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            url_entries = {}
            total_entries = 0
            
            for result in results:
                if isinstance(result, Exception):
                    self.logger.warning(f"Error querying CDX: {result}")
                    continue
                
                url, entries = result
                url_entries[url] = entries
                total_entries += len(entries)
            
            log_module_complete(self.logger, "CDX Query", f"{len(urls)} URLs", total_entries)
            self.logger.info(f"Found total of {total_entries} archived entries")
            
            return url_entries
            
        except Exception as e:
            log_error(self.logger, "CDX Query", "multiple", str(e))
            return {}
    
    def filter_entries_by_status(self, entries: List[Dict[str, Any]], status_codes: List[int] = None) -> List[Dict[str, Any]]:
        """
        Filter CDX entries by HTTP status codes
        
        Args:
            entries: List of CDX entries
            status_codes: List of status codes to keep (None for all)
            
        Returns:
            Filtered list of entries
        """
        if status_codes is None:
            return entries
        
        filtered = []
        
        for entry in entries:
            status_code = entry.get('statuscode')
            if status_code and int(status_code) in status_codes:
                filtered.append(entry)
        
        return filtered
    
    def filter_entries_by_date_range(self, entries: List[Dict[str, Any]], start_date: str = None, end_date: str = None) -> List[Dict[str, Any]]:
        """
        Filter CDX entries by date range
        
        Args:
            entries: List of CDX entries
            start_date: Start date in YYYYMMDD format
            end_date: End date in YYYYMMDD format
            
        Returns:
            Filtered list of entries
        """
        if not start_date and not end_date:
            return entries
        
        filtered = []
        
        for entry in entries:
            timestamp = entry.get('timestamp', '')
            
            if not timestamp or len(timestamp) < 8:
                continue
            
            entry_date = timestamp[:8]  # Extract YYYYMMDD
            
            # Check date range
            if start_date and entry_date < start_date:
                continue
            
            if end_date and entry_date > end_date:
                continue
            
            filtered.append(entry)
        
        return filtered
    
    def get_unique_timestamps(self, entries: List[Dict[str, Any]]) -> List[str]:
        """
        Get unique timestamps from CDX entries
        
        Args:
            entries: List of CDX entries
            
        Returns:
            List of unique timestamps
        """
        timestamps = set()
        
        for entry in entries:
            timestamp = entry.get('timestamp')
            if timestamp:
                timestamps.add(timestamp)
        
        return sorted(list(timestamps))
    
    def get_entry_statistics(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get statistics about CDX entries
        
        Args:
            entries: List of CDX entries
            
        Returns:
            Statistics dictionary
        """
        if not entries:
            return {
                "total_entries": 0,
                "status_code_distribution": {},
                "date_range": None,
                "unique_timestamps": 0
            }
        
        # Count status codes
        status_codes = {}
        timestamps = set()
        
        for entry in entries:
            # Count status codes
            status_code = entry.get('statuscode', 'unknown')
            status_codes[status_code] = status_codes.get(status_code, 0) + 1
            
            # Collect timestamps
            timestamp = entry.get('timestamp')
            if timestamp and len(timestamp) >= 8:
                timestamps.add(timestamp[:8])
        
        # Find date range
        sorted_dates = sorted(timestamps)
        date_range = None
        if sorted_dates:
            date_range = {
                "start": sorted_dates[0],
                "end": sorted_dates[-1]
            }
        
        return {
            "total_entries": len(entries),
            "status_code_distribution": status_codes,
            "date_range": date_range,
            "unique_timestamps": len(timestamps)
        }
    
    async def check_availability(self) -> bool:
        """
        Check if CDX API is available
        
        Returns:
            True if API is available
        """
        try:
            # Make a simple test query
            test_url = f"{self.cdx_url}?url=example.com&output=json&limit=1"
            
            response = await self.rate_limiter.get(test_url)
            
            if response and response.status == 200:
                content = await response.text()
                # Try to parse as JSON
                json.loads(content)
                return True
            
            return False
            
        except Exception:
            return False
    
    def build_snapshot_url(self, url: str, timestamp: str) -> str:
        """
        Build Wayback Machine snapshot URL
        
        Args:
            url: Original URL
            timestamp: Timestamp from CDX entry
            
        Returns:
            Wayback Machine snapshot URL
        """
        return f"https://web.archive.org/web/{timestamp}/{url}"

# Singleton instance
_cdx_query = None

def get_cdx_query() -> CDXQuery:
    """Get the CDX query instance"""
    global _cdx_query
    if _cdx_query is None:
        _cdx_query = CDXQuery()
    return _cdx_query
