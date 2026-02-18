"""
Deduplication module for removing duplicate URLs and data
"""

import hashlib
import re
from typing import List, Set, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlunparse

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.helpers import deduplicate_list

class Deduplicator:
    """
    Advanced deduplication for URLs and other data
    """
    
    def __init__(self):
        self.logger = get_logger()
        
        # Parameters that don't affect content for URL normalization
        self.ignore_params = {
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
            'fbclid', 'gclid', 'msclkid', '_ga', '_gid', 'mc_eid', 'ncid',
            'ref', 'source', 'campaign', 'medium', 'click_id', 'trk', 'trkCampaign',
            'pk_source', 'pk_medium', 'pk_campaign', 'jtr', 'cid', 'icid'
        }
    
    def normalize_url(self, url: str) -> str:
        """
        Normalize URL for deduplication by removing tracking parameters and standardizing format
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL
        """
        if not url:
            return ""
        
        try:
            # Parse URL
            parsed = urlparse(url)
            
            # Normalize scheme
            scheme = parsed.scheme.lower() if parsed.scheme else 'https'
            
            # Normalize netloc (remove www if present)
            netloc = parsed.netloc.lower()
            if netloc.startswith('www.'):
                netloc = netloc[4:]
            
            # Normalize path (remove trailing slash)
            path = parsed.path
            if path.endswith('/') and len(path) > 1:
                path = path[:-1]
            
            # Parse and filter query parameters
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            
            # Remove ignored parameters
            filtered_params = {}
            for key, values in query_params.items():
                if key.lower() not in self.ignore_params:
                    filtered_params[key] = values
            
            # Rebuild query string
            if filtered_params:
                # Sort parameters for consistency
                query_items = []
                for key in sorted(filtered_params.keys()):
                    for value in sorted(filtered_params[key]):
                        query_items.append(f"{key}={value}")
                query = '&'.join(query_items)
            else:
                query = ''
            
            # Remove fragment
            fragment = ''
            
            # Rebuild URL
            normalized = urlunparse((scheme, netloc, path, '', query, fragment))
            
            return normalized
            
        except Exception as e:
            self.logger.warning(f"Failed to normalize URL {url}: {e}")
            return url
    
    def deduplicate_urls(self, urls: List[str], normalize: bool = True) -> List[str]:
        """
        Remove duplicate URLs with optional normalization
        
        Args:
            urls: List of URLs to deduplicate
            normalize: Whether to normalize URLs before deduplication
            
        Returns:
            Deduplicated list of URLs
        """
        log_module_start(self.logger, "URL Deduplication", f"{len(urls)} URLs")
        
        if not urls:
            return []
        
        try:
            if normalize:
                # Normalize URLs first
                normalized_urls = []
                url_mapping = {}  # Maps normalized URL to original URL
                
                for url in urls:
                    normalized = self.normalize_url(url)
                    if normalized not in url_mapping:
                        url_mapping[normalized] = url
                    # Keep the first occurrence of each normalized URL
                
                deduplicated = list(url_mapping.values())
            else:
                # Simple deduplication
                deduplicated = deduplicate_list(urls)
            
            # Sort the results
            deduplicated.sort()
            
            log_module_complete(self.logger, "URL Deduplication", f"{len(urls)} URLs", len(deduplicated))
            self.logger.info(f"Removed {len(urls) - len(deduplicated)} duplicate URLs")
            
            return deduplicated
            
        except Exception as e:
            log_error(self.logger, "URL Deduplication", "processing", str(e))
            return urls
    
    def deduplicate_by_content(self, items: List[str]) -> List[str]:
        """
        Deduplicate items by content hash (useful for similar but not identical strings)
        
        Args:
            items: List of items to deduplicate
            
        Returns:
            Deduplicated list
        """
        if not items:
            return []
        
        seen_hashes = set()
        deduplicated = []
        
        for item in items:
            # Create hash of the item
            item_hash = hashlib.sha256(item.encode('utf-8')).hexdigest()
            
            if item_hash not in seen_hashes:
                seen_hashes.add(item_hash)
                deduplicated.append(item)
        
        return deduplicated
    
    def find_similar_urls(self, urls: List[str], similarity_threshold: float = 0.8) -> List[Tuple[str, str]]:
        """
        Find pairs of similar URLs that might be duplicates
        
        Args:
            urls: List of URLs to check
            similarity_threshold: Minimum similarity score (0-1)
            
        Returns:
            List of tuples containing similar URL pairs
        """
        similar_pairs = []
        
        for i, url1 in enumerate(urls):
            for j, url2 in enumerate(urls[i+1:], i+1):
                similarity = self.calculate_url_similarity(url1, url2)
                if similarity >= similarity_threshold:
                    similar_pairs.append((url1, url2, similarity))
        
        return similar_pairs
    
    def calculate_url_similarity(self, url1: str, url2: str) -> float:
        """
        Calculate similarity score between two URLs
        
        Args:
            url1: First URL
            url2: Second URL
            
        Returns:
            Similarity score (0-1)
        """
        if not url1 or not url2:
            return 0.0
        
        try:
            # Normalize both URLs
            norm1 = self.normalize_url(url1)
            norm2 = self.normalize_url(url2)
            
            if norm1 == norm2:
                return 1.0
            
            # Parse URLs
            parsed1 = urlparse(norm1)
            parsed2 = urlparse(norm2)
            
            # Compare components
            components = ['scheme', 'netloc', 'path', 'query']
            matches = 0
            
            for component in components:
                comp1 = getattr(parsed1, component)
                comp2 = getattr(parsed2, component)
                
                if comp1 == comp2:
                    matches += 1
            
            return matches / len(components)
            
        except Exception:
            return 0.0
    
    def deduplicate_domains(self, domains: List[str]) -> List[str]:
        """
        Deduplicate domain names
        
        Args:
            domains: List of domain names
            
        Returns:
            Deduplicated list of domains
        """
        if not domains:
            return []
        
        # Normalize domains (lowercase, remove www)
        normalized_domains = set()
        
        for domain in domains:
            if domain:
                norm = domain.lower().strip()
                if norm.startswith('www.'):
                    norm = norm[4:]
                normalized_domains.add(norm)
        
        return sorted(list(normalized_domains))
    
    def deduplicate_generic(self, items: List[Any], key_func=None) -> List[Any]:
        """
        Generic deduplication with optional key function
        
        Args:
            items: List of items to deduplicate
            key_func: Function to extract comparison key from items
            
        Returns:
            Deduplicated list
        """
        if not items:
            return []
        
        if key_func is None:
            return deduplicate_list(items)
        
        seen_keys = set()
        deduplicated = []
        
        for item in items:
            try:
                key = key_func(item)
                if key not in seen_keys:
                    seen_keys.add(key)
                    deduplicated.append(item)
            except Exception:
                # If key function fails, keep the item
                if item not in deduplicated:
                    deduplicated.append(item)
        
        return deduplicated
    
    def get_deduplication_stats(self, original: List[Any], deduplicated: List[Any]) -> Dict[str, Any]:
        """
        Get statistics about deduplication results
        
        Args:
            original: Original list
            deduplicated: Deduplicated list
            
        Returns:
            Statistics dictionary
        """
        return {
            "original_count": len(original),
            "deduplicated_count": len(deduplicated),
            "removed_count": len(original) - len(deduplicated),
            "reduction_percentage": ((len(original) - len(deduplicated)) / len(original) * 100) if original else 0
        }

# Singleton instance
_deduplicator = None

def get_deduplicator() -> Deduplicator:
    """Get the deduplicator instance"""
    global _deduplicator
    if _deduplicator is None:
        _deduplicator = Deduplicator()
    return _deduplicator
