"""
JavaScript file filter module
"""

import re
from typing import List, Set, Tuple
from urllib.parse import urlparse

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.helpers import deduplicate_list, filter_by_extension
from config.config import IMPORTANT_JS_KEYWORDS

class JSFilter:
    """
    Filter URLs to keep only JavaScript, JSON, and source map files
    """
    
    def __init__(self):
        self.logger = get_logger()
        
        # File extensions to keep
        self.js_extensions = ['.js', '.json', '.map']
        
        # Additional patterns for JS files (without extension)
        self.js_patterns = [
            r'\.js\?',  # .js?query=param
            r'\.json\?',  # .json?query=param
            r'\.map\?',  # .map?query=param
            r'/js/',  # /js/ path
            r'/javascript/',  # /javascript/ path
            r'/static/',  # /static/ path
            r'/assets/',  # /assets/ path
            r'/dist/',  # /dist/ path
            r'/build/',  # /build/ path
        ]
        
        # Common JS file patterns (without extension)
        self.js_file_patterns = [
            r'/[a-zA-Z0-9_-]+\.min\.js',
            r'/[a-zA-Z0-9_-]+\.bundle\.js',
            r'/[a-zA-Z0-9_-]+\.chunk\.js',
            r'/app\.js',
            r'/main\.js',
            r'/index\.js',
            r'/vendor\.js',
            r'/jquery.*\.js',
            r'/bootstrap.*\.js',
            r'/react.*\.js',
            r'/angular.*\.js',
            r'/vue.*\.js',
        ]
    
    def filter_js_urls(self, urls: List[str]) -> List[str]:
        """
        Filter URLs to keep only JavaScript, JSON, and source map files
        
        Args:
            urls: List of URLs to filter
            
        Returns:
            List of filtered URLs
        """
        log_module_start(self.logger, "JS Filter", f"{len(urls)} URLs")
        
        if not urls:
            return []
        
        try:
            filtered_urls = []
            
            for url in urls:
                if self.is_js_url(url):
                    filtered_urls.append(url)
            
            # Remove duplicates and sort
            filtered_urls = deduplicate_list(filtered_urls)
            filtered_urls.sort()
            
            log_module_complete(self.logger, "JS Filter", f"{len(urls)} URLs", len(filtered_urls))
            self.logger.info(f"Filtered to {len(filtered_urls)} JS/JSON/Map files")
            
            return filtered_urls
            
        except Exception as e:
            log_error(self.logger, "JS Filter", "filtering", str(e))
            return []
    
    def is_js_url(self, url: str) -> bool:
        """
        Check if a URL points to a JavaScript, JSON, or source map file
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is a JS/JSON/Map file
        """
        if not url:
            return False
        
        try:
            # Parse URL
            parsed = urlparse(url.lower())
            path = parsed.path
            
            # Check file extensions
            for ext in self.js_extensions:
                if path.endswith(ext):
                    return True
            
            # Check query parameters for JS files
            query = parsed.query.lower()
            for ext in self.js_extensions:
                if f'.{ext}' in query:
                    return True
            
            # Check path patterns
            for pattern in self.js_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    return True
            
            # Check specific file patterns
            for pattern in self.js_file_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def filter_by_extension_only(self, urls: List[str]) -> List[str]:
        """
        Filter URLs by file extensions only (simpler method)
        
        Args:
            urls: List of URLs to filter
            
        Returns:
            List of URLs with matching extensions
        """
        return filter_by_extension(urls, self.js_extensions)
    
    def get_js_statistics(self, urls: List[str]) -> dict:
        """
        Get statistics about JavaScript files in the URL list
        
        Args:
            urls: List of URLs to analyze
            
        Returns:
            Dictionary with statistics
        """
        if not urls:
            return {
                "total_urls": 0,
                "js_files": 0,
                "json_files": 0,
                "map_files": 0,
                "other_js": 0
            }
        
        stats = {
            "total_urls": len(urls),
            "js_files": 0,
            "json_files": 0,
            "map_files": 0,
            "other_js": 0
        }
        
        for url in urls:
            if self.is_js_url(url):
                url_lower = url.lower()
                if url_lower.endswith('.js') or '.js?' in url_lower:
                    stats["js_files"] += 1
                elif url_lower.endswith('.json') or '.json?' in url_lower:
                    stats["json_files"] += 1
                elif url_lower.endswith('.map') or '.map?' in url_lower:
                    stats["map_files"] += 1
                else:
                    stats["other_js"] += 1
        
        return stats
    
    def categorize_js_files(self, urls: List[str]) -> dict:
        """
        Categorize JavaScript files by type
        
        Args:
            urls: List of JS URLs to categorize
            
        Returns:
            Dictionary with categorized URLs
        """
        categories = {
            "minified": [],
            "bundles": [],
            "chunks": [],
            "libraries": [],
            "frameworks": [],
            "config": [],
            "maps": [],
            "other": []
        }
        
        for url in urls:
            url_lower = url.lower()
            
            if url_lower.endswith('.map') or '.map?' in url_lower:
                categories["maps"].append(url)
            elif '.min.js' in url_lower:
                categories["minified"].append(url)
            elif '.bundle.js' in url_lower:
                categories["bundles"].append(url)
            elif '.chunk.js' in url_lower:
                categories["chunks"].append(url)
            elif any(lib in url_lower for lib in ['jquery', 'bootstrap', 'lodash', 'moment']):
                categories["libraries"].append(url)
            elif any(fw in url_lower for fw in ['react', 'angular', 'vue', 'svelte']):
                categories["frameworks"].append(url)
            elif any(cfg in url_lower for cfg in ['config', 'settings', 'env']):
                categories["config"].append(url)
            else:
                categories["other"].append(url)
        
        return categories

    def is_important_js_file(self, url: str) -> bool:
        """
        Check if a JavaScript file is important based on filename keywords
        
        Args:
            url: URL to check
            
        Returns:
            True if file is considered important
        """
        if not url or not self.is_js_url(url):
            return False
        
        try:
            # Extract filename from URL
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            # Get filename without extension
            filename = path.split('/')[-1]
            if '.' in filename:
                filename = filename.rsplit('.', 1)[0]
            
            # Check if filename contains important keywords (case-insensitive)
            for keyword in IMPORTANT_JS_KEYWORDS:
                if keyword.lower() in filename.lower():
                    return True
            
            return False
            
        except Exception:
            return False
    
    def filter_important_js_files(self, js_urls: List[str]) -> Tuple[List[str], List[str]]:
        """
        Separate important and non-important JavaScript files
        
        Args:
            js_urls: List of JavaScript URLs to filter
            
        Returns:
            Tuple of (important_js_files, non_important_js_files)
        """
        if not js_urls:
            return [], []
        
        important_js = []
        non_important_js = []
        
        for url in js_urls:
            if self.is_important_js_file(url):
                important_js.append(url)
                self.logger.debug(f"important js detected: {url}")
            else:
                non_important_js.append(url)
                self.logger.debug(f"skipped non-important js: {url}")
        
        self.logger.info(f"Important JS files: {len(important_js)}")
        self.logger.info(f"Non-important JS files: {len(non_important_js)} (skipped)")
        
        return important_js, non_important_js
    
    def get_important_js_statistics(self, js_urls: List[str]) -> dict:
        """
        Get statistics about important vs non-important JavaScript files
        
        Args:
            js_urls: List of JavaScript URLs to analyze
            
        Returns:
            Dictionary with statistics
        """
        if not js_urls:
            return {
                "total_js_files": 0,
                "important_js_files": 0,
                "non_important_js_files": 0,
                "important_percentage": 0.0
            }
        
        important_js, non_important_js = self.filter_important_js_files(js_urls)
        
        stats = {
            "total_js_files": len(js_urls),
            "important_js_files": len(important_js),
            "non_important_js_files": len(non_important_js),
            "important_percentage": round((len(important_js) / len(js_urls)) * 100, 2) if js_urls else 0.0
        }
        
        return stats

# Singleton instance
_js_filter = None

def get_js_filter() -> JSFilter:
    """Get the JS filter instance"""
    global _js_filter
    if _js_filter is None:
        _js_filter = JSFilter()
    return _js_filter
