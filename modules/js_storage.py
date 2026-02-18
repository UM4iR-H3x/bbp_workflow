"""
JS file storage module for storing JavaScript files separately for secret scanning
"""

import asyncio
import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.rate_limiter import get_rate_limiter
from utils.helpers import safe_filename
from config.config import OUTPUT_DIR, MAX_CONCURRENT_REQUESTS

class JSFileStorage:
    """
    Store JavaScript files separately for secret scanning
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.rate_limiter = get_rate_limiter()
        
        # Create storage directories
        self.js_storage_dir = OUTPUT_DIR / "js_files"
        self.live_js_dir = self.js_storage_dir / "live"
        self.archived_js_dir = self.js_storage_dir / "archived"
        self.secrets_dir = OUTPUT_DIR / "js_secrets"
        self.js_urls_list_dir = OUTPUT_DIR / "js_urls"
        
        # Create directories if they don't exist
        for dir_path in [self.js_storage_dir, self.live_js_dir, self.archived_js_dir, self.secrets_dir, self.js_urls_list_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Index file to track stored JS files
        self.js_index_file = self.js_storage_dir / "js_index.json"
        self.js_index = self._load_js_index()
    
    def _load_js_index(self) -> Dict[str, Any]:
        """Load the JS file index"""
        try:
            if self.js_index_file.exists():
                with open(self.js_index_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.warning(f"Error loading JS index: {e}")
        
        return {
            "live_files": {},
            "archived_files": {},
            "secrets_found": [],
            "last_updated": None
        }
    
    def _save_js_index(self):
        """Save the JS file index"""
        try:
            import datetime
            self.js_index["last_updated"] = datetime.datetime.now().isoformat()
            
            with open(self.js_index_file, 'w') as f:
                json.dump(self.js_index, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving JS index: {e}")
    
    def save_js_urls_to_txt(self, urls: List[str], target: str) -> Optional[str]:
        """
        Write all unique JS URLs to a .txt file (one URL per line).
        Used for recon so you have a single file of all JS URLs per target.
        
        Args:
            urls: Deduplicated list of JS URLs
            target: Target domain/URL (used for filename)
            
        Returns:
            Path to the created file or None
        """
        if not urls:
            return None

    def save_url_list_to_txt(self, urls: List[str], target: str, suffix: str) -> Optional[str]:
        """
        Save a URL list to output/js_urls/<target>_<suffix>.txt
        (one URL per line, deduplicated + sorted).
        """
        if not urls:
            return None
        try:
            safe_target = safe_filename(
                target.replace("https://", "").replace("http://", "").strip("/").split("/")[0] or "target"
            )
            out_file = self.js_urls_list_dir / f"{safe_target}_{suffix}.txt"
            with open(out_file, "w", encoding="utf-8") as f:
                for u in sorted(set(u.strip() for u in urls if u and u.strip())):
                    f.write(u + "\n")
            return str(out_file)
        except Exception as e:
            log_error(self.logger, "JS Storage", f"save_url_list_to_txt:{suffix}", str(e))
            return None
        try:
            safe_target = safe_filename(target.replace("https://", "").replace("http://", "").strip("/").split("/")[0] or "target")
            out_file = self.js_urls_list_dir / f"{safe_target}_js_urls.txt"
            with open(out_file, "w", encoding="utf-8") as f:
                for u in sorted(set(urls)):
                    f.write(u.strip() + "\n")
            self.logger.info(f"Wrote {len(urls)} JS URLs to {out_file}")
            return str(out_file)
        except Exception as e:
            log_error(self.logger, "JS Storage", "save_js_urls_txt", str(e))
            return None
    
    def _get_safe_filename(self, url: str, timestamp: str = None) -> str:
        """Generate a safe filename from URL"""
        parsed = urlparse(url)
        domain = parsed.netloc.replace(':', '_')
        path = parsed.path.replace('/', '_').replace('.', '_')
        
        # Clean up the filename
        safe_chars = '-_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        domain = ''.join(c if c in safe_chars else '_' for c in domain)
        path = ''.join(c if c in safe_chars else '_' for c in path)
        
        if timestamp:
            filename = f"{domain}{path}_{timestamp}.js"
        else:
            filename = f"{domain}{path}.js"
        
        # Limit filename length
        if len(filename) > 200:
            filename = filename[:200] + ".js"
        
        return filename
    
    async def store_live_js_file(self, url: str, content: str) -> Optional[str]:
        """
        Store a live JavaScript file
        
        Args:
            url: Original URL
            content: JS file content
            
        Returns:
            Path to stored file or None if failed
        """
        try:
            filename = self._get_safe_filename(url)
            file_path = self.live_js_dir / filename
            
            # Handle filename conflicts
            counter = 1
            original_filename = filename
            while file_path.exists():
                name_part = original_filename[:-3]  # Remove .js
                filename = f"{name_part}_{counter}.js"
                file_path = self.live_js_dir / filename
                counter += 1
            
            # Store the file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Update index
            self.js_index["live_files"][url] = {
                "filename": filename,
                "file_path": str(file_path),
                "size": len(content),
                "stored_at": asyncio.get_event_loop().time()
            }
            
            self._save_js_index()
            self.logger.debug(f"Stored live JS file: {filename}")
            
            return str(file_path)
            
        except Exception as e:
            log_error(self.logger, "JS Storage", url, str(e))
            return None
    
    async def store_archived_js_file(self, url: str, timestamp: str, content: str, snapshot_url: str) -> Optional[str]:
        """
        Store an archived JavaScript file
        
        Args:
            url: Original URL
            timestamp: Archive timestamp
            content: JS file content
            snapshot_url: Wayback snapshot URL
            
        Returns:
            Path to stored file or None if failed
        """
        try:
            filename = self._get_safe_filename(url, timestamp)
            file_path = self.archived_js_dir / filename
            
            # Handle filename conflicts
            counter = 1
            original_filename = filename
            while file_path.exists():
                name_part = original_filename[:-3]  # Remove .js
                filename = f"{name_part}_{counter}.js"
                file_path = self.archived_js_dir / filename
                counter += 1
            
            # Store the file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Update index
            self.js_index["archived_files"][f"{url}@{timestamp}"] = {
                "filename": filename,
                "file_path": str(file_path),
                "original_url": url,
                "timestamp": timestamp,
                "snapshot_url": snapshot_url,
                "size": len(content),
                "stored_at": asyncio.get_event_loop().time()
            }
            
            self._save_js_index()
            self.logger.debug(f"Stored archived JS file: {filename}")
            
            return str(file_path)
            
        except Exception as e:
            log_error(self.logger, "JS Storage", f"{url}@{timestamp}", str(e))
            return None
    
    async def fetch_and_store_live_js(self, urls: List[str]) -> Dict[str, str]:
        """
        Fetch and store multiple live JavaScript files
        
        Args:
            urls: List of JS URLs to fetch and store
            
        Returns:
            Dictionary mapping URLs to file paths
        """
        log_module_start(self.logger, "JS Storage", f"fetching {len(urls)} live JS files")
        
        results = {}
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        
        async def fetch_and_store_single(url: str) -> tuple:
            async with semaphore:
                try:
                    response = await self.rate_limiter.get(url, timeout=15)
                    
                    if response and response.status == 200:
                        content = await response.text()
                        
                        # Check if it's actually JavaScript content
                        content_type = response.headers.get('content-type', '').lower()
                        if 'javascript' in content_type or url.endswith('.js'):
                            file_path = await self.store_live_js_file(url, content)
                            return url, file_path
                    
                    return url, None
                    
                except Exception as e:
                    self.logger.debug(f"Error fetching {url}: {e}")
                    return url, None
        
        # Fetch all files concurrently
        tasks = [fetch_and_store_single(url) for url in urls]
        completed_tasks = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for task_result in completed_tasks:
            if isinstance(task_result, Exception):
                continue
            
            url, file_path = task_result
            if file_path:
                results[url] = file_path
        
        log_module_complete(self.logger, "JS Storage", f"fetched {len(urls)} URLs", len(results))
        self.logger.info(f"Stored {len(results)} live JavaScript files")
        
        return results
    
    def store_secrets(self, secrets: List[Dict[str, Any]]):
        """
        Store secrets found in JS files
        
        Args:
            secrets: List of secrets found
        """
        try:
            if not secrets:
                return
            
            # Create a timestamped file for this batch of secrets
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            secrets_file = self.secrets_dir / f"js_secrets_{timestamp}.json"
            
            with open(secrets_file, 'w') as f:
                json.dump(secrets, f, indent=2)
            
            # Update index
            self.js_index["secrets_found"].extend([
                {
                    "file": str(secrets_file),
                    "count": len(secrets),
                    "timestamp": timestamp
                }
            ])
            
            self._save_js_index()
            self.logger.info(f"Stored {len(secrets)} JS secrets to {secrets_file}")
            
        except Exception as e:
            log_error(self.logger, "JS Storage", "secrets", str(e))
    
    def get_storage_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about stored JS files
        
        Returns:
            Statistics dictionary
        """
        try:
            live_count = len(self.js_index["live_files"])
            archived_count = len(self.js_index["archived_files"])
            secrets_count = len(self.js_index["secrets_found"])
            
            # Calculate total storage size
            total_size = 0
            for file_info in self.js_index["live_files"].values():
                total_size += file_info.get("size", 0)
            
            for file_info in self.js_index["archived_files"].values():
                total_size += file_info.get("size", 0)
            
            return {
                "live_js_files": live_count,
                "archived_js_files": archived_count,
                "secrets_files": secrets_count,
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "storage_directory": str(self.js_storage_dir),
                "last_updated": self.js_index.get("last_updated")
            }
            
        except Exception as e:
            self.logger.error(f"Error getting storage statistics: {e}")
            return {}
    
    def cleanup_old_files(self, days_old: int = 30):
        """
        Clean up old JS files to save space
        
        Args:
            days_old: Remove files older than this many days
        """
        try:
            import datetime
            cutoff_time = asyncio.get_event_loop().time() - (days_old * 24 * 60 * 60)
            
            removed_count = 0
            
            # Clean up live files
            to_remove = []
            for url, file_info in self.js_index["live_files"].items():
                if file_info.get("stored_at", 0) < cutoff_time:
                    file_path = Path(file_info["file_path"])
                    if file_path.exists():
                        file_path.unlink()
                        removed_count += 1
                    to_remove.append(url)
            
            for url in to_remove:
                del self.js_index["live_files"][url]
            
            # Clean up archived files
            to_remove = []
            for key, file_info in self.js_index["archived_files"].items():
                if file_info.get("stored_at", 0) < cutoff_time:
                    file_path = Path(file_info["file_path"])
                    if file_path.exists():
                        file_path.unlink()
                        removed_count += 1
                    to_remove.append(key)
            
            for key in to_remove:
                del self.js_index["archived_files"][key]
            
            if removed_count > 0:
                self._save_js_index()
                self.logger.info(f"Cleaned up {removed_count} old JS files")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

# Singleton instance
_js_storage = None

def get_js_storage() -> JSFileStorage:
    """Get the JS storage instance"""
    global _js_storage
    if _js_storage is None:
        _js_storage = JSFileStorage()
    return _js_storage
