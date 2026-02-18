"""
Cleanup module for removing temporary files and resources
"""

import shutil
import asyncio
from pathlib import Path
from typing import List, Optional

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.helpers import clean_temp_files
from config.config import TMP_DIR

class CleanupManager:
    """
    Manage cleanup of temporary files and resources
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.temp_dir = TMP_DIR
        
        # Subdirectories to clean
        self.cleanup_dirs = [
            "subdomains",
            "live_check", 
            "url_collection",
            "deadlink_check",
            "archive_fetcher",
            "env_scanner",
            "git_scanner",
            "cors_scanner"
        ]
    
    async def cleanup_target_temp_files(self, target: str) -> bool:
        """
        Clean up temporary files for a specific target
        
        Args:
            target: Target domain/URL
            
        Returns:
            True if successful
        """
        log_module_start(self.logger, "Cleanup", target)
        
        try:
            cleaned_count = 0
            
            # Clean each subdirectory
            for subdir in self.cleanup_dirs:
                subdir_path = self.temp_dir / subdir
                
                if subdir_path.exists():
                    # Remove all files in subdirectory
                    for item in subdir_path.iterdir():
                        try:
                            if item.is_file():
                                item.unlink()
                                cleaned_count += 1
                            elif item.is_dir():
                                shutil.rmtree(item)
                                cleaned_count += 1
                        except Exception as e:
                            self.logger.warning(f"Failed to remove {item}: {e}")
            
            # Recreate empty directories
            for subdir in self.cleanup_dirs:
                subdir_path = self.temp_dir / subdir
                subdir_path.mkdir(parents=True, exist_ok=True)
            
            log_module_complete(self.logger, "Cleanup", target, cleaned_count)
            self.logger.info(f"Cleaned {cleaned_count} temporary files for {target}")
            
            return True
            
        except Exception as e:
            log_error(self.logger, "Cleanup", target, str(e))
            return False
    
    async def cleanup_all_temp_files(self) -> bool:
        """
        Clean up all temporary files
        
        Returns:
            True if successful
        """
        log_module_start(self.logger, "Cleanup", "all temporary files")
        
        try:
            # Remove entire temp directory
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
            
            # Recreate temp directory structure
            self.temp_dir.mkdir(parents=True, exist_ok=True)
            
            for subdir in self.cleanup_dirs:
                subdir_path = self.temp_dir / subdir
                subdir_path.mkdir(parents=True, exist_ok=True)
            
            log_module_complete(self.logger, "Cleanup", "all temporary files", 1)
            self.logger.info("Cleaned all temporary files")
            
            return True
            
        except Exception as e:
            log_error(self.logger, "Cleanup", "all", str(e))
            return False
    
    def get_temp_directory_size(self) -> int:
        """
        Get total size of temporary directory
        
        Returns:
            Size in bytes
        """
        try:
            if not self.temp_dir.exists():
                return 0
            
            total_size = 0
            
            for item in self.temp_dir.rglob("*"):
                if item.is_file():
                    total_size += item.stat().st_size
            
            return total_size
            
        except Exception as e:
            self.logger.error(f"Error calculating temp directory size: {e}")
            return 0
    
    def get_temp_file_count(self) -> int:
        """
        Get total count of temporary files
        
        Returns:
            Number of files
        """
        try:
            if not self.temp_dir.exists():
                return 0
            
            file_count = 0
            
            for item in self.temp_dir.rglob("*"):
                if item.is_file():
                    file_count += 1
            
            return file_count
            
        except Exception as e:
            self.logger.error(f"Error counting temp files: {e}")
            return 0
    
    def list_temp_files(self) -> List[dict]:
        """
        List all temporary files with their details
        
        Returns:
            List of file information dictionaries
        """
        try:
            if not self.temp_dir.exists():
                return []
            
            files_info = []
            
            for item in self.temp_dir.rglob("*"):
                if item.is_file():
                    stat = item.stat()
                    files_info.append({
                        "path": str(item),
                        "name": item.name,
                        "size": stat.st_size,
                        "modified": stat.st_mtime,
                        "relative_path": str(item.relative_to(self.temp_dir))
                    })
            
            return files_info
            
        except Exception as e:
            self.logger.error(f"Error listing temp files: {e}")
            return []
    
    async def cleanup_old_files(self, max_age_hours: int = 24) -> bool:
        """
        Clean up temporary files older than specified age
        
        Args:
            max_age_hours: Maximum age in hours
            
        Returns:
            True if successful
        """
        import time
        
        log_module_start(self.logger, "Cleanup", f"files older than {max_age_hours} hours")
        
        try:
            if not self.temp_dir.exists():
                return True
            
            current_time = time.time()
            max_age_seconds = max_age_hours * 3600
            cleaned_count = 0
            
            for item in self.temp_dir.rglob("*"):
                if item.is_file():
                    file_age = current_time - item.stat().st_mtime
                    
                    if file_age > max_age_seconds:
                        try:
                            item.unlink()
                            cleaned_count += 1
                            self.logger.debug(f"Removed old file: {item}")
                        except Exception as e:
                            self.logger.warning(f"Failed to remove old file {item}: {e}")
            
            log_module_complete(self.logger, "Cleanup", f"old files", cleaned_count)
            self.logger.info(f"Cleaned {cleaned_count} old temporary files")
            
            return True
            
        except Exception as e:
            log_error(self.logger, "Cleanup", "old files", str(e))
            return False
    
    async def cleanup_large_files(self, max_size_mb: int = 100) -> bool:
        """
        Clean up temporary files larger than specified size
        
        Args:
            max_size_mb: Maximum size in MB
            
        Returns:
            True if successful
        """
        log_module_start(self.logger, "Cleanup", f"files larger than {max_size_mb}MB")
        
        try:
            if not self.temp_dir.exists():
                return True
            
            max_size_bytes = max_size_mb * 1024 * 1024
            cleaned_count = 0
            
            for item in self.temp_dir.rglob("*"):
                if item.is_file():
                    file_size = item.stat().st_size
                    
                    if file_size > max_size_bytes:
                        try:
                            item.unlink()
                            cleaned_count += 1
                            self.logger.debug(f"Removed large file: {item} ({file_size} bytes)")
                        except Exception as e:
                            self.logger.warning(f"Failed to remove large file {item}: {e}")
            
            log_module_complete(self.logger, "Cleanup", "large files", cleaned_count)
            self.logger.info(f"Cleaned {cleaned_count} large temporary files")
            
            return True
            
        except Exception as e:
            log_error(self.logger, "Cleanup", "large files", str(e))
            return False
    
    def get_cleanup_statistics(self) -> dict:
        """
        Get statistics about temporary files
        
        Returns:
            Statistics dictionary
        """
        try:
            total_size = self.get_temp_directory_size()
            file_count = self.get_temp_file_count()
            
            # Count files by subdirectory
            subdir_counts = {}
            
            if self.temp_dir.exists():
                for subdir in self.cleanup_dirs:
                    subdir_path = self.temp_dir / subdir
                    
                    if subdir_path.exists():
                        count = 0
                        for item in subdir_path.rglob("*"):
                            if item.is_file():
                                count += 1
                        subdir_counts[subdir] = count
            
            return {
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "total_files": file_count,
                "files_by_subdirectory": subdir_counts,
                "temp_directory": str(self.temp_dir)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting cleanup statistics: {e}")
            return {
                "error": str(e),
                "total_size_bytes": 0,
                "total_files": 0
            }
    
    async def schedule_periodic_cleanup(self, interval_hours: int = 6) -> None:
        """
        Schedule periodic cleanup of temporary files
        
        Args:
            interval_hours: Cleanup interval in hours
        """
        while True:
            try:
                self.logger.info(f"Starting periodic cleanup (every {interval_hours} hours)")
                
                # Clean old files (older than 24 hours)
                await self.cleanup_old_files(24)
                
                # Clean large files (larger than 100MB)
                await self.cleanup_large_files(100)
                
                # Get statistics
                stats = self.get_cleanup_statistics()
                self.logger.info(f"Cleanup stats: {stats['total_files']} files, {stats['total_size_mb']}MB")
                
                # Wait for next cleanup
                await asyncio.sleep(interval_hours * 3600)
                
            except Exception as e:
                self.logger.error(f"Error in periodic cleanup: {e}")
                await asyncio.sleep(3600)  # Wait 1 hour before retrying
    
    def verify_cleanup_permissions(self) -> bool:
        """
        Verify that we have permissions to clean up temporary files
        
        Returns:
            True if permissions are OK
        """
        try:
            # Try to create and remove a test file
            test_file = self.temp_dir / "test_cleanup_permission.txt"
            
            # Create temp directory if it doesn't exist
            self.temp_dir.mkdir(parents=True, exist_ok=True)
            
            # Write test file
            test_file.write_text("test")
            
            # Remove test file
            test_file.unlink()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Cleanup permission check failed: {e}")
            return False

# Singleton instance
_cleanup_manager = None

def get_cleanup_manager() -> CleanupManager:
    """Get the cleanup manager instance"""
    global _cleanup_manager
    if _cleanup_manager is None:
        _cleanup_manager = CleanupManager()
    return _cleanup_manager
