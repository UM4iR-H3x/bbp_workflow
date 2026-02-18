"""
URL collection module using gau, katana, and waybackurls
"""

import asyncio
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Set
import json
import re

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.helpers import normalize_url, deduplicate_list, ensure_directory, extract_urls_from_text
from utils.rate_limiter import get_rate_limiter
from config.config import EXTERNAL_TOOLS, TMP_DIR, MAX_CONCURRENT_REQUESTS

class URLCollector:
    """
    URL collection using multiple tools: gau, katana, and waybackurls
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.rate_limiter = get_rate_limiter()
        self.gau_path = EXTERNAL_TOOLS["gau"]
        self.katana_path = EXTERNAL_TOOLS["katana"]
        self.waybackurls_path = EXTERNAL_TOOLS["waybackurls"]
        self.temp_dir = TMP_DIR / "url_collection"
        ensure_directory(self.temp_dir)
    
    async def collect_urls_gau(self, target: str) -> List[str]:
        """
        Collect URLs using gau (Get All URLs)
        
        Args:
            target: Target domain or URL
            
        Returns:
            List of URLs found by gau
        """
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, dir=self.temp_dir) as temp_file:
                temp_path = temp_file.name
            
            # Run gau command
            cmd = [
                self.gau_path,
                target,
                "--subs",
                "--o", temp_path
            ]
            
            self.logger.debug(f"Running gau for target: {target}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            urls = []
            if process.returncode == 0 and Path(temp_path).exists():
                with open(temp_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        url = line.strip()
                        if url and url.startswith(('http://', 'https://')):
                            urls.append(url)
            
            Path(temp_path).unlink(missing_ok=True)
            return urls
            
        except Exception as e:
            log_error(self.logger, "URL Collection (GAU)", target, str(e))
            return []
    
    async def collect_urls_katana(self, target: str) -> List[str]:
        """
        Collect URLs using katana crawler
        
        Args:
            target: Target domain or URL
            
        Returns:
            List of URLs found by katana
        """
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, dir=self.temp_dir) as temp_file:
                temp_path = temp_file.name
            
            # Run katana command
            cmd = [
                self.katana_path,
                "-u", target,
                "-d", "3",   # Depth 2 for reasonable coverage
                "-jc",
                
                "-o", temp_path,
                "-silent",
                "-no-color"
            ]
            
            self.logger.debug(f"Running katana for target: {target}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            urls = []
            if process.returncode == 0 and Path(temp_path).exists():
                with open(temp_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        url = line.strip()
                        if url and url.startswith(('http://', 'https://')):
                            urls.append(url)
            
            Path(temp_path).unlink(missing_ok=True)
            return urls
            
        except Exception as e:
            log_error(self.logger, "URL Collection (Katana)", target, str(e))
            return []
    
    async def collect_urls_waybackurls(self, target: str) -> List[str]:
        """
        Collect URLs using waybackurls
        
        Args:
            target: Target domain or URL
            
        Returns:
            List of URLs found by waybackurls
        """
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, dir=self.temp_dir) as temp_file:
                temp_path = temp_file.name
            
            # Run waybackurls command
            cmd = [
                self.waybackurls_path,
                target,
                "|", "tee", temp_path
            ]
            
            self.logger.debug(f"Running waybackurls for target: {target}")
            
            # For waybackurls, we need to handle the pipe differently
            process1 = await asyncio.create_subprocess_exec(
                self.waybackurls_path,
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process1.communicate()
            
            urls = []
            if process1.returncode == 0:
                # Parse URLs from stdout
                output = stdout.decode('utf-8')
                urls = [url.strip() for url in output.split('\n') if url.strip()]
                
                # Also save to temp file for consistency
                with open(temp_path, 'w', encoding='utf-8') as f:
                    for url in urls:
                        f.write(f"{url}\n")
            
            Path(temp_path).unlink(missing_ok=True)
            return urls
            
        except Exception as e:
            log_error(self.logger, "URL Collection (Waybackurls)", target, str(e))
            return []
    
    async def collect_urls_all_tools(self, target: str) -> List[str]:
        """
        Collect URLs using all available tools
        
        Args:
            target: Target domain or URL
            
        Returns:
            Combined list of URLs from all tools
        """
        log_module_start(self.logger, "URL Collection", target)
        
        try:
            # Collect URLs from all tools concurrently
            tasks = []
            
            # Check which tools are available and add tasks
            if self.verify_tool_installation("gau"):
                tasks.append(("gau", self.collect_urls_gau(target)))
            
            if self.verify_tool_installation("katana"):
                tasks.append(("katana", self.collect_urls_katana(target)))
            
            if self.verify_tool_installation("waybackurls"):
                tasks.append(("waybackurls", self.collect_urls_waybackurls(target)))
            
            if not tasks:
                log_error(self.logger, "URL Collection", target, "No URL collection tools available")
                return []
            
            # Wait for all tasks to complete
            results = {}
            for tool_name, task in tasks:
                try:
                    urls = await task
                    results[tool_name] = urls
                    self.logger.info(f"{tool_name} found {len(urls)} URLs")
                except Exception as e:
                    log_error(self.logger, f"URL Collection ({tool_name})", target, str(e))
                    results[tool_name] = []
            
            # Combine all URLs
            all_urls = []
            for tool_name, urls in results.items():
                all_urls.extend(urls)
            
            # Deduplicate and sort
            all_urls = deduplicate_list(all_urls)
            
            log_module_complete(self.logger, "URL Collection", target, len(all_urls))
            self.logger.info(f"Total unique URLs collected: {len(all_urls)}")
            
            return all_urls
            
        except Exception as e:
            log_error(self.logger, "URL Collection", target, str(e))
            return []
    
    async def collect_urls_multiple_targets(self, targets: List[str]) -> Dict[str, List[str]]:
        """
        Collect URLs for multiple targets
        
        Args:
            targets: List of target domains or URLs
            
        Returns:
            Dictionary mapping targets to their URLs
        """
        results = {}
        
        # Limit concurrent requests to avoid overwhelming servers
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        
        async def collect_single_target(target: str) -> tuple:
            async with semaphore:
                urls = await self.collect_urls_all_tools(target)
                return target, urls
        
        # Run collection for all targets
        tasks = [collect_single_target(target) for target in targets]
        completed_tasks = await asyncio.gather(*tasks, return_exceptions=True)
        
        for task_result in completed_tasks:
            if isinstance(task_result, Exception):
                log_error(self.logger, "URL Collection", "multiple", str(task_result))
                continue
            
            target, urls = task_result
            results[target] = urls
        
        return results
    
    def verify_tool_installation(self, tool_name: str) -> bool:
        """
        Verify that a specific tool is installed and accessible
        
        Args:
            tool_name: Name of the tool to verify
            
        Returns:
            True if tool is available
        """
        tool_paths = {
            "gau": self.gau_path,
            "katana": self.katana_path,
            "waybackurls": self.waybackurls_path
        }
        
        if tool_name not in tool_paths:
            return False
        
        try:
            result = subprocess.run(
                [tool_paths[tool_name], "-h"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0 or result.returncode == 1  # Some tools return 1 for help
        except Exception:
            return False
    
    def get_tool_versions(self) -> Dict[str, Optional[str]]:
        """
        Get version information for all tools
        
        Returns:
            Dictionary mapping tool names to version strings
        """
        versions = {}
        
        for tool_name in ["gau", "katana", "waybackurls"]:
            try:
                result = subprocess.run(
                    [EXTERNAL_TOOLS[tool_name], "-version"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    # Extract version from output
                    version_match = re.search(r'v?(\d+\.\d+\.\d+)', result.stdout)
                    if version_match:
                        versions[tool_name] = version_match.group(1)
                    else:
                        versions[tool_name] = "Unknown"
                else:
                    versions[tool_name] = None
            except Exception:
                versions[tool_name] = None
        
        return versions

# Singleton instance
_url_collector = None

def get_url_collector() -> URLCollector:
    """Get the URL collector instance"""
    global _url_collector
    if _url_collector is None:
        _url_collector = URLCollector()
    return _url_collector
