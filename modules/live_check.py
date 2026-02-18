"""
Live host checking module using httpx
"""

import asyncio
import subprocess
import tempfile
from pathlib import Path
from typing import List, Set, Dict, Optional
import re

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.helpers import normalize_url, deduplicate_list, ensure_directory
from utils.rate_limiter import get_rate_limiter
from config.config import EXTERNAL_TOOLS, TMP_DIR, MAX_CONCURRENT_REQUESTS

class LiveHostChecker:
    """
    Live host checking using httpx tool
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.httpx_path = EXTERNAL_TOOLS["httpx"]
        self.rate_limiter = get_rate_limiter()
        self.temp_dir = TMP_DIR / "live_check"
        ensure_directory(self.temp_dir)
    
    async def check_hosts_live(self, hosts: List[str]) -> List[str]:
        """
        Check which hosts are alive using httpx
        
        Args:
            hosts: List of hosts to check
            
        Returns:
            List of live hosts
        """
        log_module_start(self.logger, "Live Host Check", f"{len(hosts)} hosts")
        
        if not hosts:
            return []
        
        try:
            # Normalize hosts
            normalized_hosts = []
            for host in hosts:
                normalized = normalize_url(host)
                if normalized:
                    normalized_hosts.append(normalized)
            
            # Remove duplicates
            normalized_hosts = deduplicate_list(normalized_hosts)
            
            # Create temporary files
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, dir=self.temp_dir) as input_file:
                for host in normalized_hosts:
                    input_file.write(f"{host}\n")
                input_path = input_file.name
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, dir=self.temp_dir) as output_file:
                output_path = output_file.name
            
            # Run httpx command
            cmd = [
                self.httpx_path,
                "-l", input_path,
                "-o", output_path,
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-json",
                "-threads", str(MAX_CONCURRENT_REQUESTS),
                "-timeout", "10",
                "-retries", "2"
            ]
            
            self.logger.info(f"Running httpx for {len(normalized_hosts)} hosts")
            
            # Run command asynchronously
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8') if stderr else "Unknown error"
                log_error(self.logger, "Live Host Check", "httpx", f"Httpx failed: {error_msg}")
                return []
            
            # Parse results from output file
            live_hosts = []
            if Path(output_path).exists():
                with open(output_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                # Parse JSON output
                                import json
                                data = json.loads(line)
                                if 'url' in data:
                                    live_hosts.append(data['url'])
                            except json.JSONDecodeError:
                                # Fallback: treat line as URL
                                if line.startswith(('http://', 'https://')):
                                    live_hosts.append(line)
                
                # Clean up temporary files
                Path(input_path).unlink(missing_ok=True)
                Path(output_path).unlink(missing_ok=True)
            
            # Deduplicate and sort
            live_hosts = deduplicate_list(live_hosts)
            live_hosts.sort()
            
            log_module_complete(self.logger, "Live Host Check", f"{len(hosts)} hosts", len(live_hosts))
            self.logger.info(f"Found {len(live_hosts)} live hosts out of {len(normalized_hosts)}")
            
            return live_hosts
            
        except Exception as e:
            log_error(self.logger, "Live Host Check", "hosts", str(e))
            return []
        finally:
            # Clean up any remaining temp files
            if 'input_path' in locals():
                Path(input_path).unlink(missing_ok=True)
            if 'output_path' in locals():
                Path(output_path).unlink(missing_ok=True)
    
    async def check_host_live_async(self, host: str) -> bool:
        """
        Check if a single host is alive using async HTTP request
        
        Args:
            host: Host to check
            
        Returns:
            True if host is alive
        """
        try:
            url = normalize_url(host)
            if not url:
                return False
            
            response = await self.rate_limiter.head(url, allow_redirects=True)
            
            if response and response.status < 500:
                return True
            
            return False
            
        except Exception:
            return False
    
    async def check_hosts_live_async(self, hosts: List[str]) -> List[str]:
        """
        Check hosts alive using async HTTP requests (fallback method)
        
        Args:
            hosts: List of hosts to check
            
        Returns:
            List of live hosts
        """
        if not hosts:
            return []
        
        # Normalize hosts
        normalized_hosts = []
        for host in hosts:
            normalized = normalize_url(host)
            if normalized:
                normalized_hosts.append(normalized)
        
        # Remove duplicates
        normalized_hosts = deduplicate_list(normalized_hosts)
        
        # Check hosts concurrently
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        
        async def check_single_host(host: str) -> Optional[str]:
            async with semaphore:
                if await self.check_host_live_async(host):
                    return host
                return None
        
        tasks = [check_single_host(host) for host in normalized_hosts]
        results = await asyncio.gather(*tasks)
        
        # Filter out None results
        live_hosts = [host for host in results if host]
        
        return live_hosts
    
    def verify_httpx_installation(self) -> bool:
        """
        Verify that httpx is installed and accessible
        
        Returns:
            True if httpx is available
        """
        try:
            result = subprocess.run(
                [self.httpx_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_httpx_version(self) -> Optional[str]:
        """
        Get httpx version information
        
        Returns:
            Version string or None if failed
        """
        try:
            result = subprocess.run(
                [self.httpx_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Extract version from output
                version_match = re.search(r'v?(\d+\.\d+\.\d+)', result.stdout)
                if version_match:
                    return version_match.group(1)
            
            return None
        except Exception:
            return None

# Singleton instance
_live_host_checker = None

def get_live_host_checker() -> LiveHostChecker:
    """Get the live host checker instance"""
    global _live_host_checker
    if _live_host_checker is None:
        _live_host_checker = LiveHostChecker()
    return _live_host_checker
