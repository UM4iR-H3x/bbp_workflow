"""
Subdomain enumeration module using subfinder
"""

import asyncio
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional
import re

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from utils.helpers import is_valid_domain, deduplicate_list, ensure_directory
from config.config import EXTERNAL_TOOLS, TMP_DIR

class SubdomainEnumerator:
    """
    Subdomain enumeration using subfinder tool
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.subfinder_path = EXTERNAL_TOOLS["subfinder"]
        self.temp_dir = TMP_DIR / "subdomains"
        ensure_directory(self.temp_dir)
    
    async def enumerate_subdomains(self, domain: str) -> List[str]:
        """
        Enumerate subdomains for a given domain
        
        Args:
            domain: Target domain
            
        Returns:
            List of discovered subdomains
        """
        log_module_start(self.logger, "Subdomain Enumeration", domain)
        
        if not is_valid_domain(domain):
            log_error(self.logger, "Subdomain Enumeration", domain, "Invalid domain format")
            return []
        
        try:
            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, dir=self.temp_dir) as temp_file:
                temp_path = temp_file.name
            
            # Run subfinder command
            cmd = [
                self.subfinder_path,
                "-d", domain,
                "-o", temp_path,
                "-silent",
                "-all"
            ]
            
            self.logger.info(f"Running subfinder for domain: {domain}")
            
            # Run command asynchronously
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8') if stderr else "Unknown error"
                log_error(self.logger, "Subdomain Enumeration", domain, f"Subfinder failed: {error_msg}")
                return []
            
            # Read results from temporary file
            subdomains = []
            if Path(temp_path).exists():
                with open(temp_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain and is_valid_domain(subdomain):
                            subdomains.append(subdomain)
                
                # Clean up temporary file
                Path(temp_path).unlink(missing_ok=True)
            
            # Add the main domain if not present
            if domain not in subdomains:
                subdomains.append(domain)
            
            # Deduplicate and sort
            subdomains = deduplicate_list(subdomains)
            subdomains.sort()
            
            log_module_complete(self.logger, "Subdomain Enumeration", domain, len(subdomains))
            self.logger.info(f"Found {len(subdomains)} subdomains for {domain}")
            
            return subdomains
            
        except Exception as e:
            log_error(self.logger, "Subdomain Enumeration", domain, str(e))
            return []
        finally:
            # Clean up any remaining temp files
            if 'temp_path' in locals():
                Path(temp_path).unlink(missing_ok=True)
    
    async def enumerate_multiple_domains(self, domains: List[str]) -> dict:
        """
        Enumerate subdomains for multiple domains
        
        Args:
            domains: List of target domains
            
        Returns:
            Dictionary mapping domains to their subdomains
        """
        results = {}
        
        # Run enumeration concurrently for multiple domains
        tasks = []
        for domain in domains:
            if is_valid_domain(domain):
                task = self.enumerate_subdomains(domain)
                tasks.append((domain, task))
        
        # Wait for all tasks to complete
        for domain, task in tasks:
            try:
                subdomains = await task
                results[domain] = subdomains
            except Exception as e:
                log_error(self.logger, "Subdomain Enumeration", domain, str(e))
                results[domain] = []
        
        return results
    
    def verify_subfinder_installation(self) -> bool:
        """
        Verify that subfinder is installed and accessible
        
        Returns:
            True if subfinder is available
        """
        try:
            result = subprocess.run(
                [self.subfinder_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_subfinder_version(self) -> Optional[str]:
        """
        Get subfinder version information
        
        Returns:
            Version string or None if failed
        """
        try:
            result = subprocess.run(
                [self.subfinder_path, "-version"],
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
_subdomain_enumerator = None

def get_subdomain_enumerator() -> SubdomainEnumerator:
    """Get the subdomain enumerator instance"""
    global _subdomain_enumerator
    if _subdomain_enumerator is None:
        _subdomain_enumerator = SubdomainEnumerator()
    return _subdomain_enumerator
