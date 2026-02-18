#!/usr/bin/env python3
"""
Ultimate Automated Recon + Leak Detection Framework
Main orchestrator for comprehensive security scanning
"""

import asyncio
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from utils.logger import get_logger, setup_logger
from utils.helpers import is_valid_domain, normalize_url
from utils.rate_limiter import get_rate_limiter
from config.config import MAX_CONCURRENT_REQUESTS, DEFAULT_DELAY

# Import all modules
from modules.subdomain_enum import get_subdomain_enumerator
from modules.live_check import get_live_host_checker
from modules.url_collector import get_url_collector
from modules.js_filter import get_js_filter
from modules.deduper import get_deduplicator
from modules.deadlink_checker import get_dead_link_checker
from modules.cdx_query import get_cdx_query
from modules.timestamp_picker import get_timestamp_picker
from modules.archive_fetcher import get_archive_fetcher
from modules.secret_scanner import get_secret_scanner
from modules.env_scanner import get_env_scanner
from modules.git_scanner import get_git_scanner
from modules.cors_scanner import get_cors_scanner
from modules.logger import get_result_logger
from modules.notifier import get_discord_notifier
from modules.cleanup import get_cleanup_manager

class ReconFramework:
    """
    Main orchestrator for the reconnaissance framework
    """
    
    def __init__(self, threads: int = MAX_CONCURRENT_REQUESTS, delay: tuple = DEFAULT_DELAY):
        self.logger = get_logger()
        self.threads = threads
        self.delay = delay
        
        # Initialize all modules
        self.subdomain_enum = get_subdomain_enumerator()
        self.live_checker = get_live_host_checker()
        self.url_collector = get_url_collector()
        self.js_filter = get_js_filter()
        self.deduplicator = get_deduplicator()
        self.deadlink_checker = get_dead_link_checker()
        self.cdx_query = get_cdx_query()
        self.timestamp_picker = get_timestamp_picker()
        self.archive_fetcher = get_archive_fetcher()
        self.secret_scanner = get_secret_scanner()
        self.env_scanner = get_env_scanner()
        self.git_scanner = get_git_scanner()
        self.cors_scanner = get_cors_scanner()
        self.result_logger = get_result_logger()
        self.discord_notifier = get_discord_notifier()
        self.cleanup_manager = get_cleanup_manager()
        self.rate_limiter = get_rate_limiter()
    
    async def scan_single_target(self, target: str) -> Dict[str, Any]:
        """
        Perform complete scan on a single target
        
        Args:
            target: Target domain or URL
            
        Returns:
            Scan results dictionary
        """
        self.logger.info(f"Starting comprehensive scan for target: {target}")
        
        # Normalize target
        target = normalize_url(target)
        if not target:
            self.logger.error(f"Invalid target: {target}")
            return {"target": target, "error": "Invalid target format"}
        
        results = {
            "target": target,
            "start_time": asyncio.get_event_loop().time(),
            "findings": [],
            "statistics": {}
        }
        
        try:
            # 1. Subdomain Enumeration
            self.logger.info("Step 1: Subdomain Enumeration")
            
            # Extract domain from target for subdomain enumeration
            from utils.helpers import extract_domain
            target_domain = extract_domain(target) if target.startswith(('http://', 'https://')) else target
            
            subdomains = await self.subdomain_enum.enumerate_subdomains(target_domain)
            results["subdomains"] = subdomains
            self.logger.info(f"Found {len(subdomains)} subdomains")
            
            # 2. Live Host Check
            self.logger.info("Step 2: Live Host Check")
            live_hosts = await self.live_checker.check_hosts_live(subdomains)
            results["live_hosts"] = live_hosts
            self.logger.info(f"Found {len(live_hosts)} live hosts")
            
            # 3. URL Collection
            self.logger.info("Step 3: URL Collection")
            url_results = await self.url_collector.collect_urls_multiple_targets(live_hosts)
            all_urls = []
            for host, urls in url_results.items():
                all_urls.extend(urls)
            self.logger.info(f"Collected {len(all_urls)} URLs")
            
            # 4. JS Filter
            self.logger.info("Step 4: JavaScript File Filtering")
            js_urls = self.js_filter.filter_js_urls(all_urls)
            results["js_urls"] = js_urls
            self.logger.info(f"Filtered to {len(js_urls)} JavaScript files")
            
            # 5. Deduplication
            self.logger.info("Step 5: Deduplication")
            js_urls = self.deduplicator.deduplicate_urls(js_urls)
            self.logger.info(f"After deduplication: {len(js_urls)} unique JS files")
            
            # 6. Dead Link Check
            self.logger.info("Step 6: Dead Link Check")
            dead_js_results = await self.deadlink_checker.check_urls_dead(js_urls)
            dead_js_urls = [result["url"] for result in dead_js_results if result.get("is_dead", False)]
            results["dead_js_urls"] = dead_js_urls
            self.logger.info(f"Found {len(dead_js_urls)} dead JS files")
            
            # 7-9. Wayback Archive Analysis (for dead JS files)
            archived_secrets = []
            if dead_js_urls:
                self.logger.info("Step 7-9: Wayback Archive Analysis")
                archived_secrets = await self._analyze_archived_js(dead_js_urls)
                results["archived_secrets"] = archived_secrets
            
            # 10. Live JS Importance Filtering
            self.logger.info("Step 10: Live JS Importance Filtering")
            live_js_urls = [url for url in js_urls if url not in dead_js_urls]
            important_live_js, non_important_live_js = self.js_filter.filter_important_js_files(live_js_urls)
            results["important_live_js"] = important_live_js
            results["non_important_live_js"] = non_important_live_js
            
            # 11. Live JS Secret Scanning (only important files)
            live_secrets = []
            if important_live_js:
                self.logger.info("Step 11: Live JS Secret Scanning")
                live_secrets = await self._scan_live_js_secrets(important_live_js)
                results["live_secrets"] = live_secrets
            else:
                self.logger.info("Step 11: Live JS Secret Scanning - No important JS files to scan")
                results["live_secrets"] = []
            
            # 12. ENV File Scanning
            self.logger.info("Step 12: Environment File Scanning")
            env_findings = await self.env_scanner.scan_multiple_targets(live_hosts)
            results["env_findings"] = env_findings
            
            # 13. Git Exposure Scanning
            self.logger.info("Step 13: Git Repository Scanning")
            git_findings = await self.git_scanner.scan_multiple_targets(live_hosts)
            results["git_findings"] = git_findings
            
            # 14. CORS Misconfiguration Testing
            self.logger.info("Step 14: CORS Misconfiguration Testing")
            cors_findings = await self.cors_scanner.scan_multiple_urls(live_hosts)
            results["cors_findings"] = cors_findings
            
            # 15. Process and log all findings
            self.logger.info("Step 15: Processing Findings")
            all_findings = await self._process_all_findings(results)
            results["all_findings"] = all_findings
            
            # 16. Send notifications
            self.logger.info("Step 16: Sending Notifications")
            await self._send_notifications(all_findings)
            
            # 17. Cleanup
            self.logger.info("Step 17: Cleanup")
            await self.cleanup_manager.cleanup_target_temp_files(target)
            
            # Generate statistics
            results["statistics"] = self._generate_scan_statistics(results)
            results["end_time"] = asyncio.get_event_loop().time()
            results["duration"] = results["end_time"] - results["start_time"]
            
            self.logger.info(f"Scan completed for {target} in {results['duration']:.2f} seconds")
            return results
            
        except Exception as e:
            self.logger.error(f"Error during scan of {target}: {e}")
            results["error"] = str(e)
            return results
    
    async def _analyze_archived_js(self, dead_js_urls: List[str]) -> List[Dict[str, Any]]:
        """Analyze archived JavaScript files for secrets"""
        archived_secrets = []
        
        try:
            # Query CDX for all dead JS URLs
            cdx_results = await self.cdx_query.query_multiple_urls(dead_js_urls)
            
            for url, entries in cdx_results.items():
                if not entries:
                    continue
                
                # Select timestamps
                timestamps = self.timestamp_picker.select_timestamps(entries)
                
                if not timestamps:
                    continue
                
                # Fetch snapshots
                snapshots = await self.archive_fetcher.fetch_snapshots_for_url(url, timestamps)
                
                # Filter JS snapshots and scan for secrets
                js_snapshots = self.archive_fetcher.filter_js_snapshots(snapshots)
                
                for snapshot in js_snapshots:
                    content = self.archive_fetcher.extract_js_content(snapshot)
                    if content:
                        secrets = self.secret_scanner.scan_content(content, snapshot["snapshot_url"])
                        
                        for secret in secrets:
                            archived_secrets.append({
                                "target": url,
                                "module": "Archive Scanner",
                                "url": snapshot["snapshot_url"],
                                "vulnerability_type": f"Archived {secret['type']}",
                                "severity": secret["severity"],
                                "evidence": secret["matched_text"],
                                "timestamp": snapshot["timestamp"],
                                "original_url": url
                            })
        
        except Exception as e:
            self.logger.error(f"Error analyzing archived JS: {e}")
        
        return archived_secrets
    
    async def _scan_live_js_secrets(self, live_js_urls: List[str]) -> List[Dict[str, Any]]:
        """Scan live JavaScript files for secrets"""
        live_secrets = []
        
        try:
            # Fetch live JS content
            semaphore = asyncio.Semaphore(self.threads)
            
            async def fetch_js_content(url: str) -> tuple:
                async with semaphore:
                    response = await self.rate_limiter.get(url, timeout=10)
                    if response and response.status == 200:
                        content = await response.text()
                        return url, content
                    return url, None
            
            tasks = [fetch_js_content(url) for url in live_js_urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Scan fetched content
            js_contents = []
            for result in results:
                if isinstance(result, Exception):
                    continue
                url, content = result
                if content:
                    js_contents.append((url, content))
            
            # Scan for secrets
            scan_results = self.secret_scanner.scan_multiple_files(js_contents)
            
            for url, secrets in scan_results.items():
                for secret in secrets:
                    live_secrets.append({
                        "target": url,
                        "module": "Live JS Scanner",
                        "url": url,
                        "vulnerability_type": f"Live {secret['type']}",
                        "severity": secret["severity"],
                        "evidence": secret["matched_text"],
                        "line_number": secret.get("line_number", 0)
                    })
        
        except Exception as e:
            self.logger.error(f"Error scanning live JS secrets: {e}")
        
        return live_secrets
    
    async def _process_all_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process and categorize all findings"""
        all_findings = []
        
        # Process archived secrets
        for secret in results.get("archived_secrets", []):
            all_findings.append(secret)
        
        # Process live secrets
        for secret in results.get("live_secrets", []):
            all_findings.append(secret)
        
        # Process ENV findings
        for target, env_findings in results.get("env_findings", {}).items():
            for finding in env_findings:
                all_findings.append({
                    "target": target,
                    "module": "ENV Scanner",
                    "url": finding["url"],
                    "vulnerability_type": "Environment File Exposure",
                    "severity": finding["severity"],
                    "evidence": f"Exposed .env file with {len(finding['secrets'])} secrets"
                })
        
        # Process Git findings
        for target, git_findings in results.get("git_findings", {}).items():
            for finding in git_findings:
                all_findings.append({
                    "target": target,
                    "module": "Git Scanner",
                    "url": finding["url"],
                    "vulnerability_type": "Git Repository Exposure",
                    "severity": finding["severity"],
                    "evidence": finding["evidence"]
                })
        
        # Process CORS findings
        for url, cors_findings in results.get("cors_findings", {}).items():
            for finding in cors_findings:
                all_findings.append({
                    "target": url,
                    "module": "CORS Scanner",
                    "url": url,
                    "vulnerability_type": "CORS Misconfiguration",
                    "severity": finding["severity"],
                    "evidence": finding["evidence"]
                })
        
        # Log all findings
        if all_findings:
            await self.result_logger.log_findings(all_findings)
        
        return all_findings
    
    async def _send_notifications(self, findings: List[Dict[str, Any]]) -> None:
        """Send Discord notifications for findings"""
        if not findings:
            return
        
        try:
            # Group findings by type for appropriate webhooks
            for finding in findings:
                vuln_type = finding.get("vulnerability_type", "").lower()
                
                if "archived" in vuln_type or "live" in vuln_type:
                    await self.discord_notifier.send_js_leak_alert(finding)
                elif "environment" in vuln_type:
                    await self.discord_notifier.send_env_exposure_alert(finding)
                elif "git" in vuln_type:
                    await self.discord_notifier.send_git_exposure_alert(finding)
                elif "cors" in vuln_type:
                    await self.discord_notifier.send_cors_alert(finding)
        
        except Exception as e:
            self.logger.error(f"Error sending notifications: {e}")
    
    def _generate_scan_statistics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive scan statistics"""
        stats = {
            "subdomains_found": len(results.get("subdomains", [])),
            "live_hosts_found": len(results.get("live_hosts", [])),
            "urls_collected": 0,  # Would need to track this
            "js_files_found": len(results.get("js_urls", [])),
            "dead_js_files": len(results.get("dead_js_urls", [])),
            "important_live_js_files": len(results.get("important_live_js", [])),
            "non_important_live_js_files": len(results.get("non_important_live_js", [])),
            "archived_secrets": len(results.get("archived_secrets", [])),
            "live_secrets": len(results.get("live_secrets", [])),
            "env_findings": sum(len(f) for f in results.get("env_findings", {}).values()),
            "git_findings": sum(len(f) for f in results.get("git_findings", {}).values()),
            "cors_findings": sum(len(f) for f in results.get("cors_findings", {}).values()),
            "total_findings": len(results.get("all_findings", []))
        }
        
        return stats
    
    async def scan_multiple_targets(self, targets: List[str]) -> Dict[str, Any]:
        """Scan multiple targets"""
        self.logger.info(f"Starting scan for {len(targets)} targets")
        
        all_results = {}
        
        for target in targets:
            try:
                result = await self.scan_single_target(target)
                all_results[target] = result
                
                # Brief pause between targets to be respectful
                await asyncio.sleep(2)
                
            except Exception as e:
                self.logger.error(f"Failed to scan {target}: {e}")
                all_results[target] = {"target": target, "error": str(e)}
        
        return all_results

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Ultimate Automated Recon + Leak Detection Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s -l targets.txt
  %(prog)s example.com --threads 5 --delay 3 5
  %(prog)s -l targets.txt --output custom_results.json
        """
    )
    
    parser.add_argument(
        "target",
        nargs="?",
        help="Single target domain or URL to scan"
    )
    
    parser.add_argument(
        "-l", "--list",
        type=str,
        help="File containing list of targets (one per line)"
    )
    
    parser.add_argument(
        "--threads",
        type=int,
        default=MAX_CONCURRENT_REQUESTS,
        help=f"Number of concurrent threads (default: {MAX_CONCURRENT_REQUESTS})"
    )
    
    parser.add_argument(
        "--delay",
        nargs=2,
        type=int,
        metavar=("MIN", "MAX"),
        default=DEFAULT_DELAY,
        help=f"Random delay range in seconds (default: {DEFAULT_DELAY[0]} {DEFAULT_DELAY[1]})"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        help="Custom output file for results (default: output/results.json)"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)"
    )
    
    parser.add_argument(
        "--cleanup-only",
        action="store_true",
        help="Only run cleanup of temporary files"
    )
    
    parser.add_argument(
        "--test-webhooks",
        action="store_true",
        help="Test Discord webhook configurations"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logger(log_level=args.log_level)
    
    # Validate arguments
    if not args.target and not args.list and not args.cleanup_only and not args.test_webhooks:
        parser.error("Either provide a target, use -l for a list, or use --cleanup-only")
    
    # Initialize framework
    framework = ReconFramework(threads=args.threads, delay=tuple(args.delay))
    
    try:
        if args.cleanup_only:
            logger.info("Running cleanup only")
            await framework.cleanup_manager.cleanup_all_temp_files()
            return
        
        if args.test_webhooks:
            logger.info("Testing Discord webhooks")
            webhook_config = framework.discord_notifier.test_webhook_configuration()
            for webhook_type, is_valid in webhook_config.items():
                status = "✓" if is_valid else "✗"
                logger.info(f"{status} {webhook_type}: {'Valid' if is_valid else 'Invalid'}")
            return
        
        # Prepare targets
        targets = []
        if args.target:
            targets.append(args.target)
        
        if args.list:
            try:
                targets_file = Path(args.list)
                if not targets_file.exists():
                    logger.error(f"Targets file not found: {args.list}")
                    return
                
                with open(targets_file, 'r') as f:
                    file_targets = [line.strip() for line in f if line.strip()]
                    targets.extend(file_targets)
                
                logger.info(f"Loaded {len(file_targets)} targets from {args.list}")
                
            except Exception as e:
                logger.error(f"Error reading targets file: {e}")
                return
        
        # Remove duplicates and validate
        targets = list(set(targets))
        valid_targets = []
        for target in targets:
            if is_valid_domain(target) or target.startswith(('http://', 'https://')):
                valid_targets.append(target)
            else:
                logger.warning(f"Invalid target format: {target}")
        
        if not valid_targets:
            logger.error("No valid targets found")
            return
        
        logger.info(f"Starting scan for {len(valid_targets)} valid targets")
        
        # Run scan
        if len(valid_targets) == 1:
            results = await framework.scan_single_target(valid_targets[0])
        else:
            results = await framework.scan_multiple_targets(valid_targets)
        
        # Save custom output if specified
        if args.output:
            output_file = Path(args.output)
            from utils.helpers import save_json
            save_json(results, output_file)
            logger.info(f"Results saved to {output_file}")
        
        # Print summary
        if isinstance(results, dict) and "all_findings" in results:
            findings_count = len(results["all_findings"])
            logger.info(f"Scan completed. Total findings: {findings_count}")
        elif isinstance(results, dict):
            total_findings = sum(
                len(r.get("all_findings", [])) 
                for r in results.values() 
                if isinstance(r, dict) and "all_findings" in r
            )
            logger.info(f"Scan completed. Total findings across all targets: {total_findings}")
        
        # Send summary notification
        try:
            stats = framework.result_logger.get_statistics()
            if stats["total_findings"] > 0:
                await framework.discord_notifier.send_summary_alert(stats)
        except Exception as e:
            logger.warning(f"Failed to send summary notification: {e}")
    
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        # Cleanup rate limiter
        await framework.rate_limiter.close()

if __name__ == "__main__":
    asyncio.run(main())
