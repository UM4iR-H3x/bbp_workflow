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
from utils.printer import get_printer
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
from modules.js_scanner import JSScanner
from modules.logger import get_result_logger
from modules.js_storage import get_js_storage
from modules.notifier import get_discord_notifier
from modules.cleanup import get_cleanup_manager

class ReconFramework:
    """
    Main orchestrator for the reconnaissance framework
    """
    
    def __init__(self, threads: int = MAX_CONCURRENT_REQUESTS, delay: tuple = DEFAULT_DELAY):
        self.logger = get_logger()
        self.printer = get_printer()
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
        self.js_scanner = JSScanner()
        self.result_logger = get_result_logger()
        self.js_storage = get_js_storage()
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
            # 1. Subdomain Enumeration Phase
            self.printer.phase("Subdomain Enumeration Phase", target)
            from utils.helpers import extract_domain
            target_domain = extract_domain(target) if target.startswith(('http://', 'https://')) else target
            
            subdomains = await self.subdomain_enum.enumerate_subdomains(target_domain)
            results["subdomains"] = subdomains
            self.printer.count("Subdomains found", len(subdomains))
            
            # 2. HTTPX Phase (Live Host Check)
            self.printer.phase("HTTPX Phase (Live Host Check)", target)
            live_hosts = await self.live_checker.check_hosts_live(subdomains)
            results["live_hosts"] = live_hosts
            self.printer.count("Live hosts", len(live_hosts), self.printer.GREEN)
            
            # 3. URLs Gathering Phase: gau (all hosts) -> waybackurls (all hosts) -> katana (all hosts) -> dedup, save to one file
            self.printer.phase("URLs Gathering Phase", target)
            urls_file = self.url_collector.get_urls_file_path(target)
            all_urls = await self.url_collector.collect_urls_all_hosts_by_tool(
                live_hosts,
                urls_file,
                on_tool_start=lambda name: self.printer.tool_running(name),
                on_tool_done=lambda name, count: self.printer.tool_done(name, count),
            )
            
            if not all_urls:
                self.printer.warning("No URLs collected! Check if tools are working correctly.")
                self.logger.warning(f"URLs file saved at: {urls_file}")
                # Continue anyway - maybe JS files are already in the file
            
            self.printer.success(f"Got {len(all_urls)} total URLs (saved to {urls_file})")
            
            # 4. JS Files Phase
            self.printer.phase("JS Files Phase", target)
            if not all_urls:
                self.printer.warning("Skipping JS phase - no URLs to process")
                js_urls = []
            else:
                self.printer.info(f"Filtering {len(all_urls)} URLs for JS files...")
                js_urls = self.js_filter.filter_js_urls(all_urls)
                js_urls = self.deduplicator.deduplicate_urls(js_urls)
            results["js_urls_file"] = self.js_storage.save_js_urls_to_txt(js_urls, target)
            results["js_urls"] = js_urls
            
            # Dead Link Check (identify 200 vs 404)
            if js_urls:
                self.printer.info(f"Validating {len(js_urls)} JS URLs (200 vs 404) ...")
                status_results = await self.deadlink_checker.check_urls_statuses(js_urls)

                live_js_urls = [r["url"] for r in status_results if r.get("status_code") == 200]
                dead_js_urls = [r["url"] for r in status_results if r.get("status_code") in (404, 410)]
                other_js = [r for r in status_results if r.get("status_code") not in (200, 404, 410)]

                # Save exact lists to files so you can review
                results["js_200_file"] = self.js_storage.save_url_list_to_txt(live_js_urls, target, "js_200")
                results["js_404_file"] = self.js_storage.save_url_list_to_txt(dead_js_urls, target, "js_404")

                results["dead_js_urls"] = dead_js_urls
                results["js_status_other"] = other_js
            else:
                dead_js_urls = []
                live_js_urls = []
                results["dead_js_urls"] = []
            
            self.printer.count("Total JS files", len(js_urls))
            self.printer.count("Live JS files (200)", len(live_js_urls), self.printer.GREEN)
            self.printer.count("Dead JS files (404/410)", len(dead_js_urls), self.printer.YELLOW)
            if js_urls and results.get("js_status_other"):
                self.printer.count("Other status (401/403/405/etc)", len(results["js_status_other"]), self.printer.YELLOW)
                self.printer.info("Saved 200/404 lists to:")
                if results.get("js_200_file"):
                    self.printer.info(f"  200 JS: {results['js_200_file']}")
                if results.get("js_404_file"):
                    self.printer.info(f"  404 JS: {results['js_404_file']}")
            
            # 7-8. Process LIVE (200) JS first: fetch, store, scan for secrets (100% coverage - ALL files)
            live_secrets = []
            if live_js_urls:
                self.printer.info(f"Scanning {len(live_js_urls)} live JS files for secrets...")
                try:
                    important_live_js, non_important_live_js = self.js_filter.filter_important_js_files(live_js_urls)
                    results["important_live_js"] = important_live_js
                    results["non_important_live_js"] = non_important_live_js
                    
                    # Store important JS files (for reference)
                    stored_live_js = {}
                    if important_live_js:
                        self.printer.info(f"Storing {len(important_live_js)} important JS files...")
                        stored_live_js = await self.js_storage.fetch_and_store_live_js(important_live_js)
                    results["stored_live_js"] = stored_live_js
                    
                    # CRITICAL: Scan ALL live JS files for secrets
                    self.printer.info(f"Fetching and scanning {len(live_js_urls)} live JS files...")
                    live_secrets = await self._scan_live_js_secrets(live_js_urls)
                    self.printer.success(f"Found {len(live_secrets)} secrets in live JS files")
                    
                    # Send webhooks immediately for live JS secrets
                    for secret in live_secrets:
                        await self._send_finding_webhook(secret)
                        self.printer.finding(f"JS Secret: {secret.get('vulnerability_type', 'Unknown')} in {secret.get('url', 'N/A')}")
                except Exception as e:
                    self.logger.error(f"Error processing live JS files: {e}")
                    self.printer.error(f"Error scanning live JS: {e}")
            else:
                self.printer.info("No live JS files to scan")
            results["live_secrets"] = live_secrets
            
            # 9-10. Then process DEAD (404) JS via Wayback Archive
            archived_secrets = []
            if dead_js_urls:
                self.printer.info(f"Checking {len(dead_js_urls)} dead JS files via Wayback...")
                try:
                    archived_secrets = await self._analyze_archived_js(dead_js_urls)
                    self.printer.success(f"Found {len(archived_secrets)} secrets in archived JS files")
                    # Send webhooks immediately for archived secrets
                    for secret in archived_secrets:
                        await self._send_finding_webhook(secret)
                        self.printer.finding(f"Archived JS Secret: {secret.get('vulnerability_type', 'Unknown')} in {secret.get('url', 'N/A')}")
                except Exception as e:
                    self.logger.error(f"Error processing archived JS files: {e}")
                    self.printer.error(f"Error scanning archived JS: {e}")
            else:
                self.printer.info("No dead JS files to check via Wayback")
            results["archived_secrets"] = archived_secrets
            
            # Store all found secrets (live + archived)
            all_secrets = live_secrets + archived_secrets
            if all_secrets:
                self.js_storage.store_secrets(all_secrets)
            
            # JavaScript Scanning Phase
            self.printer.phase("JS Scanner Phase", target)
            if js_urls:
                self.printer.info(f"Scanning {len(js_urls)} JavaScript files for secrets and vulnerabilities...")
                try:
                    js_results = await self.js_scanner.scan_urls(js_urls)
                    results["js_scanner_findings"] = js_results
                    total_js_findings = sum(len(r.findings) for r in js_results)
                    if total_js_findings > 0:
                        self.printer.count("JS findings", total_js_findings, self.printer.RED)
                    else:
                        self.printer.info("No secrets or vulnerabilities found in JS files")
                except Exception as e:
                    self.logger.error(f"Error scanning JS files: {e}")
                    self.printer.error(f"Error in JS scan: {e}")
                    results["js_scanner_findings"] = []
            else:
                self.printer.info("No JS files to scan")
                results["js_scanner_findings"] = []
            
            # Final Results Summary
            self.printer.phase("Results Summary", target)
            all_findings = await self._process_all_findings(results)
            results["all_findings"] = all_findings
            
            # Cleanup
            await self.cleanup_manager.cleanup_target_temp_files(target)
            
            # Generate statistics
            results["statistics"] = self._generate_scan_statistics(results)
            results["end_time"] = asyncio.get_event_loop().time()
            results["duration"] = results["end_time"] - results["start_time"]
            
            # Finish Phase
            self.printer.phase("Finish", target)
            self.printer.success(f"Scan completed in {results['duration']:.2f} seconds")
            self.printer.count("Total findings", len(all_findings), self.printer.MAGENTA if all_findings else self.printer.GREEN)
            
            # Return slim structure: only js_urls, live_hosts, and results (findings)
            return self._build_slim_results(results)
            
        except Exception as e:
            self.logger.error(f"Error during scan of {target}: {e}")
            results["error"] = str(e)
            results["all_findings"] = results.get("all_findings", [])
            results["statistics"] = results.get("statistics") or {}
            return self._build_slim_results(results)
    
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
                
                # Store archived JS files
                for snapshot in js_snapshots:
                    content = self.archive_fetcher.extract_js_content(snapshot)
                    if content:
                        await self.js_storage.store_archived_js_file(
                            url, 
                            snapshot["timestamp"], 
                            content, 
                            snapshot["snapshot_url"]
                        )
                        
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
        """
        Scan ALL live JavaScript files for secrets (100% coverage).
        Fetches each file and scans content - no files are skipped.
        """
        live_secrets = []
        
        if not live_js_urls:
            return live_secrets
        
        try:
            # Fetch ALL live JS content (concurrent but rate-limited) and show per-URL progress
            semaphore = asyncio.Semaphore(self.threads)
            fetched_count = 0
            failed_count = 0

            async def fetch_js_content(url: str) -> tuple:
                async with semaphore:
                    try:
                        response = await self.rate_limiter.get(url, timeout=10)
                        if response and response.status == 200:
                            # This reads the full JS code into memory (as requested)
                            content = await response.text()
                            return url, content, None
                        return url, None, f"Status {response.status if response else 'None'}"
                    except Exception as e:
                        return url, None, str(e)

            tasks = [asyncio.create_task(fetch_js_content(url)) for url in live_js_urls]

            js_contents = []
            completed = 0
            total = len(tasks)

            for fut in asyncio.as_completed(tasks):
                result = await fut
                completed += 1
                url, content, error = result

                # One-line progress update (won't spam)
                self.printer.progress(f"Scanning ({completed}/{total}) {url}")

                if content:
                    js_contents.append((url, content))
                    fetched_count += 1
                else:
                    failed_count += 1
                    if error:
                        self.logger.debug(f"Failed to fetch {url}: {error}")

            self.printer.progress_done(f"JS fetch done: {fetched_count}/{len(live_js_urls)} (failed {failed_count})")

            # Scan ALL fetched content for secrets (no skipping)
            if js_contents:
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
            else:
                self.logger.warning("No JS content fetched - cannot scan for secrets")
        
        except Exception as e:
            self.logger.error(f"Error scanning live JS secrets: {e}")
        
        return live_secrets
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings (same target, module, url, type, evidence)."""
        seen = set()
        out = []
        for f in findings:
            key = (
                str(f.get("target", "")),
                str(f.get("module", "")),
                str(f.get("url", "")),
                str(f.get("vulnerability_type", "")),
                str(f.get("evidence", ""))[:500],
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out
    
    async def _process_all_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process and categorize all findings (no duplicates)."""
        all_findings = []
        
        # Process archived secrets
        for secret in results.get("archived_secrets", []):
            all_findings.append(secret)
        
        # Process live secrets
        for secret in results.get("live_secrets", []):
            all_findings.append(secret)
        
        # Process JS Scanner findings
        for js_result in results.get("js_scanner_findings", []):
            for finding in js_result.findings:
                all_findings.append({
                    "target": js_result.url,
                    "module": "JS Scanner",
                    "url": finding.url,
                    "vulnerability_type": finding.type,
                    "severity": finding.severity,
                    "evidence": finding.matched_string,
                    "line_number": finding.line_number,
                    "context": finding.context
                })
        
        # Remove duplicate findings
        all_findings = self._deduplicate_findings(all_findings)
        
        # Log all findings
        if all_findings:
            await self.result_logger.log_findings(all_findings)
        
        return all_findings
    
    async def _send_finding_webhook(self, finding: Dict[str, Any]) -> None:
        """Send webhook notification immediately when finding is discovered"""
        try:
            vuln_type = finding.get("vulnerability_type", "").lower()
            
            if "archived" in vuln_type or "live" in vuln_type or "js" in vuln_type:
                await self.discord_notifier.send_js_leak_alert(finding)
                self.printer.webhook_sent("JS Leak")
            elif "environment" in vuln_type or "env" in vuln_type:
                await self.discord_notifier.send_env_exposure_alert(finding)
                self.printer.webhook_sent("ENV Exposure")
            elif "git" in vuln_type:
                await self.discord_notifier.send_git_exposure_alert(finding)
                self.printer.webhook_sent("Git Exposure")
            elif "cors" in vuln_type:
                await self.discord_notifier.send_cors_alert(finding)
                self.printer.webhook_sent("CORS Misconfiguration")
        except Exception as e:
            self.logger.debug(f"Error sending webhook: {e}")
    
    def _build_slim_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build slim result: only js_urls, live_hosts (live subdomains), and results (findings).
        Keeps target, duration, and statistics for reference.
        """
        out = {
            "target": results.get("target"),
            "live_hosts": results.get("live_hosts", []),
            "js_urls": results.get("js_urls", []),
            "js_urls_file": results.get("js_urls_file"),
            "results": results.get("all_findings", []),
            "statistics": results.get("statistics", {}),
            "duration_seconds": results.get("duration"),
        }
        if results.get("error"):
            out["error"] = results["error"]
        return out
    
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
            "js_scanner_findings": sum(len(r.findings) for r in results.get("js_scanner_findings", [])),
            "total_findings": len(results.get("all_findings", []))
        }
        
        return stats
    
    async def scan_multiple_targets(self, targets: List[str]) -> Dict[str, Any]:
        """Scan multiple targets with progress indication"""
        self.printer.info(f"Starting scan for {len(targets)} targets")
        
        all_results = {}
        
        for idx, target in enumerate(targets, 1):
            try:
                self.printer.target_start(target, idx, len(targets))
                result = await self.scan_single_target(target)
                all_results[target] = result
                
                findings_count = len(result.get("results", []))
                self.printer.target_done(target, findings_count)
                
                # Brief pause between targets to be respectful
                if idx < len(targets):
                    await asyncio.sleep(2)
                
            except Exception as e:
                self.logger.error(f"Failed to scan {target}: {e}")
                all_results[target] = {"target": target, "error": str(e)}
                self.printer.error(f"{target} failed: {e}")
        
        return all_results
    

async def main():
    """Main entry point"""
    # Show banner
    printer = get_printer()
    printer.banner()
    
    parser = argparse.ArgumentParser(
        description="l0bo - Automated Recon + Leak Detection Framework",
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
        if isinstance(results, dict) and "results" in results:
            findings_count = len(results["results"])
            logger.info(f"Scan completed. Total findings: {findings_count}")
        elif isinstance(results, dict):
            total_findings = sum(
                len(r.get("results", [])) 
                for r in results.values() 
                if isinstance(r, dict)
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
