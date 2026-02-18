"""
Result logger module for saving findings to JSON
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from utils.logger import get_logger, log_vulnerability
from utils.helpers import save_json, load_json, ensure_directory
from config.config import RESULTS_FILE

class ResultLogger:
    """
    Log and save scan results to JSON file
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.results_file = RESULTS_FILE
        ensure_directory(self.results_file.parent)
    
    def log_finding(self, finding: Dict[str, Any]) -> bool:
        """
        Log a single finding to the results file
        
        Args:
            finding: Finding dictionary
            
        Returns:
            True if successful
        """
        try:
            # Ensure finding has required fields
            required_fields = ["target", "module", "url", "timestamp", "vulnerability_type", "severity", "evidence"]
            
            for field in required_fields:
                if field not in finding:
                    finding[field] = "unknown"
            
            # Add timestamp if not present
            if not finding.get("timestamp"):
                finding["timestamp"] = datetime.now().isoformat()
            
            # Load existing results
            existing_results = self.load_results()
            
            # Add new finding
            existing_results.append(finding)
            
            # Save results
            success = save_json(existing_results, self.results_file)
            
            if success:
                self.logger.info(f"Logged finding: {finding['vulnerability_type']} for {finding['target']}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error logging finding: {e}")
            return False
    
    def log_findings(self, findings: List[Dict[str, Any]]) -> bool:
        """
        Log multiple findings to the results file
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            True if successful
        """
        try:
            if not findings:
                return True
            
            # Load existing results
            existing_results = self.load_results()
            
            # Add new findings
            for finding in findings:
                # Ensure finding has required fields
                required_fields = ["target", "module", "url", "timestamp", "vulnerability_type", "severity", "evidence"]
                
                for field in required_fields:
                    if field not in finding:
                        finding[field] = "unknown"
                
                # Add timestamp if not present
                if not finding.get("timestamp"):
                    finding["timestamp"] = datetime.now().isoformat()
                
                existing_results.append(finding)
            
            # Save results
            success = save_json(existing_results, self.results_file)
            
            if success:
                self.logger.info(f"Logged {len(findings)} findings")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error logging findings: {e}")
            return False
    
    def load_results(self) -> List[Dict[str, Any]]:
        """
        Load existing results from file
        
        Returns:
            List of existing findings
        """
        try:
            results = load_json(self.results_file)
            
            if results is None:
                return []
            
            # Ensure it's a list
            if not isinstance(results, list):
                self.logger.warning("Results file is not a list, creating new one")
                return []
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error loading results: {e}")
            return []
    
    def clear_results(self) -> bool:
        """
        Clear all results from the file
        
        Returns:
            True if successful
        """
        try:
            return save_json([], self.results_file)
        except Exception as e:
            self.logger.error(f"Error clearing results: {e}")
            return False
    
    def get_results_by_target(self, target: str) -> List[Dict[str, Any]]:
        """
        Get all findings for a specific target
        
        Args:
            target: Target domain/URL
            
        Returns:
            List of findings for the target
        """
        try:
            all_results = self.load_results()
            
            target_findings = [
                finding for finding in all_results
                if finding.get("target", "").lower() == target.lower()
            ]
            
            return target_findings
            
        except Exception as e:
            self.logger.error(f"Error getting results for target {target}: {e}")
            return []
    
    def get_results_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """
        Get all findings by severity level
        
        Args:
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            
        Returns:
            List of findings with specified severity
        """
        try:
            all_results = self.load_results()
            
            severity_findings = [
                finding for finding in all_results
                if finding.get("severity", "").upper() == severity.upper()
            ]
            
            return severity_findings
            
        except Exception as e:
            self.logger.error(f"Error getting results by severity {severity}: {e}")
            return []
    
    def get_results_by_module(self, module: str) -> List[Dict[str, Any]]:
        """
        Get all findings by module
        
        Args:
            module: Module name
            
        Returns:
            List of findings from specified module
        """
        try:
            all_results = self.load_results()
            
            module_findings = [
                finding for finding in all_results
                if finding.get("module", "").lower() == module.lower()
            ]
            
            return module_findings
            
        except Exception as e:
            self.logger.error(f"Error getting results by module {module}: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about all findings
        
        Returns:
            Statistics dictionary
        """
        try:
            all_results = self.load_results()
            
            if not all_results:
                return {
                    "total_findings": 0,
                    "targets_count": 0,
                    "severity_distribution": {},
                    "module_distribution": {},
                    "type_distribution": {}
                }
            
            # Count by severity
            severity_counts = {}
            for finding in all_results:
                severity = finding.get("severity", "UNKNOWN")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by module
            module_counts = {}
            for finding in all_results:
                module = finding.get("module", "unknown")
                module_counts[module] = module_counts.get(module, 0) + 1
            
            # Count by vulnerability type
            type_counts = {}
            for finding in all_results:
                vuln_type = finding.get("vulnerability_type", "unknown")
                type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
            
            # Count unique targets
            targets = set()
            for finding in all_results:
                targets.add(finding.get("target", ""))
            
            return {
                "total_findings": len(all_results),
                "targets_count": len(targets),
                "severity_distribution": severity_counts,
                "module_distribution": module_counts,
                "type_distribution": type_counts,
                "latest_finding": max(all_results, key=lambda x: x.get("timestamp", "")) if all_results else None
            }
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {}
    
    def export_results(self, output_file: Path, format: str = "json") -> bool:
        """
        Export results to different formats
        
        Args:
            output_file: Output file path
            format: Export format (json, csv, txt)
            
        Returns:
            True if successful
        """
        try:
            results = self.load_results()
            
            if format.lower() == "json":
                return save_json(results, output_file)
            
            elif format.lower() == "csv":
                return self._export_csv(results, output_file)
            
            elif format.lower() == "txt":
                return self._export_txt(results, output_file)
            
            else:
                self.logger.error(f"Unsupported export format: {format}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error exporting results: {e}")
            return False
    
    def _export_csv(self, results: List[Dict[str, Any]], output_file: Path) -> bool:
        """Export results to CSV format"""
        try:
            import csv
            
            if not results:
                return True
            
            # Define CSV headers
            headers = [
                "timestamp", "target", "module", "url", "vulnerability_type",
                "severity", "evidence"
            ]
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                writer.writeheader()
                
                for finding in results:
                    row = {header: finding.get(header, "") for header in headers}
                    writer.writerow(row)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting to CSV: {e}")
            return False
    
    def _export_txt(self, results: List[Dict[str, Any]], output_file: Path) -> bool:
        """Export results to text format"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("=== Security Scan Results ===\n\n")
                
                for finding in results:
                    f.write(f"Target: {finding.get('target', 'N/A')}\n")
                    f.write(f"Module: {finding.get('module', 'N/A')}\n")
                    f.write(f"URL: {finding.get('url', 'N/A')}\n")
                    f.write(f"Type: {finding.get('vulnerability_type', 'N/A')}\n")
                    f.write(f"Severity: {finding.get('severity', 'N/A')}\n")
                    f.write(f"Timestamp: {finding.get('timestamp', 'N/A')}\n")
                    f.write(f"Evidence: {finding.get('evidence', 'N/A')}\n")
                    f.write("-" * 50 + "\n\n")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting to TXT: {e}")
            return False
    
    def create_summary_report(self) -> str:
        """
        Create a summary report of all findings
        
        Returns:
            Summary report string
        """
        try:
            stats = self.get_statistics()
            results = self.load_results()
            
            report = []
            report.append("=== Security Scan Summary Report ===\n")
            report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            # Basic statistics
            report.append(f"Total Findings: {stats['total_findings']}")
            report.append(f"Targets Scanned: {stats['targets_count']}\n")
            
            # Severity distribution
            if stats['severity_distribution']:
                report.append("Findings by Severity:")
                for severity, count in sorted(stats['severity_distribution'].items(), 
                                            key=lambda x: self._severity_order(x[0])):
                    report.append(f"  {severity}: {count}")
                report.append("")
            
            # Module distribution
            if stats['module_distribution']:
                report.append("Findings by Module:")
                for module, count in stats['module_distribution'].items():
                    report.append(f"  {module}: {count}")
                report.append("")
            
            # Type distribution
            if stats['type_distribution']:
                report.append("Findings by Type:")
                for vuln_type, count in stats['type_distribution'].items():
                    report.append(f"  {vuln_type}: {count}")
                report.append("")
            
            # Critical findings
            critical_findings = [f for f in results if f.get('severity') == 'CRITICAL']
            if critical_findings:
                report.append("CRITICAL FINDINGS:")
                for finding in critical_findings[:10]:  # Show first 10
                    report.append(f"  - {finding.get('target', 'N/A')}: {finding.get('vulnerability_type', 'N/A')}")
                
                if len(critical_findings) > 10:
                    report.append(f"  ... and {len(critical_findings) - 10} more")
                report.append("")
            
            return "\n".join(report)
            
        except Exception as e:
            self.logger.error(f"Error creating summary report: {e}")
            return f"Error generating report: {e}"
    
    def _severity_order(self, severity: str) -> int:
        """Helper function to sort severities"""
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return order.get(severity.upper(), 99)

# Singleton instance
_result_logger = None

def get_result_logger() -> ResultLogger:
    """Get the result logger instance"""
    global _result_logger
    if _result_logger is None:
        _result_logger = ResultLogger()
    return _result_logger
