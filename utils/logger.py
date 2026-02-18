"""
Logging utilities for the Ultimate Automated Recon + Leak Detection Framework
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset_color = self.COLORS['RESET']
        
        # Format the message
        formatted = super().format(record)
        return f"{log_color}[{record.levelname}]{reset_color} {formatted}"

def setup_logger(
    name: str = "recon_framework",
    log_level: str = "INFO",
    log_file: Optional[Path] = None
) -> logging.Logger:
    """
    Setup a logger with console and optional file output
    
    Args:
        name: Logger name
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = ColoredFormatter(
        '%(asctime)s - %(name)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

def log_vulnerability(
    logger: logging.Logger,
    target: str,
    module: str,
    url: str,
    vuln_type: str,
    severity: str,
    evidence: str
) -> dict:
    """
    Log a vulnerability finding and return structured data
    
    Args:
        logger: Logger instance
        target: Target domain
        module: Module that found the vulnerability
        url: URL where vulnerability was found
        vuln_type: Type of vulnerability
        severity: Severity level
        evidence: Evidence or snippet
    
    Returns:
        Dictionary with vulnerability data
    """
    timestamp = datetime.now().isoformat()
    
    # Log to console
    logger.warning(
        f"[{severity}] {vuln_type} found in {target} by {module}"
    )
    logger.info(f"URL: {url}")
    logger.info(f"Evidence: {evidence[:200]}...")
    
    # Return structured data
    return {
        "target": target,
        "module": module,
        "url": url,
        "timestamp": timestamp,
        "vulnerability_type": vuln_type,
        "severity": severity,
        "evidence": evidence
    }

def log_module_start(logger: logging.Logger, module_name: str, target: str):
    """Log the start of a module execution"""
    logger.info(f"Starting {module_name} for target: {target}")

def log_module_complete(logger: logging.Logger, module_name: str, target: str, items_found: int = 0):
    """Log the completion of a module execution"""
    logger.info(f"Completed {module_name} for target: {target} (Items found: {items_found})")

def log_error(logger: logging.Logger, module_name: str, target: str, error: str):
    """Log an error that occurred during module execution"""
    logger.error(f"Error in {module_name} for target {target}: {error}")

# Global logger instance
_global_logger = None

def get_logger() -> logging.Logger:
    """Get the global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = setup_logger()
    return _global_logger
