"""
Beautiful terminal UI printer for l0bo recon tool
"""

import sys
from typing import Optional
from colorama import Fore, Style, init

# Initialize colorama for Windows compatibility
init(autoreset=True)

class Printer:
    """Beautiful colored terminal output"""
    
    # Colors
    CYAN = Fore.CYAN
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    MAGENTA = Fore.MAGENTA
    BLUE = Fore.BLUE
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT
    DIM = Style.DIM
    
    @staticmethod
    def banner():
        """Print l0bo banner"""
        banner = f"""
{Printer.CYAN}{Printer.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║              {Printer.GREEN}l0bo{Printer.CYAN} - Automated Recon Framework          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
{Printer.RESET}
"""
        print(banner)
    
    @staticmethod
    def phase(phase_name: str, target: Optional[str] = None):
        """Print phase header"""
        if target:
            print(f"\n{Printer.CYAN}{Printer.BOLD}═══ {phase_name} [{target}] ═══{Printer.RESET}")
        else:
            print(f"\n{Printer.CYAN}{Printer.BOLD}═══ {phase_name} ═══{Printer.RESET}")
    
    @staticmethod
    def info(message: str):
        """Print info message"""
        print(f"{Printer.GREEN}[+] {message}{Printer.RESET}")
    
    @staticmethod
    def success(message: str):
        """Print success message"""
        print(f"{Printer.GREEN}{Printer.BOLD}[✓] {message}{Printer.RESET}")
    
    @staticmethod
    def warning(message: str):
        """Print warning message"""
        print(f"{Printer.YELLOW}[!] {message}{Printer.RESET}")
    
    @staticmethod
    def error(message: str):
        """Print error message"""
        print(f"{Printer.RED}[✗] {message}{Printer.RESET}")
    
    @staticmethod
    def finding(message: str):
        """Print finding/leak message"""
        print(f"{Printer.MAGENTA}{Printer.BOLD}[LEAK] {message}{Printer.RESET}")
    
    @staticmethod
    def tool_running(tool_name: str):
        """Print tool running message"""
        print(f"{Printer.BLUE}[→] Running {tool_name}...{Printer.RESET}", end='', flush=True)
    
    @staticmethod
    def tool_done(tool_name: str, count: Optional[int] = None):
        """Print tool done message"""
        if count is not None:
            print(f"\r{Printer.GREEN}[✓] {tool_name} done - Found {count} items{Printer.RESET}")
        else:
            print(f"\r{Printer.GREEN}[✓] {tool_name} done{Printer.RESET}")
    
    @staticmethod
    def count(label: str, count: int, color: str = GREEN):
        """Print count"""
        print(f"{color}{Printer.BOLD}  {label}: {count}{Printer.RESET}")
    
    @staticmethod
    def separator():
        """Print separator"""
        print(f"{Printer.DIM}{'─' * 60}{Printer.RESET}")
    
    @staticmethod
    def target_start(target: str, index: int, total: int):
        """Print target start"""
        print(f"\n{Printer.CYAN}{Printer.BOLD}{'='*60}")
        print(f"Target {index}/{total}: {target}")
        print(f"{'='*60}{Printer.RESET}\n")
    
    @staticmethod
    def target_done(target: str, findings: int):
        """Print target done"""
        if findings > 0:
            print(f"\n{Printer.GREEN}{Printer.BOLD}[✓] {target} completed - {findings} findings{Printer.RESET}\n")
        else:
            print(f"\n{Printer.GREEN}{Printer.BOLD}[✓] {target} completed{Printer.RESET}\n")
    
    @staticmethod
    def webhook_sent(finding_type: str):
        """Print webhook notification"""
        print(f"{Printer.MAGENTA}[📢] Webhook sent: {finding_type}{Printer.RESET}")

    @staticmethod
    def progress(message: str):
        """
        Print a single-line progress message (updates in-place).
        Useful for scanning many URLs without spamming the terminal.
        """
        sys.stdout.write(f"\r{Printer.BLUE}[→] {message}{Printer.RESET}")
        sys.stdout.flush()

    @staticmethod
    def progress_done(message: str = ""):
        """Finish progress line and move to next line."""
        if message:
            sys.stdout.write(f"\r{Printer.GREEN}[✓] {message}{Printer.RESET}\n")
        else:
            sys.stdout.write("\n")
        sys.stdout.flush()

# Global printer instance
_printer = None

def get_printer() -> Printer:
    """Get printer instance"""
    global _printer
    if _printer is None:
        _printer = Printer()
    return _printer
