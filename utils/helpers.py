"""
Helper utilities for the Ultimate Automated Recon + Leak Detection Framework
"""

import re
import math
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import List, Set, Dict, Any, Optional
from urllib.parse import urlparse
import base64

def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string
    
    Args:
        text: Input string
        
    Returns:
        Entropy value (0-8)
    """
    if not text:
        return 0.0
    
    # Count character frequencies
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    text_len = len(text)
    
    for count in char_counts.values():
        probability = count / text_len
        entropy -= probability * math.log2(probability)
    
    return entropy

def is_high_entropy_string(text: str, threshold: float = 4.5, min_length: int = 20) -> bool:
    """
    Check if a string has high entropy (likely a secret)
    
    Args:
        text: Input string
        threshold: Entropy threshold
        min_length: Minimum string length
        
    Returns:
        True if string has high entropy
    """
    if len(text) < min_length:
        return False
    
    entropy = calculate_entropy(text)
    return entropy >= threshold

def normalize_url(url: str) -> str:
    """
    Normalize URL format
    
    Args:
        url: Input URL
        
    Returns:
        Normalized URL
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Remove trailing slash
    if url.endswith('/'):
        url = url[:-1]
    
    return url

def extract_domain(url: str) -> str:
    """
    Extract domain from URL
    
    Args:
        url: Input URL
        
    Returns:
        Domain name
    """
    parsed = urlparse(url)
    return parsed.netloc

def is_valid_domain(domain: str) -> bool:
    """
    Check if a string is a valid domain
    
    Args:
        domain: Domain string
        
    Returns:
        True if valid domain
    """
    if not domain:
        return False
    
    # Basic domain regex
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def deduplicate_list(items: List[str]) -> List[str]:
    """
    Remove duplicates from a list while preserving order
    
    Args:
        items: Input list
        
    Returns:
        Deduplicated list
    """
    seen = set()
    result = []
    
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    
    return result

def filter_by_extension(urls: List[str], extensions: List[str]) -> List[str]:
    """
    Filter URLs by file extensions
    
    Args:
        urls: List of URLs
        extensions: List of extensions to keep (with dot)
        
    Returns:
        Filtered URLs
    """
    extensions = [ext.lower() for ext in extensions]
    filtered = []
    
    for url in urls:
        for ext in extensions:
            if url.lower().endswith(ext):
                filtered.append(url)
                break
    
    return filtered

def safe_filename(filename: str) -> str:
    """
    Create a safe filename by removing invalid characters
    
    Args:
        filename: Input filename
        
    Returns:
        Safe filename
    """
    # Remove invalid characters
    invalid_chars = r'[<>:"/\\|?*]'
    filename = re.sub(invalid_chars, '_', filename)
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename

def get_file_hash(file_path: Path) -> str:
    """
    Calculate SHA256 hash of a file
    
    Args:
        file_path: Path to file
        
    Returns:
        SHA256 hash
    """
    hash_sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    
    return hash_sha256.hexdigest()

def ensure_directory(path: Path) -> Path:
    """
    Ensure directory exists, create if it doesn't
    
    Args:
        path: Directory path
        
    Returns:
        Path object
    """
    path.mkdir(parents=True, exist_ok=True)
    return path

def clean_temp_files(temp_dir: Path) -> bool:
    """
    Clean all files in temporary directory
    
    Args:
        temp_dir: Temporary directory path
        
    Returns:
        True if successful
    """
    try:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
            temp_dir.mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False

def save_json(data: Any, file_path: Path) -> bool:
    """
    Save data to JSON file
    
    Args:
        data: Data to save
        file_path: Output file path
        
    Returns:
        True if successful
    """
    try:
        ensure_directory(file_path.parent)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return True
    except Exception:
        return False

def load_json(file_path: Path) -> Optional[Any]:
    """
    Load data from JSON file
    
    Args:
        file_path: Input file path
        
    Returns:
        Loaded data or None if failed
    """
    try:
        if not file_path.exists():
            return None
        
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None

def extract_urls_from_text(text: str) -> List[str]:
    """
    Extract URLs from text using regex
    
    Args:
        text: Input text
        
    Returns:
        List of URLs found
    """
    # URL regex pattern
    url_pattern = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
    
    urls = re.findall(url_pattern, text)
    return deduplicate_list(urls)

def is_base64_string(s: str) -> bool:
    """
    Check if a string is valid base64
    
    Args:
        s: Input string
        
    Returns:
        True if valid base64
    """
    try:
        # Remove whitespace and padding check
        s = s.strip()
        # Base64 strings should have length divisible by 4
        if len(s) % 4 != 0:
            return False
        
        # Try to decode
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

def decode_base64_safe(s: str) -> Optional[str]:
    """
    Safely decode base64 string
    
    Args:
        s: Base64 string
        
    Returns:
        Decoded string or None if failed
    """
    try:
        decoded_bytes = base64.b64decode(s, validate=True)
        return decoded_bytes.decode('utf-8')
    except Exception:
        return None

def get_timestamp() -> str:
    """
    Get current timestamp as string
    
    Returns:
        Timestamp string
    """
    from datetime import datetime
    return datetime.now().strftime('%Y%m%d_%H%M%S')

def format_size(size_bytes: int) -> str:
    """
    Format file size in human readable format
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    
    if i >= len(size_names):
        i = len(size_names) - 1
    
    p = 1024 ** i
    s = size_bytes / p
    return f"{s:.1f}{size_names[i]}"
