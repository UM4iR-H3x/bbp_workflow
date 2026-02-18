"""
Rate limiting utilities for the Ultimate Automated Recon + Leak Detection Framework
"""

import asyncio
import random
import time
from typing import List, Optional
import aiohttp
from config.config import DEFAULT_DELAY, MAX_CONCURRENT_REQUESTS, USER_AGENTS

class RateLimiter:
    """
    Rate limiter with concurrent request control, delays, and retry logic
    """
    
    def __init__(
        self,
        max_concurrent: int = MAX_CONCURRENT_REQUESTS,
        delay_range: tuple = DEFAULT_DELAY,
        max_retries: int = 3,
        backoff_factor: float = 2.0
    ):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.delay_range = delay_range
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.session = None
        self.request_count = 0
        self.last_request_time = 0
        
    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session with proper headers"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                connector=aiohttp.TCPConnector(limit=max_concurrent)
            )
        return self.session
    
    async def delay(self):
        """Apply random delay between requests"""
        delay_time = random.uniform(*self.delay_range)
        await asyncio.sleep(delay_time)
    
    async def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[aiohttp.ClientResponse]:
        """
        Make a rate-limited HTTP request with retry logic
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: URL to request
            **kwargs: Additional arguments for aiohttp.request
            
        Returns:
            Response object or None if all retries failed
        """
        async with self.semaphore:
            session = await self.get_session()
            
            for attempt in range(self.max_retries + 1):
                try:
                    # Apply delay between requests
                    if self.request_count > 0:
                        await self.delay()
                    
                    # Rotate user agent for each request
                    session.headers['User-Agent'] = random.choice(USER_AGENTS)
                    
                    # Make the request
                    async with session.request(method, url, **kwargs) as response:
                        self.request_count += 1
                        self.last_request_time = time.time()
                        
                        # Check if we got a rate limit response
                        if response.status == 429:
                            retry_after = int(response.headers.get('Retry-After', 5))
                            wait_time = retry_after * (self.backoff_factor ** attempt)
                            await asyncio.sleep(wait_time)
                            continue
                        
                        return response
                        
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempt == self.max_retries:
                        return None
                    
                    # Exponential backoff
                    wait_time = (self.backoff_factor ** attempt) + random.uniform(0, 1)
                    await asyncio.sleep(wait_time)
                    
            return None
    
    async def get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a GET request with rate limiting"""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a POST request with rate limiting"""
        return await self.request('POST', url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a HEAD request with rate limiting"""
        return await self.request('HEAD', url, **kwargs)
    
    async def close(self):
        """Close the aiohttp session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    def __del__(self):
        """Cleanup when object is destroyed"""
        if self.session and not self.session.closed:
            # Note: This is not ideal, but ensures cleanup
            try:
                loop = asyncio.get_event_loop()
                if not loop.is_closed():
                    loop.create_task(self.close())
            except:
                pass

class RequestQueue:
    """
    Queue for managing requests with priority and rate limiting
    """
    
    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.queue = asyncio.Queue()
        self.processing = False
    
    async def add_request(
        self,
        method: str,
        url: str,
        priority: int = 0,
        callback=None,
        **kwargs
    ):
        """
        Add a request to the queue
        
        Args:
            method: HTTP method
            url: URL to request
            priority: Priority (lower number = higher priority)
            callback: Optional callback function for response
            **kwargs: Additional arguments
        """
        await self.queue.put((priority, method, url, callback, kwargs))
    
    async def process_queue(self):
        """Process all requests in the queue"""
        if self.processing:
            return
        
        self.processing = True
        requests = []
        
        # Collect all requests
        while not self.queue.empty():
            try:
                item = self.queue.get_nowait()
                requests.append(item)
            except asyncio.QueueEmpty:
                break
        
        # Sort by priority
        requests.sort(key=lambda x: x[0])
        
        # Process requests
        for priority, method, url, callback, kwargs in requests:
            response = await self.rate_limiter.request(method, url, **kwargs)
            if callback:
                await callback(response)
        
        self.processing = False

# Global rate limiter instance
_global_rate_limiter = None

def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance"""
    global _global_rate_limiter
    if _global_rate_limiter is None:
        _global_rate_limiter = RateLimiter()
    return _global_rate_limiter
