import time
import logging
from typing import Dict, Any, Tuple, Optional
import httpx
from app.core.config import settings

logger = logging.getLogger(__name__)

class SecurityHTTPClient:
    def __init__(self, timeout: float = settings.DEFAULT_TIMEOUT_SECONDS, user_agent: str = settings.DEFAULT_USER_AGENT):
        self.timeout = timeout
        self.user_agent = user_agent

    async def fetch(self, url: str) -> Tuple[Optional[httpx.Response], float, Optional[str]]:
        """
        Fetches target URL safely and returns (httpx.Response, elapsed_ms, error_message).
        """
        headers = {"User-Agent": self.user_agent}
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(
                verify=False,  # Allow self-signed or test certificates for security audit purposes
                follow_redirects=True,
                timeout=httpx.Timeout(self.timeout)
            ) as client:
                response = await client.get(url, headers=headers)
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                return response, elapsed_ms, None
        except httpx.RequestError as exc:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            logger.warning(f"HTTP Request failed for {url}: {exc}")
            return None, elapsed_ms, str(exc)

    async def check_sensitive_endpoint(self, base_url: str, relative_path: str) -> Tuple[bool, Optional[httpx.Response]]:
        """
        Checks if a sensitive path (e.g. .env, .git/HEAD) exists on the host.
        """
        target = base_url.rstrip("/") + "/" + relative_path.lstrip("/")
        response, _, error = await self.fetch(target)
        if response and response.status_code == 200:
            # Simple heuristic: response shouldn't be HTML 404 page masquerading as 200
            if "html" not in response.headers.get("content-type", "").lower() or relative_path == "robots.txt":
                return True, response
            if any(term in response.text.lower() for term in ["db_password", "ref: refs/", "user-agent:"]):
                return True, response
        return False, response
