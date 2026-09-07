import logging
from typing import Set, List, Dict, Any, Tuple
from urllib.parse import urlparse, urljoin, urlunparse
from bs4 import BeautifulSoup
from app.core.http_client import SecurityHTTPClient

logger = logging.getLogger(__name__)

class AsyncCrawler:
    def __init__(
        self,
        target_url: str,
        max_depth: int = 3,
        max_pages: int = 50,
        http_client: SecurityHTTPClient = None
    ):
        self.target_url = self.normalize_url(target_url)
        self.parsed_target = urlparse(self.target_url)
        self.target_domain = self.parsed_target.netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.client = http_client or SecurityHTTPClient()
        
        self.visited_urls: Set[str] = set()
        self.crawled_data: List[Dict[str, Any]] = []

    @staticmethod
    def normalize_url(url: str) -> str:
        """
        Normalizes URL by stripping fragments and trailing slashes.
        """
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')
        clean_url = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            path,
            parsed.params,
            parsed.query,
            ''  # drop fragment
        ))
        return clean_url

    def is_same_domain(self, url: str) -> bool:
        """
        Verifies if candidate URL belongs to the target domain scope.
        Allows apex domain and www subdomains of the target domain.
        """
        parsed = urlparse(url)
        candidate_netloc = parsed.netloc.lower().split(':')[0]
        target_netloc = self.target_domain.lower().split(':')[0]
        
        # Strip leading www. for apex domain comparison
        candidate_base = candidate_netloc[4:] if candidate_netloc.startswith("www.") else candidate_netloc
        target_base = target_netloc[4:] if target_netloc.startswith("www.") else target_netloc

        return candidate_base == target_base

    def extract_links(self, html_content: str, current_url: str) -> List[str]:
        """
        Extracts links from <a href>, <form action>, and <script src> tags.
        """
        links = []
        if not html_content:
            return links

        soup = BeautifulSoup(html_content, "html.parser")
        
        # 1. Hyperlinks
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full_url = urljoin(current_url, href)
                links.append(self.normalize_url(full_url))

        # 2. Form actions
        for form in soup.find_all("form", action=True):
            action = form["action"].strip()
            if action and not action.startswith("javascript:"):
                full_url = urljoin(current_url, action)
                links.append(self.normalize_url(full_url))

        return links

    async def crawl(self) -> List[Dict[str, Any]]:
        """
        Executes asynchronous BFS crawl within target domain boundary.
        """
        queue: List[Tuple[str, int]] = [(self.target_url, 0)]
        self.visited_urls.add(self.target_url)

        while queue and len(self.crawled_data) < self.max_pages:
            current_url, depth = queue.pop(0)

            if depth > self.max_depth:
                continue

            logger.info(f"Crawling [Depth {depth}]: {current_url}")
            response, elapsed_ms, error = await self.client.fetch(current_url)

            if response:
                final_url = self.normalize_url(str(response.url))
                self.visited_urls.add(final_url)

                status_code = response.status_code
                content_type = response.headers.get("content-type", "")
                is_textual = any(t in content_type.lower() for t in ["html", "text", "json", "xml"])
                # Limit memory footprint: only decode textual responses and cap to 256KB to fit within 512MB RAM
                body = response.text[:256000] if is_textual else ""
                headers = dict(response.headers)
                
                # Parse each Set-Cookie header individually to get per-cookie attributes
                raw_set_cookie_headers = response.headers.get_list("set-cookie") if hasattr(response.headers, 'get_list') else [response.headers.get("set-cookie", "")]
                # Build a lookup from cookie name -> raw set-cookie line
                cookie_raw_map: dict = {}
                for raw_sc in raw_set_cookie_headers:
                    parts = raw_sc.split(";")[0].split("=", 1)
                    if parts:
                        cookie_raw_map[parts[0].strip()] = raw_sc.lower()

                cookies = []
                for name, value in response.cookies.items():
                    raw_line = cookie_raw_map.get(name, "")
                    cookies.append({
                        "name": name,
                        "value": value,
                        "secure": "secure" in raw_line,
                        "httponly": "httponly" in raw_line,
                        "samesite": (
                            "lax" if "samesite=lax" in raw_line
                            else ("strict" if "samesite=strict" in raw_line
                                  else ("none" if "samesite=none" in raw_line else ""))
                        )
                    })

                self.crawled_data.append({
                    "url": final_url if final_url else current_url,
                    "initial_url": current_url,
                    "status_code": status_code,
                    "content_type": content_type,
                    "response_time_ms": elapsed_ms,
                    "headers": headers,
                    "body": body,
                    "cookies": cookies,
                    "depth": depth
                })

                # Extract and queue further links if HTML
                if "html" in content_type.lower() and depth < self.max_depth:
                    new_links = self.extract_links(body, final_url)
                    for link in new_links:
                        if link not in self.visited_urls and self.is_same_domain(link):
                            self.visited_urls.add(link)
                            queue.append((link, depth + 1))
            else:
                self.crawled_data.append({
                    "url": current_url,
                    "initial_url": current_url,
                    "status_code": None,
                    "content_type": None,
                    "response_time_ms": elapsed_ms,
                    "headers": {},
                    "body": "",
                    "cookies": [],
                    "error": error,
                    "depth": depth
                })

        return self.crawled_data

