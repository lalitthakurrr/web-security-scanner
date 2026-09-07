import pytest
from app.core.crawler import AsyncCrawler

def test_url_normalization():
    raw_url = "HTTP://TEST.LOCAL/path/to/page/#section"
    normalized = AsyncCrawler.normalize_url(raw_url)
    assert normalized == "http://test.local/path/to/page"

def test_same_domain_check():
    crawler = AsyncCrawler(target_url="http://test.local/app")
    assert crawler.is_same_domain("http://test.local/login") is True
    assert crawler.is_same_domain("http://sub.test.local/login") is False
    assert crawler.is_same_domain("http://external.com/page") is False

def test_link_extraction():
    crawler = AsyncCrawler(target_url="http://test.local")
    html = """
    <html>
        <body>
            <a href="/about">About Us</a>
            <a href="http://test.local/contact">Contact</a>
            <a href="javascript:void(0)">Click</a>
            <form action="/submit" method="POST"></form>
        </body>
    </html>
    """
    links = crawler.extract_links(html, "http://test.local")
    assert "http://test.local/about" in links
    assert "http://test.local/contact" in links
    assert "http://test.local/submit" in links
    assert not any("javascript" in link for link in links)
