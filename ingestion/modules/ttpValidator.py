"""Article text fetcher with Playwright fallback.

TTP extraction (GPT-4o) has been merged into articleValidator.analyzeArticle()
so that nlp.py makes a single API call instead of two.
"""
from newspaper import Article
from playwright.sync_api import sync_playwright
import playwright

def fetch_article_text(url: str) -> str:
    """Fetch article body text via Playwright. Returns empty string on failure."""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
            )
            page = browser.new_page()
            page.set_extra_http_headers({
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/91.0.4472.124 Safari/537.36"
                )
            })
            page.goto(url, timeout=30000)
            content = page.content()
            browser.close()

        article = Article(url=url)
        article.set_html(content)
        article.download_state = 2
        article.parse()
        return article.text or ""
    except Exception:
        return ""
