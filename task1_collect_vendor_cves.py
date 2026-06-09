import hashlib
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter


OUTPUT_PATH = Path("data/result_task_1.json")
CACHE_DIR = Path("data/cache/vendor_pages")

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
DATE_FROM_URL_PATTERN = re.compile(r"/(\d{4})/(\d{2})/(\d{2})/")

MAX_WORKERS = int(os.getenv("LAB2_MAX_WORKERS", "12"))
REQUEST_TIMEOUT = int(os.getenv("LAB2_REQUEST_TIMEOUT", "20"))
USE_CACHE = os.getenv("LAB2_DISABLE_CACHE", "0") != "1"

HEADERS = {
    "User-Agent": "Mozilla/5.0 lab2-cve-collector/2.0"
}

SITEMAP_URLS = [
    "https://suricata.io/sitemap.xml",
    "https://suricata.io/sitemap_index.xml",
    "https://suricata.io/post-sitemap.xml",
    "https://suricata.io/post-sitemap1.xml",
]

# Запасной список страниц, если sitemap недоступен.
FALLBACK_URLS = [
    "https://suricata.io/2026/03/17/suricata-8-0-4-and-7-0-15-released/",
    "https://suricata.io/2026/01/13/suricata-8-0-3-and-7-0-14-released/",
    "https://suricata.io/2025/11/06/suricata-8-0-2-and-7-0-13-released/",
    "https://suricata.io/2025/09/16/suricata-8-0-1-and-7-0-12-released/",
    "https://suricata.io/2025/07/08/suricata-7-0-11-released/",
    "https://suricata.io/2025/03/18/suricata-7-0-9-released/",
    "https://suricata.io/2024/12/12/suricata-7-0-8-released/",
]

# Уязвимости Suricata обычно публикуются в релизных/безопасностных записях.
# Фильтр резко сокращает число HTML-страниц, которые надо открывать после sitemap.
RELEVANT_SLUG_KEYWORDS = (
    "release",
    "released",
    "security",
    "advisory",
    "suricata",
    "cve",
)

_thread_local = threading.local()


def get_session() -> requests.Session:
    session = getattr(_thread_local, "session", None)

    if session is None:
        session = requests.Session()
        session.headers.update(HEADERS)
        adapter = HTTPAdapter(
            pool_connections=MAX_WORKERS * 2,
            pool_maxsize=MAX_WORKERS * 2,
            max_retries=1,
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        _thread_local.session = session

    return session


def cache_path_for_url(url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return CACHE_DIR / f"{digest}.html"


def fetch_text(url: str, *, use_cache: bool = False) -> str | None:
    cache_path = cache_path_for_url(url)

    if use_cache and USE_CACHE and cache_path.exists():
        return cache_path.read_text(encoding="utf-8", errors="ignore")

    try:
        response = get_session().get(url, timeout=REQUEST_TIMEOUT)

        if response.status_code >= 400:
            return None

        text = response.text

        if use_cache and USE_CACHE:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(text, encoding="utf-8")

        return text

    except requests.RequestException:
        return None


def is_suricata_post_url(url: str) -> bool:
    parsed = urlparse(url)

    if parsed.netloc != "suricata.io":
        return False

    return bool(DATE_FROM_URL_PATTERN.search(parsed.path))


def is_relevant_post_url(url: str) -> bool:
    if not is_suricata_post_url(url):
        return False

    path = urlparse(url).path.lower()
    return any(keyword in path for keyword in RELEVANT_SLUG_KEYWORDS)


def get_urls_from_sitemap(sitemap_url: str, visited: set[str] | None = None) -> list[str]:
    if visited is None:
        visited = set()

    if sitemap_url in visited:
        return []

    visited.add(sitemap_url)
    xml_text = fetch_text(sitemap_url)

    if not xml_text:
        return []

    soup = BeautifulSoup(xml_text, "xml")
    loc_values = [loc.get_text(strip=True) for loc in soup.find_all("loc")]

    urls: list[str] = []

    if soup.find("sitemapindex"):
        for child_sitemap_url in loc_values:
            if child_sitemap_url.endswith(".xml"):
                urls.extend(get_urls_from_sitemap(child_sitemap_url, visited))
    else:
        urls.extend(loc_values)

    return urls


def collect_candidate_urls() -> list[str]:
    urls: set[str] = set()

    for sitemap_url in SITEMAP_URLS:
        for url in get_urls_from_sitemap(sitemap_url):
            if is_relevant_post_url(url):
                urls.add(url)

    if not urls:
        urls.update(FALLBACK_URLS)

    return sorted(urls, reverse=True)


def extract_date_from_html_or_url(html: str, url: str) -> str:
    soup = BeautifulSoup(html, "html.parser")

    meta_date = soup.find("meta", attrs={"property": "article:published_time"})
    if meta_date and meta_date.get("content"):
        return datetime.fromisoformat(
            meta_date["content"].replace("Z", "+00:00")
        ).date().isoformat()

    time_tag = soup.find("time")
    if time_tag and time_tag.get("datetime"):
        return datetime.fromisoformat(
            time_tag["datetime"].replace("Z", "+00:00")
        ).date().isoformat()

    match = DATE_FROM_URL_PATTERN.search(url)
    if match:
        year, month, day = match.groups()
        return f"{year}-{month}-{day}"

    return ""


def collect_from_page(url: str) -> tuple[str, str, list[str]] | None:
    html = fetch_text(url, use_cache=True)

    if not html:
        return None

    # Для поиска CVE не нужен полный BeautifulSoup-разбор страницы: регулярное
    # выражение по HTML быстрее. BeautifulSoup запускается только если CVE найдены.
    cve_ids = sorted({cve.upper() for cve in CVE_PATTERN.findall(html)})

    if not cve_ids:
        return None

    release_date = extract_date_from_html_or_url(html, url)
    return url, release_date, cve_ids


def collect_cves() -> list[dict]:
    result_by_id: dict[str, dict] = {}
    urls = collect_candidate_urls()

    print(f"Candidate URLs found: {len(urls)}")
    workers = max(1, min(MAX_WORKERS, len(urls) or 1))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_url = {executor.submit(collect_from_page, url): url for url in urls}

        for future in as_completed(future_to_url):
            page_result = future.result()

            if not page_result:
                continue

            url, release_date, cve_ids = page_result
            print(f"{url} -> {len(cve_ids)} CVE")

            for cve_id in cve_ids:
                result_by_id.setdefault(
                    cve_id,
                    {
                        "ID": cve_id,
                        "vendor_release_date": release_date,
                        "vendor_release_url": url,
                    },
                )

    return sorted(
        result_by_id.values(),
        key=lambda item: (item["vendor_release_date"], item["ID"]),
        reverse=True,
    )


def main() -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    result = collect_cves()

    with OUTPUT_PATH.open("w", encoding="utf-8") as file:
        json.dump(result, file, ensure_ascii=False, indent=2)

    print(f"Collected CVE records: {len(result)}")
    print(f"Saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
