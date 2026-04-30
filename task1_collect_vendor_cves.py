import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


OUTPUT_PATH = Path("data/result_task_1.json")

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
DATE_FROM_URL_PATTERN = re.compile(r"/(\d{4})/(\d{2})/(\d{2})/")

HEADERS = {
    "User-Agent": "Mozilla/5.0 lab2-cve-collector/1.0"
}

SITEMAP_URLS = [
    "https://suricata.io/sitemap.xml",
    "https://suricata.io/sitemap_index.xml",
    "https://suricata.io/post-sitemap.xml",
    "https://suricata.io/post-sitemap1.xml",
]

# Запасной список страниц, если sitemap недоступен
FALLBACK_URLS = [
    "https://suricata.io/2026/03/17/suricata-8-0-4-and-7-0-15-released/",
    "https://suricata.io/2026/01/13/suricata-8-0-3-and-7-0-14-released/",
    "https://suricata.io/2025/11/06/suricata-8-0-2-and-7-0-13-released/",
    "https://suricata.io/2025/09/16/suricata-8-0-1-and-7-0-12-released/",
    "https://suricata.io/2025/07/08/suricata-7-0-11-released/",
    "https://suricata.io/2025/03/18/suricata-7-0-9-released/",
    "https://suricata.io/2024/12/12/suricata-7-0-8-released/",
]


def fetch_text(url: str) -> str | None:
    try:
        response = requests.get(url, headers=HEADERS, timeout=30)

        if response.status_code >= 400:
            return None

        return response.text

    except requests.RequestException:
        return None


def is_suricata_post_url(url: str) -> bool:
    parsed = urlparse(url)

    if parsed.netloc != "suricata.io":
        return False

    # Оставляем только записи вида /YYYY/MM/DD/...
    return bool(DATE_FROM_URL_PATTERN.search(parsed.path))


def get_urls_from_sitemap(sitemap_url: str) -> list[str]:
    xml_text = fetch_text(sitemap_url)

    if not xml_text:
        return []

    soup = BeautifulSoup(xml_text, "xml")
    urls = []

    # Если это индекс sitemap, внутри будут ссылки на другие sitemap
    sitemap_links = [loc.get_text(strip=True) for loc in soup.find_all("loc")]

    for link in sitemap_links:
        if link.endswith(".xml"):
            child_xml = fetch_text(link)
            if not child_xml:
                continue

            child_soup = BeautifulSoup(child_xml, "xml")
            urls.extend(
                loc.get_text(strip=True)
                for loc in child_soup.find_all("loc")
            )
        else:
            urls.append(link)

    return urls


def collect_candidate_urls() -> list[str]:
    urls = set()

    for sitemap_url in SITEMAP_URLS:
        for url in get_urls_from_sitemap(sitemap_url):
            if is_suricata_post_url(url):
                urls.add(url)

    if not urls:
        urls.update(FALLBACK_URLS)

    return sorted(urls, reverse=True)


def clean_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    return soup.get_text(" ", strip=True)


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


def collect_cves() -> list[dict]:
    result_by_id = {}
    urls = collect_candidate_urls()

    print(f"Candidate URLs found: {len(urls)}")

    for url in urls:
        html = fetch_text(url)

        if not html:
            continue

        text = clean_html(html)
        cve_ids = sorted(set(cve.upper() for cve in CVE_PATTERN.findall(text)))

        if not cve_ids:
            continue

        release_date = extract_date_from_html_or_url(html, url)

        print(f"{url} -> {len(cve_ids)} CVE")

        for cve_id in cve_ids:
            if cve_id not in result_by_id:
                result_by_id[cve_id] = {
                    "ID": cve_id,
                    "vendor_release_date": release_date,
                    "vendor_release_url": url,
                }

    return sorted(
        result_by_id.values(),
        key=lambda item: (item["vendor_release_date"], item["ID"]),
        reverse=True,
    )


def main():
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    result = collect_cves()

    with OUTPUT_PATH.open("w", encoding="utf-8") as file:
        json.dump(result, file, ensure_ascii=False, indent=2)

    print(f"Collected CVE records: {len(result)}")
    print(f"Saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()