import io
import json
import os
import re
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from xml.etree import ElementTree as ET

import requests
from requests.adapters import HTTPAdapter


INPUT_PATH = Path("data/result_task_1.json")
OUTPUT_PATH = Path("data/result_task_2.json")

CACHE_DIR = Path("data/cache")
CVE_CACHE_DIR = CACHE_DIR / "cve_records"
CWE_CACHE_PATH = CACHE_DIR / "cwe_catalog.json"

CVE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
CVE_ORG_URL = "https://www.cve.org/CVERecord?id={cve_id}"
CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)
CPE_PATTERN = re.compile(r"^cpe:(?:/|2\.3:)", re.IGNORECASE)

MAX_WORKERS = int(os.getenv("LAB2_MAX_WORKERS", "8"))
REQUEST_TIMEOUT = int(os.getenv("LAB2_REQUEST_TIMEOUT", "30"))
USE_CACHE = os.getenv("LAB2_DISABLE_CACHE", "0") != "1"

HEADERS = {
    "User-Agent": "lab2-cve-enricher/2.0"
}

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


def request_json(url: str) -> dict | None:
    for attempt in range(5):
        try:
            response = get_session().get(url, timeout=REQUEST_TIMEOUT)

            if response.status_code == 404:
                return None

            if response.status_code == 429 or response.status_code >= 500:
                time.sleep(1.5 * (attempt + 1))
                continue

            response.raise_for_status()
            return response.json()

        except requests.RequestException:
            if attempt == 4:
                raise
            time.sleep(1.5 * (attempt + 1))

    return None


def request_cve_record(cve_id: str) -> dict | None:
    cache_path = CVE_CACHE_DIR / f"{cve_id}.json"

    if USE_CACHE and cache_path.exists():
        with cache_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    record = request_json(CVE_API_URL.format(cve_id=cve_id))

    if record and USE_CACHE:
        CVE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with cache_path.open("w", encoding="utf-8") as file:
            json.dump(record, file, ensure_ascii=False)

    return record


def normalize_date(value: str | None) -> str | None:
    if not value:
        return None

    return value.replace("Z", "+00:00")


def get_english_description(descriptions: list[dict]) -> str | None:
    if not descriptions:
        return None

    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value")

    return descriptions[0].get("value")


def get_all_containers(record: dict) -> list[dict]:
    containers = record.get("containers", {})
    result = []

    cna = containers.get("cna")
    if isinstance(cna, dict):
        result.append(cna)

    adp = containers.get("adp", [])
    if isinstance(adp, list):
        result.extend(item for item in adp if isinstance(item, dict))
    elif isinstance(adp, dict):
        result.append(adp)

    return result


def normalize_cvss_version(key: str, cvss_data: dict) -> str:
    version = cvss_data.get("version")

    if version:
        return "cvss" + version.replace(".", "")

    mapping = {
        "cvssV4_0": "cvss40",
        "cvssV3_1": "cvss31",
        "cvssV3_0": "cvss30",
        "cvssV2_0": "cvss20",
    }

    return mapping.get(key, key.replace("cvssV", "cvss").replace("_", ""))


def extract_cvss_list(record: dict) -> list[dict]:
    cvss_items = []
    seen = set()

    for container in get_all_containers(record):
        for metric in container.get("metrics", []):
            if not isinstance(metric, dict):
                continue

            for key, value in metric.items():
                if not key.startswith("cvssV") or not isinstance(value, dict):
                    continue

                item = {
                    "version": normalize_cvss_version(key, value),
                    "score": value.get("baseScore"),
                    "vector": value.get("vectorString"),
                    "severity": value.get("baseSeverity") or value.get("severity"),
                }

                unique_key = (
                    item["version"],
                    item["score"],
                    item["vector"],
                    item["severity"],
                )

                if unique_key not in seen:
                    seen.add(unique_key)
                    cvss_items.append(item)

    return cvss_items


def add_cpe_if_valid(result: set[str], value) -> None:
    if isinstance(value, str):
        value = value.strip()
        if CPE_PATTERN.match(value):
            result.add(value)


def walk_cpe_applicability(value, result: set[str]) -> None:
    """Extract CPE values only from the CVE API cpeApplicability structure.

    CVE Record Format 5.1.1+ supports CPE Applicability Language. In this
    structure the CPE is commonly stored in cpeMatch[].criteria. Some feeds or
    older examples may use cpe23Uri/cpe22Uri/cpeName, so these fields are also
    handled.
    """

    if isinstance(value, dict):
        for key in ("criteria", "cpe23Uri", "cpe22Uri", "cpeName", "cpe"):
            add_cpe_if_valid(result, value.get(key))

        for nested_value in value.values():
            if isinstance(nested_value, (dict, list)):
                walk_cpe_applicability(nested_value, result)

    elif isinstance(value, list):
        for item in value:
            walk_cpe_applicability(item, result)


def extract_cpe_list(record: dict) -> list[str]:
    """Collect CPE values provided by the CVE API.

    The previous variant walked through the whole JSON and picked any string
    beginning with "cpe:". This worked accidentally, but did not show where the
    data comes from. Here CPEs are taken from the documented API structures:
    1) containers.*.affected[].cpes[]
    2) containers.*.cpeApplicability[].nodes[].cpeMatch[].criteria
    """

    result: set[str] = set()

    for container in get_all_containers(record):
        for affected_item in container.get("affected", []):
            if not isinstance(affected_item, dict):
                continue

            for cpe in affected_item.get("cpes", []):
                add_cpe_if_valid(result, cpe)

        cpe_applicability = container.get("cpeApplicability", [])
        walk_cpe_applicability(cpe_applicability, result)

    return sorted(result)


def download_cwe_catalog() -> dict:
    if USE_CACHE and CWE_CACHE_PATH.exists():
        with CWE_CACHE_PATH.open("r", encoding="utf-8") as file:
            return json.load(file)

    response = get_session().get(CWE_XML_URL, timeout=60)
    response.raise_for_status()

    catalog = {}

    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        xml_name = next(name for name in archive.namelist() if name.endswith(".xml"))

        with archive.open(xml_name) as xml_file:
            tree = ET.parse(xml_file)
            root = tree.getroot()

    for weakness in root.findall(".//{*}Weakness"):
        cwe_id = "CWE-" + weakness.attrib.get("ID", "")
        name = weakness.attrib.get("Name")

        description_node = weakness.find("{*}Description")
        description = (
            description_node.text.strip()
            if description_node is not None and description_node.text
            else ""
        )

        if cwe_id != "CWE-":
            catalog[cwe_id] = {
                "name": name,
                "description": description,
            }

    if USE_CACHE:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with CWE_CACHE_PATH.open("w", encoding="utf-8") as file:
            json.dump(catalog, file, ensure_ascii=False)

    return catalog


def extract_cwe_ids(record: dict) -> set[str]:
    cwe_ids = set()

    for container in get_all_containers(record):
        for problem_type in container.get("problemTypes", []):
            descriptions = problem_type.get("descriptions", [])

            for description in descriptions:
                cwe_id = description.get("cweId")

                if cwe_id and CWE_PATTERN.fullmatch(cwe_id):
                    cwe_ids.add(cwe_id.upper())
                    continue

                text = description.get("description", "")
                for found in CWE_PATTERN.findall(text):
                    cwe_ids.add(found.upper())

    return cwe_ids


def build_cwe_object(record: dict, cwe_catalog: dict) -> dict:
    result = {}

    for cwe_id in sorted(extract_cwe_ids(record)):
        catalog_item = cwe_catalog.get(cwe_id, {})

        result[cwe_id] = {
            "name": catalog_item.get("name") or cwe_id,
            "description": catalog_item.get("description") or "",
        }

    return result


def build_empty_enriched(item: dict) -> dict:
    cve_id = item["ID"]

    return {
        "ID": cve_id,
        "vendor_release_date": item.get("vendor_release_date"),
        "vendor_release_url": item.get("vendor_release_url"),
        "url": CVE_ORG_URL.format(cve_id=cve_id),
        "published_date": None,
        "updated_date": None,
        "description": None,
        "cvss_list": [],
        "cpe_list": [],
        "cwe": {},
    }


def enrich_item(item: dict, cwe_catalog: dict) -> dict:
    cve_id = item["ID"]
    enriched = build_empty_enriched(item)

    record = request_cve_record(cve_id)

    if not record:
        print(f"[WARN] CVE not found in API: {cve_id}")
        return enriched

    metadata = record.get("cveMetadata", {})
    containers = get_all_containers(record)

    enriched["published_date"] = normalize_date(metadata.get("datePublished"))
    enriched["updated_date"] = normalize_date(metadata.get("dateUpdated"))

    for container in containers:
        description = get_english_description(container.get("descriptions", []))
        if description:
            enriched["description"] = description
            break

    enriched["cvss_list"] = extract_cvss_list(record)
    enriched["cpe_list"] = extract_cpe_list(record)
    enriched["cwe"] = build_cwe_object(record, cwe_catalog)

    return enriched


def main() -> None:
    if not INPUT_PATH.exists():
        raise FileNotFoundError(f"Не найден файл {INPUT_PATH}. Сначала выполни задачу 1.")

    with INPUT_PATH.open("r", encoding="utf-8") as file:
        source_items = json.load(file)

    print("Loading CWE catalog...")
    cwe_catalog = download_cwe_catalog()

    result: list[dict | None] = [None] * len(source_items)
    workers = max(1, min(MAX_WORKERS, len(source_items) or 1))

    print(f"Enriching {len(source_items)} CVE records with {workers} workers...")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_index = {
            executor.submit(enrich_item, item, cwe_catalog): index
            for index, item in enumerate(source_items)
        }

        for done_count, future in enumerate(as_completed(future_to_index), start=1):
            index = future_to_index[future]
            item = source_items[index]

            try:
                result[index] = future.result()
                print(f"[{done_count}/{len(source_items)}] Done {item['ID']}")
            except Exception as exc:
                print(f"[WARN] Failed to enrich {item['ID']}: {exc}")
                result[index] = build_empty_enriched(item)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as file:
        json.dump(result, file, ensure_ascii=False, indent=2)

    print(f"Saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
