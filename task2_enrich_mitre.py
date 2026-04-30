import io
import json
import re
import time
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

import requests


INPUT_PATH = Path("data/result_task_1.json")
OUTPUT_PATH = Path("data/result_task_2.json")

CVE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
CVE_ORG_URL = "https://www.cve.org/CVERecord?id={cve_id}"
CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)

HEADERS = {
    "User-Agent": "lab2-cve-enricher/1.0"
}


def request_json(url: str) -> dict | None:
    for attempt in range(3):
        response = requests.get(url, headers=HEADERS, timeout=30)

        if response.status_code == 404:
            return None

        if response.status_code == 429:
            time.sleep(3 + attempt)
            continue

        response.raise_for_status()
        return response.json()

    return None


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
                if not key.startswith("cvssV"):
                    continue

                if not isinstance(value, dict):
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


def extract_cpe_list(obj) -> list[str]:
    result = set()

    def walk(value):
        if isinstance(value, dict):
            for dict_value in value.values():
                walk(dict_value)

        elif isinstance(value, list):
            for list_value in value:
                walk(list_value)

        elif isinstance(value, str) and value.startswith("cpe:"):
            result.add(value)

    walk(obj)
    return sorted(result)


def download_cwe_catalog() -> dict:
    response = requests.get(CWE_XML_URL, headers=HEADERS, timeout=60)
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
        description = description_node.text.strip() if description_node is not None and description_node.text else ""

        if cwe_id != "CWE-":
            catalog[cwe_id] = {
                "name": name,
                "description": description,
            }

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


def enrich_item(item: dict, cwe_catalog: dict) -> dict:
    cve_id = item["ID"]
    api_url = CVE_API_URL.format(cve_id=cve_id)

    record = request_json(api_url)

    enriched = {
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


def main():
    if not INPUT_PATH.exists():
        raise FileNotFoundError(f"Не найден файл {INPUT_PATH}. Сначала выполни задачу 1.")

    with INPUT_PATH.open("r", encoding="utf-8") as file:
        source_items = json.load(file)

    print("Downloading CWE catalog...")
    cwe_catalog = download_cwe_catalog()

    result = []

    for index, item in enumerate(source_items, start=1):
        print(f"[{index}/{len(source_items)}] Enriching {item['ID']}")
        result.append(enrich_item(item, cwe_catalog))
        time.sleep(0.3)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as file:
        json.dump(result, file, ensure_ascii=False, indent=2)

    print(f"Saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()