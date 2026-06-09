import json
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom import minidom


INPUT_PATH = Path("data/result_task_2.json")
OUTPUT_PATH = Path("data/result_task_3.xml")


FIRST_LEVEL_FIELDS = [
    "ID",
    "vendor_release_date",
    "vendor_release_url",
    "url",
    "published_date",
    "updated_date",
    "description",
]


def safe_text(value) -> str:
    if value is None:
        return ""
    return str(value)


def add_text_element(parent: Element, tag: str, value) -> None:
    element = SubElement(parent, tag)
    element.text = safe_text(value)


def build_xml(data: list[dict]) -> Element:
    root = Element("vulnerabilities")

    for item in data:
        vulnerability = SubElement(root, "vulnerability")

        # Поля 1 уровня
        for field in FIRST_LEVEL_FIELDS:
            add_text_element(vulnerability, field, item.get(field))

        # cvss_list
        cvss_list_element = SubElement(vulnerability, "cvss_list")

        for cvss_item in item.get("cvss_list", []):
            cvss_element = SubElement(
                cvss_list_element,
                "cvss",
                {
                    "version": safe_text(cvss_item.get("version")),
                    "score": safe_text(cvss_item.get("score")),
                    "severity": safe_text(cvss_item.get("severity")),
                },
            )
            cvss_element.text = safe_text(cvss_item.get("vector"))

        # cpe_list
        cpe_list_element = SubElement(vulnerability, "cpe_list")

        for cpe in item.get("cpe_list", []):
            cpe_element = SubElement(cpe_list_element, "cpe")
            cpe_element.text = safe_text(cpe)

        # cwe_list
        cwe_list_element = SubElement(vulnerability, "cwe_list")

        for cwe_id, cwe_data in item.get("cwe", {}).items():
            cwe_element = SubElement(
                cwe_list_element,
                "cwe",
                {
                    "id": safe_text(cwe_id),
                    "name": safe_text(cwe_data.get("name")),
                },
            )
            cwe_element.text = safe_text(cwe_data.get("description"))

    return root


def prettify_xml(root: Element) -> str:
    rough_xml = tostring(root, encoding="utf-8")
    parsed_xml = minidom.parseString(rough_xml)
    return parsed_xml.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")


def main():
    if not INPUT_PATH.exists():
        raise FileNotFoundError(f"Не найден файл {INPUT_PATH}. Сначала выполни задачу 2.")

    with INPUT_PATH.open("r", encoding="utf-8") as file:
        data = json.load(file)

    root = build_xml(data)
    xml_content = prettify_xml(root)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as file:
        file.write(xml_content)

    print(f"Converted records: {len(data)}")
    print(f"Saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
