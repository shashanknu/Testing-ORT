import os
import json
import requests
import sys

def extract_cves_and_cvss(advisor_json):
    cves = []
    for result in advisor_json.get("advisor", {}).get("results", []):
        for vulnerability in result.get("vulnerabilities", []):
            cve_id = vulnerability.get("id")
            if cve_id and cve_id.startswith("CVE-"):
                cves.append(cve_id)
    return list(set(cves))

def fetch_epss_scores(cve_ids):
    url = "https://api.first.org/data/v1/epss"
    params = {"cve": ",".join(cve_ids)}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json().get("data", [])
    else:
        print(f"Error fetching EPSS scores: {response.status_code}")
        return []

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 extract_epss.py <advisor-results.json>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_dir = "tools/epss"
    os.makedirs(output_dir, exist_ok=True)

    with open(input_path, "r") as f:
        advisor_data = json.load(f)

    cve_ids = extract_cves_and_cvss(advisor_data)
    epss_data = fetch_epss_scores(cve_ids)

    with open(os.path.join(output_dir, "epss-results.json"), "w") as f:
        json.dump(epss_data, f, indent=2)

    print(f"EPSS results written to {os.path.join(output_dir, 'epss-results.json')}")

if __name__ == "__main__":
    main()
