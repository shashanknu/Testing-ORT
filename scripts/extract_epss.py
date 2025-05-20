import json
import requests
import sys
import os

def extract_cves(advisor_json):
    cves = set()
    for result in advisor_json.get("advisor", {}).get("results", []):
        for vulnerability in result.get("vulnerabilities", []):
            cve_id = vulnerability.get("id")
            if cve_id and cve_id.startswith("CVE-"):
                cves.add(cve_id)
    return list(cves)

def get_epss_score(cve):
    url = f"https://api.first.org/data/v1/epss?cve={cve}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        score_data = data.get("data", [])
        if score_data:
            return {
                "cve": score_data[0].get("cve"),
                "epss": float(score_data[0].get("epss", 0)),
                "percentile": float(score_data[0].get("percentile", 0))
            }
    except Exception as e:
        print(f"Failed to fetch EPSS for {cve}: {e}")
    return {"cve": cve, "epss": None, "percentile": None}

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 extract_epss.py <path_to_advisor-results.json>")
        sys.exit(1)

    advisor_path = sys.argv[1]

    if not os.path.exists(advisor_path):
        print(f"Error: File '{advisor_path}' does not exist.")
        sys.exit(1)

    with open(advisor_path, "r", encoding="utf-8") as f:
        advisor_json = json.load(f)

    cve_list = extract_cves(advisor_json)
    print(f"Found {len(cve_list)} unique CVEs.")

    epss_results = [get_epss_score(cve) for cve in cve_list]

    output_path = "epss-results.json"
    with open(output_path, "w", encoding="utf-8") as out_file:
        json.dump(epss_results, out_file, indent=2)

    print(f"EPSS results written to '{output_path}'.")

if __name__ == "__main__":
    main()

