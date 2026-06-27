from __future__ import annotations

import requests


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cves(keyword: str) -> list[dict]:
    if not keyword.strip():
        return []
    try:
        resp = requests.get(NVD_URL, params={"keywordSearch": keyword, "cvssV3Severity": "HIGH"}, timeout=8)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return [{"id": "NVD-OFFLINE", "summary": f"NVD lookup unavailable: {exc}", "score": None, "severity": "Info"}]
    out = []
    for item in data.get("vulnerabilities", [])[:8]:
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cvss = metrics[key][0]
                break
        score = None
        severity = "Unknown"
        if cvss:
            score = cvss.get("cvssData", {}).get("baseScore")
            severity = cvss.get("cvssData", {}).get("baseSeverity") or cvss.get("baseSeverity", "Unknown")
        out.append(
            {
                "id": cve.get("id"),
                "summary": cve.get("descriptions", [{}])[0].get("value", "No description"),
                "published": cve.get("published"),
                "score": score,
                "severity": severity,
            }
        )
    return out
