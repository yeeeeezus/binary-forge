#!/usr/bin/env python3
"""
binary-forge make_iocs — extract an IOC table from a triage JSON report.

Every IOC traces to an observed string or structural fact in the analyzed
sample. Output: CSV (spreadsheet-ready) + JSON (SIEM/tooling-ready), with
type, value, context and confidence.

Usage:
    make_iocs.py <triage.json> [--out-prefix iocs]   # writes iocs.csv + iocs.json
"""
import argparse
import csv
import datetime
import json
import re
import sys

CONF = {"ransom": "high", "keylog": "high", "persistence": "high", "ps-encoded": "high",
        "shell": "high", "miner": "medium", "cred": "high", "net-url": "medium",
        "ipv4": "low", "mutex": "medium", "pdb": "medium", "injection": "high",
        "android-sms": "high", "android-a11y": "high", "android-install": "medium",
        "vm-check": "low", "anti-debug": "medium"}

TYPE_MAP = {"net-url": "url", "ipv4": "ipv4-addr", "mutex": "mutex",
            "pdb": "pdb-path", "persistence": "registry-run-key",
            "shell": "shell-command", "ps-encoded": "encoded-command",
            "injection": "windows-api", "ransom": "ransomware-artifact",
            "keylog": "keylogger-api", "miner": "mining-indicator",
            "cred": "credential-artifact", "android-sms": "android-permission",
            "android-a11y": "android-permission", "android-install": "android-permission"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--out-prefix", default="iocs")
    args = ap.parse_args()

    rep = json.load(open(args.report))
    if "reports" in rep:
        rows = []
        for r in rep["reports"]:
            rows.extend(extract(r))
    else:
        rows = extract(rep)

    seen, deduped = set(), []
    for r in rows:
        key = (r["type"], r["value"].lower())
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    csv_path, json_path = args.out_prefix + ".csv", args.out_prefix + ".json"
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["type", "value", "context", "confidence", "source_sha256", "observed_utc"])
        for r in deduped:
            w.writerow([r["type"], r["value"], r["context"], r["confidence"], r["source_sha256"], r["observed"]])
    with open(json_path, "w") as f:
        json.dump({"generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   "sample": {"file": rep.get("file"), "sha256": rep.get("sha256"),
                              "verdict": rep.get("verdict")},
                   "indicators": deduped}, f, indent=2)
    print(f"wrote {csv_path} ({len(deduped)} IOCs) and {json_path}")
    for r in deduped[:15]:
        print(f"  confidence={r['confidence']:<6} type={r['type']:<22} value={r['value'][:70]}")
    return 0


def extract(rep):
    out = []
    sha = rep.get("sha256", "")
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cats = rep.get("string_categories", {})
    for cid, c in cats.items():
        typ = TYPE_MAP.get(cid)
        conf = CONF.get(cid, "low")
        if not typ:
            continue
        for h in c.get("hits", []):
            h = h.strip()
            if typ == "url":
                dom = re.match(r"https?://([^/:]+)", h)
                if dom:
                    out.append({"type": "domain-name", "value": dom.group(1), "context": f"observed in {cid} URL: {h[:60]}", "confidence": "medium", "source_sha256": sha, "observed": now})
            out.append({"type": typ, "value": h[:120], "context": f"string category: {cid} ({c.get('label','')})", "confidence": conf, "source_sha256": sha, "observed": now})
    for h in ({"type": "sha256", "value": sha} if sha else []),:
        if h:
            out.append({"type": "file-hash-sha256", "value": h["value"], "context": "analyzed sample", "confidence": "fact", "source_sha256": sha, "observed": now})
    for i in rep.get("indicators", []):
        if i["id"] == "packer-section":
            out.append({"type": "packer", "value": i["evidence"][0] if i["evidence"] else "packed section", "context": "high-entropy/packer section", "confidence": "medium", "source_sha256": sha, "observed": now})
    return out


if __name__ == "__main__":
    sys.exit(main() or 0)
