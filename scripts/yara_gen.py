#!/usr/bin/env python3
"""
binary-forge yara_gen — turn a triage JSON report into a YARA detection rule.

Picks the most distinctive observed strings/indicators, emits a compilable
rule with an exact-hash match clause OR'd with a string-count clause. If the
`yara` CLI is installed, the rule is compile-and-match verified against the
sample automatically.

Usage:
    yara_gen.py <triage.json> [--name RuleName] [--out rule.yar] [--verify <sample>]
"""
import argparse
import json
import os
import re
import subprocess
import sys

# categories whose strings make good YARA signatures, in priority order
PRIORITY = ["ps-encoded", "ransom", "persistence", "keylog", "shell", "miner",
            "cred", "android-sms", "android-a11y", "android-install",
            "net-url", "mutex", "pdb", "injection", "vm-check"]
MIN_LEN, MAX_LEN, MAX_STRINGS = 8, 96, 12
# strings too generic to be signatures
TOO_COMMON = re.compile(r"(?i)^(https?://(www\.)?(microsoft|google|w3\.org|gnu\.org|apache|xiph|python|adobe|mozilla)\.|kernel32|user32|gdi32|advapi32|msvcrt|windows|microsoft corporation|\.pdb$)")


def yara_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def pick_strings(rep):
    picked, seen = [], set()
    cats = rep.get("string_categories", {})
    for cid in PRIORITY:
        for hit in cats.get(cid, {}).get("hits", []):
            h = hit.strip()
            if not (MIN_LEN <= len(h) <= MAX_LEN) or h.lower() in seen:
                continue
            if TOO_COMMON.search(h):
                continue
            if not all(32 <= ord(c) < 127 for c in h):
                continue
            seen.add(h.lower())
            picked.append((cid, h))
            if len(picked) >= MAX_STRINGS:
                return picked
    return picked


def gen_rule(rep, name):
    sha = rep.get("sha256")
    fmt = rep.get("format")
    strings = pick_strings(rep)
    lines = [
        'import "hash"',
        "",
        f"rule {name} {{",
        "    meta:",
        '        author = "binary-forge automated triage"',
        f'        description = "auto-generated from triage verdict: {rep.get("verdict", "unknown")}"',
        f'        sample_sha256 = "{sha}"',
        f'        source_file = "{os.path.basename(rep.get("file", "?"))}"',
        "    strings:",
    ]
    for i, (cid, s) in enumerate(strings, 1):
        lines.append(f'        $s{i} = "{yara_escape(s)}" // {cid}')
    if not strings:
        lines.append("        // no distinctive strings observed — hash-match only")
    n = max(1, (len(strings) * 3) // 4)  # 75% of strings must match
    hash_clause = f'hash.sha256(0, filesize) == "{sha}"'
    cond = f"({hash_clause}) or {n} of ($s*)" if strings else hash_clause
    lines += [
        "    condition:",
        f"        filesize < 50MB and ({cond})",
        "}",
    ]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report", help="triage JSON (single-file report)")
    ap.add_argument("--name", default=None, help="rule name (default: Forge_<sha8>)")
    ap.add_argument("--out", help="write rule to file")
    ap.add_argument("--verify", help="sample path: compile rule + test match if yara CLI exists")
    args = ap.parse_args()

    rep = json.load(open(args.report))
    if "reports" in rep:  # folder report → highest scoring sample
        rep = rep["reports"][0]
        print(f"# folder report: using top-ranked sample {rep.get('file')}", file=sys.stderr)
    name = args.name or ("Forge_" + (rep.get("sha256") or "sample")[:8])
    rule = gen_rule(rep, name)
    if args.out:
        open(args.out, "w").write(rule)
        print(f"wrote {args.out}")
    else:
        print(rule)
    if args.verify:
        if not os.path.exists(args.verify):
            print(f"verify: sample not found: {args.verify}", file=sys.stderr)
            return 2
        path = args.out or "/tmp/_forge_rule.yar"
        if not args.out:
            open(path, "w").write(rule)
        # verification path 1: yara CLI
        if subprocess.run(["which", "yara"], capture_output=True).returncode == 0:
            r = subprocess.run(["yara", "-w", path, args.verify], capture_output=True, text=True)
            if r.returncode == 0 and name in (r.stdout or ""):
                print(f"VERIFIED: rule compiles and matches {args.verify} (yara CLI)")
                return 0
            print(f"yara result rc={r.returncode}: {r.stdout or r.stderr}", file=sys.stderr)
            return 1
        # verification path 2: yara-python
        try:
            import yara
            rules = yara.compile(filepath=path)
            m = rules.match(args.verify)
            if m:
                print(f"VERIFIED: rule compiles and matches {args.verify} (yara-python)")
                return 0
            print("rule compiled but did NOT match sample", file=sys.stderr)
            return 1
        except ImportError:
            print("no yara CLI and no yara-python — rule emitted but not compile-checked")
        except Exception as e:
            print(f"yara-python error: {e}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
