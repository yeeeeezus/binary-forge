#!/usr/bin/env python3
"""
binary-forge triage — static malware triage for unknown files/bins/APKs.

Pure Python 3 stdlib. Never executes the sample. Read-only analysis:
hashes, format identification, PE/ELF/Mach-O/APK structure, section entropy,
imports, entry-point location, categorized strings, packer heuristics, and a
scored verdict where every point traces to observed evidence.

Usage:
    triage.py <file-or-folder> [--json] [--out report.json]
    triage.py <file>             # human-readable summary
"""
import argparse
import datetime
import hashlib
import json
import math
import os
import re
import struct
import sys
import zipfile

MAX_SCAN = 200 * 1024 * 1024  # bytes read for parsing/strings (hashes use full stream)
MAX_STRINGS = 4000

# ----------------------------------------------------------------------------
# string categories: (id, regex-on-bytes, points, label)
# byte-regexes so they match both ascii and can be applied to raw data
# ----------------------------------------------------------------------------
STRING_SIGS = [
    ("net-url",        rb"https?://[^\s\"'<>]{4,}", 1, "network URL"),
    ("ipv4",           rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0, "IPv4 address"),
    ("shell",          rb"(?i)(cmd\.exe|/bin/(ba)?sh|powershell(\.exe)?|cmd /c|/c del |%COMSPEC%)", 3, "shell invocation"),
    ("ps-encoded",     rb"(?i)powershell[^\x00]{0,24}-(e|enc|ew|w)\b", 4, "encoded PowerShell"),
    ("persistence",    rb"(?i)(CurrentVersion\\\\?Run|schtasks.{0,20}/create|sc\s+create|Startup\\\\|Atastartup)", 3, "persistence mechanism"),
    ("injection",      rb"(?i)(VirtualAlloc(Ex)?|WriteProcessMemory|CreateRemoteThread(Ex)?|SetWindowsHookEx|NtMapViewOfSection|QueueUserAPC)", 2, "process-injection API"),
    ("anti-debug",     rb"(?i)(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugStringA|OLLYDBG)", 2, "anti-debug check"),
    ("vm-check",       rb"(?i)(vbox|vmware|qemu|virtualbox|sandboxie|xendetect| GENERIC_Sandbox)", 1, "VM/sandbox check"),
    ("ransom",         rb"(?i)(ransom|README_RESTORE|\.locked|restore_your_files|encrypt.{0,16}files|bitcoin.{0,32}(wallet|restore))", 4, "ransomware marker"),
    ("keylog",         rb"(?i)(GetAsyncKeyState|keylog|OpenClipboard|GetClipboardData|ClipboardMonitor)", 3, "keylogger/clipboard capture"),
    ("miner",          rb"(?i)(xmrig|stratum\+tcp|monero|pool\.(minergate|nanopool)|cryptonight)", 2, "cryptominer marker"),
    ("cred",           rb"(?i)(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|wallet\.dat|Login Data|lsass|SAM\.hive)", 2, "credential/secret material"),
    ("pdb",            rb"[A-Za-z]:\\[^\x00]{2,120}\.pdb|/[a-z0-9_/.-]{2,120}\.pdb", 0, "PDB build path (IOC)"),
    ("mutex",          rb"(?i)(Global\\\\|BaseNamedObjects\\\\|Local\\\\.{4,64}Mutex)", 0, "named mutex (IOC)"),
    ("android-sms",    rb"(?i)(READ_SMS|SEND_SMS|RECEIVE_SMS|SMS_RECEIVED)", 3, "Android SMS abuse permission"),
    ("android-install",rb"(?i)(REQUEST_INSTALL_PACKAGES|INSTALL_PACKAGES|PACKAGE_INSTALLER)", 2, "Android sideload permission"),
    ("android-a11y",   rb"(?i)(AccessibilityService|BIND_ACCESSIBILITY_SERVICE|android\.permission\.SYSTEM_ALERT_WINDOW)", 2, "Android accessibility overlay abuse"),
]

# section names that indicate known packers
PACKER_SECTIONS = re.compile(rb"(?i)^(upx[01]|\.aspack|\.adata|\.themida|\.vmp[0-3]|\.nsp[0-2]|\.enigma[01]?|\.petite|\.nnp|\.UPX!)$")
SECTION_NAME_ENTROPY_CAP = 6  # max points from entropy across sections


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    h = 0.0
    for c in freq:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return round(h, 3)


def extract_strings(data: bytes, limit: int = MAX_STRINGS):
    """ASCII + UTF-16LE strings as list of str, capped."""
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{5,}", data):
        out.append(m.group().decode("ascii", "replace"))
        if len(out) >= limit:
            return out
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){5,}", data):
        out.append(m.group().decode("utf-16-le", "replace"))
        if len(out) >= limit:
            break
    return out


def categorize_strings(strings):
    """returns {category_id: {label, points, hits:[str]}}"""
    cats = {}
    joined = "\n".join(strings).encode("utf-8", "replace")
    for cid, rx, pts, label in STRING_SIGS:
        hits = []
        for m in re.finditer(rx, joined):
            hits.append(m.group().decode("ascii", "replace")[:120])
            if len(hits) >= 12:
                break
        if hits:
            cats[cid] = {"label": label, "points": pts, "hits": hits}
    return cats


# ----------------------------------------------------------------------------
# PE parsing
# ----------------------------------------------------------------------------
MACHINES = {0x014c: "x86", 0x8664: "x64", 0x01c0: "ARM", 0xAA64: "ARM64", 0x0000: "unknown"}
SUBSYSTEMS = {1: "native", 2: "GUI", 3: "console", 9: "CE GUI", 10: "EFI", 14: "Xbox"}


def rva_to_offset(rva, sections):
    for s in sections:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
            if s["rawptr"] == 0:
                return None
            off = s["rawptr"] + (rva - s["vaddr"])
            return off if off < 10**12 else None
    return None


def parse_pe(data):
    info = {"type": "PE"}
    try:
        if data[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        machine, nsec, tstamp, _sym, _symn, opt_size, _chars = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
        info["machine"] = MACHINES.get(machine, hex(machine))
        info["compiled"] = datetime.datetime.fromtimestamp(tstamp, datetime.timezone.utc).isoformat().replace("+00:00", "Z") if tstamp else None
        opt_off = e_lfanew + 24
        magic = struct.unpack_from("<H", data, opt_off)[0]
        pe32p = magic == 0x20B
        info["magic"] = "PE32+" if pe32p else "PE32"
        entry_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        subsystem = struct.unpack_from("<H", data, opt_off + (68 if pe32p else 68))[0]
        info["subsystem"] = SUBSYSTEMS.get(subsystem, str(subsystem))
        # data directories
        dd_off = opt_off + (112 if pe32p else 96)
        dd_count = struct.unpack_from("<I", data, opt_off + (108 if pe32p else 92))[0]
        dirs = []
        for i in range(min(dd_count, 16)):
            rva, size = struct.unpack_from("<II", data, dd_off + i * 8)
            dirs.append((rva, size))
        sec_off = opt_off + opt_size
        sections = []
        for i in range(min(nsec, 96)):
            base = sec_off + i * 40
            if base + 40 > len(data):
                break
            name = data[base:base + 8].rstrip(b"\x00")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
            ent = shannon_entropy(data[rawptr:rawptr + rawsize]) if rawsize and rawptr + rawsize <= len(data) and rawptr < len(data) else None
            sections.append({
                "name": name.decode("ascii", "replace"),
                "vsize": vsize, "vaddr": vaddr, "rawsize": rawsize, "rawptr": rawptr,
                "entropy": ent,
            })
        info["sections"] = sections
        # entry section
        esec = None
        for idx, s in enumerate(sections):
            if s["vaddr"] <= entry_rva < s["vaddr"] + max(s["vsize"], 1):
                esec = (idx, s)
                break
        info["entry_rva"] = hex(entry_rva)
        info["entry_section"] = {"index": esec[0], "name": esec[1]["name"]} if esec else None
        # imports
        imports = {}
        if len(dirs) > 1 and dirs[1][0]:
            off = rva_to_offset(dirs[1][0], sections)
            desc_i = 0
            while off is not None and off + 20 <= len(data) and desc_i < 256:
                oft, _td, _fc, name_rva, ft = struct.unpack_from("<IIIII", data, off + desc_i * 20)
                if oft == 0 and name_rva == 0 and ft == 0:
                    break
                noff = rva_to_offset(name_rva, sections)
                dll = b""
                if noff is not None:
                    end = data.find(b"\x00", noff)
                    dll = data[noff:end if 0 < end - noff < 64 else noff + 32]
                thunk_rva = oft or ft
                toff = rva_to_offset(thunk_rva, sections)
                funcs = []
                j = 0
                while toff is not None and j < 4096:
                    step = 8 if pe32p else 4
                    if toff + j * step + step > len(data):
                        break
                    (val,) = struct.unpack_from("<Q" if pe32p else "<I", data, toff + j * step)
                    if val == 0:
                        break
                    if val & (0x8000000000000000 if pe32p else 0x80000000):
                        funcs.append(f"ord#{val & 0xFFFF}")
                    else:
                        foff = rva_to_offset(val, sections)
                        if foff is not None and foff + 2 < len(data):
                            end = data.find(b"\x00", foff + 2)
                            fn = data[foff + 2:end if 0 < end - foff - 2 < 64 else foff + 34]
                            funcs.append(fn.decode("ascii", "replace"))
                    j += 1
                if dll:
                    imports[dll.decode("ascii", "replace")] = funcs
                desc_i += 1
        info["imports"] = imports
        # .NET?
        info["dotnet"] = bool(len(dirs) > 14 and dirs[14][0] != 0)
        # signature + resources presence
        info["signed_dir"] = bool(len(dirs) > 4 and dirs[4][0] != 0 and dirs[4][1] > 0)
        info["has_resources"] = bool(len(dirs) > 2 and dirs[2][0] != 0)
        return info
    except Exception as e:  # malformed PE — report what we got
        info["parse_error"] = str(e)[:100]
        return info


# ----------------------------------------------------------------------------
# ELF parsing
# ----------------------------------------------------------------------------
ELF_MACHines = {3: "x86", 62: "x86_64", 40: "ARM", 183: "AArch64", 20: "PowerPC", 243: "RISC-V"}


def parse_elf(data):
    try:
        if data[:4] != b"\x7fELF":
            return None
        info = {"type": "ELF", "class": "64" if data[4] == 2 else "32",
                "endian": "LE" if data[5] == 1 else "BE"}
        end = "<" if data[5] == 1 else ">"
        (etype, machine, _ver, entry, _phoff, shoff, _flags, _ehsize, _phentsize, _phnum,
         shentsize, shnum, shstrndx) = struct.unpack_from(end + "HHIQQQIHHHHHH", data, 16)
        info["machine"] = ELF_MACHines.get(machine, machine)
        info["elf_type"] = {2: "EXEC", 3: "DYN(PIE)", 4: "CORE"}.get(etype, etype)
        info["entry"] = hex(entry)
        sections, shstr = [], b""
        if shoff and shnum and shoff + shnum * shentsize <= len(data):
            raw_shstr = struct.unpack_from(end + "IIQQQQIIQQ", data, shoff + shstrndx * shentsize)
            off = raw_shstr[4]
            shstr = data[off:off + raw_shstr[5]] if raw_shstr[5] else b""
        for i in range(min(shnum, 128)):
            base = shoff + i * shentsize
            if base + shentsize > len(data):
                break
            (nameoff, _type, _flags, _addr, offset, size) = struct.unpack_from(end + "IIQQQQ", data, base)[:6]
            nm_end = shstr.find(b"\x00", nameoff) if shstr else -1
            nm = shstr[nameoff:nm_end if nm_end > 0 else nameoff + 24].decode("ascii", "replace")
            ent = shannon_entropy(data[offset:offset + size]) if size and offset + size <= len(data) else None
            sections.append({"name": nm, "size": size, "offset": offset, "entropy": ent})
        info["sections"] = sections
        # undefined dynamic symbols = imports
        dyn, dynstr, dynsyms = None, None, []
        for s in sections:
            if s["name"] == ".dynsym":
                dyn = s
            elif s["name"] == ".dynstr":
                dynstr = s
        if dyn and dynstr and dynstr["offset"] + dynstr["size"] <= len(data):
            strtab = data[dynstr["offset"]:dynstr["offset"] + dynstr["size"]]
            entsize = 24 if info["class"] == "64" else 16
            n = dyn["size"] // entsize
            for i in range(min(n, 8192)):
                base = dyn["offset"] + i * entsize
                if base + entsize > len(data):
                    break
                if info["class"] == "64":
                    _nm, _info, _other, _shndx, _val, _sz = struct.unpack_from(end + "IBBHQQ", data, base)
                else:
                    _nm, _val, _sz, _info, _other, _shndx = struct.unpack_from(end + "IIIBBH", data, base)
                if _shndx == 0 and _nm < len(strtab):  # UND
                    e = strtab.find(b"\x00", _nm)
                    nm = strtab[_nm:e if 0 < e - _nm < 64 else _nm + 32]
                    if nm:
                        dynsyms.append(nm.decode("ascii", "replace"))
        info["imports"] = dynsyms[:600]
        info["static"] = not any(s["name"] == ".dynsym" and s["size"] for s in sections) or \
                         not any(s["name"] == ".interp" for s in sections)
        info["stripped"] = not any(s["name"] in (".symtab", ".debug_info") for s in sections)
        return info
    except Exception as e:
        return {"type": "ELF", "parse_error": str(e)[:100]}


# ----------------------------------------------------------------------------
# Mach-O / APK / JAR / WASM / DEX
# ----------------------------------------------------------------------------
def parse_macho(data):
    magics = {b"\xfe\xed\xfa\xce": "Mach-O 32 BE", b"\xfe\xed\xfa\xcf": "Mach-O 64 BE",
              b"\xce\xfa\xed\xfe": "Mach-O 32 LE", b"\xcf\xfa\xed\xfe": "Mach-O 64 LE",
              b"\xca\xfe\xba\xbe": "Fat/universal binary"}
    for m, label in magics.items():
        if data[:4] == m:
            info = {"type": label}
            if m != b"\xca\xfe\xba\xbe":
                (cputype, _cpusub, filetype, ncmds) = struct.unpack_from(">IIII" if "BE" in label else "<IIII", data, 4)
                info["cputype"] = {7: "x86", 0x0100000C: "ARM64", 12: "ARM"}.get(cputype, hex(cputype))
                info["filetype"] = {2: "executable", 6: "dylib", 8: "bundle"}.get(filetype, filetype)
                info["load_commands"] = ncmds
            return info
    return None


def parse_apk(data, path):
    try:
        if not zipfile.is_zipfile(path):
            return None
        info = {"type": "APK" if path.lower().endswith((".apk", ".apks", ".xapk")) else "JAR/ZIP app"}
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
        info["entries"] = len(names)
        info["dex_files"] = [n for n in names if re.match(r"classes\d*\.dex$", n)]
        info["native_libs"] = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.endswith(".so")})
        info["has_manifest"] = "AndroidManifest.xml" in names
        info["has_arsc"] = "resources.arsc" in names
        info["assets"] = [n for n in names if n.startswith("assets/")][:40]
        return info
    except Exception as e:
        return {"type": "APK", "parse_error": str(e)[:100]}


def detect_format(path, data):
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    if data[:4] == b"\x00asm":
        return "wasm"
    if path.lower().endswith((".apk", ".apks", ".xapk", ".jar")) and data[:2] == b"PK":
        return "apk"
    if data[:4] == b"dex\n":
        return "dex"
    if data[:4] == b"\xca\xfe\xba\xbe" and data[4:5] == b"\x00":  # java class (minor 0)
        return "javaclass"
    if data[:2] == b"PK":
        return "zip"
    return "raw"


# ----------------------------------------------------------------------------
# scoring
# ----------------------------------------------------------------------------
def score_sample(rep):
    indicators = []

    def add(iid, pts, evidence):
        indicators.append({"id": iid, "points": pts, "evidence": [str(e)[:160] for e in evidence[:6]]})

    pe = rep.get("pe")
    if pe:
        secs = pe.get("sections", [])
        for s in secs:
            if PACKER_SECTIONS.match(s["name"].encode()):
                add("packer-section", 3, [f"section {s['name']}"])
        ent_pts = 0
        for s in secs:
            if s["entropy"] is not None and s["rawsize"] > 0x400:
                if s["entropy"] > 7.5:
                    ent_pts += 3
                elif s["entropy"] > 7.2:
                    ent_pts += 2
        ent_pts = min(ent_pts, SECTION_NAME_ENTROPY_CAP)
        if ent_pts:
            hi = [f"{s['name']} H={s['entropy']}" for s in secs if s["entropy"] and s["entropy"] > 7.2]
            add("high-entropy", ent_pts, hi)
        if pe.get("entry_section") and secs:
            es = pe["entry_section"]
            if es["index"] == len(secs) - 1 and es["name"].lower() not in (".text", "code"):
                add("entry-in-last-section", 2, [f"entry at section[{es['index']}]={es['name']}"])
        imps = pe.get("imports", {})
        allfuncs = [f for fs in imps.values() for f in fs]
        if imps and len(allfuncs) <= 12 and set(k.lower() for k in imps) <= {"kernel32.dll", "kernel32"}:
            add("skeleton-imports", 2, [f"{len(allfuncs)} imports, only kernel32: {', '.join(allfuncs[:8])}"])
        loader = {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress", "VirtualAlloc"}
        if loader & set(allfuncs) and len(loader & set(allfuncs)) >= 3:
            add("dynamic-resolver-combo", 3, sorted(loader & set(allfuncs)))
    cats = rep.get("string_categories", {})
    for cid, c in cats.items():
        if c["points"]:
            add(f"str:{cid}", c["points"], c["hits"])
    apk = rep.get("apk")
    if apk and apk.get("has_manifest"):
        if not apk.get("dex_files"):
            add("apk-no-dex", 2, ["manifest but no classes.dex (dropper?)"])
    total = sum(i["points"] for i in indicators)
    verdict = "likely-malicious" if total >= 8 else ("suspicious" if total >= 4 else "no-static-indicators")
    return total, verdict, indicators


# ----------------------------------------------------------------------------
# main triage
# ----------------------------------------------------------------------------
def triage_file(path):
    rep = {"file": os.path.abspath(path)}
    size = os.path.getsize(path)
    rep["size"] = size
    h = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk); md5.update(chunk); sha1.update(chunk)
    rep["sha256"] = h.hexdigest()
    rep["md5"] = md5.hexdigest()
    rep["sha1"] = sha1.hexdigest()
    data = open(path, "rb").read(MAX_SCAN)
    if len(data) < size:
        rep["note"] = f"only first {len(data)//1024//1024}MB parsed (file is {size//1024//1024}MB)"
    fmt = detect_format(path, data)
    rep["format"] = fmt
    if fmt == "pe":
        rep["pe"] = parse_pe(data)
    elif fmt == "elf":
        rep["elf"] = parse_elf(data)
    elif fmt == "macho":
        rep["macho"] = parse_macho(data)
    elif fmt == "apk":
        rep["apk"] = parse_apk(data, path)
    elif fmt == "wasm":
        rep["wasm"] = {"version": struct.unpack_from("<I", data, 4)[0]}
    elif fmt == "dex":
        rep["dex"] = True
    strings = extract_strings(data)
    rep["string_count"] = len(strings)
    rep["string_categories"] = categorize_strings(strings)
    total, verdict, indicators = score_sample(rep)
    rep["score"] = total
    rep["verdict"] = verdict
    rep["indicators"] = indicators
    return rep


def human_summary(rep):
    lines = []
    lines.append(f"== binary-forge triage: {os.path.basename(rep['file'])} ==")
    lines.append(f"verdict   : {rep['verdict'].upper()}  (score {rep['score']})")
    lines.append(f"format    : {rep['format']}  size {rep['size']:,}B")
    lines.append(f"sha256    : {rep['sha256']}")
    if rep.get("pe"):
        p = rep["pe"]
        lines.append(f"pe        : {p.get('magic')} {p.get('machine')} {p.get('subsystem')} entry={p.get('entry_rva')} sec={p.get('entry_section')}")
        lines.append(f"compiled  : {p.get('compiled')}   .NET={p.get('dotnet')}  signed_dir={p.get('signed_dir')}")
        for s in p.get("sections", []):
            lines.append(f"  section {s['name']:<10} raw={s['rawsize']:>10,}  H={s['entropy'] if s['entropy'] is not None else '-'}")
        imps = p.get("imports", {})
        lines.append(f"imports   : {len(imps)} dlls, {sum(len(v) for v in imps.values())} functions")
        for dll, fns in list(imps.items())[:12]:
            lines.append(f"  {dll}: {', '.join(fns[:14])}{' …' if len(fns) > 14 else ''}")
    if rep.get("elf"):
        e = rep["elf"]
        lines.append(f"elf       : {e.get('class')}-bit {e.get('machine')} {e.get('elf_type')} static={e.get('static')} stripped={e.get('stripped')}")
        lines.append(f"imports   : {len(e.get('imports', []))} dynamic symbols")
    if rep.get("apk"):
        a = rep["apk"]
        lines.append(f"apk       : entries={a.get('entries')} dex={a.get('dex_files')} abi={a.get('native_libs')}")
    if rep["indicators"]:
        lines.append("indicators:")
        for i in rep["indicators"]:
            lines.append(f"  +{i['points']:>2} {i['id']}: {i['evidence'][0] if i['evidence'] else ''}")
    else:
        lines.append("indicators: none observed")
    lines.append("note      : static analysis only — no execution. Score is probability, not proof.")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="static malware triage (read-only)")
    ap.add_argument("target")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="write JSON report to this file")
    args = ap.parse_args()

    path = args.target
    if not os.path.exists(path):
        print(f"not found: {path}", file=sys.stderr)
        return 2
    if os.path.isdir(path):
        results = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fn in sorted(files):
                fp = os.path.join(root, fn)
                try:
                    if os.path.islink(fp) or os.path.getsize(fp) > MAX_SCAN * 4:
                        continue
                    results.append(triage_file(fp))
                except Exception as e:
                    results.append({"file": fp, "error": str(e)[:120], "verdict": "error", "score": 0})
        results.sort(key=lambda r: -r.get("score", 0))
        summary = {"folder": os.path.abspath(path), "scanned": len(results),
                   "ranking": [{"file": r["file"], "score": r.get("score", 0), "verdict": r.get("verdict")} for r in results[:20]],
                   "reports": results}
        out = json.dumps(summary, indent=2)
        if args.out:
            open(args.out, "w").write(out)
        if args.json:
            print(out)
        else:
            print(f"scanned {len(results)} files in {path}, ranked by score:")
            for r in summary["ranking"]:
                print(f"  {r['score']:>3}  {r['verdict']:<22} {os.path.basename(r['file'])}")
        return 0
    rep = triage_file(path)
    out = json.dumps(rep, indent=2)
    if args.out:
        open(args.out, "w").write(out)
    if args.json:
        print(out)
    else:
        print(human_summary(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
