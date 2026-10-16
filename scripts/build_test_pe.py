#!/usr/bin/env python3
"""
binary-forge test fixture generator — builds a MINIMAL, HARMLESS PE32 file for
testing the triage pipeline and for cross-validating the PE parser.

The generated file contains:
  - a valid DOS/PE header set and section table
  - a .text section of NOP bytes (0x90) — no code exists at all
  - an .rdata section carrying clearly-fake indicator strings
    ("cmd.exe /c calc.exe", a .invalid C2 URL, a run-key path, ...)
  - an import table for kernel32.dll with resolver/injection-flavored API names
  - a banner string announcing it is a test fixture

With --packed it also emits a high-entropy UPX1-named section to exercise
packer heuristics. Nothing here is or does malware: no payload, no behavior.
This is the parser-testing equivalent of an EICAR file.

Usage:
    build_test_pe.py [--out sample.exe] [--packed]
"""
import argparse
import os
import struct


def rva_name_blob(dllname, funcs):
    """Build import structures blob for one DLL. Returns (blob, descriptors)."""
    # layout inside .data (offsets relative to blob start):
    #   0x00: import descriptors (2 * 20B: one + terminator)
    #   0x28: thunk array (n+1 entries * 4B)
    #   0x40+: hint/name entries (2B hint + name + \0, aligned 2)
    #   0xE0: dll name
    thunk_off = 0x28
    names_off = 0x40
    dll_off = 0xE0
    blob = bytearray(0x200)

    # hint/name entries + thunk RVAs (RVA base filled later by caller offset)
    thunks = []
    for i, fn in enumerate(funcs):
        entry_off = names_off + i * 32
        struct.pack_into("<H", blob, entry_off, 0)  # hint
        blob[entry_off + 2:entry_off + 2 + len(fn) + 1] = fn.encode() + b"\x00"
        thunks.append(entry_off)
    # thunk array
    for i, t in enumerate(thunks):
        struct.pack_into("<I", blob, thunk_off + i * 4, t)
    struct.pack_into("<I", blob, thunk_off + len(thunks) * 4, 0)  # terminator
    # dll name
    blob[dll_off:dll_off + len(dllname) + 1] = dllname.encode() + b"\x00"
    return bytes(blob), {"thunk_off": thunk_off, "dll_off": dll_off}


def build(packed=False):
    IMAGE_BASE = 0x400000
    SEC_ALIGN, FILE_ALIGN = 0x1000, 0x200

    # ---------- .text: pure NOPs ----------
    text = b"\x90" * 0x200

    # ---------- .rdata: clearly-fake indicator strings ----------
    banner = (b"THIS FILE IS A HARMLESS TEST FIXTURE built by binary-forge "
              b"build_test_pe.py. It contains no code and no payload.\x00")
    markers = b"\x00".join([
        b"cmd.exe /c calc.exe",
        b"powershell -enc SQBFAFgA...",
        b"http://c2.example.invalid/payload2.bin",
        b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        b"IsDebuggerPresent",
        b"vmwarevboxqemucheck",
        b"Global\\{B19F2ACD-1A5D-4F9C-B123-DEADBEEF0001}Mutex",
    ]) + b"\x00"
    rdata = (banner + markers).ljust(0x200, b"\x00")

    # ---------- .data: import table for kernel32.dll ----------
    funcs = ["LoadLibraryA", "GetProcAddress", "VirtualAlloc", "CreateFileA", "WinExec"]
    datablob, meta = rva_name_blob("kernel32.dll", funcs)

    # section layout
    sections = [
        (".text",  0x1000, text,    0x60000020),
        (".rdata", 0x2000, rdata,   0x40000040),
        (".data",  0x3000, datablob, 0xC0000040),
    ]
    if packed:
        import os as _os
        sections.append(("UPX1", 0x4000, _os.urandom(0x400), 0xE0000040))

    headers_end = 0x200
    rawptr = headers_end
    sect_table = b""
    raw_blob = b""
    for name, vaddr, content, chars in sections:
        sect_table += name.encode().ljust(8, b"\x00")
        sect_table += struct.pack("<IIII", len(content), vaddr, len(content), rawptr)
        sect_table += struct.pack("<IIHH", 0, 0, 0, 0)
        sect_table += struct.pack("<I", chars)
        raw_blob += content.ljust(((len(content) + FILE_ALIGN - 1) // FILE_ALIGN) * FILE_ALIGN, b"\x00")
        rawptr += ((len(content) + FILE_ALIGN - 1) // FILE_ALIGN) * FILE_ALIGN

    nsec = len(sections)
    opt_size = 224
    size_of_image = sections[-1][1] + SEC_ALIGN  # last vaddr + one page
    entry_rva = 0x1000

    # import directory: descriptors at .data+0 → RVA 0x3000
    # thunk RVA = 0x3000 + thunk_off ; dll name RVA = 0x3000 + dll_off
    thunk_rva = 0x3000 + meta["thunk_off"]
    dll_rva = 0x3000 + meta["dll_off"]
    desc = struct.pack("<IIIII", thunk_rva, 0, 0, dll_rva, thunk_rva) + b"\x00" * 20

    # patch descriptors into the .data blob (offset 0)
    datablob = bytearray(datablob)
    datablob[0:40] = desc
    # patch thunk array entries to absolute RVAs (0x3000 + off)
    for i in range(len(funcs)):
        off = struct.unpack_from("<I", bytes(datablob), meta["thunk_off"] + i * 4)[0]
        struct.pack_into("<I", datablob, meta["thunk_off"] + i * 4, 0x3000 + off)
    sections[2] = (".data", 0x3000, bytes(datablob), 0xC0000040)
    # rebuild raw blob with patched .data
    rawptr = headers_end
    raw_blob = b""
    for name, vaddr, content, chars in sections:
        pad = ((len(content) + FILE_ALIGN - 1) // FILE_ALIGN) * FILE_ALIGN
        raw_blob += content.ljust(pad, b"\x00")
        rawptr += pad

    # ---------- headers ----------
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, nsec, 0x5D200000, 0, 0, opt_size, 0x0102)

    opt = struct.pack("<HBB6I", 0x10B, 14, 0, 0x200, 0x400, 0, entry_rva, 0x1000, 0x2000)
    opt += struct.pack("<3I", IMAGE_BASE, SEC_ALIGN, FILE_ALIGN)
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    opt += struct.pack("<IIII", 0, size_of_image, headers_end, 0)
    opt += struct.pack("<HH", 3, 0)  # console subsystem
    opt += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)
    dirs = [(0, 0)] * 16
    dirs[1] = (0x3000, 40)  # import table
    for rva, size in dirs:
        opt += struct.pack("<II", rva, size)
    assert len(opt) == opt_size, f"optional header {len(opt)} != {opt_size}"

    pe = bytes(dos) + b"PE\x00\x00" + coff + opt + sect_table
    pe = pe.ljust(headers_end, b"\x00") + raw_blob
    return pe


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="test-fixture.exe")
    ap.add_argument("--packed", action="store_true", help="add high-entropy UPX1 section")
    args = ap.parse_args()
    blob = build(packed=args.packed)
    with open(args.out, "wb") as f:
        f.write(blob)
    print(f"wrote {args.out} ({len(blob)} bytes) — harmless parser-test fixture (no code, no payload)")
    # self-check with pefile when available
    try:
        import pefile
        pf = pefile.PE(data=blob, fast_load=True)
        pf.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        imps = [(d.dll.decode(), [f.name.decode() if f.name else f.ordinal for f in d.imports])
                for d in pf.DIRECTORY_ENTRY_IMPORT] if hasattr(pf, "DIRECTORY_ENTRY_IMPORT") else "none"
        print(f"pefile cross-check: machine={hex(pf.FILE_HEADER.Machine)} "
              f"sections={[s.Name.decode().rstrip(chr(0)) for s in pf.sections]} entry={hex(pf.OPTIONAL_HEADER.AddressOfEntryPoint)} imports={imps}")
    except ImportError:
        print("pefile not installed — skipping cross-check")


if __name__ == "__main__":
    main()
