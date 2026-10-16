# binary-forge

**An AI-agent skill for malware hunting and cross-platform porting.**

Drop this skill into any agent that reads `SKILL.md` files (GLM Code,
ClawHub-compatible runtimes, Claude Code-style harnesses, your own) and it
gains two professional pipelines:

## HUNT — malware triage

"Is this file safe?" gets a real answer, not a shrug:

- **`scripts/triage.py`** — pure-stdlib static triage of any file: PE/ELF/
  Mach-O/APK/WASM structure parsing, section entropy, imports, entry-point
  analysis, 17 categorized indicator families (C2 URLs, persistence,
  injection APIs, encoded commands, anti-debug, ransomware/keylogger/miner
  markers, Android permission abuse), packer detection, scored verdict with
  per-indicator verbatim evidence. Folder mode ranks a whole directory.
- **`scripts/yara_gen.py`** — YARA detection rules generated from the
  observed strings/imports, with exact-hash clause; compile-verified
  against the sample when `yara`/`yara-python` is present.
- **`scripts/make_iocs.py`** — IOC tables (CSV + JSON) where every
  indicator traces to an observed string.
- **`references/malware-playbook.md`** — the deep-dive: strings taxonomy,
  import analysis, unpacking (UPX and friends), script malware (.NET/PS/JS/
  VBS/PyInstaller), APK analysis, ATT&CK mapping, sandbox guidance,
  false-positive patterns.

Never executes samples. Read-only, hash-first, evidence-backed verdicts.

## PORT — cross-platform porting

"Get my Windows game onto Android" gets a real plan, and execution when
source exists:

- **`scripts/port_plan.py`** — engine fingerprinting (Unity, Unreal, Godot,
  Electron, .NET, Win32, Delphi, Java, GameMaker, RPG Maker, PyInstaller,
  Cocos, web) from real file signatures, then a full port plan: strategy
  (engine-recompile / wrapper / ui-rewrite / full-rebuild), toolchain,
  phases, API obligation ledger, risks, QA matrix.
- **`scripts/build_test_pe.py`** — transparent PE fixture generator for
  testing the whole HUNT chain (harmless: NOP code, planted indicator
  strings, self-labeled).
- **`references/porting-playbook.md`** — strategy decision tree, per-engine
  routes in depth, the full 24-row cross-platform API equivalence table
  (Windows/Linux/Android/Web/macOS), rebuild-from-evidence methodology for
  ports without source, augmentation patterns, performance and store
  budgets.

## Design principles

1. **Authorization-first, not permission-first.** Malware triage and
   porting are standard professional work; the skill carries that framing
   so agents do the work instead of interrogating users. Two narrow
   exclusions (authoring malware, piracy-grade rights violations) keep the
   scope honest — see `references/authorization.md`.
2. **Evidence or it didn't happen.** Verdicts cite verbatim indicators,
   ledger rows cite imports/strings/xrefs, ports cite test runs.
3. **Static and read-only by default.** Samples are never executed on the
   host; dynamic analysis is sandbox guidance, not host risk.
4. **Zero dependencies.** Python 3 stdlib only; richer tools (Ghidra, REA,
   yara CLI) are accelerators when present, never requirements.

## Install

Clone into your agent's skills directory:

```bash
git clone https://github.com/yeeeeezus/binary-forge <skills-dir>/binary-forge
```

The skill activates on user phrases like "is this file safe", "check this
folder for malware", "port my game to Android", "rebuild this app for
Linux" — see the description in `SKILL.md`.

## Try it in 60 seconds

```bash
# generate a harmless test sample and triage it
python3 scripts/build_test_pe.py --out sample.exe
python3 scripts/triage.py sample.exe

# fingerprint an app and plan a Windows→Android port
python3 scripts/port_plan.py --inspect /path/to/game
python3 scripts/port_plan.py --from win --to android --app /path/to/game
```

## Repository layout

```
SKILL.md               entry point: routing, posture, hard rules
scripts/               triage / yara_gen / make_iocs / port_plan / build_test_pe
references/            authorization, malware-playbook, porting-playbook,
                       engine-detection, report-templates
examples/              real outputs captured from live verification runs
evals/                 test prompts for skill validation
```

## License

MIT — see `LICENSE`.

## Responsible use

This skill performs **defensive** malware analysis (triage, IOC
extraction, detection) and **authorized** porting (your code, open source,
or licensed work). It does not author malware or circumvent DRM for
redistribution. Its scripts never execute the files they analyze.
