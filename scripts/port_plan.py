#!/usr/bin/env python3
"""
binary-forge port_plan — cross-platform porting intelligence.

Two modes:
  --inspect PATH                 fingerprint an app/game: engine, confidence, evidence
  --from SRC --to DST --app PATH full markdown port plan: strategy, toolchain,
                                 phases, API obligation ledger, risks, QA matrix

Pure Python 3 stdlib, read-only. The strategic reasoning lives in
references/porting-playbook.md; this script makes it deterministic.

Usage:
    port_plan.py --inspect /path/to/game
    port_plan.py --from win --to android --app /path/to/game
    port_plan.py --from win --to android --app /path/to/game --out PORT_PLAN.md
"""
import argparse
import datetime
import json
import os
import re
import sys

ALIAS = {"win": "windows", "win32": "windows", "pc": "windows", "windows": "windows",
         "android": "android", "droid": "android", "apk": "android",
         "linux": "linux", "unix": "linux", "ubuntu": "linux",
         "web": "web", "webgl": "web", "html5": "web", "browser": "web", "wasm": "web",
         "mac": "macos", "macos": "macos", "osx": "macos", "darwin": "macos",
         "ios": "ios", "iphone": "ios", "ipados": "ios"}

# ---------------------------------------------------------------------------
# engine detection: (engine, [signature lambdas over (files, dirs, sample_pe)])
# a signature returns evidence-string or None
# ---------------------------------------------------------------------------
def sig_file(*names):
    def f(files, dirs, _pe):
        for n in names:
            hits = [x for x in files if os.path.basename(x).lower() == n]
            if hits:
                return f"file {n}"
        return None
    return f


def sig_glob(pattern):
    rx = re.compile(pattern, re.I)

    def f(files, dirs, _pe):
        hits = [x for x in files if rx.search(os.path.basename(x))]
        if hits:
            return f"{len(hits)} file(s) match {pattern} (e.g. {os.path.basename(hits[0])})"
        return None
    return f


def sig_file_content(name, marker=None):
    """read a small config file's first meaningful line into evidence"""
    def f(files, _dirs, _pe):
        for x in files:
            if os.path.basename(x).lower() == name.lower():
                try:
                    if os.path.getsize(x) > 4096:
                        return None
                    for line in open(x, errors="replace"):
                        line = line.strip()
                        if not line or line.startswith("//"):
                            continue
                        if marker and marker not in line and "=" not in line and ":" not in line:
                            continue
                        return f"{os.path.basename(x)} → {line[:80]}"
                except Exception:
                    return None
        return None
    return f


def sig_dir(*names):
    def f(files, dirs, _pe):
        for n in names:
            if n in dirs:
                return f"directory {n}/"
        return None
    return f


def sig_pe_strings(*words):
    def f(files, dirs, pe):
        if not pe:
            return None
        blob = pe.get("_strings", "")
        hits = [w for w in words if re.search(re.escape(w), blob, re.I)]
        return f"PE strings: {', '.join(hits)}" if hits else None
    return f


def sig_pe_imports(*dllnames):
    def f(files, dirs, pe):
        if not pe:
            return None
        imps = pe.get("imports", {})
        hits = [d for d in dllnames if any(d.lower() == k.lower() for k in imps)]
        if hits:
            return f"imports {', '.join(hits)}"
        return None
    return f


ENGINES = [
    ("unity", "Unity (C#, IL2CPP/Mono)", 3, [
        sig_file("assembly-csharp.dll", "globalgamemanagers", "projectversion.txt"),
        sig_file_content("ProjectVersion.txt", marker="m_EditorVersion"),
        sig_glob(r".*\.(unity3d|unity|assets|asset|prefab|unitypackage)$"),
        sig_dir("ProjectSettings", "Assets"),
    ]),
    ("unreal", "Unreal Engine (C++/Blueprints)", 3, [
        sig_glob(r".*\.(uproject|uasset|umap|pak)$"),
        sig_dir("Content", "Engine", "Binaries"),
    ]),
    ("godot", "Godot (GDScript/C#)", 3, [
        sig_file("project.godot"),
        sig_glob(r".*\.pck$"),
        sig_dir(".godot", "gdscript_cache"),
    ]),
    ("gamemaker", "GameMaker (GML)", 3, [
        sig_file("data.win"),
        sig_glob(r".*\.(yyp|yyz|gml)$"),
    ]),
    ("rpgmaker", "RPG Maker", 3, [
        sig_glob(r"(?i)(rgss.*\.dll|game\.rgssad.*|game\.exe)$"),
        sig_file("game.ini"),
    ]),
    ("electron", "Electron (web desktop wrapper)", 3, [
        sig_file("app.asar", "licenses.chromium.html"),
        sig_dir("resources"),
    ]),
    ("web", "Web app (HTML/JS)", 2, [
        sig_file("index.html"),
    ]),
    ("dotnet", ".NET desktop (WinForms/WPF/Avalonia)", 2, [
        sig_glob(r".*\.(exe\.config|deps\.json|csproj|sln|xaml)$"),
        sig_pe_imports("mscoree.dll"),
    ]),
    ("java", "Java desktop (Swing/JavaFX)", 2, [
        sig_file("manifest.mf"),
        sig_glob(r".*\.(jar|jmod)$"),
        sig_dir("META-INF"),
    ]),
    ("delphi", "Delphi/C++Builder (VCL/FMX)", 2, [
        sig_pe_strings("Borland", "Delphi", "CodeGear", "Embarcadero"),
        sig_glob(r".*\.(dpr|dproj|dfm|fmx)$"),
    ]),
    ("pyinstaller", "PyInstaller-packaged Python", 2, [
        sig_pe_strings("MEIPASS", "pyi-", "Python"),
        sig_glob(r"python\d+\.dll$"),
    ]),
    ("cocos", "Cocos (cocos2d-x / Cocos Creator)", 2, [
        sig_glob(r"(?i)(libcocos2d.*|cocos.*\.so|.*\.cconb|.*\.fire)$"),
    ]),
    ("win32", "Win32 native (C/C++)", 1, [
        sig_pe_imports("kernel32.dll", "user32.dll", "gdi32.dll"),
    ]),
]

# ---------------------------------------------------------------------------
# porting matrix — strategy, toolchain, phases, risks per engine×target
# strategy ∈ engine-recompile | wrapper | ui-rewrite | full-rebuild | web-wrap
# ---------------------------------------------------------------------------
MATRIX = {
    "unity": {
        "windows": {"android": ("engine-recompile", "Unity 2021+ with Android Build Support (IL2CPP arm64, Gradle)",
                      ["Install Android Build Support module in Unity Hub (SDK+NDK+JDK come bundled)",
                       "File → Build Settings → Android → Switch Platform",
                       "Player Settings: IL2CPP, ARM64 + (optional ARMv7), strip engine code",
                       "Remap input to New Input System touch bindings; add on-screen controls",
                       "UI: switch Canvas Scaler to Scale With Screen Size (portrait or ratio-matched)",
                       "Gradle build → .apk/.aab → test on device via adb",
                       "Store prep: target API level per current Play requirements, 16KB page size"],
                      ["Native plugins (.dll) need Android .so equivalents or removal",
                       "IL2CPP stripping can break reflection-heavy code (link.xml to preserve)",
                       "Textures: switch to ASTC compression for GPU mem"])},
        "linux": {"android": None},
        "web": {"web": ("engine-recompile", "Unity WebGL (IL2CPP → WASM)",
                  ["File → Build Settings → WebGL → Switch Platform",
                   "Player Settings: compression (Brotli/Gzip per server), strip engine code",
                   "Watch managed stripping level — Medium/High breaks reflection",
                   "Host with correct COOP/COEP headers if using threads; single-threaded otherwise",
                   "Test asset streaming: WebGL build bundles load via HTTP fetch"],
                  ["No threads/file IO/sockets: WebRequest → fetch wrapper, PlayerPrefs → IndexedDB",
                   "Memory budget: 2GB wasm32 ceiling — profile asset streaming",
                   "First-load size: use asset bundles + compression, add loading bar"])},
    },
    "unreal": {
        "windows": {"android": ("engine-recompile", "UE4/5 Android platform (ASTC, Gradle, NDK)",
                     ["Install Android Studio + NDK; set SDK paths in Editor preferences",
                      "Project Settings → Android: configure package name, min/target SDK",
                      "Switch texture format to ASTC; disable desktop-only features",
                      "Add touch controls (Common UI / virtual joysticks) to every user-facing screen",
                      "Package as .apk/.aab; test with adb logcat for on-device shader compile stalls",
                      "Profile: mobile renderer, dynamic resolution, particle budget"],
                     ["Desktop-only plugins need Android path or replacement",
                      "Shader permutation count explodes compile time on device",
                      "APK size: pak chunking + OnDemand resources for >150MB"])},
    },
    "godot": {
        "windows": {"android": ("engine-recompile", "Godot Android export preset",
                     ["Editor → Manage Export Templates → download Android templates",
                      "Project → Export → Android: keystore setup (debug then release)",
                      "Set orientation, permissions ( INTERNET etc.) in preset",
                      "Remap keyboard actions to touch screen buttons (TouchScreenButton nodes)",
                      "UI anchors: switch to full-rect anchor containers",
                      "Export .apk → adb install → test",
                      "Store prep: AAB via Godot 4 export; 64-bit is default (arm64-v8a)"],
                     ["GDNative/C++ modules need Android .a builds",
                      "Copyrighted export template must match editor version exactly",
                      "Android back button handling must be wired or app feels broken"])},
    },
    "electron": {
        "windows": {"android": ("web-wrap", "Capacitor (or Tauri v2 mobile) wrapping the existing web code",
                     ["Audit node-only deps (fs, child_process, native modules) — replace with Capacitor plugins or fetch backend",
                      "npm i @capacitor/core @capacitor/cli && npx cap init",
                      "Point webDir at the built assets (dist/)",
                      "npx cap add android → open in Android Studio",
                      "Map Electron IPC calls to Capacitor plugin bridges (write small adapters)",
                      "UI pass: mobile breakpoints, touch targets ≥48px, safe-area insets",
                      "Build .apk/.aab in Android Studio; test on device"],
                     ["Node backend code must move to HTTP service or be reimplemented as plugins",
                      "Window APIs (BrowserWindow, tray, menus) don't exist — feature-gap audit needed",
                      "Memory: Chromium-per-app on Android is heavy vs native"])},
    },
    "dotnet": {
        "windows": {"android": ("ui-rewrite", ".NET MAUI (or Avalonia) — keep C# logic, replace WinForms/WPF UI",
                     ["Inventory UI surface: forms/controls map to MAUI pages/views",
                      "Extract business logic into a shared netstandard/net8 class library (no UI refs)",
                      "Create MAUI head project; reference shared library",
                      "Rebuild each screen in XAML/C# (WinForms→MAUI mapping is 1:1-ish for CRUD apps)",
                      "Replace System.IO paths with MAUI Essentials FileSystem.AppDataDirectory",
                      "Replace registry/settings with Preferences; WinHTTP with HttpClient",
                      "dotnet build -t:Run -f net8.0-android → device test"],
                     ["WinForms drag-drop/designer workflows need manual re-creation",
                      "P/Invoke to Win32 must be stubbed/replaced per platform",
                      "MAUI Android needs Windows build host only for iOS — Android builds anywhere"])},
    },
    "java": {
        "windows": {"android": ("ui-rewrite", "Kotlin/Java logic reuse + Compose UI rewrite",
                     ["Split codebase: pure-JVM logic module vs Swing/JavaFX UI module",
                      "Reference logic module from new Android Studio project (Gradle)",
                      "Rebuild screens in Jetpack Compose (1:1 panel mapping usually viable)",
                      "Replace JFrame dialogs with Compose dialogs/activities",
                      "File IO → app-scoped storage; System.exit → lifecycle-aware finish",
                      "Test logic module unchanged with existing JUnit suite"],
                     ["Swing threading (SwingUtilities) → coroutines/Dispatchers",
                      "Look-and-feel custom painting has no direct equivalent — redesign",
                      "JVM flags/bundled JRE concepts don't apply"])},
    },
    "win32": {
        "windows": {"android": ("full-rebuild", "C/C++ logic salvage + Android NDK shell (or full rewrite)",
                     ["Decompile/recover per malware-playbook-grade RE: entry, message loop, core routines",
                      "Isolate portable core (math, game logic, parsers) from Win32 shell",
                      "Create Android Studio project with C++ support (CMake, STL, arm64-v8a)",
                      "Rebuild shell: message loop → Activity + InputEvent callbacks; WinMain → android_main",
                      "Render loop: GDI/DirectX → ANativeWindow + OpenGL ES/Vulkan (or SDL3 port — often cheaper)",
                      "Resources (.rc) → Android res/ assets; strings → strings.xml",
                      "Build, run under logcat, iterate"],
                     ["Inline asm (x86) must be rewritten; SIMD needs NEON ports",
                      "Threading (CreateThread) → pthreads works, message-queue coupling doesn't",
                      "Effort scales with UI density: full-UI apps often better as rewrite"])},
        "windows": {"linux": ("full-rebuild", "C/C++ rebuild against POSIX + SDL3/GTK (or Wine wrapper first)",
                     ["Wine check first: does it already run? If yes, wrapper route: ship .desktop + bundled Wine",
                      "Else: isolate portable core, map Win32→POSIX (CreateFile→open, CRITICAL_SECTION→pthread_mutex)",
                      "GDI/DirectX → SDL3 (2D) or Vulkan/OpenGL port; .rc resources → plain files",
                      "Registry usage → config file in XDG_CONFIG_HOME",
                      "Build with CMake + pkg-config; test under X11 and Wayland",
                      "Package as AppImage/Flatpak/deb"],
                     ["Installer logic (MSI/NSIS) never ports — replace with package manager story",
                      "DRM/anti-tamper may block both Wine and rebuild routes — plan around it"])},
    },
    "delphi": {
        "windows": {"android": ("engine-recompile", "FireMonkey (FMX) multi-device — Delphi's own cross-platform path",
                     ["Verify the project uses VCL → requires FMX migration pass (forms port, controls remap)",
                      "Open in latest RAD Studio; add Android platform to project",
                      "Replace Windows-only units (Winapi.*) with cross-platform equivalents",
                      "FMX handles UI scaling/touch; test on device via PAServer or USB",
                      "Build .apk from the IDE; bundle intent permissions in manifest template"],
                     ["VCL-only components need FMX replacements (third-party grids etc.)",
                      "Legacy BDE/database layers need FireDAC migration",
                      "License: RAD Studio multi-device edition required"])},
    },
    "pyinstaller": {
        "windows": {"android": ("full-rebuild", "Python reuse via Chaquopy/Kivy (or BeeWare) — UI rewritten",
                     ["Extract sources (PyInstaller archive is unpackable — use pyinstxtractor)",
                      "Split logic vs UI (tkinter/PyQt won't run on Android)",
                      "Android Studio + Chaquopy plugin: ship .py files + deps as Python components",
                      "Rebuild UI in Kotlin/Compose calling Python via Chaquopy API — or Kivy rewrite for pure-python",
                      "Pure-python fallback: Kivy buildozer .apk (if UI is simple)",
                      "Test on device; watch Python startup cost (~1-2s)"],
                     ["Binary wheels of C extensions need Android builds (often absent)",
                      "tkinter/PySide have no Android story — UI rewrite is mandatory"])},
    },
    "web": {
        "windows": {"android": ("web-wrap", "PWA or Capacitor shell around existing web app",
                     ["PWA first if app is offline-capable: manifest + service worker + install prompt",
                      "Capacitor when device APIs (camera, storage, push) are needed",
                      "Mobile UI pass: viewport, touch targets, safe areas, offline states",
                      "Ship same web bundle — no code rewrite of app logic"],
                     ["Requires server/backend to be reachable or offline-first design",
                      "Store review: Apple is strict on 'repackaged websites' — add native value"])},
    },
    "gamemaker": {
        "windows": {"android": ("engine-recompile", "GameMaker Android export",
                     ["GameMaker Studio 2: target Android module (license includes it)",
                      "Game Options → Android: package id, SDK/NDK config",
                      "Input: keyboard/mouse events need touch equivalents (device_mouse)",
                      "Texture pages: resize for mobile GPUs; test scaling",
                      "Build .apk, test via adb, wire back-button handling"],
                     ["Legacy GM8.x games must first be imported to GMS2 (importer lossy)",
                      "Desktop shaders may need mobile variants"])},
    },
    "rpgmaker": {
        "windows": {"android": ("full-rebuild", "RPG Maker MV/MZ games are web — wrap; older engines rebuild",
                     ["MV/MZ: game IS HTML5 → Capacitor wrap (see web matrix) — half-day job",
                      "VX Ace and older: Ruby RGSS internals — rebuild in Godot (common route) or use paid converters",
                      "Touch controls: on-screen D-pad + A/B buttons over the canvas",
                      "Save system: localStorage (MV/MZ) persists inside wrapper"],
                     ["RGSS Ruby scripts don't run anywhere but Windows player",
                      "Asset licensing: RPG Maker RTP assets may not ship outside RM engines"])},
    },
    "cocos": {
        "windows": {"android": ("engine-recompile", "Cocos Creator / cocos2d-x native Android target",
                     ["Cocos Creator: build panel → Android target directly",
                      "cocos2d-x: proj.android Gradle project ships in tree — build with NDK",
                      "Design resolution: switch to fit-width policy for phones",
                      "Add touch/multitouch handlers for mouse-only logic",
                      "Build .apk/.aab; test low-end device perf budget"],
                     ["Windows-specific GL code paths need ES 2.0/3.0 variants",
                      "C++ cocos2d-x is EOL — consider Creator migration"])},
    },
}

GENERIC_NATIVE = ("full-rebuild", "reverse-engineer → portable core → target platform shell",
                  ["Recover logic via RE (Ghidra pseudocode / decompilers per malware-playbook)",
                   "Catalog capabilities against the API obligation ledger below",
                   "Rebuild shell on target (Activity/main loop/render)",
                   "Re-implement ledgered capabilities using target column",
                   "Golden-test: same inputs → same outputs vs original"],
                  ["Fidelity ceiling: compiled optimizations, lost types, inlined logic",
                   "Rights: rebuild requires owning or licensing the software"])

# distilled cross-platform API equivalence ledger (windows/linux/android/web/macos, difficulty)
API_LEDGER = [
    ("window creation", "ui", "CreateWindowEx + message loop", "X11/XCB or Wayland", "Activity + Window", "DOM canvas / fullscreen", "NSWindow", "moderate"),
    ("controls / widgets", "ui", "BUTTON class / dialogs", "GTK / Qt widgets", "android.widget.* (XML)", "<button> etc + CSS", "NSButton/NSView", "easy"),
    ("2D drawing", "graphics", "GDI / Direct2D", "Cairo / Skia", "android.graphics.Canvas", "Canvas2D / WebGL / SVG", "Core Graphics", "moderate"),
    ("3D rendering", "graphics", "Direct3D / OpenGL", "OpenGL / Vulkan", "OpenGL ES / Vulkan", "WebGL / WebGPU", "Metal", "hard"),
    ("file read/write", "fs", "CreateFileW / ReadFile", "open/read/write", "java.io / SAF", "File System Access / OPFS", "NSFileHandle", "easy"),
    ("file dialog", "ui", "GetOpenFileName", "GtkFileChooser", "ACTION_OPEN_DOCUMENT", "<input type=file>", "NSOpenPanel", "easy"),
    ("network socket", "net", "Winsock2", "BSD sockets", "java.net.Socket", "WebSocket/fetch only (no raw TCP)", "BSD sockets", "moderate"),
    ("HTTP client", "net", "WinHTTP / WinInet", "libcurl", "OkHttp / HttpURLConnection", "fetch() (CORS-bound)", "NSURLSession", "easy"),
    ("TLS / crypto", "crypto", "SChannel / CNG", "OpenSSL", "Conscrypt / JSSE", "browser TLS + crypto.subtle", "Security.framework", "easy"),
    ("process spawn", "process", "CreateProcessW", "fork/exec", "NOT ALLOWED — intents/services", "Web Workers / WASI only", "NSTask", "hard"),
    ("threads", "process", "CreateThread / SRWLock", "pthreads", "coroutines / java.util.concurrent", "Web Workers + Atomics", "GCD / NSThread", "moderate"),
    ("settings persistence", "system", "registry", "XDG config files", "SharedPreferences / DataStore", "localStorage / IndexedDB", "NSUserDefaults", "easy"),
    ("system info", "system", "GetSystemInfo", "uname / sysconf", "Build.* constants", "navigator.*", "sysctl", "trivial"),
    ("clipboard", "input", "OpenClipboard", "X11 selections / wl-clipboard", "ClipboardManager", "navigator.clipboard", "NSPasteboard", "easy"),
    ("keyboard input", "input", "WM_KEYDOWN / raw input", "XKB / libinput", "KeyEvent / IME", "keydown/keyup", "NSEvent", "moderate"),
    ("mouse / touch", "input", "WM_MOUSEMOVE / WM_TOUCH", "libinput / XInput2", "MotionEvent (touch-first)", "pointer events", "NSEvent / NSTouch", "moderate"),
    ("audio output", "audio", "WASAPI / XAudio2", "ALSA / PipeWire", "AudioTrack / Oboe", "Web Audio API", "Core Audio", "moderate"),
    ("audio input", "audio", "WASAPI capture", "ALSA/PipeWire capture", "AudioRecord (permission)", "getUserMedia (permission)", "Core Audio input", "moderate"),
    ("dynamic libraries", "system", "LoadLibraryW", "dlopen / dlsym", "System.loadLibrary (JNI)", "ESM import() / WASM", "dlopen", "moderate"),
    ("shared memory", "process", "CreateFileMappingW", "shm_open / mmap", "Ashmem (internal)", "SharedArrayBuffer + COOP/COEP", "POSIX shm", "hard"),
]

QA_MATRIX = {
    "android": ["installs via adb on real device (not just emulator)", "cold start < 5s on a mid-tier phone",
                "core loop 60fps (or honest degraded mode)", "touch input + back button correct",
                "save/load survives app kill", "network failure paths degrade gracefully",
                "64-bit only (arm64-v8a) — Play requirement", "target API level current", "16KB page-size alignment (new devices)"],
    "linux": ["launches on X11 AND Wayland", "no hardcoded C:\\ paths anywhere", "saves to XDG dirs",
              "runs from AppImage/Flatpak sandbox", "no root needed", "hi-DPI scaling"],
    "web": ["first meaningful render with loading progress", "works offline if claimed",
            "no raw-socket assumptions (fetch/WebSocket only)", "memory stays under 2GB (wasm32)",
            "mobile Safari/Chrome pass (touch, safe areas)", "CORS/COOP/COEP headers correct if threaded"],
    "macos": ["signed + notarized (Gatekeeper)", "Universal binary (arm64+x86_64)", "retina rendering",
              "menu bar + cmd-Q/standard shortcuts"],
    "ios": ["requires macOS build host + paid Apple Developer account", "signed via Xcode/Transporter",
            "touch targets ≥44pt", "no JIT-dependent code paths (or documented WKWebView route)"],
}


# ---------------------------------------------------------------------------
def quick_pe(path):
    """real PE fingerprint via the triage parser (sibling module), read-only"""
    try:
        data = open(path, "rb").read(2 * 1024 * 1024)
        if data[:2] != b"MZ":
            return None
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from triage import parse_pe, extract_strings
        pe = parse_pe(data)
        if pe is None:
            return None
        pe["_strings"] = "\n".join(extract_strings(data, limit=1500))
        return pe
    except Exception:
        # parser unavailable or malformed file — fall back to raw scan
        try:
            data = open(path, "rb").read(1024 * 1024)
            if data[:2] != b"MZ":
                return None
            return {"_strings": data.decode("latin-1", "replace"), "imports": {}}
        except Exception:
            return None


def inspect(path):
    files, dirs = [], []
    if os.path.isdir(path):
        for root, ds, fs in os.walk(path):
            ds[:] = [d for d in ds if d not in (".git", "node_modules", "Library", "Build", ".gradle")]
            for fn in fs:
                files.append(os.path.join(root, fn))
            if root == path:
                dirs = ds
            if len(files) > 20000:
                break
        sample_pe = None
        for f in files:
            if f.lower().endswith(".exe") and os.path.getsize(f) < 80 * 1024 * 1024:
                sample_pe = quick_pe(f)
                if sample_pe:
                    break
    else:
        files = [path]
        sample_pe = quick_pe(path) if path.lower().endswith(".exe") else None

    results = []
    for name, label, weight, sigs in ENGINES:
        evidence = [s(files, dirs, sample_pe) for s in sigs]
        evidence = [e for e in evidence if e]
        if evidence:
            score = weight * len(evidence)
            results.append({"engine": name, "label": label, "score": score, "evidence": evidence})
    results.sort(key=lambda r: -r["score"])
    best = results[0] if results else {"engine": "unknown", "label": "Unknown — treat as native binary", "score": 0, "evidence": []}
    # integrity notes: empty-marker files hint at partial snapshots
    notes = []
    zero_marker = [f for f in files if os.path.basename(f).lower() in
                   ("assembly-csharp.dll", "data.win", "project.godot") and os.path.getsize(f) == 0]
    if zero_marker:
        notes.append("engine-marker file(s) are 0 bytes — likely a partial snapshot, not a full project: "
                     + ", ".join(os.path.basename(f) for f in zero_marker))
    # infer source env from artifacts if not told
    src_guess = "windows"
    exes = [f for f in files if f.lower().endswith((".exe", ".dll"))]
    if not exes and any(f.lower().endswith((".so",)) for f in files):
        src_guess = "linux"
    if best["engine"] == "web":
        src_guess = "web"
    return {"path": os.path.abspath(path), "engine": best, "candidates": results,
            "file_count": len(files), "source_guess": src_guess, "notes": notes}


def ledger_for(target, engines_hit):
    """obligation rows relevant to a target, from the API ledger"""
    col = {"windows": 2, "linux": 3, "android": 4, "web": 5, "macos": 6}[target]
    rows = []
    for row in API_LEDGER:
        cap, cat, *api_cols, diff = row
        rows.append({"capability": cap, "category": cat, "target_api": api_cols[col - 2], "difficulty": diff})
    return rows


def plan(app_path, src, dst, inspection):
    eng = inspection["engine"]["engine"]
    label = inspection["engine"]["label"]
    evidence = inspection["engine"]["evidence"]
    # find matrix entry: engine → src env → dst
    entry = MATRIX.get(eng, {}).get(src) or MATRIX.get(eng, {}).get("windows")
    if entry is None:
        entry = MATRIX.get(eng, {})
        cell = entry.get(dst) if isinstance(entry, dict) else None
    else:
        cell = entry.get(dst)
    if cell is None:
        # engine known but this exact src→dst cell missing: use canonical windows-src cell
        cell = MATRIX.get(eng, {}).get("windows", {}).get(dst)
    strategy, toolchain, phases, risks = cell if cell else GENERIC_NATIVE
    if cell is None:
        strategy, toolchain, phases, risks = GENERIC_NATIVE
        risks = list(risks) + ["no curated route for engine=%s → target=%s — using generic rebuild" % (eng, dst)]

    L = []
    a = L.append
    a(f"# Port Plan — {os.path.basename(app_path.rstrip('/'))}")
    a("")
    a(f"*Generated by binary-forge {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · "
      f"route: **{src} → {dst}** · strategy: **{strategy}***")
    a("")
    a("## 1. What we are porting")
    a(f"- Engine: **{label}** (confidence: {inspection['engine']['score']} pts from {len(evidence)} signal(s))")
    for e in evidence[:5]:
        a(f"  - evidence: `{e}`")
    a(f"- Artifacts scanned: {inspection['file_count']} files")
    for note in inspection.get("notes", []):
        a(f"- ⚠ {note}")
    if inspection["engine"]["score"] == 0:
        a("- Engine not recognized — treat as opaque native binary; see references/porting-playbook.md § rebuild-from-evidence")
    a("")
    a("> **Licensing note (informational, not a gate):** if this isn't your own code, confirm you "
      "hold the rights or a license to port and redistribute it — that's between you and the "
      "software's license. The plan below is purely technical and works either way.")
    a("")
    a("## 2. Strategy")
    a(f"**{strategy}** — {toolchain}.")
    a("")
    strat_note = {
        "engine-recompile": "The engine itself targets the destination: this is configuration + adaptation work, not a rewrite. Usually days, not weeks.",
        "wrapper": "A compatibility layer or web shell ships the original artifact with minimal changes. Fastest route; fidelity high; performance and store-compliance caveats apply.",
        "web-wrap": "The app is already web tech — wrap it natively (PWA/Capacitor) instead of rewriting.",
        "ui-rewrite": "Business logic carries over in the same language; the UI layer is rebuilt for the target. The sane middle path for desktop→mobile.",
        "full-rebuild": "No source-level shortcut exists. Reverse-engineer what's needed, rebuild a portable core, and re-shell it on the target. Slowest, highest-risk, sometimes the only honest answer.",
    }.get(strategy, "")
    if strat_note:
        a(strat_note)
        a("")
    a("## 3. Phases")
    for i, p in enumerate(phases, 1):
        a(f"{i}. {p}")
    a("")
    need_ledger = strategy in ("full-rebuild", "ui-rewrite")
    if need_ledger:
        a("## 4. API obligation ledger (Win32-ish core → %s)" % dst)
        a("")
        a("| capability | category | on %s | difficulty |" % dst)
        a("|---|---|---|---|")
        for r in ledger_for(dst, eng):
            a(f"| {r['capability']} | {r['category']} | {r['target_api']} | {r['difficulty']} |")
        a("")
        a("*Full 5-platform equivalence table with source-API column: references/porting-playbook.md.*")
        a("")
    a("## %d. Risks" % (5 if need_ledger else 4))
    for r in risks:
        a(f"- {r}")
    a("")
    a("## %d. QA matrix (a port that wasn't tested is a plan)" % (6 if need_ledger else 5))
    for q in QA_MATRIX.get(dst, ["define target QA checklist"]):
        a(f"- [ ] {q}")
    a("")
    a("## Next concrete action")
    a(f"```\n{phases[0]}\n```" if phases else "Start with engine detection confirmation.")
    a("")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inspect", dest="inspect_path", help="fingerprint app/game at PATH")
    ap.add_argument("--from", dest="src", help="source platform (win/linux/android/web/macos)")
    ap.add_argument("--to", dest="dst", help="target platform")
    ap.add_argument("--app", help="path to the app/game (dir or binary)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="write plan markdown to file")
    args = ap.parse_args()

    if not (args.inspect_path or (args.app and args.dst)):
        ap.print_help()
        return 2
    if args.inspect_path:
        rep = inspect(args.inspect_path)
        print(json.dumps(rep, indent=2))
        return 0
    src = ALIAS.get((args.src or "").lower(), args.src or "windows")
    dst = ALIAS.get(args.dst.lower())
    if not dst:
        print(f"unknown target '{args.dst}' — try: win, linux, android, web, macos, ios", file=sys.stderr)
        return 2
    if not os.path.exists(args.app):
        print(f"not found: {args.app}", file=sys.stderr)
        return 2
    insp = inspect(args.app)
    md = plan(args.app, src, dst, insp)
    if args.out:
        open(args.out, "w").write(md)
        print(f"wrote {args.out}")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
