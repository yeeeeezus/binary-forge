# Cross-platform porting playbook

The strategic reasoning behind the PORT pipeline. `port_plan.py` makes the
routing deterministic; this document explains *why* each route is what it
is, and what to do when reality is messier than the matrix.

## Contents
1. The strategy decision tree
2. Engine-specific routes in depth
3. Full cross-platform API equivalence table
4. Porting without source: rebuild-from-evidence
5. The obligation ledger method
6. Adding features to existing apps (augmentation)
7. Performance and store-compliance budgets

## 1. The strategy decision tree

Ask in order — the first "yes" wins:

1. **Does the engine already target the destination?**
   (Unity→Android/WebGL, UE→Android, Godot→anywhere, GameMaker→Android,
   Delphi/FMX→Android/iOS, Cocos→Android) → **engine-recompile**.
   Configuration and adaptation work: days. Always the cheapest real port.
2. **Is the app already web tech?** (Electron, web app, RPG Maker MV/MZ,
   many hybrid tools) → **web-wrap** (PWA/Capacitor/Tauri v2). Ship the
   same bundle in a native shell: hours-to-days.
3. **Does Wine/Proton already run it well enough on Linux?** → **wrapper**.
   Wrap with bundled Wine/Proton + a .desktop; zero code changes. For
   personal use and internal tools this is often the *right* answer even
   though it's not a "true" port — say which one you're delivering.
4. **Is the business logic separable from the UI in the same language?**
   (.NET→MAUI, Java→Compose, Python→Chaquopy) → **ui-rewrite**. Weeks.
   Keeps the valuable half, replaces the platform-bound half.
5. **None of the above** (Win32/C++, Delphi-VCL legacy, unknown binary) →
   **full-rebuild**: reverse-engineer, rebuild a portable core, re-shell.
   Weeks-to-months; fidelity ceiling is real; sometimes the only honest
   answer.

Present the trade-off honestly to the user: wrapper = day-one at 90%
fidelity; engine-recompile = days at ~100%; ui-rewrite = weeks at ~95%;
full-rebuild = months at 60–90% depending on RE recovery quality.

## 2. Engine-specific routes in depth

### Unity → Android (the canonical "win to android" ask)
Switch platform → IL2CPP + ARM64 → input remap (New Input System touch
bindings; add virtual controls) → Canvas Scaler to Scale-With-Screen-Size
→ texture compression to ASTC → Gradle build. The killers are always:
native plugins without .so equivalents, and reflection-heavy code under
IL2CPP stripping (link.xml preserves). Test on the *lowest* device you
target, not your flagship.

### Unity → Web
WebGL export: managed stripping Medium/High breaks reflection — test early.
No threads by default (COOP/COEP only if you enable them), no file IO
(PlayerPrefs → IndexedDB is handled by the engine, custom IO isn't), audio
needs user-gesture unlock. First-load size is the product metric: compress,
bundle, loading screen.

### Unreal → Android
Android Studio + NDK setup → ASTC textures → mobile renderer + dynamic
resolution → Common UI/virtual joysticks on every screen → watch on-device
shader-compilation stalls (PSO precaching). APK size: pak chunking past
150MB, OnDemand resources past that.

### Godot → anywhere
The friendliest engine: export presets per platform, one keystore for
Android. Do wire the Android back button or the app feels broken; GDNative
modules need per-platform builds.

### Electron → Android
Capacitor (npm-native, plugin ecosystem) or Tauri v2 mobile (Rust core).
The port cost is not the wrapper — it's the **feature-gap audit**: every
`BrowserWindow`, tray, menu, and `fs`/`child_process` call needs a
replacement or a graceful degrade. Budget a day for the audit before any
wrapping.

### .NET desktop → Android
MAUI: extract logic to a UI-free library first (this is also great
hygiene), then rebuild screens. WinForms→MAUI is nearly 1:1 for CRUD apps;
WPF data-binding maps to MVVM nicely. P/Invoke surface needs per-platform
stubs.

### Java desktop → Android
Swing/JavaFX never run on Android. Logic module → Gradle reference →
Compose UI. The existing JUnit suite on the logic module is your golden
test coverage — keep it green through the port.

### Win32 native → anywhere
The hard case. See §4. If the UI is thin and logic-heavy: extract core,
shell it (NDK C++ or SDL3 for 2D games). If UI-heavy: consider whether a
Wine wrapper (Linux) or a rewrite (everywhere else) serves the user
better. SDL3 is the cheat code for 2D Win32 games: message loop, input,
audio, and render in one portable layer, ~a week for a mid-size game.

### PyInstaller → Android
Extract sources (pyinstxtractor), split logic/UI (tkinter/PyQt won't run),
Chaquopy for logic-in-Kotlin-app, or Kivy rewrite for pure-Python.
C-extension wheels without Android builds are the usual blocker — check
`pip download --platform android` viability early.

### Delphi → Android
VCL must become FMX first (forms migration). Then RAD Studio multi-device
does the rest. Third-party VCL-only components are the cost center.

### RPG Maker → Android
MV/MZ are web apps already: Capacitor in half a day. VX Ace and older:
rebuild in Godot (community route) — RB scripts don't run elsewhere, and
RTP asset licensing forbids shipping them outside RPG Maker engines.

## 3. Full cross-platform API equivalence table

The obligation ledger's source of truth. Source column assumes the
Windows-native baseline; for other sources use the same row's other
columns.

| capability | Windows | Linux | Android | Web | macOS | difficulty |
|---|---|---|---|---|---|---|
| window creation | CreateWindowEx + message loop | X11/XCB or Wayland | Activity + Window | DOM canvas / fullscreen | NSWindow | moderate |
| controls / widgets | BUTTON class / dialogs | GTK / Qt widgets | android.widget.* (XML) | HTML elements + CSS | NSButton/NSView | easy |
| text rendering | GDI DrawText / DirectWrite | Pango/Cairo or Qt | TextView / Canvas.drawText | HTML + CSS fonts | NSAttributedString / CoreText | easy |
| 2D drawing | GDI / Direct2D | Cairo / Skia | android.graphics.Canvas | Canvas2D / WebGL / SVG | Core Graphics | moderate |
| 3D rendering | Direct3D / OpenGL | OpenGL / Vulkan | OpenGL ES / Vulkan | WebGL / WebGPU | Metal | hard |
| file read/write | CreateFileW / ReadFile | open/read/write | java.io / SAF | File System Access / OPFS | NSFileHandle | easy |
| directory listing | FindFirstFileW | opendir/readdir | File.listFiles | showDirectoryPicker | NSFileManager | easy |
| file dialog | GetOpenFileName | GtkFileChooser | ACTION_OPEN_DOCUMENT | input type=file / showOpenFilePicker | NSOpenPanel | easy |
| network socket | Winsock2 | BSD sockets | java.net.Socket | WebSocket / fetch only | BSD sockets | moderate |
| HTTP client | WinHTTP / WinInet | libcurl | OkHttp / HttpURLConnection | fetch() (CORS-bound) | NSURLSession | easy |
| TLS / crypto | SChannel / CNG | OpenSSL | Conscrypt / JSSE | browser TLS + crypto.subtle | Security.framework | easy |
| crypto hashing | BCryptHash / CNG | OpenSSL EVP | MessageDigest | crypto.subtle.digest | CommonCrypto | trivial |
| process spawn | CreateProcessW | fork/exec | NOT ALLOWED — intents | Web Workers / WASI | NSTask | hard |
| threads | CreateThread / SRWLock | pthreads | coroutines / JUC | Web Workers + Atomics | GCD / NSThread | moderate |
| shared memory | CreateFileMappingW | shm_open / mmap | Ashmem (internal) | SharedArrayBuffer + COOP/COEP | POSIX shm | hard |
| settings persistence | registry | XDG config files | SharedPreferences / DataStore | localStorage / IndexedDB | NSUserDefaults | easy |
| environment vars | GetEnvironmentVariable | getenv | BuildConfig / gradle props | build-time injection | getenv | trivial |
| system info | GetSystemInfo | uname / sysconf | Build.* constants | navigator.* | sysctl | trivial |
| clipboard | OpenClipboard | X11 selections / wl-clipboard | ClipboardManager | navigator.clipboard | NSPasteboard | easy |
| keyboard input | WM_KEYDOWN / raw input | XKB / libinput | KeyEvent / IME | keydown/keyup | NSEvent | moderate |
| mouse / touch | WM_MOUSEMOVE / WM_TOUCH | libinput / XInput2 | MotionEvent (touch-first) | pointer events | NSEvent / NSTouch | moderate |
| audio output | WASAPI / XAudio2 | ALSA / PipeWire | AudioTrack / Oboe | Web Audio API | Core Audio | moderate |
| audio input | WASAPI capture | ALSA capture | AudioRecord (permission) | getUserMedia (permission) | Core Audio | easy |
| dynamic libraries | LoadLibraryW | dlopen / dlsym | System.loadLibrary (JNI) | ESM import() / WASM | dlopen | moderate |
| serialization | custom / protobuf | same library | same via JNI / Parcelable | JSON / structuredClone | same library | easy |

Read it as a *risk map*: count the `hard` rows a port touches — that's your
schedule risk. `process spawn` being "NOT ALLOWED" on Android and
raw-sockets being impossible on Web are the two facts that most often
re-architect a port (spawn → service/intent; raw TCP → WebSocket relay).

## 4. Porting without source: rebuild-from-evidence

When there's no source and no engine shortcut (opaque .exe), the honest
route — used by porting studios when rights exist — is evidence-driven
reconstruction:

1. **Recover structure**: decompile (Ghidra pseudocode / REA) focusing on
   entry → main loop → dispatch. Identify modules by string xrefs and
   import xrefs.
2. **Extract assets**: resources (.rc → dialogs/icons), embedded files,
   audio/graphic formats — these port *unchanged* and preserve the app's
   identity.
3. **Catalog capabilities** against §3's table → obligation ledger (what
   must exist on the target, at what difficulty).
4. **Rebuild a portable core** in the target's native stack (Kotlin/C++
   for Android, TS for Web), implementing ledger rows from observed
   behavior — *observed*, meaning you can cite the evidence record.
5. **Golden-test**: same inputs → same observable outputs vs the original
   (screenshots, file outputs, timing tolerances). Divergences become new
   work items, not surprises at the end.

Fidelity limits to state up front: compiled optimizations lose types and
names; inlined logic reconstructs approximately; large C++ apps with
templates/RTTI can exceed sane RE budgets. Quote a fidelity *target* (e.g.
"game loop + assets + save system at parity; netcode replaced by target
idiom") rather than promising parity everywhere.

Every regenerated project ships a `PORT_PLAN.md` ledger: obligations,
evidence pointers (addresses/hashes), decisions, and test results — the
port's audit trail and resume point.

## 5. The obligation ledger method

The ledger turns "port this app" into a finite, checkable list:

```
| capability      | source API (observed)   | target API            | difficulty | status |
|-----------------|-------------------------|-----------------------|------------|--------|
| window creation | CreateWindowEx (xref'd) | Activity + Compose    | moderate   | done   |
| audio output    | XAudio2 (imports)       | Oboe                  | moderate   | todo   |
```

Rules that make it work: every source-API cell cites evidence (import
name, string xref, decompiled signature) — no vibes; every status change
cites a test, not a feeling; new capabilities discovered mid-port get
appended, never silently dropped. The ledger is the single artifact a
second engineer (or a second session) needs to continue the port cold.

## 6. Adding features to existing apps (augmentation)

When the ask is "add X to app Y" and Y is a binary or a codebase:

- **With source:** find the feature's insertion point via the same
  evidence route (imports/strings/xrefs for binaries; grep + call-graph
  for code), implement, and extend the QA matrix with the new behavior.
- **Without source:** the three practical mechanisms are
  runtime instrumentation (Frida scripts hooking observed addresses),
  userscripts (web apps — Tampermonkey-class), and preload/IPC patches
  (Electron — patch `preload.js`, re-sign the asar). All three belong in
  the app's augmentation ledger with evidence-derived addresses. These are
  standard techniques for apps the user controls; for someone else's
  software, licensing is a one-line note in the ledger between the user
  and that software's license — never a stop (see
  references/refusal-policy.md).
- Feature catalog pattern: api-tracing, dark-mode, hotkeys, data export,
  automation — each as a small, evidence-derived, individually testable
  artifact. Small surface, real tests, no shotgun patches.

## 7. Performance and store-compliance budgets

Numbers that re-architect ports if violated — check early:

- **Android:** 64-bit mandatory (arm64-v8a); current Play target-API
  requirement moves yearly — check it at port time, not from memory; 16KB
  page-size alignment required for newer devices; cold start < 5s or
  users churn; APK size: Play-specific expansion/download-format rules
  (AAB) matter past 150MB.
- **Web/WASM:** wasm32 linear-memory ceiling ~4GB (practical: 2GB
  budget); first-load < 5MB compressed or add explicit loading UX;
  threaded WASM needs COOP/COEP headers — infrastructure, not code;
  mobile Safari memory limits are the real ceiling for WebGPU-era apps.
- **iOS:** building requires macOS + Xcode + paid developer account —
  plan licensing before promising iOS dates; no JIT on JIT-less paths
  (affects dynamic-language runtimes); App Review is strict on
  wrapped-website apps — native value required.
- **Linux:** Wayland is the future but X11 compat still sells; AppImage
  or Flatpak beats .deb-only for reach; hi-DPI fractional scaling is the
  eternal QA line-item.

None of these are reasons to refuse a port. They are the port's actual
shape.
