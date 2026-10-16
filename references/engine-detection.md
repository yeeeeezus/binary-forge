# Engine detection guide

How `port_plan.py --inspect` decides what an app is, and how to sharpen
the call by hand when signals conflict. Detection is evidence-based: every
conclusion ships with the file/dir/import evidence that produced it.

## Signature table

| Engine | Strong signals (near-certain) | Weak signals (corroborating) |
|---|---|---|
| Unity | `Assembly-CSharp.dll`, `globalgamemanagers`, `ProjectSettings/ProjectVersion.txt` | `*.unity3d`/`.assets`, `Assets/`, `Library/` |
| Unreal | `*.uproject`, `Content/Paks/*.pak`, `*.uasset`/`*.umap` | `Binaries/Win64/`, `Engine/` |
| Godot | `project.godot`, `*.pck` | `.godot/` cache dir |
| GameMaker | `data.win` | `*.yyp`, `*.gml` |
| RPG Maker | `RGSS*.dll`, `Game.rgssad`/`rgssad` strings, `Game.ini` | `Audio/BGM` layout |
| Electron | `app.asar`, `resources/`, `LICENSES.chromium.html` | chromium `.pak` files |
| Web app | `index.html` + `package.json` | bundler configs (vite/webpack) |
| .NET desktop | `mscoree.dll` import, `*.exe.config`, `*.deps.json` | `*.csproj`, `*.xaml` |
| Java desktop | `META-INF/MANIFEST.MF`, `*.jar` | `*.class`, swing/javafx in strings |
| Delphi | PE strings: `Borland`, `Delphi`, `CodeGear`, `Embarcadero` | `*.dpr`/`*.dfm`/`*.fmx` |
| PyInstaller | PE strings: `MEIPASS`, `pyi-` | `python3*.dll` next to exe |
| Cocos | `libcocos2d*`, `*.cconb`, `*.fire` | `cocos` in lib names |
| Win32 native | imports kernel32/user32/gdi32 | PE + absence of all above |

## Reading an inspection result

`--inspect` returns a ranked candidate list with scores. Interpretation:

- **score ≥ 3** (one strong or several weak signals): treat as confirmed;
  route the port matrix.
- **score 1–2 with a single weak signal**: corroborate before committing —
  the table's strong signals for the *next* candidate are the fastest
  tiebreak. `file_count` matters: a 3-file folder matching "Win32" is
  really "unknown single binary".
- **score 0 / unknown**: opaque binary. Route to the rebuild-from-evidence
  section of porting-playbook.md, and say so — mislabeling an unknown as
  Win32-native sends the port down the wrong track.

## Sharpening by hand

When two engines tie (e.g. Electron vs web for an unpacked app):

1. Check what *executes*: `.exe` loading `app.asar` → Electron;
   `index.html` served/opened directly → web.
2. Check the toolchain residue: `package.json` `main:` + electron in
   devDependencies → Electron; vite/webpack + no electron → web.
3. For single binaries, strings beat filenames: `Godot Engine` string in
   an unnamed exe is Godot; `This program cannot be run in DOS mode` is
   just "is a PE".

Android sources (for reverse-direction ports, e.g. android→windows):
`AndroidManifest.xml` + `build.gradle` → Android Studio project;
`*.apk` → run triage (format=apk), unzip for structure;
`*.aab` → bundletool to inspect.

## After detection

Feed the result to the plan: `port_plan.py --from win --to android --app <path>`
uses the same inspection internally. If your manual read disagrees with the
script's call (conflicting evidence), trust the manual read, say why in the
plan (which evidence outweighed which), and proceed — the evidence trail
in the plan keeps the disagreement auditable.
