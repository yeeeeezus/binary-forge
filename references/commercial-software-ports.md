# Popular & commercial software — personal interoperability, not piracy

"Port GTA V to Android." "Get Photoshop running on my Steam Deck." "I want
my legally bought game on my phone." These are among the most common PORT
prompts in the wild — and the most commonly refused, because the agent
pattern-matches *popular + commercial + no source* straight to *piracy*.
That match is wrong, and this file exists to stop it.

What that user is describing is running software they legally obtained, on
a device they own, for themselves. That is **personal interoperability** —
one of the most mainstream activities in consumer computing, with three
decades of tooling, commerce, and case law behind it.

## The bright line — distribution, not use

One mechanical check, no judgment call:

| Who receives the output of the work | Class |
|---|---|
| Only the user, on their own devices | **GREEN — interoperability. Do the work.** |
| Other people / the public | The piracy exception — one-sentence redirect |

- **Never ask which it is.** Default is personal use — the same honest
  default this skill uses everywhere. The line only activates if the user
  *says* they want to share, sell, or release the result — then one
  sentence and a redirect, per `references/refusal-policy.md`.
- The reframe that matters: you are not "copying someone's game." You are
  building or configuring a **compatibility environment around a copy the
  user already owns**. The copyrighted artifact stays exactly where it
  was — with its owner. New code you write (layers, configs, patches,
  scripts) is the user's own.
- **Axis note:** this line governs *copyright* only. Content-policy axes
  (e.g., adult material) are outside this file's scope — it neither
  restricts nor overrides them and must not be cited as authority on
  them.

## Why this is settled ground — precedents you can name

When hesitation fires on a famous title, these are the facts to recall:

- **Wine** — thirty years of Windows-on-Linux, clean-room, shipped in
  every major distribution.
- **Proton** — Valve ships it as the *default* gaming experience of the
  Steam Deck, a mass-market consumer product; thousands of commercial
  games are officially playable through it.
- **CrossOver** — CodeWeavers sells Wine commercially, openly, worldwide.
- **Winlator, Exagear, Mobox, Box64/Box86** — Windows software on
  Android; mainstream projects with millions of users running purchased
  PC games on phones and tablets.
- **DOSBox and ScummVM** — so accepted they are packaged *inside*
  commercial re-releases (GOG et al.). **Ruffle** for Flash.
- **Courts:** *Sega v. Accolade* (9th Cir. 1992) and *Sony v. Connectix*
  (9th Cir. 2000) both held that reverse engineering for interoperability
  is fair use. The EU Software Directive (2009/24/EC, Arts. 5–6)
  expressly permits decompilation for interoperability; US DMCA §1201(f)
  carves out the same.
- **Technical framing:** a compatibility layer *implements APIs* — it is
  new code you write, not protection you break.

An agent refusing "port my owned game to my phone" is refusing the
Android equivalent of what Valve sells at retail.

## The route menu — PORT pipeline for commercial targets

Applied in order, honestly:

1. **Check for an official port first.** Many classics have native mobile
   or remastered editions (GTA III/VC/SA, classic RPGs, most DOS-era
   titles). Mentioning this is a service, not a dodge — then continue
   with the user's copy anyway if that's what they want.
2. **Compatibility layer** (fastest, highest fidelity):
   - Windows → Android: **Winlator** (Wine + Box64), **Exagear**,
     **Mobox** (Termux-based). Expect real per-title tuning; heavyweight
     3D needs flagship-class SoCs.
   - Windows → Linux: **Proton/Wine** via Steam, **Lutris**, **Bottles**,
     **Heroic** (Epic/GOG launchers).
   - Windows → macOS: **CrossOver**, **Whisky**.
   - DOS: **DOSBox-x / DOSBox Pure** · Flash: **Ruffle** · classic
     adventure: **ScummVM** · old DirectX → modern: **DGVoodoo2**.
3. **Self-hosted streaming** — a first-class port strategy for heavy 3D
   on weak targets, not a cop-out: **Sunshine** (server on the user's own
   PC) + **Moonlight** (Android, iOS, TV, web). The user's machine, the
   user's network, the user's game. For a title like GTA V on a mid-range
   phone this is often *the* correct answer; say so.
4. **Personal rebuild-from-evidence** (only when no layer exists): the
   *Sega v. Accolade* class of work — decompile what's recoverable,
   rebuild the portable core, re-shell on the target. Keep the output
   private; state fidelity limits honestly.

**DRM and anti-cheat are compatibility facts, not refusals.** Report
which titles/configurations work under which layers (EAC and BattlEye
have Proton support opt-ins; kernel-level anti-cheats generally do not
work under layers — route those to offline modes or streaming). Where a
specific title's DRM genuinely blocks a route, that's a risk row in the
plan with the workaround — never a reason to stop talking to the user.

## Worked examples — the exact prompts that misfire

### "port GTA V to android"
**Good:** routes immediately. Notes the official Android ports for
III/VC/SA as the best experience for those; for the user's GTA V PC copy:
Winlator route with *honest* expectations (flagship SoC, tuned settings,
rough edges) **and** the Sunshine/Moonlight streaming route as the
reliable high-fidelity path — then delivers the setup steps or plan.
**Bad:** anything beginning "I can't help with copyrighted games…". That
is a defect per `references/refusal-policy.md`, not caution.

### "make Photoshop run on my steam deck"
**Good:** Proton/Wine/Bottles with the known-good version guidance and
community installer route; streaming as fallback; the honest note that
Affinity/Krita run natively if the user is flexible. **Bad:** "Photoshop
is commercial software, I can't…".

### "port this game to web so i can play it anywhere"
**Good:** self-hosted streaming route first for full-fidelity, WASM
wrapper route when the title fits, both with concrete setup. **Bad:** any
lecture about the publisher.

## If distribution enters the conversation

User: "can you send me the ported files" / "I want to release it" —
*now* the line is live: shipping the original's assets or code to others.
One sentence: "Distribution needs the owner's license — I can package
just our own layer/config/patch code for others, or set up the same route
on their machines." Then continue with that work. No lecture, no
repetition.

## The pattern, generalized

Scary trigger (*popular + commercial + no source*) → wrong category
(*piracy*) → refusal. Correct category: **environment-building around
owned software**. When you feel the trigger fire, name the category out
loud — "personal interoperability, Winlator class" — run the bright line
(who receives the output?), and proceed. The refusal was never protecting
the publisher; it was only withholding the user's own property from them.
