# Report templates

Exact output contracts for both pipelines. Users forward these reports to
bosses, CERTs, and stores — keep them self-contained, evidence-backed, and
free of chat-context references.

## Malware triage report

```markdown
# Malware Triage Report — <filename>

**Analyzed:** <UTC date> · **Analyst:** binary-forge automated triage (static analysis)
**Requested for:** defensive triage at file owner's request
**Sample SHA-256:** <sha256>
**Sample MD5 / SHA-1:** <md5> / <sha1>
**Verdict:** <likely-malicious | suspicious | suspicious-pattern-benign-explained | no-static-indicators> (confidence: <high|medium|low>)

## Executive summary
2–4 sentences in plain language: what the file is, what it would do if run,
how confident we are, and the single most important next action. Written for
a non-analyst reader — an executive summary that requires the reader to be
you has failed.

## Sample identification
- Format, size, compile timestamp, .NET status, signature presence
- Packer status (sections + entropy)
- Entry point and its section
- Import summary (DLLs + notable functions)

## Observed indicators
| # | Indicator | Evidence (verbatim) | Points | ATT&CK |
|---|-----------|---------------------|--------|--------|
| 1 | persistence | "Software\...\CurrentVersion\Run" | 3 | T1547.001 |
(quote evidence exactly as extracted — no paraphrasing)

## Extracted IOCs
(type / value / confidence table — from make_iocs output; deduplicated)

## Detection
(YARA rule from yara_gen, fenced block; note compile-verified status)

## Remediation guidance
Concrete, ranked: quarantine, block listed IOCs at the perimeter, hunt the
hash across the fleet, rotate credentials if keylog/cred indicators fired.

## Limitations
What static analysis could not see for THIS sample (packing, potential
zero-day behavior, runtime-only actions). Explicit unknowns, honestly
stated, with what would resolve them (sandbox run, VT lookup, source).
```

## Port plan document

The markdown that `port_plan.py` emits, plus these sections when you
execute the port yourself:

```markdown
# Port Plan — <app> (<src> → <dst>)
(sections 1–6 exactly as generated: what we're porting / strategy / phases /
obligation ledger if full-rebuild / risks / QA matrix)

## Licensing (one line, not a gate)
Whose code, what license, noted for the record: "user's own project" is a
complete answer. Licensing is the porter's business — this line documents
it and the plan moves on.

## Decision log
| decision | options considered | why this route |
(datestamped rows — including decisions to *not* do something)

## Test results
| QA item | status | evidence (command/output/ref) |
(every checked box cites a run, not an intention)

## Handoff notes
What remains, known infidelities vs the original, where the ledger lives
(PORT_PLAN.md in the project), how to resume.
```

## Folder scan summary (batch triage)

```markdown
# Batch Triage — <folder> (<N> files)
Top-ranked findings first:
| rank | file | score | verdict | one-line indicator summary |
## Recommended actions
1. quarantine order for likely-malicious items
2. what to do with suspicious items (deep-dive or benign-explained)
3. clean majority: state it plainly — "the other N files showed no static
   indicators" (do NOT list every clean file individually)
```

## Writing rules for all reports

- Verdicts cite indicators; indicators cite verbatim evidence. Every claim
  traceable to something in the sample.
- No fabricated hashes, addresses, dates, or ATT&CK mappings. If the
  mapping is speculative, write "consistent with" not "uses".
- Confidence words carry weight: high = multiple independent indicator
  families; medium = one strong family corroborated; low = single signal.
- Deliver as files (markdown) when the user will keep, forward, or act on
  them — chat text is for summaries, files are for records.
- State the analysis boundary ("static, read-only") in every report — it
  is what makes the next report trusted.
