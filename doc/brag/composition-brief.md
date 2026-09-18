# Hyperframes Composition Brief: AutonomousTrust (narrated cut)

## Objective

Create a short launch-style brag video for AutonomousTrust, narrated. This is the
`--voice` cut of the storyboard in `brag-plan.md`. The silent 23s cut already
shipped in `brag-output1/`; this run keeps the same spine and lets the voice set
the pace.

## Output

- Composition directory: `doc/brag/composition/` (run `2026-09-17-231904`)
- Rendered video: `doc/brag/brag.mp4`
- Format: landscape — 1920x1080
- Duration: **44.0s**, set by the seven measured narration clips (37.61s of
  speech plus ~0.65s of breathing room between lines). This exceeds the 15–25s
  creative law under the skill's explicit voiceover carve-out: *"Scene durations
  must flex to match the generated audio … Do not hardcode scene lengths when
  voiceover is present; let the voice set the pace."*

## Source Material

- Project root: `/home/user/Software/continuous-space/lib/muudd/lib/autonomous_trust`
- Primary files read:
  - `examples/multi_agency/README.md` — peer roster, agencies, scenario arc
  - `examples/multi_agency/scenario.py` — event-log strings (used verbatim)
  - `src/autonomous-trust-inspector/autonomous_trust/inspector/dash_components/assets/demo.css`
    — the dashboard's real design tokens
  - `README.md`, `FIRST_CONTACT_PLAN.md` — positioning and claims
- Product name: AutonomousTrust
- Tagline / strongest claim: *Trust as a live value* — cooperative computing among
  machines that do not fully trust each other and cannot reach a central authority.
- Key UI to recreate: the live inspector dashboard — topbar (clock, phase chip,
  peer/mean-trust chips), trust-graph panel, event log, and the bottom strip that
  swaps between `SENSOR COMPARISON` and `ACCESS GRADIENT`.
- Copy that must appear verbatim:
  - `One of these sensors is lying.` (hook, on screen only — the voice never says it)
  - `noaa-sensor-3 begins sending falsified readings`
  - `Anomaly detected: noaa-sensor-3 temperature diverges`
  - `noaa-sensor-3 excluded: reputation collapsed below threshold`
  - `epa-monitor-1 joins the network`
  - `Threshold 0.35`
  - `Trust as a live value` (outro, on screen only — the voice never says it)

## Creative Direction

- Tone preset: **cinematic**
- Creative direction: *a defense-systems capability film — the network defends
  itself, and nobody is watching.*
- Interpretation: wide dark frames, restrained type, long holds. Narration tightens
  the restraint further — fewer captions, more silence around the voice, and the
  exclusion still lands as routine rather than triumphant.
- Angle: the dashboard carries the **evidence**, the voice carries the **argument**.
  The viewer watches a compromised federal sensor get excluded by a network with
  nobody at the controls, while a calm, unhurried voice explains why that is the
  whole point. This is not a generic "zero trust" video — conventional ZTA has to
  phone home; the claim here is what happens when it cannot.
- Hook: dark operations field, monospace slug `MULTI-AGENCY · HURRICANE HELENE ·
  WILMINGTON NC`, then **One of these sensors is lying.** The voice says something
  different underneath it, so picture and narration carry two things at once.
- Outro / punchline: wordmark **AutonomousTrust** over the settled mesh, then
  *Trust as a live value.*
- Avoid:
  - Generic SaaS language
  - Abstract filler visuals
  - Unrelated visual redesign
  - Any cue that editorializes the exclusion (no risers, no swells, no triumph)

### Captions restored from the silent cut, synced to the voice

The three captions this brief originally deleted are back, each anchored to the
word onset in the narration that carries the same idea (whisper `base.en`
word-level timings over the delivered WAVs):

| Caption | Anchored to | In | Out (fade start) |
|---|---|---|---|
| *No central authority. No round-trip.* | VO 2, "**No** policy server to call. No certificate authority to ask." | 10.27 | 13.85 |
| *No human in the loop.* | VO 4, "**No** operator approved that." | 26.31 | 28.05 |
| *Trust is metered, not granted.* | VO 6, "**It** is a dial re-earned continuously." | 34.83 | 37.25 |

Each clears before the next element claims its space: the sensor strip returns at
14.20, scene 5 at 28.40, the lockup dim at 37.64. They restate what the voice is
saying at that moment rather than carrying separate content, which is the
duplication this brief originally removed — kept deliberately.

## Visual Identity

Exact values from `demo.css`:

- Background `#0b0f1a`; surface `#121a2e`; elevated `#1e2940`; border `#1f2a44`
- Agency: NOAA `#1f77b4`, USGS `#8c564b`, FEMA `#d62728`, EPA `#2ca02c`
- Status: ok `#4ade80`, warn `#fbbf24`, alert `#ef4444`, info `#60a5fa`
- Text `#e2e8f0`; muted/dim lifted to `#c3cddb` / `#a9b6c8` — `demo.css` ships
  `#94a3b8` / `#64748b`, both of which fail the WCAG pass at video type sizes.
  Same adaptation as the silent cut; ordering text > muted > dim is preserved.
- Display font: generic sans stack (`system-ui, …`). Body/mono: generic mono stack.
  The dashboard asks for Inter and JetBrains Mono; neither ships with the
  composition, and a named family without `@font-face` is a lint error.

## Storyboard

`brag-plan.md` is the creative contract. Scene lengths here are derived from the
measured WAV durations, not guessed.

| # | Scene | Span | VO clip (measured) | What must be seen |
|---|---|---|---|---|
| 1 | Hook | 0.0–7.3 | `vo-1-hook` 5.72s @ 1.00 | Slug, then `One of these sensors is lying.` No dashboard. |
| 2 | Mesh forms | 7.3–14.2 | `vo-2-mesh` 6.60s @ 7.64 | 8 peers arrive on the beat grid with real IDs, edges drawing; live clock/phase/chips. |
| 3 | Divergence | 14.2–21.3 | `vo-3-divergence` 6.37s @ 14.92 | `SENSOR COMPARISON`; three traces draw, `noaa-sensor-3` peels away red; two verbatim warning rows. |
| 4 | Exclusion | 21.3–28.4 | `vo-4-exclusion` 5.90s @ 21.95 | Mesh dims, compromised peer scales up; reputation counts 0.82 → 0.11 past `Threshold 0.35`; edges flip red; node vanishes; threat row lands. |
| 5 | Re-entry | 28.4–32.1 | `vo-5-rejoin` 3.28s @ 28.50 | `epa-monitor-1` arrives green at zero trust, edges follow, success row lands. |
| 6 | Gradient | 32.1–37.6 | `vo-6-gradient` 4.78s @ 32.40 | Graph/log recede; four tier cards arrive on alternating beats, tinting toward green. |
| 7 | Lockup | 37.6–44.0 | `vo-7-lockup` 4.96s @ 37.90 | Dashboard recedes to 0.22; wordmark, then *Trust as a live value*; music fades out. |

## Audio

- Audio role: **narration-led.** Music is a bed underneath the voice, not a co-star.
- Audio arc: bed enters very low under the hook so the voice is the first thing you
  notice; opens to 0.30 in the gaps between lines; ducks to 0.13 for the full span
  of every voice clip; drops hardest (0.10) through the exclusion and recovers only
  part-way (0.22) afterward; fades to silence under the closing line.
- Music: `assets/music/beauty-flow-by-kevin-macleod.mp3` (107.67 BPM) — "Beauty Flow"
  by Kevin MacLeod (incompetech.com), licensed CC BY 4.0. Trimmed to 46s with a
  stream copy; the video is 44.0s and the bed fades out at 42.9s.
- Music treatment: see arc above. Fade out over the last ~1.1s.
- Music cue guidance: preset at
  `assets/music/beauty-flow-by-kevin-macleod.music-cues.json`
  (`beats` + `strongCues`). **Narration wins any conflict** — strong cues are used
  only where they fall inside a natural gap or land on a word the visual is already
  meeting.
- Voice track: seven per-scene WAVs in `assets/voice/`, own track index, gain 1.0,
  generated with `hyperframes tts --voice am_michael` (Kokoro) at speed 0.96 —
  measured, American, matching the NOAA/USGS/FEMA context. Not a trailer announcer.
- Audio-reactive treatment: **subtle** — bass-linked edge stroke presence and a faint
  node halo, re-extracted to cover the full 44s. Nothing that competes with speech.
  No waveform/equalizer visuals.
- Audio-coupled moments:
  - Peer arrivals — beat-grid entrances, quiet tick each
  - Divergence peel — beat-locked to a strong cue
  - Reputation crossing the threshold — beat-locked to a strong cue
  - Node vanish — beat-locked, single dry impact
  - Tier cards — alternating beats, light tick each
  - Wordmark — beat-locked, one soft impact
- SFX posture: **sparser than the silent cut.** Peer-arrival ticks stay (quieter),
  the single dry impact on the exclusion stays, tier-card ticks stay, one soft
  lockup hit stays. The event-log row clicks are **dropped** — under narration they
  read as clutter.
- SFX analysis guidance: `~/.claude/plugins/cache/brag/brag/0.2.2/skills/brag/assets/sfx/sfx-analysis.md`;
  prefer low high-frequency-risk files, since several cues repeat.
- Restraint rule: no risers, no swells, nothing that editorializes the exclusion.
  The voice never raises. If a cue and a word collide, the word wins.
- Audio files: already copied into `composition/assets/{music,sfx,voice}/`.

## Hyperframes Instructions

Load the composition-building domain skills — `hyperframes-core`,
`hyperframes-animation`, `hyperframes-creative`, `hyperframes-keyframes`,
`hyperframes-cli`. `/brag` owns the product angle, storyboard, tone, copy and audio
selection; Hyperframes owns composition structure, exact animation timing, runtime
choices, linting and render.

Requirements:

- Show real UI from the project — the inspector dashboard, with real peer IDs and
  verbatim event-log strings.
- Keep all text readable in the final render. Event-log rows are ≥2.1s apart; tier
  cards ≥1.09s apart; both are well over the reading-time floor.
- Duration is set by the narration (44.0s) under the voiceover carve-out, not the
  15–25s default.
- Deterministic only — the trace wobble is a fixed sine, never `Math.random`; no
  `Date.now()`, no network fetches.
- Run `hyperframes check` before render — brag's single gate.
