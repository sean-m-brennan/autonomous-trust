# Brag Plan: AutonomousTrust (narrated cut)

Run: `2026-09-17-231904`. Invoked as `/brag --voice`, so narration is on for this
run only. The silent 23s cut from the earlier run lives in `brag-output1/`.

## What is this app?

AutonomousTrust (AT) is a framework for cooperative computing among machines that
do not fully trust each other and cannot reach a central authority to vouch for
anyone — trust is a live value, continuously re-evaluated from observed behavior,
and every access decision is made at the node with no round-trip to a policy or
PKI service.

## The angle

Same spine as the silent cut, but narration changes the division of labor: the
dashboard carries the *evidence* and the voice carries the *argument*. On-screen
captions that the voice would otherwise duplicate are removed. The viewer watches
a compromised federal sensor get excluded by a network with nobody at the controls,
while a calm, unhurried voice explains why that is the whole point.

This is not a generic "zero trust" video. Conventional ZTA has to phone home; the
claim here is what happens when it cannot.

## Hook (first 2-4 seconds)

Dark operations field. Monospace slug `MULTI-AGENCY · HURRICANE HELENE ·
WILMINGTON NC`, then **One of these sensors is lying.**

The voice does *not* say that line. It sets the stakes underneath it instead, so
the picture and the narration are saying two different things at once.

## Key moments (the middle)

- **Eight peers arrive one by one** into the trust-graph panel, agency-colored,
  edges drawing as the mesh forms.
- **The divergence.** Three NOAA temperature traces track together, then
  `noaa-sensor-3` peels away in red. The verbatim event-log lines land beside it.
- **The collapse.** Reputation falls 0.82 → 0.11 through the threshold, edges flip
  red, the node is gone. The music ducks; nothing celebrates.
- **The re-entry.** `epa-monitor-1` joins post-exclusion and starts at zero.
- **The gradient.** Four tier cards — the reason this is not allow/deny.

## Outro / punchline

Wordmark **AutonomousTrust** over the settled mesh, and *For dynamically cooperative machines.*

## User flow worth showing

Entry → key action → result, from the working demo (`python -m examples.multi_agency`,
dashboard at `localhost:8050`):

1. **Entry** — NOAA, USGS and FEMA peers discover each other and form a trust mesh.
2. **Key action** — `noaa-sensor-3` reports falsified temperatures; cross-source
   validation flags the divergence.
3. **Result** — reputation collapses below threshold, the network excludes it, and
   sharing resumes with the remaining peers plus a new EPA monitor.

## Tone

- Preset: **cinematic**
- Creative direction: *a defense-systems capability film — the network defends
  itself, and nobody is watching.*
- Interpretation: Wide dark frames, restrained type, long holds. With narration the
  restraint tightens further: fewer captions, more silence around the voice, and
  the exclusion still lands as routine rather than triumphant.
- Voice: `am_michael` (Kokoro) at speed 0.96 — measured, American, matching the
  NOAA/USGS/FEMA context. Not a trailer announcer.

## Format: landscape — 1920x1080
## Duration: set by the narration (~42-46s target; see build notes for the final figure)

The 15–25s creative law is deliberately exceeded here under the skill's own
voiceover carve-out: *"Scene durations must flex to match the generated audio …
Do not hardcode scene lengths when voiceover is present; let the voice set the
pace."* Scene lengths below are placeholders until the WAVs are measured.

## Visual identity (from the project)

From `src/autonomous-trust-inspector/autonomous_trust/inspector/dash_components/assets/demo.css`:

- Background `#0b0f1a`; surface `#121a2e`; elevated `#1e2940`; border `#1f2a44`
- Agency: NOAA `#1f77b4`, USGS `#8c564b`, FEMA `#d62728`, EPA `#2ca02c`
- Status: ok `#4ade80`, warn `#fbbf24`, alert `#ef4444`, info `#60a5fa`
- Text `#e2e8f0`; muted and dim lifted to `#c3cddb` / `#a9b6c8` for WCAG AA at
  video type sizes (same adaptation as the silent cut)
- Display: generic sans stack; body/mono: generic mono stack (Inter and JetBrains
  Mono are not shipped with the composition)

## Share copy (draft)

AutonomousTrust: federal sensors from four agencies share data through a hurricane,
one of them is lying, and the network works out which — with no central authority
and nobody watching.

## Audio direction

- Role: **narration-led.** Music is a bed underneath the voice, not a co-star.
- Music: `beauty-flow-by-kevin-macleod.mp3` (107.67 BPM) — Kevin MacLeod,
  incompetech.com, CC BY 4.0. Arpeggiated analog synth: a steady technical bed
  that leaves the speech band clear rather than competing with the voice.
- Music treatment: 0.30 in the gaps between narration lines, ducked to **0.13**
  for the full span of every voice clip, and further held down through the
  exclusion. Fade out over the last ~1.0s.
- Voice track: per-scene WAVs on their own track at gain 1.0, so scene boundaries
  can be timed to measured audio rather than guessed.
- Music cue guidance: the beat grid (≈0.545s) still drives the peer arrivals and
  the tier cards, but **narration wins any conflict**. Strong cues are only used
  where they fall inside a natural gap in the script.
- Audio-reactive treatment: subtle, unchanged — bass-linked edge presence and a
  faint node halo. Nothing that competes with speech.
- SFX posture: **sparser than the silent cut.** Peer-arrival ticks stay (quiet),
  the single dry impact on the exclusion stays, tier-card ticks stay. The event-log
  row clicks are dropped — under narration they read as clutter.
- Restraint rule: no risers, no swells, nothing that editorializes the exclusion.
  The voice never raises. If a cue and a word collide, the word wins.

## Voiceover script

Seven clips, generated with `hyperframes tts --voice am_michael`. Each is written
to complement what is on screen rather than read it.

1. **hook** — "Four federal agencies. One hurricane. And a live data feed nobody can verify by hand."
2. **mesh** — "The peers find each other and build a trust graph. No policy server to
   call. No certificate authority to ask. Every decision happens at the node."
3. **divergence** — "Then one of them starts reporting temperatures that don't match
   its neighbors. Nobody flags it. Cross-source validation just notices."
4. **exclusion** — "Its reputation falls through the threshold, and the network drops
   it. No operator necessary."
5. **rejoin** — "A new peer joins moments later, and starts at zero, like everyone
   else."
6. **gradient** — "Because trust here is not a yes or a no. It is a dial, and every
   peer's position on it is re-earned continuously."
7. **lockup** — "AutonomousTrust. Cooperative computing for machines that are out of reach."

The silent cut's three captions — *No central authority. No round-trip.* / *No
human in the loop.* / *Trust is metered, not granted.* — were removed here as
duplication, then **restored on request** and timed to the word onset in the
narration that carries the same idea (12.08s, 33.56s, 44.84s; see the table in
`composition-brief.md`). The hook line and the closing tagline stay on screen —
the voice says neither.

### As synthesized

The first synthesis came back shorter than the script: Kokoro dropped or
compressed a sentence in most clips, and the 44.0s cut was timed to that audio.
The clips were regenerated on 2026-09-30 with `scripts/make_voice.py`, which reads
the list above, and this time every line was delivered whole. Transcribed from
the WAVs (`hyperframes transcribe`, whisper `base.en`; word timings in
`voice-transcripts/`):

1. *"Four federal agencies, one hurricane, and a live data feed nobody can verify by hand."*
2. *"The peers find each other and build a trust graph. No policy server to call. No certificate authority to ask. Every decision happens at the node."*
3. *"Then one of them starts reporting temperatures that don't match its neighbors. Nobody flags it. Cross-source validation just notices."*
4. *"Its reputation falls through the threshold, and the network drops it. No operator necessary."*
5. *"A new peer joins moments later and starts at zero like everyone else."*
6. *"Because trust here is not a yes or a no. It is a dial and every peer's position on it is re-earned continuously."*
7. *"Autonomous trust, cooperative computing for machines that are out of reach."*

## Storyboard

Durations are set by the measured narration clips; the beats below fix the order
and what must be visible.

### Scene 1 — Hook
Slug fades in, then the hook line lands and holds through VO 1. No dashboard yet.
Sequential/interaction: none.
Audio intent: bed enters very low; the voice is the first thing you notice.
Transition: dramatic → Scene 2

### Scene 2 — The mesh forms itself
Dashboard enters. Eight peers arrive one per beat with their real IDs, edges
drawing in. Topbar clock, phase chip and keystat chips run live. No caption.
Sequential/interaction: yes — eight nodes on the beat grid, edges following.
Audio intent: quiet competence under VO 2; soft tick per arrival.
Transition: clean cut → Scene 3

### Scene 3 — The divergence
Bottom strip brings up `SENSOR COMPARISON`. Three traces draw; `noaa-sensor-3`
peels away in red. Two verbatim warning rows land in the event log.
Sequential/interaction: yes — traces draw, then log rows.
Audio intent: no sting on the divergence. The voice stays flat.
Transition: hard cut → Scene 4

### Scene 4 — The exclusion
Strip clears. The mesh dims; `noaa-sensor-3` holds full brightness and scales up.
Reputation card counts 0.82 → 0.11 past `Threshold 0.35`; edges flip red; node and
edges vanish. Verbatim threat row lands.
Sequential/interaction: yes — counter, flip, vanish, re-settle, in that order.
Audio intent: music ducks hardest here; one dry impact at the vanish; nothing else.
Transition: soft → Scene 5

### Scene 5 — The re-entry
Mesh comes back up. `epa-monitor-1` arrives green, edges follow, success row lands.
Sequential/interaction: yes — one arrival.
Audio intent: recovery under VO 5.
Transition: clean → Scene 6

### Scene 6 — The gradient
Graph and log panels recede to 0.35. Four tier cards arrive on alternating beats,
tinting toward green as the tier rises: REFUSE TRAFFIC / REFUSE COMPUTE /
WITHHOLD DATA / SHARE DATA.
Sequential/interaction: yes — four cards, ~1.09s apart, all persisting.
Audio intent: bed opens slightly in the gaps; light tick per card.
Transition: clean → Scene 7

### Scene 7 — Lockup
Dashboard recedes to 0.22. Wordmark **AutonomousTrust**, then *For dynamically
cooperative machines.* Music fades out under the last line.
Audio intent: settle and release.

**Music mood for this video:** cinematic — low, restrained, subordinate to speech.

**Audio summary:** A low bed sits under seven narration clips, ducking to 0.13 for
every spoken span and opening a little in the gaps, dropping hardest through the
exclusion, and fading out under the closing line.

---

## Build notes (final figures)

Written after the narration was generated and measured, replacing the placeholder
scene lengths above.

**Final duration: 56.7s** (retimed 2026-09-30 from 44.0s). Seven Kokoro clips
(`am_michael`, speed 0.96) totalling 50.33s of speech, with the same breathing
room between lines as the 44.0s cut (0.62–0.92s).

| Clip              | Measured | Starts at | Ends  |
| ----------------- | -------- | --------- | ----- |
| `vo-1-hook`       | 6.805s   | 1.00      | 7.81  |
| `vo-2-mesh`       | 10.261s  | 8.73      | 18.99 |
| `vo-3-divergence` | 8.661s   | 19.67     | 28.33 |
| `vo-4-exclusion`  | 6.379s   | 28.99     | 35.37 |
| `vo-5-rejoin`     | 5.035s   | 36.01     | 41.05 |
| `vo-6-gradient`   | 8.043s   | 41.66     | 49.70 |
| `vo-7-lockup`     | 5.141s   | 50.42     | 55.56 |

Scene spans that follow from those clips: hook 0–8.4 · mesh 8.4–18.9 ·
divergence 18.9–28.3 · exclusion 28.3–35.9 · re-entry 35.9–41.3 ·
gradient 41.3–50.1 · lockup 50.1–56.7.

The retime carried every timeline constant through the word it was anchored to
(old and new whisper transcripts aligned word by word), kept elements that sit
in a gap at their offset from the neighbouring clip boundary, and re-snapped
beat-locked moments to the 107.67 BPM grid. The cue preset's analysis window ends
at 44.0s; beats past it are extrapolated from the fitted grid (0.009s maximum
residual over 81 beats, and zero phase error against the audio's onsets in
44–57s).

### Where the picture meets the word

- Peer arrivals ride the beat grid under VO 2: 9.47 … 13.36, one per beat.
- The falsified trace peels away on strong cue **21.70s**, landing under
  *"temperatures that don't match its neighbors."*
- The reputation count is tuned (start 30.03 on *"falls"*, duration 2.384,
  `power2.in`) so 0.82 crosses `Threshold 0.35` **exactly** on strong cue
  **31.97s** — which is where the voice finishes *"falls through the threshold."*
- The node vanishes on beat **32.81s**, under *"the network drops it."*
  One dry impact, nothing else.
- Mean trust dips 0.86 → 0.79 when `epa-monitor-1` arrives (beat 37.25), because
  the new peer starts at zero — which is what VO 5 is saying over that beat.
- Tier cards on alternating beats 42.81 / 43.92 / 45.03 / 46.14.
- Wordmark on beat 51.14; tagline on beat 53.36; music credit on beat 54.47.
- Every sfx start equals the constant it accompanies. Before the retime the
  arrival ticks, the exclusion impact, the tier ticks and the lockup hit still
  sat on the previous music track's grid, up to 0.17s off their visuals.

### Audio outcome (measured off the render)

Voice spans sit at ≈ −23 dB mean with peaks −3.6 to −7.9 dB; the gaps between
lines drop to ≈ −31 to −33 dB (bed only), so speech clears the music by ~8 dB
throughout. Final fade reaches −40 dB.

### Captions dropped, as planned

*No central authority. No round-trip.* / *No human in the loop.* / *Trust is
metered, not granted.* — all three removed; the voice carries them. The hook line
and the closing tagline remain on screen and the voice says neither.

### Deliverables

- `brag.mp4` — 1920x1080, 44.0s, h264 + AAC, 3.5 MB
- `brag.jpg` — poster pulled at 20.3s (the settled divergence frame) and
  attached to the MP4 as cover art (an `attached_pic` mjpeg stream), so every
  platform's thumbnail grabber picks it up. `build.sh` does this on a stream
  copy, so it costs no re-encode
- `composition-brief.md`, `share-copy.txt`, `composition/`

`hyperframes check`: **0 errors**, 137/137 text checks pass WCAG AA. The one
remaining warning is `composition_file_too_large` (702 lines), same as the silent
cut — accepted rather than split, since the composition is a single continuous
dashboard.
