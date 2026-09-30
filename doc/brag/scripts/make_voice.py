#!/usr/bin/env python3
"""Regenerate the narration WAVs in composition/assets/voice/ from brag-plan.md.

The words live in one place, the numbered list under "## Voiceover script" in
brag-plan.md; item N named **<name>** becomes vo-N-<name>.wav. Each clip is
synthesized with the pinned hyperframes CLI (Kokoro, am_michael at 0.96), then
transcribed with word timings, and the measured durations are printed so the
timeline in index.html can be re-cut to them.

    python3 scripts/make_voice.py              # all seven clips
    python3 scripts/make_voice.py 2 6          # just clips 2 and 6
    python3 scripts/make_voice.py --dry-run    # show the parsed lines only
    python3 scripts/make_voice.py --measure    # durations of the existing WAVs

Transcripts go to voice-transcripts/<clip>.json (word-level, whisper base.en,
the model the original caption anchors were measured with), and each clip's
heard text is printed beside the script line so a dropped phrase is obvious.

Dependencies come from config/cfg/devel_environ.yml (ffmpeg, whisper.cpp,
onnxruntime, pysoundfile, and kokoro-onnx / espeakng-loader / phonemizer from
pip). Run inside that env and hyperframes finds them through `python3` on PATH.
Outside it, point HYPERFRAMES_PYTHON at a python that has them. Keep that
python at a SHORT path: espeak-ng keeps its data path in a fixed buffer, and a
long prefix (a sandbox scratchpad is ~200 chars) silently falls back to a
compiled-in build-machine path that does not exist.

Without whisper.cpp's `whisper-cli` on PATH, `hyperframes transcribe` clones
and builds it under ~/.cache/hyperframes/whisper/ on first use (cmake and a C
compiler).

Behind the sandbox proxy, Node's downloads ignore http(s)_proxy, so
anything the CLI would fetch itself fails with ECONNREFUSED even for
allow-listed hosts. Fetch those with curl into the cache first:

    B=https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0
    curl -fLo ~/.cache/hyperframes/tts/models/kokoro-v1.0.onnx --create-dirs $B/kokoro-v1.0.onnx
    curl -fLo ~/.cache/hyperframes/tts/voices/voices-v1.0.bin --create-dirs $B/voices-v1.0.bin
    curl -fLo ~/.cache/hyperframes/whisper/models/ggml-base.en.bin --create-dirs \
        https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.en.bin

The npm install hits the same problem in onnxruntime-node's postinstall,
which fetches optional CUDA binaries from github.com. Kokoro runs on the CPU
binaries bundled in the package, so this script sets
ONNXRUNTIME_NODE_INSTALL_CUDA=skip.

build.sh sets npm_config_ignore_scripts=true to skip every postinstall, which is
right for rendering and wrong here, so this script drops it from the child
environment. HYPERFRAMES="<cmd>" overrides the CLI invocation, e.g. to use an
existing local install.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import wave
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent  # doc/brag
PLAN = HERE / "brag-plan.md"
COMPOSITION = HERE / "composition"
VOICE_DIR = COMPOSITION / "assets" / "voice"
TRANSCRIPTS = HERE / "voice-transcripts"

HYPERFRAMES = os.environ.get("HYPERFRAMES", "npx --yes hyperframes@0.8.47").split()
VOICE = "am_michael"
SPEED = "0.96"

ITEM = re.compile(r'^(\d+)\.\s+\*\*([\w-]+)\*\*\s+—\s+"(.*)"\s*$', re.S)


def parse_script(plan: Path) -> list[tuple[int, str, str]]:
    """Return (number, name, text) for each item of the Voiceover script list."""
    body = plan.read_text(encoding="utf-8")
    m = re.search(r"^## Voiceover script\n(.*?)(?=^#)", body, re.M | re.S)
    if not m:
        sys.exit(f"no '## Voiceover script' section in {plan}")
    # List items wrap onto indented continuation lines; fold each item into one.
    items, cur = [], None
    for line in m.group(1).splitlines():
        if re.match(r"^\d+\.\s", line):
            cur = [line.strip()]
            items.append(cur)
        elif cur is not None and line.startswith("   ") and line.strip():
            cur.append(line.strip())
        else:
            cur = None
    clips = []
    for parts in items:
        joined = " ".join(parts)
        im = ITEM.match(joined)
        if not im:
            sys.exit(f"cannot parse voiceover item: {joined}")
        clips.append((int(im.group(1)), im.group(2), im.group(3)))
    return clips


def child_env() -> dict[str, str]:
    env = dict(os.environ)
    env.pop("npm_config_ignore_scripts", None)
    env.pop("NPM_CONFIG_IGNORE_SCRIPTS", None)
    env.setdefault("ONNXRUNTIME_NODE_INSTALL_CUDA", "skip")
    return env


def tts_flags() -> tuple[str, str | None]:
    """Work out the output and speed flag spellings from `tts --help`.

    The flag names were never recorded when the clips were first made, so read
    them off the CLI rather than guess.
    """
    proc = subprocess.run(
        [*HYPERFRAMES, "tts", "--help"],
        cwd=COMPOSITION, env=child_env(), capture_output=True, text=True,
    )
    text = proc.stdout + proc.stderr
    if proc.returncode != 0 and "--voice" not in text:
        sys.exit(f"`hyperframes tts --help` failed:\n{text}")
    out = "--output" if "--output" in text else "-o" if re.search(r"(^|\s)-o[,\s]", text) else None
    if out is None:
        sys.exit(f"cannot find an output flag in `tts --help`:\n{text}")
    speed = "--speed" if "--speed" in text else None
    if speed is None:
        print(f"warning: `tts --help` lists no --speed; generating at the default, not {SPEED}",
              file=sys.stderr)
    return out, speed


def transcribe(wav: Path, script_text: str) -> None:
    """Word-time one clip into voice-transcripts/<clip>.json and show what was heard."""
    TRANSCRIPTS.mkdir(exist_ok=True)
    # The CLI always writes <dir>/transcript.json, so give each clip its own dir.
    with tempfile.TemporaryDirectory() as tmp:
        tr = subprocess.run(
            [*HYPERFRAMES, "transcribe", str(wav), "--model", "base.en",
             "--engine", "whisper", "--json", "--dir", tmp],
            cwd=COMPOSITION, env=child_env(), capture_output=True, text=True,
        )
        produced = Path(tmp) / "transcript.json"
        if tr.returncode != 0 or not produced.exists():
            print(f"warning: transcribe failed for {wav.name}:\n{tr.stdout[-800:]}{tr.stderr[-800:]}",
                  file=sys.stderr)
            return
        words = json.loads(produced.read_text(encoding="utf-8"))
        (TRANSCRIPTS / f"{wav.stem}.json").write_text(json.dumps(words, indent=2) + "\n",
                                                     encoding="utf-8")
    print(f"    script: {script_text}")
    print(f"    heard:  {' '.join(w['text'] for w in words)}")


def duration(path: Path) -> float:
    with wave.open(str(path), "rb") as w:
        return w.getnframes() / w.getframerate()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("clips", nargs="*", type=int, help="clip numbers to regenerate (default: all)")
    ap.add_argument("--dry-run", action="store_true", help="print the parsed lines and stop")
    ap.add_argument("--measure", action="store_true", help="only print durations of the existing WAVs")
    ap.add_argument("--no-transcribe", action="store_true", help="skip the word-timing pass")
    args = ap.parse_args()

    clips = parse_script(PLAN)
    wanted = [c for c in clips if not args.clips or c[0] in args.clips]
    if args.clips and len(wanted) != len(set(args.clips)):
        sys.exit(f"unknown clip number in {args.clips}; the script has 1-{len(clips)}")

    if args.dry_run:
        for n, name, text in wanted:
            print(f"vo-{n}-{name}.wav  {text}")
        return

    if not args.measure:
        out_flag, speed_flag = tts_flags()
        for n, name, text in wanted:
            wav = VOICE_DIR / f"vo-{n}-{name}.wav"
            cmd = [*HYPERFRAMES, "tts", text, "--voice", VOICE, out_flag, str(wav)]
            if speed_flag:
                cmd += [speed_flag, SPEED]
            print(f"--> {wav.name}", flush=True)
            subprocess.run(cmd, cwd=COMPOSITION, env=child_env(), check=True)
            if not args.no_transcribe:
                transcribe(wav, text)

    print("\nclip                   seconds")
    total = 0.0
    for n, name, _ in clips:
        wav = VOICE_DIR / f"vo-{n}-{name}.wav"
        d = duration(wav)
        total += d
        print(f"{wav.stem:<22} {d:7.3f}")
    print(f"{'total speech':<22} {total:7.3f}")


if __name__ == "__main__":
    main()
