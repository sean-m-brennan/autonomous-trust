#!/usr/bin/env python3
"""Generate composition/assets/audio-data.js from the background music track.

The composition's audio-reactive layer (index.html, "Audio-reactive layer")
reads window.AUDIO_DATA to breathe the mesh edge opacity and the node halos in
time with the bass. The data is pre-extracted rather than analysed at runtime so
renders stay deterministic and seek-safe.

Regenerate this whenever the music track changes:

    python3 scripts/make_audio_data.py \
        composition/assets/music/<track>.mp3 \
        --output composition/assets/audio-data.js

Only ffmpeg and numpy are required; librosa is not.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import numpy as np

SR = 22050
FPS = 30
BANDS = 16
# Video length plus a little margin; the composition never reads past T_END.
DEFAULT_SECONDS = 44.3
# Log-spaced band edges: index 0 is bass, 15 is treble.
BAND_LO, BAND_HI = 30.0, 10000.0


def decode(path: Path, seconds: float) -> np.ndarray:
    """Decode to mono float32 PCM at SR via ffmpeg."""
    proc = subprocess.run(
        ["ffmpeg", "-v", "error", "-i", str(path), "-t", f"{seconds:.3f}",
         "-ac", "1", "-ar", str(SR), "-f", "f32le", "-"],
        capture_output=True,
    )
    if proc.returncode != 0:
        sys.exit(f"ffmpeg failed on {path}: {proc.stderr.decode()[:400]}")
    return np.frombuffer(proc.stdout, dtype=np.float32)


def analyze(samples: np.ndarray, frames: int) -> tuple[np.ndarray, np.ndarray]:
    """Return (per-frame band magnitudes, per-frame rms), both frame-aligned."""
    n_fft = 2048
    window = np.hanning(n_fft)
    freqs = np.fft.rfftfreq(n_fft, 1.0 / SR)
    edges = np.geomspace(BAND_LO, BAND_HI, BANDS + 1)
    masks = [(freqs >= edges[b]) & (freqs < edges[b + 1]) for b in range(BANDS)]

    bands = np.zeros((frames, BANDS), dtype=np.float64)
    rms = np.zeros(frames, dtype=np.float64)
    for f in range(frames):
        centre = int(round(f / FPS * SR))
        start = max(0, centre - n_fft // 2)
        chunk = samples[start:start + n_fft]
        if chunk.size < n_fft:
            chunk = np.pad(chunk, (0, n_fft - chunk.size))
        rms[f] = float(np.sqrt(np.mean(chunk**2)))
        mag = np.abs(np.fft.rfft(chunk * window))
        for b, mask in enumerate(masks):
            bands[f, b] = mag[mask].mean() if mask.any() else 0.0
    return bands, rms


def normalize(values: np.ndarray) -> np.ndarray:
    """Per-band normalization to 0-1 against the 99th percentile."""
    out = np.zeros_like(values)
    for b in range(values.shape[1]):
        col = values[:, b]
        high = np.percentile(col, 99)
        if high <= 1e-12:
            high = col.max()
        if high <= 1e-12:
            continue
        out[:, b] = np.clip(col / high, 0.0001, 1.0)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path, help="Background music track.")
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--seconds", type=float, default=DEFAULT_SECONDS)
    args = ap.parse_args()

    probe = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "default=nw=1:nk=1", str(args.input)],
        capture_output=True, text=True,
    )
    duration = round(float(probe.stdout.strip()), 2)

    samples = decode(args.input, args.seconds)
    frames = int(round(args.seconds * FPS))
    bands, rms = analyze(samples, frames)
    bands = normalize(bands)
    rms_peak = max(float(rms.max()), 1e-12)

    data = {
        "duration": duration,
        "fps": FPS,
        "bands": BANDS,
        "totalFrames": frames,
        "frames": [
            {
                "time": round(f / FPS, 4),
                "rms": round(float(rms[f] / rms_peak), 4),
                "bands": [round(float(v), 4) for v in bands[f]],
            }
            for f in range(frames)
        ],
    }
    args.output.write_text(
        "window.AUDIO_DATA=" + json.dumps(data, separators=(",", ":")) + ";\n",
        encoding="utf-8",
    )
    print(f"wrote {args.output} ({args.output.stat().st_size} bytes, {frames} frames)")


if __name__ == "__main__":
    main()
