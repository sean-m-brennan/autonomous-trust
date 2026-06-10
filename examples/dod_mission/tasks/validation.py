# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Cross-source validators for the DoD scenario.

These are the mechanism by which the network detects the MQ-800's
contradictory ISR data.  Each validator watches one data_type from
multiple peers and flags an outlier — the same machinery the
multi-agency demo uses to catch the falsified NOAA temperature, just
applied to ISR position and electronic-noise readings.

Validators are run by fusion-capable peers (squad-intel, command).
The framework's `CrossSourceValidator` lives in
`examples.multi_agency.tasks.validation`; we reuse it here so any
threshold-tuning improvements benefit both demos.

Detection economics:
  * `target_position_x` / `target_position_y` thresholds are tight (50m) —
    independent overhead platforms tracking the same target should
    agree within meters, so even a small offset trips the validator.
  * `electronic_noise_db` threshold is wider (15 dB) — RQ-86s legitimately
    see varying noise; we only want to flag impossible-looking spikes.

Tuning notes:
  * If detection is too slow at demo cadence, drop window_sec.
  * If the MQ-800's compromise lands inside the threshold, dial up the
    AbruptDeviation offset in compromise/contradictory_isr.py rather
    than loosening the validator (we want the bar set by the physical
    plausibility of the data, not by the demo's narrative needs).
"""

from __future__ import annotations

from examples.multi_agency.tasks.validation import CrossSourceValidator


# Position validators: independent overhead trackers should agree
# within tens of meters on the same target.  50m is generous; real
# CEPs are tighter but we want headroom for path-jitter in the sim.
POSITION_VALIDATOR_X = CrossSourceValidator(
    data_type="target_position_x",
    threshold=50.0,          # meters from consensus
    # 3, not 2: with only 2 active sources the "median of others" is a
    # single value, so any natural spread between two honest overhead
    # platforms (orbit parallax, path jitter) trips the validator and
    # the two RQ-86s flag each other before the squad/microdrones are
    # producing position readings — the "anomalous way too early" false
    # positive. Requiring ≥3 means each reading is judged against the
    # median of ≥2 others (robust to one outlier); the validator just
    # returns None until that many independent sources exist. The
    # MQ-800 joins at phase 4 when the full roster is reporting, so its
    # detection is unaffected.
    min_sources=3,
    window_sec=10.0,
)

POSITION_VALIDATOR_Y = CrossSourceValidator(
    data_type="target_position_y",
    threshold=50.0,
    min_sources=3,           # see POSITION_VALIDATOR_X
    window_sec=10.0,
)

# Electronic-noise validator: flags impossible readings.  RQ-86s
# legitimately see 30-60 dB; the MQ-800's compromise pushes well past
# that floor when it tries to mask its own emissions.
ELECTRONIC_NOISE_VALIDATOR = CrossSourceValidator(
    data_type="electronic_noise_db",
    threshold=15.0,
    min_sources=3,           # see POSITION_VALIDATOR_X — avoid 2-source
                             # degenerate consensus flagging honest RQ-86s
    window_sec=10.0,
)


ALL_VALIDATORS = [
    POSITION_VALIDATOR_X,
    POSITION_VALIDATOR_Y,
    ELECTRONIC_NOISE_VALIDATOR,
]
