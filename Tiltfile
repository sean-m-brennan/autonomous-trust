# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
# Top-level Tiltfile — dispatches to a variant-specific Tiltfile
# Usage: tilt up -- --variant=python       [--num-nodes=4 --backend=native|python ...]
#        tilt up -- --variant=c            [--num-nodes=4 ...]
#        tilt up -- --variant=multi-agency [--namespace=disaster-demo --log-level=info]
#        tilt up -- --variant=dod-mission  [--namespace=dod-demo ...]
#
# Two axes here, easy to confuse:
#   * --variant  picks which sub-Tiltfile to include (which demo).
#       python       — multi-node Python demo (uses the C library via
#                      CFFI by default; --backend=python switches to
#                      Dockerfile-lite for a pure-Python build).
#       c            — multi-node pure-C demo (Dockerfile-c). Was
#                      called --variant=native, renamed to avoid
#                      colliding with the python variant's
#                      --backend=native (CFFI).
#       multi-agency — disaster-response scenario in k8s.
#       dod-mission  — DoD squad-infiltration scenario in k8s.
#   * --backend  only meaningful when --variant=python; selects the
#                C library binding flavor inside that sub-Tiltfile.
#
# The k8s scenarios set peer count from scenario.py, not --num-nodes.

config.define_string("variant")
config.define_string("num-nodes")
config.define_string("exclude-logs")
config.define_string("log-level")
config.define_string("backend")
config.define_string("metrics-dir")
config.define_string("namespace")
cfg = config.parse()
variant = cfg.get("variant", "python")

# Pass parsed config to sub-Tiltfiles via environment variables,
# since include() does not share local variables.
os.putenv("_TILT_NUM_NODES", cfg.get("num-nodes", "2"))
os.putenv("_TILT_EXCLUDE_LOGS", cfg.get("exclude-logs", "network"))
os.putenv("_TILT_LOG_LEVEL", cfg.get("log-level", "info"))
os.putenv("_TILT_BACKEND", cfg.get("backend", "native"))
os.putenv("_TILT_METRICS_DIR", cfg.get("metrics-dir", ""))
os.putenv("_TILT_NAMESPACE", cfg.get("namespace", "disaster-demo"))

if variant == "c":
    include("tilt/native.tiltfile")
elif variant == "python":
    include("tilt/python.tiltfile")
elif variant == "multi-agency":
    include("tilt/multi_agency.tiltfile")
elif variant == "dod-mission":
    include("tilt/dod_mission.tiltfile")
else:
    fail("Unknown variant '{}'. Use 'python', 'c', 'multi-agency', or 'dod-mission'.".format(variant))
