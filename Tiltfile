# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
# Usage: tilt up -- --variant=python [--num-nodes=4 ...]
#        tilt up -- --variant=native [--num-nodes=4 ...]

config.define_string("variant")
config.define_string("num-nodes")
config.define_string("exclude-logs")
config.define_string("log-level")
config.define_string("backend")
config.define_string("metrics-dir")
cfg = config.parse()
variant = cfg.get("variant", "python")

# Pass parsed config to sub-Tiltfiles via environment variables,
# since include() does not share local variables.
os.putenv("_TILT_NUM_NODES", cfg.get("num-nodes", "2"))
os.putenv("_TILT_EXCLUDE_LOGS", cfg.get("exclude-logs", "network"))
os.putenv("_TILT_LOG_LEVEL", cfg.get("log-level", "info"))
os.putenv("_TILT_BACKEND", cfg.get("backend", "native"))
os.putenv("_TILT_METRICS_DIR", cfg.get("metrics-dir", ""))

if variant == "native":
    include("tilt/native.tiltfile")
elif variant == "python":
    include("tilt/python.tiltfile")
else:
    fail("Unknown variant '{}'. Use 'python' or 'native'.".format(variant))
