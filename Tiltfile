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
cfg = config.parse()
variant = cfg.get("variant", "python")

if variant == "native":
    include("tilt/native.tiltfile")
elif variant == "python":
    include("tilt/python.tiltfile")
else:
    fail("Unknown variant '{}'. Use 'python' or 'native'.".format(variant))
