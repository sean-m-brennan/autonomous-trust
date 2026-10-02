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
"""Run from a checkout: the core (and this distribution) on sys.path, as the
core's own tests and the sibling distributions' do. Generates the AAP 2.0
bindings when a checkout has not yet run scripts/build-py.sh."""
import os
import subprocess
import sys

_repo_src = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
for _pkg in ('autonomous-trust', 'autonomous-trust-dtn'):
    _pkg_dir = os.path.join(_repo_src, _pkg)
    if _pkg_dir not in sys.path and os.path.isdir(_pkg_dir):
        sys.path.insert(0, _pkg_dir)

_proto_dir = os.path.join(_repo_src, 'c', 'extensions', 'dtn', 'proto')
_out_dir = os.path.join(_repo_src, 'autonomous-trust-dtn', 'autonomous_trust', 'dtn', '_python')
if (not os.path.exists(os.path.join(_out_dir, 'aap2_pb2.py'))
        and os.path.exists(os.path.join(_proto_dir, 'aap2.proto'))):
    try:
        subprocess.run(['protoc', '--python_out=' + _out_dir, '-I', _proto_dir,
                        os.path.join(_proto_dir, 'aap2.proto')], check=True)
    except (OSError, subprocess.CalledProcessError):
        pass  # the AAP 2.0 tests skip without it
