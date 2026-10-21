# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

import os

TEST_DIR = '/tmp/at_tests'
PRESERVE_FILES = False
INSIDE_DOCKER = os.path.exists('/.dockerenv')


def rendered_log(mock_method):
    """The message a logging call would actually EMIT, from a mocked logger.

    Asserting on ``call_args[0][0]`` asserts on the FORMAT STRING, which stops
    covering anything the moment a call is written lazily: after the §5 S13
    sweep, ``logger.warning('refusing %s=%r ...', var, val)`` has no ``var`` in
    argument 0, so three operator-diagnostic tests here went from meaningful to
    passing-on-nothing (they failed loudly instead, which is how they were
    found). Render the way `logging` does, and the assertion is about what the
    operator reads under either style.
    """
    args = mock_method.call_args[0]
    if len(args) > 1:
        return args[0] % args[1:]
    return args[0]
