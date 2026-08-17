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


def rendered_log(mock_method):
    """The message a logging call would actually EMIT, from a mocked logger.

    Asserting on ``call_args[0][0]`` asserts on the format string, which
    silently stops covering anything the moment a call is written lazily --
    ``logger.error('unhandled %s', kind)`` has no ``kind`` in argument 0. That
    is not a hypothetical: converting this package to lazy logging (ISSUES §5
    S13) broke four such assertions at once, each of which had been passing by
    reading a value that is no longer there.

    Rendering the way `logging` does keeps the assertion on what an operator
    reads, and works under either style.
    """
    args = mock_method.call_args[0]
    if len(args) > 1:
        return args[0] % args[1:]
    return args[0]
