# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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
from ..config import base_dir


class UPlatform(object):
    linuxu = 'linuxu'
    kvm = 'kvm'
    xen = 'xen'


default_platform = UPlatform.kvm


class UImpl(object):
    c = 'c'
    py = 'py'


default_implementation = UImpl.py


class Kraft(object):
    pykraft = 'pykraft'
    kraftkit = 'kraftkit'


kraft_tool = Kraft.pykraft  # 2023/04/06: pykraft deprecated, but KraftKit too alpha to use
unikernel_dir = os.path.join(base_dir, 'unikernel')
uk_workdir = os.path.join(unikernel_dir, '.unikraft')

