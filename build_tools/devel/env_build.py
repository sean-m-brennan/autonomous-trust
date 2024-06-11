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
import sys
import venv
from subprocess import Popen, PIPE
from threading import Thread
from urllib.parse import urlparse
from urllib.request import urlretrieve


class EnvironBuilder(venv.EnvBuilder):
    def __init__(self):
        super().__init__(system_site_packages=True, clear=True, with_pip=True)

    def post_setup(self, context):
        os.environ['VIRTUAL_ENV'] = context.env_dir
        self.install_setuptools(context)
        self.install_pip(context)
