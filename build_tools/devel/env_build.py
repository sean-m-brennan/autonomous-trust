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
