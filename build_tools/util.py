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
import subprocess
import re
import shutil
import tempfile
import getpass

os.system('')  # allows colors for Windows terminals
BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'


def which(cmd, all=False):
    query = ['which', cmd]
    if all:
        query = ['which', '-a', cmd]
    result = subprocess.run(query, capture_output=True, text=True)
    if all:
        paths = []
        for path in list(set(result.stdout.strip().split('\n'))):
            if len(path) > 0:
                paths.append(path)
        if len(paths) == 0:
            return [None]
        return paths
    path = result.stdout.strip()
    if len(path) == 0:
        return None
    return path


def sed_on_file(filepath, original, replacement):
    temp_fd, temp_file = tempfile.mkstemp(text=True)
    with os.fdopen(temp_fd, 'w') as temp:
        with open(filepath, 'r') as file:
            for line in file:
                temp.write(re.sub(original, replacement, line))
    shutil.move(temp_file, filepath)


def cat(filepath):
    with open(filepath, 'r') as file:
        lines = file.read()
    return lines


def sudo_command(cmd, passwd=None, cwd=None, output=True, check=True):
    import pexpect
    if not isinstance(cmd, str):
        cmd = ' '.join(cmd)
    print("Running sudo '%s'" % cmd)
    if passwd is None:
            passwd = getpass.getpass('[sudo] password for %s: ' % getpass.getuser()) + '\n'
    proc = pexpect.spawn('sudo ' + cmd, cwd=cwd)
    if proc.expect(['(?i)password.*']) == 0:
        proc.sendline(passwd)
    proc.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=1)
    proc.close()
    out = proc.before.decode()
    if output:
        print(out)
    if check and proc.exitstatus != 0:
        raise RuntimeError('sudo command failed: %d' % proc.exitstatus)
    return passwd


def git_describe():
    rv = subprocess.getoutput('git describe')
    if rv.startswith('fatal'):
        rv = 'v0.0.0-0-a'
    return rv[1:].split('-')
