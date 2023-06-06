import os
import subprocess
import re
import shutil
import tempfile

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
    temp, temp_file = tempfile.mkstemp(text=True)
    with open(filepath, 'r') as file:
        for line in file:
            temp.write(re.sub(original, replacement, line))
    temp.close()
    shutil.move(temp_file, filepath)
