#!/usr/bin/env -S python3 -m

import os
from automate import main
from configuration import Configuration


if __name__ == '__main__':
    this_dir = os.path.abspath(os.path.dirname(__file__))
    os.environ[Configuration.VARIABLE_NAME] = os.path.join(this_dir, Configuration.PATH_DEFAULT)
    main()
