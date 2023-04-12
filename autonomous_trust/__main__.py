#!/usr/bin/env -S python3 -m

import os
from automate import main, CFG_VAR_NAME, CFG_DEFAULT


if __name__ == '__main__':
    this_dir = os.path.abspath(os.path.dirname(__file__))
    os.environ[CFG_VAR_NAME] = os.path.join(this_dir, CFG_DEFAULT)
    main()
