#!/usr/bin/env python3

import sys
import platform

print('%s-%s' % (sys.platform, platform.architecture()[0][:-3]))
