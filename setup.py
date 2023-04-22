#!/usr/bin/env -S python3

from distutils.core import setup

setup(name='autonomous_trust',
      version='1.0',
      description='',
      author='Sean Brennan',
      author_email='sean.brennan@tekfive.com',
      packages=['autonomous_trust', 'autonomous_trust.network',
                'autonomous_trust.identity', 'autonomous_trust.viz'],
      )
