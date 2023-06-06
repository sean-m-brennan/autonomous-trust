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

