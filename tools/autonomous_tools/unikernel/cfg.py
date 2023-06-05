class UPlatform(object):
    linuxu = 'linuxu'
    kvm = 'kvm'
    xen = 'xen'


default_platform = UPlatform.kvm


class UImpl(object):
    c = 'c'
    py = 'py'


default_implementation = UImpl.py
