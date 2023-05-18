
class ClassEnumMeta(type):
    """
    Allows using class variables as enums with membership checks
    """
    def __contains__(cls, item):
        return item in [attr for attr in dir(cls)
                        if not attr.startswith('_') and not callable(getattr(cls, attr))]

    def __iter__(cls):
        for attr in dir(cls):
            if not attr.startswith('_') and not callable(getattr(cls, attr)):
                yield attr
