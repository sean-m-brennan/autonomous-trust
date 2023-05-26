from enum import Enum


class AgreementImpl(str, Enum):
    """
    Possible implementations for reaching agreements
    """
    POW = 'work'
    POS = 'stake'
    POA = 'authority'

    def __str__(self) -> str:
        return str.__str__(self)
