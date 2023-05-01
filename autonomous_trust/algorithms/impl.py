from aenum import Enum


class AgreementImpl(Enum):
    """
    Possible implementations for reaching agreements
    """
    POW = 'work'
    POS = 'stake'
    POA = 'authority'
