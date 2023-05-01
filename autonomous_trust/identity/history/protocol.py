from aenum import Enum


class IdentityProtocol(Enum):
    """
    Protocol for establishing Identity
    1. request history on open broadcast channel, providing my key
    2. optionally receive history / group key on closed single channel, merge with my own, send diff on closed broadcast
    3. listen on open broadcast channel for history requests -> respond
    4. listen on closed broadcast channel for history updates -> ingest -> branches for inconsistencies
    5. listen on closed broadcast channel for group key updates -> carefully consider -> record for use
    """
    request = 'request_history'
    provide = 'provide_history'
    propose = 'propose_block'
    vote = 'vote_on_block'
