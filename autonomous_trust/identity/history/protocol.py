from aenum import Enum

from ...config import Configuration


class IdentityProtocol(Enum):
    """
    Protocol for establishing Identity
    ----------------------------------

    Three channels:
        - unsecured broadcast channel
        - secure broadcast channel with group key
        - secure private channel with private key

    1. announce: open broadcast my own Identity
    2. full_history on secure private channel:
       a. wait to receive history + group <- steps list + Group
          - merge with my own
          - send history_diff on closed broadcast -> steps list
       b. timeout, create group
    3. border-mode: listen on open broadcast channel for announce
       a. propose: initiate internal voting (closed broadcast) -> IdentityObj
       b. listen for propose <- IdentityObj
          - eldest n remain in border-mode
       c. vote -> (blob, proof, sig)
       d. listen for votes <- (blob, proof, sig)
          - if approved, respond with full_history + group key privately -> steps list + Group
       e. confirm peer -> IdentityObj
       f. update group -> Group
    4. listen on closed broadcast channel for peer confirmation <- IdentityObj
    5. listen on closed broadcast channel for history_diffs <- steps list
       a. add as branch to history
       b. merge if ok
    6. listen on closed broadcast channel for group updates (address list additions) <- Group
    7. listen for hierarchy roots # FIXME

    Items 3, 4, & 5 are concurrent
    """
    announce = 'request_access'
    history = 'full_history'
    diff = 'history_diff'
    propose = 'propose_peer'
    vote = 'vote_on_peer'
    confirm = 'peer_accepted'
    update = 'group_key_update'


class FullHistoryMessage(Configuration):
    def __init__(self, history, group):
        self.history = history
        self.group = group
