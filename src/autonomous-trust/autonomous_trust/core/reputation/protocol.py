from ..protocol import Protocol

# see https://understandingpaxos.wordpress.com


class ReputationProtocol(Protocol):
    """
    Protocol for establishing Reputation
    ------------------------------------

    Permissioned consensus: assumes IdentityProtocol has previously succeeded

    Leaderless Byzantine Multi-Paxos protocol:
    1. request the floor: unique proposal id (timestamp + index + my uuid)
    2. granted (or not) - from majority of peers: proposal id + last id + chain hash
    2a. if timestamp < max approved -> nack: proposal id -> requestor must retry (exponential backoff?)
    2b. if requestor index < my index -> update nack
    2c. if my index < requestor index -> catch up
    3. proposal: proposal id + value
    4. accepted: proposal id -> confirmed iff #accepted >= #peers/2+1
    5. To guarantee up-to-date do only steps 1,2
    5a. request update from 3 peers: depth of chain

    Overall process
    1. transaction from main -> record, broadcast out
    2. peer transaction score (uses task uuid)
    3. coupled, saved to history (to disk?)
    4. reputation request
    4a. compute
    5. reputation response
    """
    request = 'ask permission'
    grant = 'permission granted'
    nack = 'try again'
    backdate = 'out of date'
    transaction = 'transaction'
    accepted = 'tx accepted'
    outdated = 'update needed'
    update = 'latest update'
    rep_req = 'request reputation'
    rep_resp = 'reputation response'
