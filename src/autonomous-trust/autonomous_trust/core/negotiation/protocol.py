from ..protocol import Protocol


class NegotiationProtocol(Protocol):
    """
    1. invite participation, with task info
    2. haggle
    3. finalized task
    4. ack (optional)
    5. status request for long-running tasks
    6. status response
    7. results -> triggers reputation module
    """
    start = 'spawn task'
    announce = 'invitation'
    response = 'haggle'
    task = 'task info'
    acceptance = 'ack'
    refusal = 'nack'
    status_req = 'status request'
    status_resp = 'status response'
    result = 'report results'
