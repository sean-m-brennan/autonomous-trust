[< Identity Protocol](identity-protocol.md)

# Task Negotiation

The negotiation subsystem handles distributed task assignment, parameter haggling, execution monitoring, and result collection.

## Protocol Messages

| Message | Constant | Direction | Purpose |
|---------|----------|-----------|---------|
| `spawn task` | `start` | main -> negotiation | Local: initiate a new task |
| `invitation` | `announce` | requester -> capable peers | Invite peers to execute a task |
| `haggle` | `response` | peer -> requester | Counter-propose modified parameters |
| `task info` | `task` | -- | (reserved) |
| `ack` | `acceptance` | peer -> requester | Peer accepts the task |
| `nack` | `refusal` | peer -> requester | Peer refuses the task |
| `status request` | `status_req` | requester -> peer | Check long-running task status |
| `status response` | `status_resp` | peer -> requester | Report task execution status |
| `report results` | `result` | peer -> requester | Deliver task results |

## Task Lifecycle

```mermaid
sequenceDiagram
    participant Main as Main Orchestrator
    participant NegL as Local Negotiation
    participant Net as Network
    participant NegR as Remote Negotiation
    participant MainR as Remote Main

    Main->>NegL: start (Task)
    NegL->>NegL: Create TaskTracker<br/>Find capable peers via<br/>PeerCapabilities

    loop For each capable peer
        NegL->>Net: announce (Task)<br/>[encrypted peer-to-peer]
        Net->>NegR: invitation
    end

    alt Peer accepts parameters
        NegR->>NegR: Add to JobQueue
        NegR->>Net: acceptance (Task)
        Net->>NegL: ack
        NegL->>NegL: Record confirmation

    else Peer haggles (timing or content)
        NegR->>Net: response (modified Task)
        Net->>NegL: haggle

        alt Parameters flexible
            NegL->>Net: announce (adjusted Task)
            Net->>NegR: re-invitation
        else Not flexible
            NegL->>NegL: Cancel participant
        end

    else Peer not capable
        NegR->>Net: refusal (Task)
        Net->>NegL: nack
        NegL->>NegL: Cancel participant
    end

    note over NegR: JobQueue scheduled time arrives

    NegR->>MainR: Task (for execution)
    MainR->>MainR: Execute capability
    MainR->>NegR: TaskResult (with ZKP)
    NegR->>Net: result (TaskResult)
    Net->>NegL: report results
    NegL->>Main: TaskResult

    note over Main: Verify ZKP, submit<br/>TransactionScore to Reputation

    opt Long-running task monitoring
        NegL->>Net: status_req
        Net->>NegR: status request
        NegR->>MainR: TaskStatus
        MainR->>NegR: TaskStatus (with psutil status)
        NegR->>Net: status_resp
        Net->>NegL: status response

        alt Task still running
            NegL->>NegL: Extend timeout
        else Task dead/stopped
            NegL->>NegL: Cancel participant
        end
    end
```

## Key Components

### JobQueue

A priority queue of `Job` objects ordered by scheduled execution time. Tasks are popped when `now() >= job.when`. Duplicate tasks are limited to `max_task_duplicates` (5) to prevent spam.

### PeerCapabilities

Maps capability names to lists of peer UUIDs. When a task is started, the negotiation process looks up which peers have registered the required capability and sends invitations only to those peers.

### TaskTracker

Tracks outstanding remote tasks by UUID, storing expected results per peer. A task is complete when results from all expected participants are collected.

### Spam Protection

If a peer sends duplicate task invitations beyond `max_task_duplicates`, the peer is demoted in the hierarchy.

[Reputation Consensus >](reputation.md)
