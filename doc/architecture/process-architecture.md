[< System Overview](overview.md)

# Process Architecture

## Orchestrator

The `AutonomousTrust` class (in `core/automate.py`) is the main orchestrator. It spawns a pool of `Process` subclasses, each running in its own OS process (or thread, configurable), communicating via `multiprocessing.Queue`.

> **Applies to both backends.** This Python `multiprocessing.Queue` process
> model is retained even when the native (C/CFFI) backend is selected — C
> functions are called *within* these Python subsystem processes via CFFI, not
> by a C-driven process tree. The standalone C daemon (`run_autonomous_trust()`,
> wrapped by `NativeAutonomousTrust`) is a separate runtime used by the embedded
> build. See [Native / FFI Dual Implementation](native-ffi-dual-implementation.md).

The orchestrator itself extends `Protocol`, giving it message-handling capabilities for task results, reputation responses, and external control commands.

## Core Processes

Four subsystem processes are registered via `ProcessTracker` and listed in `subsystems.cfg.json`:

| Process | CfgId | Dependencies | Purpose |
|---------|-------|-------------|---------|
| `NetworkProcess` | `network` | none | Send/receive messages over UDP/TCP sockets |
| `IdentityProcess` | `identity` | network | Peer discovery, group formation, voting |
| `NegotiationProcess` | `negotiation` | network, identity | Task distribution and haggling |
| `ReputationProcess` | `reputation` | network, identity, negotiation | Paxos-based trust scoring |

## Process Plugin System

Processes self-register via the `ProcMeta` metaclass. Each `Process` subclass declares its `proc_name` and `description` in the metaclass arguments. The `ProcessTracker` reads `subsystems.cfg.json` to determine which process classes to instantiate and in what order (respecting dependency declarations).

Additional worker processes can be added at runtime via `AutonomousTrust.add_worker()`. One such worker is the **`BootstrapWorker`** (`core/_python/bootstrap_worker.py`), auto-registered to run the bootstrap-capability corpus that lets freshly-admitted peers accumulate a baby-steps transaction history. See [Trust Tiers §6](trust-tiers.md) and [Node Lifecycle](node-lifecycle.md).

## IPC and Queue Routing

Each process gets a named queue in a shared `queues` dict. The orchestrator creates one queue per process plus one for itself (`main`). Messages are routed by process name:

- **Outbound (to network)**: Any process places a `Message` on the `network` queue with a `to_whom` field indicating the recipient(s).
- **Inbound (from network)**: `NetworkProcess` parses incoming wire data into `Message` objects and routes them to the appropriate process queue based on `message.process`.
- **Inter-process**: Processes can place objects directly on another process's queue (e.g., `TransactionScore` to the reputation queue, `PeerCapabilities` to negotiation).

The orchestrator's main loop (`autonomous_loop`) cycles through: monitoring subprocess health, handling messages from its own queue, collecting task results, and running user-defined tasking logic.

## Process Relationships

```mermaid
flowchart TB
    Main["AutonomousTrust<br/>(main orchestrator)"]
    Net["NetworkProcess"]
    Id["IdentityProcess"]
    Neg["NegotiationProcess"]
    Rep["ReputationProcess"]

    Main -- "tasks, control" --> Neg
    Main -- "rep queries" --> Rep
    Neg -- "outbound messages" --> Net
    Id -- "outbound messages" --> Net
    Rep -- "outbound messages" --> Net
    Net -- "inbound identity msgs" --> Id
    Net -- "inbound negotiation msgs" --> Neg
    Net -- "inbound reputation msgs" --> Rep
    Neg -- "tasks to execute" --> Main
    Neg -- "task results" --> Main
    Rep -- "reputation scores" --> Main
    Id -- "peer updates" --> Main
    Id -- "peer capabilities" --> Neg
    Main -- "transaction scores" --> Rep
```

[Networking >](networking.md)
