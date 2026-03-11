# FIXME / TODO Tracker

Items that could not be fixed without architectural decisions or more context.
Organized by priority and subsystem.

---

## Fixed This Session

### C Bugs (Fixed)
- **`identity.c:171-176`** — `identity_from_json` cast `json_t*` to `uint8_t*` instead of using `json_string_value()`. Caused segfault in coverage mode.
- **`msg_types.c:string_to_message_type`** — Used `strncmp` (prefix matching); "TASK" matched "TASK_STATUS". Changed to `strcmp`.
- **`map.c:map_to_json`** — Called `strlen` on NULL keys in empty/deleted slots. Added NULL check.
- **`util.c:makedirs`** — Didn't handle `EEXIST` for intermediate directories. Added `errno != EEXIST` check.
- **`configuration.c:num_config_files`** — Missing `closedir()` before return. Added.
- **`map.c:map_remove`** — Setting key=NULL broke linear probing chains. Replaced with backward-shift deletion.
- **`daemonize.c:117,126`** — Operator precedence bug: `*fd = dup2(...) == -1` stored 0/1 instead of fd. Added parentheses.
- **`identity.c:62`** — `exit(-1)` in library function on `sodium_init` failure. Changed to `return -1`.
- **`msg_types.c:120`** — `string_to_message_type` returned 0 for unknown types (ambiguous). Changed to -1.
- **`msg_types.c:137`** — `google__protobuf__any__pack` return value unchecked. Added error check.
- **`configuration.c:132`** — `get_cfg_dir()` return value unchecked. Added bounds/error checking.

### Python Bugs (Fixed)
- **`dag.py:31`** — `Step.__init__` always set `self.uuid = None` ignoring the parameter. Fixed.
- **`merkle.py:147`** — `_rehash` passed `Node` object to `Tree.delete()` which expects int key. Fixed to pass `.key`.
- **`data_client.py:107-111`** — `summary()` compared string dict keys with int (`r < n`). Fixed with `enumerate`.
- **`automate.py:445`** — Vague "Process failed" error message. Added task/capability details.
- **`ping.py:128`** — Used `print()` instead of logger. Changed to `logging.getLogger(__name__).debug()`.
- **`async_ping.py:120`** — Always slept 1s instead of remainder. Calculates actual remaining time.
- **`capabilities.py:37`** — No error handling on capability run. Added try/except with RuntimeError.

---

## C Library — Remaining FIXMEs

### Architecture / Design Decisions (Need User Input)

| File | Line | Issue |
|------|------|-------|
| `autonomous_trust.h:42` | 42 | Number of processes should come from config file, not hardcoded |
| `autonomous_trust.c:123` | 123 | Same: process count from config |
| `autonomous_trust.c:126` | 126 | Capabilities should be passed in/registered dynamically |
| `autonomous_trust.c:285` | 285 | Consider converting loose parameters to a struct |
| `msg_types.h:51` | 51 | Protobuf obj member needs max size or dynamic allocation |
| `msg_types.h:106` | 106 | `generic_msg_t` union uses `net_msg_t` catch-all instead of specific protocol types |
| `message.h:27` | 27 | `MAX_MSG_SIZE 1024` is arbitrary; should be configurable or derived |
| `process_tracker.h:32` | 32 | `process_t` forward declaration placement is unclear |
| `identity.h:71` | 71 | `msg_str_t` should be in a separate file |
| `capabilities.h:74-76` | 74 | Need JSON serialization for peer capability lists |
| `datetime.h:68` | 68 | DateTime normalization not implemented |

### Error Handling Improvements

| File | Line | Issue |
|------|------|-------|
| `autonomous_trust.c:156` | 156 | Handle partial process-start errors (use 'required' process list?) |
| `autonomous_trust.c:165` | 165 | Handle partial errors in process startup |
| `autonomous_trust.c:201` | 201 | Deal with partial failures in queue operations |
| `autonomous_trust.c:233-234` | 233 | `EMAP_NOKEY` when process not found — should it quit retrying? |
| `autonomous_trust.c:348,360,366` | 348 | Various unhandled error conditions in main loop (ECONNREFUSED, etc.) |
| `processes.c:160` | 160 | Missing logging on `process_handler` error |
| `processes.c:256` | 256 | Consider repair action when process message handling fails |
| `processes.c:264` | 264 | Missing logging when skipping unhandled message types |
| `processes.c:269` | 269 | Post-message handling activity not implemented |
| `process_tracker.c:165` | 165 | Returns generic -1 instead of specific error code |
| `datetime.c:92` | 92 | `datetime_now` needs different signature for error reporting |
| `network.c:66,104` | 66 | Returns `EINVAL` where custom network error codes would be better |

### Incomplete Implementations

| File | Line | Issue |
|------|------|-------|
| `negotiation/task.c:31` | 31 | Returns generic -1 instead of specific error |
| `negotiation/task.c:44` | 44 | Thread for task results not tracked |
| `negotiation/task.c:46` | 46 | Task args ownership/freeing unclear |
| `negotiation/task.c:50` | 50 | `task.proto` is empty — no protobuf types generated for tasks |
| `network.c:29` | 29 | Protobuf not used for inter-host communication yet |
| `net_proc.c:762` | 762 | Multicast membership (`IP_ADD_MEMBERSHIP`) not implemented |
| `identity.c:59` | 59 | `identity_create` should accept 4 name fields (address + fullname + nickname + petname) |
| `identity.c:245` | 245 | `identity_free` doesn't free signature/encryptor resources |
| `process_tracker.c:91` | 91 | Should use `map_to_json` instead of manual serialization |
| `msg_types.c:222,232` | 222 | Incomplete handling in message conversion functions |
| `configuration.c:147` | 147 | Error message says 'network' but should reference actual config name |
| `configuration.c:278` | 278 | `smrt_create`'d data_struct not freed in all paths |
| `map.c:204-205` | 204 | Key ownership semantics unclear (copy vs reference) |
| `daemonize.c:107` | 107 | Code block disabled with `#if 0` — needs review |

### Example Code

| File | Line | Issue |
|------|------|-------|
| `example.c:84` | 84 | `// FIXME ??` — unclear what the issue is |

---

## Python — Remaining FIXMEs

### Core — Identity / History (High Impact)

| File | Line | Issue |
|------|------|-------|
| `identity/history/history.py:29` | 29 | DAG vs Merkle tree relationship unclear |
| `identity/history/history.py:65` | 65 | `pass` body — `validate_step` not implemented |
| `identity/history/history.py:84` | 84 | `IdentityHistory` needs config representation |
| `identity/history/history.py:117` | 117 | Need to confirm eligibility (uuid, fullname, signature uniqueness) |
| `identity/history/history.py:124` | 124 | Minimum info check not implemented |
| `identity/history/history.py:144` | 144 | Better validation needed for history entries |
| `identity/history/history.py:166` | 166 | Signature verification not implemented |
| `identity/history/history.py:170` | 170 | Debug logging should be removed |
| `identity/history/history.py:179` | 179 | Serialization not implemented |
| `identity/history/history.py:189` | 189 | Signature required but check allows None |
| `identity/history/history.py:210` | 210 | Branch divergence handling not implemented |
| `identity/history/poa.py:38` | 38 | Should use `blob.validate(proof, sig)` |
| `identity/history/pos.py:42` | 42 | Needs to get reputation for proof-of-stake |

### Core — Identity Process

| File | Line | Issue |
|------|------|-------|
| `identity/idprocess.py:117` | 117 | Commented-out `self.update()` call |
| `identity/idprocess.py:188` | 188 | Step validation not implemented |
| `identity/idprocess.py:190` | 190 | History-group verification not implemented |
| `identity/idprocess.py:202` | 202 | Peer handling after group recording unclear |
| `identity/idprocess.py:206` | 206 | DAG has digests, not peer data — need peers for verification |
| `identity/idprocess.py:208,229` | 208 | Debug logging should be removed |
| `identity/idprocess.py:356` | 356 | Commented-out cadence sleep |
| `identity/idprocess.py:360` | 360 | Validation not implemented |
| `identity/idprocess.py:375` | 375 | `amnesia` parameter unused |
| `identity/idprocess.py:377-380` | 377 | Group delay and update strategy unclear |
| `identity/idprocess.py:389` | 389 | Exception should have been thrown earlier |
| `identity/idprocess.py:390` | 390 | Redundant peer recording may not be necessary |
| `identity/idprocess.py:405` | 405 | `confirmed_block` shouldn't be loaded on failure |
| `identity/idprocess.py:424` | 424 | Border guard mode decision unclear |
| `identity/idprocess.py:426` | 426 | Verification not implemented |
| `identity/idprocess.py:447` | 447 | Handle case when proposer receives the vote |
| `identity/idprocess.py:483` | 483 | Blob validation not implemented |
| `identity/idprocess.py:505` | 505 | Validation not implemented |

### Core — Network

| File | Line | Issue |
|------|------|-------|
| `network/message.py:64` | 64 | Message `__init__` should sign content with sender's NaCl key |
| `network/message.py:68` | 68 | Serialized output should include signature for wire verification |
| `network/netprocess.py:202` | 202 | `reject_message` implementation incomplete |
| `network/netprocess.py:361` | 361 | `self.group` must be non-None for encryption |
| `network/netprocess.py:444` | 444 | CryptoError logged too frequently |
| `network/netprocess.py:448` | 448 | Should ask other group members for help decrypting |
| `network/tcp.py:71` | 71 | TCP length-prefix encoding needs review |

### Core — Negotiation / Reputation

| File | Line | Issue |
|------|------|-------|
| `negotiation/negprocess.py:102` | 102 | Error not sent to main process |
| `negotiation/negprocess.py:128` | 128 | Reputation-based rejection not implemented |
| `negotiation/negprocess.py:165` | 165 | Conflict resolution in task parameters not implemented |
| `reputation/repprocess.py:217` | 217 | Transaction score NaCl signature verification needed |
| `reputation/repprocess.py:246` | 246 | Acceptance message NaCl signature verification needed |
| `reputation/repprocess.py:333` | 333 | Consider using transaction memory for pre-reputation scoring |
| `algorithms/agreement.py:153` | 153 | Signature verification: "must be exactly 64 bytes long" |
| `algorithms/authority.py:31` | 31 | Threshold rank should be derived, not hardcoded |

### Core — Other

| File | Line | Issue |
|------|------|-------|
| `system.py:47` | 47 | TCP network process not working |
| `system.py:55` | 55 | Encoding should be hex instead of utf-8? |
| `system.py:72` | 72 | `now()` should be NTP-sourced |
| `config/configuration.py:50` | 50 | Value should come from config |
| `config/generate.py:69` | 69 | Multi-device address detection |
| `config/generate.py:88` | 88 | Always generates dynamic config |
| `processes.py:242` | 242 | `Mockery` class should move to testing module |
| `structures/redblack.py:275,356` | 275 | Recolor functions have duplicated logic |
| `structures/merkle.py:160` | 160 | `level_nodes` list always empty — inner node rehashing never executes |
| `identity/group.py:91` | 91 | Decrypted output may need decoding |
| `identity/identity.py:131` | 131 | Same: decrypted output may need decoding |
| `identity/protocol.py:54` | 54 | Hierarchy root listening not implemented |

### Services Package

| File | Line | Issue |
|------|------|-------|
| `video/processor.py:56` | 56 | Face detection takes ~0.5s, need selective processing |
| `video/server.py:33` | 33 | `VideoProtocol` class may be removable |
| `peer/position.py:80` | 80 | Hardcoded `UTMPosition` class check |
| `peer/metadata.py:48` | 48 | NTP integration needed |
| `peer/metadata.py:71` | 71 | Position source instantiation needs parameters |

### Inspector Package

| File | Line | Issue |
|------|------|-------|
| `inspector.py:45` | 45 | Object should be converted to JSON, not `str()` |
| `inspector.py:73` | 73 | Peer-of-peer connections not visualized |
| `__main__.py:26` | 26 | Should use static identity instead of random config |
| `peer/daq.py:156` | 156 | Exception silently ignored |
| `peer/daq.py:163` | 163 | Dynamic queue creation causes pickling security error |
| `peer/daq.py:212` | 212 | 'total' field not handled in data parsing |
| `dash_components/peer_status.py:50` | 50 | Dependent on 'video' in peer metadata |
| `dash_components/peer_status.py:82` | 82 | Must record all data; render is fully dynamic |
| `dash_components/peer_status.py:155` | 155 | Reputation is `random.random()` — placeholder |
| `dash_components/peer_status.py:183` | 183 | Should use `NetworkStats` objects |
| `dash_components/peer_status.py:243` | 243 | Data not populating |
| `dash_components/peer_status.py:265` | 265 | Modification handling missing |
| `dash_components/core.py:95` | 95 | Should get other client info beyond socket |
| `dash_components/core.py:216` | 216 | WebSocket serving should differentiate clients |
| `dash_components/core.py:251,256,258` | 251 | Error messages are empty strings |
| `dash_components/core.py:332` | 332 | Missing Ctrl-C handler |
| `dash_components/video_feed.py:41` | 41 | Need dynamic video feed addition |
| `dash_components/dynamic_map.py:89` | 89 | Map height/width should be 75% of screen |
| `dash_components/dynamic_map.py:129` | 129 | Previous marker not disabled |
| `dash_components/dynamic_map.py:134` | 134 | Pitch/bearing/follow changes not detected |
| `dash_components/dynamic_map.py:215` | 215 | Initial flag prevents running components |
| `dash_components/dynamic_map.py:219` | 219 | Z-scale hardcoded; should be computed |
| `dash_components/dynamic_map.py:224` | 224 | Should insert at update instead |
| `viz/network_graph.py:292` | 292 | Should prefer nodes from same group |
| `viz/live_graph.py:34` | 34 | Node data reading not implemented |
| `viz/server.py:36` | 36 | App name detection broken for Quart/SassASGI |

### Simulator Package

| File | Line | Issue |
|------|------|-------|
| `sim_client.py:40` | 40 | Lock within multiprocessing doesn't work |
| `sim_client.py:53` | 53 | Cadence setter should be removed |
| `simulator.py:176` | 176 | Continuous simulation mode not implemented |
| `video/noise.py:52` | 52 | Salt-and-pepper noise works; other noise types broken |
| `sim_net.py:55` | 55 | Need reconnection logic on "No data" |
| `sim_net.py:89` | 89 | What if there's no data en-route? |
| `peer/path.py:127` | 127 | Movement calculation was wrong (commented out) |
| `peer/path.py:146` | 146 | Distance multiplied by 10 — unclear why |
| `peer/path.py:367-368` | 367 | Speed/accel fields should be removed |
| `radio/routing.py:180` | 180 | PREROUTING chain not handled |
| `dash_components/mock_sources.py:58` | 58 | Debug print left in; all sources always active |
| `dash_components/mock_sources.py:64` | 64 | FPS sleep timing questionable |
| `dash_components/mock_sources.py:81` | 81 | `SimNetSource` class unused |
| `dash_components/mock_client.py:98` | 98 | Reputation not implemented |
| `dash_components/mock_client.py:139` | 139 | Video and data sources need merging |
| `dash_components/mock_client.py:149` | 149 | Extra video processing needed |
| `dash_components/sim_iface.py:96` | 96 | Should also sync paused state |
| `dash_components/sim_iface.py:102` | 102 | Sync objects iteration incomplete |

### Test FIXMEs

| File | Line | Issue |
|------|------|-------|
| `tests/b_integration/test_integration.py:39` | 39 | Test pathologies not implemented |
| `tests/local/test_system.py:23` | 23 | Extra functionality tests not implemented |
| `tests/local/test_system.py:36` | 36 | Pathology tests not implemented |
| `tests/local/autonomoustrustcontainer.py:38` | 38 | Docker container builds differently than bash-scripted |
| `tests/local/autonomoustrustcontainer.py:80` | 80 | Wait condition unclear |
| `inspector/tests/a_unit/test_viz.py:37,56,64,71` | 37 | Multiple test stubs not fully implemented |
