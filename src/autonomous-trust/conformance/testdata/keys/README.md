# Frozen test keys

These hex-encoded seeds are deliberately public and used only to drive
deterministic conformance vectors. They MUST NOT be used as production keys.

| File                       | Seed (hex)  | Source                |
|----------------------------|-------------|------------------------|
| rfc8032-test1.ed25519      | 9d61b1...   | RFC 8032 Test 1        |
| rfc8032-test2.ed25519      | 4ccd08...   | RFC 8032 Test 2        |

Add new key fixtures by dropping the 32-byte seed (hex-encoded, optionally
0x-prefixed and trailing newline allowed) into this directory and referencing
the file by path from a scenario or vector YAML.
