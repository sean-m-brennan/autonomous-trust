/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

#ifndef AT_GATEWAY_H
#define AT_GATEWAY_H

/**
 * @file at_gateway.h
 * @brief The gateway relay extension (libat_gateway).
 *
 * Linking libat_gateway registers the "gateway" extension. It does nothing
 * until a node's network config sets "envelope": true; then, at network
 * start, it installs the "envelope" network filter (network/net_filter.h),
 * which wraps every frame in the 36-byte plaintext routing envelope
 * (net_envelope.h), forwards PEER frames for other nodes when this node is
 * a gateway, and relays broadcasts across legs. "group_forward" and
 * "cross_cluster" in the same config turn on cross-leg group forwarding and
 * cross-cluster discovery.
 *
 * A shared link registers the extension when the library loads. A static
 * link keeps it only if something references the object, so a program that
 * links at_gateway_static without --whole-archive calls at_gateway_link()
 * once.
 *
 * See doc/architecture/extensions.md and network-wire-format.md.
 */

/** Keeps the gateway's registration constructor in a static link. No-op at
 *  run time. */
void at_gateway_link(void);

#endif /* AT_GATEWAY_H */
