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

#include "zta/zta_msg_types.h"

AT_MSG_ASSERT_FITS(zta_event_msg_t);

static const at_msg_vtable_t revocation_alert_vt = {
    .name = "ZTA_REVOCATION_ALERT", .size = sizeof(zta_event_msg_t) };
static const at_msg_vtable_t verification_result_vt = {
    .name = "ZTA_VERIFICATION_RESULT", .size = sizeof(zta_event_msg_t) };

AT_MSG_TYPE_REGISTER(revocation_alert, ZTA_REVOCATION_ALERT, &revocation_alert_vt)
AT_MSG_TYPE_REGISTER(verification_result, ZTA_VERIFICATION_RESULT, &verification_result_vt)

void at_zta_msg_types_link(void) {}
