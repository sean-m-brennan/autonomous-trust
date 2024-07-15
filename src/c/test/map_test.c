/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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

#include <stdlib.h>
#include "autonomous_trust/structures/map_priv.h"
#include "autonomous_trust/utilities/protobuf_shutdown.h"
#include "autonomous_trust/utilities/exception.h"
#include "autonomous_trust/utilities/logger.h"

#define DEBUG_TESTS 0

#include "test_setup.h"

DEFINE_TEST(test_map)
{
    logger_t logger;
    ck_assert_ret_ok(logger_init(&logger, DEBUG, NULL));

    // FIXME
    log_exception(&logger);
}
END_TEST_DEFINITION()

RUN_TESTS(Map, test_map)
