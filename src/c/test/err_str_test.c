/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>

/* _get_err_str has external linkage but no header declaration */
extern const char *_get_err_str(int err);

DEFINE_TEST(test_base_errors)
{
    ck_assert_str_eq(_get_err_str(0), "SUCCESS");
    ck_assert_str_eq(_get_err_str(1), "EPERM");
    ck_assert_str_eq(_get_err_str(2), "ENOENT");
    ck_assert_str_eq(_get_err_str(12), "ENOMEM");
    ck_assert_str_eq(_get_err_str(22), "EINVAL");
    ck_assert_str_eq(_get_err_str(34), "ERANGE");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_extended_errors)
{
    ck_assert_str_eq(_get_err_str(35), "EDEADLK");
    ck_assert_str_eq(_get_err_str(42), "ENOMSG");
    ck_assert_str_eq(_get_err_str(110), "ETIMEDOUT");
    ck_assert_str_eq(_get_err_str(111), "ECONNREFUSED");
    ck_assert_str_eq(_get_err_str(133), "EHWPOISON");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gai_errors)
{
    ck_assert_str_eq(_get_err_str(-1), "EAI_BADFLAGS");
    ck_assert_str_eq(_get_err_str(-2), "EAI_NONAME");
    ck_assert_str_eq(_get_err_str(-10), "EAI_MEMORY");
    ck_assert_str_eq(_get_err_str(-12), "EAI_OVERFLOW");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gai_ext_errors)
{
    ck_assert_str_eq(_get_err_str(-100), "EAI_INPROGRESS");
    ck_assert_str_eq(_get_err_str(-101), "EAI_CANCELED");
    ck_assert_str_eq(_get_err_str(-105), "EAI_IDN_ENCODE");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unknown_error)
{
    /* Out of range returns empty string */
    ck_assert_str_eq(_get_err_str(9999), "");
    ck_assert_str_eq(_get_err_str(-50), "");
    ck_assert_str_eq(_get_err_str(-200), "");
}
END_TEST_DEFINITION()

RUN_TESTS(ErrStr, test_base_errors, test_extended_errors,
          test_gai_errors, test_gai_ext_errors, test_unknown_error)
