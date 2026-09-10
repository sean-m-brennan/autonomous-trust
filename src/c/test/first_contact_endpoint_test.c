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

/**
 * @file first_contact_endpoint_test.c
 * @brief Endpoint resolution for the 1:1 handshake
 *        (at_first_contact_endpoint_host).
 *
 * `initiate` has to turn a rendezvous hint into a bare host, and the naive way
 * to do that -- strip everything after the last colon -- is wrong for IPv6,
 * where the colons ARE the address. It turned `fe80::1` into `fe80:`: a
 * well-formed address quietly replaced by an unroutable one that still looks
 * like an address, so nothing downstream can tell the difference between "we
 * mangled it" and "that peer is unreachable".
 *
 * A port is only expressible in two forms, and only those two may be split:
 * a single colon (`10.0.0.1:9000`), or a bracketed literal
 * (`[fe80::1]:9000`). Everything else is the host, entire.
 *
 * The table here is the same table Python's
 * test_first_contact_handshake.py::test_endpoint_host asserts, degenerate
 * inputs included -- the two runtimes have to agree on the shape they hand the
 * inviter, so the cases are a cross-language contract and not just local
 * coverage. The conformance case
 * `identity/first-contact-initiate-endpoint-forms` compares them running.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <string.h>

#include "identity/identity.h"        /* ADDR_LEN */
#include "identity/first_contact.h"

struct host_case {
    const char *raw;
    const char *want;
};

/* Kept verbatim in step with the Python parametrization. */
static const struct host_case CASES[] = {
    /* IPv4 and hostnames: a single colon is a port. */
    { "10.0.0.1",                     "10.0.0.1" },
    { "10.0.0.1:9000",                "10.0.0.1" },
    { "relay.example",                "relay.example" },
    { "relay.example:9000",           "relay.example" },
    /* Bracketless IPv6: the colons are the ADDRESS, no port is expressible,
     * so nothing may be stripped. The case the old strrchr mangled. */
    { "fe80::1",                      "fe80::1" },
    { "::1",                          "::1" },
    { "2001:db8:85a3::8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334" },
    { "2001:db8::1%eth0",             "2001:db8::1%eth0" },
    { "::ffff:10.0.0.1",              "::ffff:10.0.0.1" },
    /* Bracketed IPv6: the brackets delimit the host, so a port IS
     * expressible. */
    { "[fe80::1]",                    "fe80::1" },
    { "[fe80::1]:9000",               "fe80::1" },
    { "[::1]:80",                     "::1" },
    /* A path tail is dropped before any port search. */
    { "relay.example:9000/introduce", "relay.example" },
    { "[fe80::1]:9000/introduce",      "fe80::1" },
    { "fe80::1/introduce",            "fe80::1" },
    /* Degenerate, defined so both runtimes agree. */
    { "",                             "" },
    { "[fe80::1",                     "fe80::1" },  /* unterminated bracket */
};

DEFINE_TEST(test_endpoint_host_table)
{
    size_t n = sizeof(CASES) / sizeof(CASES[0]);
    for (size_t i = 0; i < n; i++) {
        char out[ADDR_LEN + 1] = "sentinel";
        int rc = at_first_contact_endpoint_host(CASES[i].raw, out, sizeof(out));
        /* Print the input first: a bare string mismatch in a 18-row table is
         * otherwise unattributable (no ck_assert_msg in the DEBUG_TESTS
         * branch of test_setup.h). */
        if (rc != 0 || strcmp(out, CASES[i].want) != 0)
            printf("endpoint_host(\"%s\") -> rc=%d \"%s\", expected \"%s\"\n",
                   CASES[i].raw, rc, out, CASES[i].want);
        ck_assert_int_eq(rc, 0);
        ck_assert_str_eq(out, CASES[i].want);
    }
}

DEFINE_TEST(test_ipv6_is_not_shortened)
{
    /* Called out on its own because it is the actual defect: every other row
     * could pass while this one silently produced a prefix. */
    char out[ADDR_LEN + 1] = {0};
    ck_assert_int_eq(at_first_contact_endpoint_host("fe80::1", out, sizeof(out)), 0);
    ck_assert_str_eq(out, "fe80::1");
    ck_assert(strcmp(out, "fe80:") != 0);
}

DEFINE_TEST(test_null_is_refused_and_clears)
{
    char out[ADDR_LEN + 1] = "sentinel";
    ck_assert_int_eq(at_first_contact_endpoint_host(NULL, out, sizeof(out)), -1);
    ck_assert_str_eq(out, "");
    /* A zero-length destination cannot even hold the NUL. */
    char tiny[1];
    ck_assert_int_eq(at_first_contact_endpoint_host("10.0.0.1", tiny, 0), -1);
}

DEFINE_TEST(test_any_numeric_address_fits)
{
    /* ADDR_LEN was 32 until 2026-09-10, which could not hold a full
     * uncompressed IPv6 literal (39 chars) -- so the widening is what this
     * asserts, in an ADDR_LEN-sized buffer exactly like production uses.
     * The longest text form of an IP address is 45 characters, and
     * ADDR_LEN + 1 is now INET6_ADDRSTRLEN, so both of these fit whole. */
    const char *full  = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";  /* 39 */
    const char *v4map = "0000:0000:0000:0000:0000:ffff:255.255.255.255";  /* 45 */
    ck_assert_int_eq((int)strlen(v4map), 45);

    char out[ADDR_LEN + 1] = {0};
    ck_assert_int_eq(at_first_contact_endpoint_host(full, out, sizeof(out)), 0);
    ck_assert_str_eq(out, "2001:0db8:85a3:0000:0000:8a2e:0370:7334");

    char out2[ADDR_LEN + 1] = {0};
    ck_assert_int_eq(at_first_contact_endpoint_host(v4map, out2, sizeof(out2)), 0);
    ck_assert_str_eq(out2, "0000:0000:0000:0000:0000:ffff:255.255.255.255");

    /* Bracketed and with a port, at full length: the brackets and ":9000" come
     * off, and what is left still has to fit. */
    char out3[ADDR_LEN + 1] = {0};
    ck_assert_int_eq(
        at_first_contact_endpoint_host("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:9000",
                                       out3, sizeof(out3)), 0);
    ck_assert_str_eq(out3, "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
}

DEFINE_TEST(test_too_long_fails_loudly_rather_than_truncating)
{
    /* The refusal branch still matters for what does NOT fit: a scoped literal
     * (which the transport's inet_pton rejects anyway) or a name. Policy
     * matches cidr_split -- half an address still LOOKS like an address, so the
     * buffer is cleared and the call fails rather than handing back a prefix. */
    const char *scoped =
        "fe80:0000:0000:0000:0204:61ff:fe9d:f156%enp0s31f6";  /* 49 */
    ck_assert(strlen(scoped) > ADDR_LEN);
    char out[ADDR_LEN + 1] = "sentinel";
    ck_assert_int_eq(at_first_contact_endpoint_host(scoped, out, sizeof(out)), -1);
    ck_assert_str_eq(out, "");

    /* And it is length alone, not the family or the '%': the same address
     * compressed fits, zone included. */
    char ok[ADDR_LEN + 1] = {0};
    ck_assert_int_eq(
        at_first_contact_endpoint_host("fe80::204:61ff:fe9d:f156%enp0s31f6",
                                       ok, sizeof(ok)), 0);
    ck_assert_str_eq(ok, "fe80::204:61ff:fe9d:f156%enp0s31f6");
}

RUN_TESTS(FirstContactEndpoint,
          test_endpoint_host_table,
          test_ipv6_is_not_shortened,
          test_null_is_refused_and_clears,
          test_any_numeric_address_fits,
          test_too_long_fails_loudly_rather_than_truncating)
