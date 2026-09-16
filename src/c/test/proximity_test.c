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
 * @file proximity_test.c
 * @brief Private-proximity math (Phase 2): grid-tag derivation, the band
 *        decision, pairwise-key symmetry, the privacy property (no shared key
 *        ⇒ no match), and JSON round-trip.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <math.h>
#include <string.h>
#include <sodium.h>

#include "identity/proximity.h"

/* Shift a latitude (deg) by @p dy metres north in the same projection the module
 * uses for the y axis (y = R * radians(lat)). */
static double lat_shift(double lat_deg, double dy_m)
{
    double lat_rad = lat_deg * (M_PI / 180.0);
    return (lat_rad + dy_m / 6371000.0) * (180.0 / M_PI);
}

/* A pair of nodes whose derived pairwise key we control. */
static void two_keys(unsigned char a_to_b[crypto_box_BEFORENMBYTES],
                     unsigned char b_to_a[crypto_box_BEFORENMBYTES])
{
    unsigned char apk[crypto_box_PUBLICKEYBYTES], ask[crypto_box_SECRETKEYBYTES];
    unsigned char bpk[crypto_box_PUBLICKEYBYTES], bsk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(apk, ask);
    crypto_box_keypair(bpk, bsk);
    ck_assert(proximity_derive_key(bpk, ask, a_to_b)); /* A derives with B.pub */
    ck_assert(proximity_derive_key(apk, bsk, b_to_a)); /* B derives with A.pub */
}

DEFINE_TEST(test_band_logic_synthetic)
{
    uint8_t mine[AT_PROX_NTAGS][AT_PROX_TAG_LEN];
    uint8_t theirs[AT_PROX_NTAGS][AT_PROX_TAG_LEN];
    /* All distinct → far. */
    for (int i = 0; i < AT_PROX_NTAGS; i++) {
        memset(mine[i], (int)(i + 1), AT_PROX_TAG_LEN);
        memset(theirs[i], (int)(i + 100), AT_PROX_TAG_LEN);
    }
    ck_assert_int_eq(proximity_band(mine, theirs), AT_PROX_FAR);

    /* Match only at a res-1 slot (index 3 = res 1, grid 0) → mid. */
    memcpy(theirs[3], mine[3], AT_PROX_TAG_LEN);
    ck_assert_int_eq(proximity_band(mine, theirs), AT_PROX_MID);

    /* A res-0 match (index 1 = res 0, grid 1) wins → near. */
    memcpy(theirs[1], mine[1], AT_PROX_TAG_LEN);
    ck_assert_int_eq(proximity_band(mine, theirs), AT_PROX_NEAR);
}

DEFINE_TEST(test_identical_position_is_near)
{
    unsigned char kab[crypto_box_BEFORENMBYTES], kba[crypto_box_BEFORENMBYTES];
    two_keys(kab, kba);
    unsigned char salt[AT_PROX_SALT_LEN];
    randombytes_buf(salt, sizeof(salt));

    uint8_t ta[AT_PROX_NTAGS][AT_PROX_TAG_LEN];
    uint8_t tb[AT_PROX_NTAGS][AT_PROX_TAG_LEN];
    ck_assert(proximity_compute_tags(37.7749, -122.4194, kab, salt, ta));
    ck_assert(proximity_compute_tags(37.7749, -122.4194, kba, salt, tb));
    /* Same key (symmetric), same salt, same cell ⇒ every tag matches. */
    ck_assert_int_eq(proximity_band(ta, tb), AT_PROX_NEAR);
}

DEFINE_TEST(test_two_km_is_mid)
{
    unsigned char kab[crypto_box_BEFORENMBYTES], kba[crypto_box_BEFORENMBYTES];
    two_keys(kab, kba);
    unsigned char salt[AT_PROX_SALT_LEN];
    randombytes_buf(salt, sizeof(salt));

    const double lat = 1.0, lon = 1.0;
    const double lat2 = lat_shift(lat, 2000.0); /* 2 km north */
    uint8_t ta[AT_PROX_NTAGS][AT_PROX_TAG_LEN];
    uint8_t tb[AT_PROX_NTAGS][AT_PROX_TAG_LEN];
    ck_assert(proximity_compute_tags(lat, lon, kab, salt, ta));
    ck_assert(proximity_compute_tags(lat2, lon, kba, salt, tb));
    /* 2 km apart: never the same 1 km cell, but the same 5 km cell ⇒ mid. */
    ck_assert_int_eq(proximity_band(ta, tb), AT_PROX_MID);
}

DEFINE_TEST(test_twenty_km_is_far)
{
    unsigned char kab[crypto_box_BEFORENMBYTES], kba[crypto_box_BEFORENMBYTES];
    two_keys(kab, kba);
    unsigned char salt[AT_PROX_SALT_LEN];
    randombytes_buf(salt, sizeof(salt));

    const double lat = 1.0, lon = 1.0;
    const double lat2 = lat_shift(lat, 20000.0); /* 20 km north */
    uint8_t ta[AT_PROX_NTAGS][AT_PROX_TAG_LEN];
    uint8_t tb[AT_PROX_NTAGS][AT_PROX_TAG_LEN];
    ck_assert(proximity_compute_tags(lat, lon, kab, salt, ta));
    ck_assert(proximity_compute_tags(lat2, lon, kba, salt, tb));
    ck_assert_int_eq(proximity_band(ta, tb), AT_PROX_FAR);
}

DEFINE_TEST(test_no_shared_key_no_match)
{
    /* Two nodes that are NOT connected do not share the pairwise key: even at
     * the identical position their tags do not match ⇒ far. This is the privacy
     * property — a third party (or a non-connected peer) learns nothing. */
    unsigned char k1[crypto_box_BEFORENMBYTES], k2[crypto_box_BEFORENMBYTES];
    randombytes_buf(k1, sizeof(k1));
    randombytes_buf(k2, sizeof(k2));
    unsigned char salt[AT_PROX_SALT_LEN];
    randombytes_buf(salt, sizeof(salt));

    uint8_t ta[AT_PROX_NTAGS][AT_PROX_TAG_LEN];
    uint8_t tb[AT_PROX_NTAGS][AT_PROX_TAG_LEN];
    ck_assert(proximity_compute_tags(10.0, 10.0, k1, salt, ta));
    ck_assert(proximity_compute_tags(10.0, 10.0, k2, salt, tb));
    ck_assert_int_eq(proximity_band(ta, tb), AT_PROX_FAR);
}

DEFINE_TEST(test_tags_json_round_trip)
{
    unsigned char key[crypto_box_BEFORENMBYTES];
    randombytes_buf(key, sizeof(key));
    unsigned char salt[AT_PROX_SALT_LEN];
    randombytes_buf(salt, sizeof(salt));
    uint8_t ta[AT_PROX_NTAGS][AT_PROX_TAG_LEN];
    ck_assert(proximity_compute_tags(48.85, 2.35, key, salt, ta));

    json_t *arr = proximity_tags_to_json(ta);
    ck_assert(arr != NULL);
    ck_assert_int_eq((int)json_array_size(arr), AT_PROX_NTAGS);
    uint8_t back[AT_PROX_NTAGS][AT_PROX_TAG_LEN];
    ck_assert(proximity_tags_from_json(arr, back));
    ck_assert_int_eq(memcmp(ta, back, sizeof(ta)), 0);
    json_decref(arr);

    /* Wrong-length array is rejected. */
    json_t *bad = json_array();
    json_array_append_new(bad, json_string("00"));
    ck_assert(!proximity_tags_from_json(bad, back));
    json_decref(bad);
}

DEFINE_TEST(test_out_of_range_coords_rejected)
{
    unsigned char key[crypto_box_BEFORENMBYTES];
    randombytes_buf(key, sizeof(key));
    unsigned char salt[AT_PROX_SALT_LEN];
    randombytes_buf(salt, sizeof(salt));
    uint8_t t[AT_PROX_NTAGS][AT_PROX_TAG_LEN];
    ck_assert(!proximity_compute_tags(91.0, 0.0, key, salt, t));
    ck_assert(!proximity_compute_tags(0.0, 181.0, key, salt, t));
    ck_assert(proximity_compute_tags(-90.0, 180.0, key, salt, t)); /* edges ok */
}

RUN_TESTS(Proximity,
          test_band_logic_synthetic,
          test_identical_position_is_near,
          test_two_km_is_mid,
          test_twenty_km_is_far,
          test_no_shared_key_no_match,
          test_tags_json_round_trip,
          test_out_of_range_coords_rejected)
