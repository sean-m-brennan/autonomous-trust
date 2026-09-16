/* Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors. Apache-2.0.
 *
 * Private-proximity testing — the pure core (see proximity.h).
 */
#include "identity/proximity.h"

#ifdef AT_SOCIAL_ENABLED

#include <math.h>
#include <string.h>

/* Earth radius (metres), spherical approximation — a coarse band does not need
 * the ellipsoid. */
#define AT_PROX_EARTH_R 6371000.0

/* Domain-separation prefix so a proximity tag can never collide with any other
 * keyed hash in the system. */
static const char AT_PROX_DOMAIN[] = "at-proximity-v1";

const double AT_PROX_CELL_M[AT_PROX_NRES] = {1000.0, 5000.0};

bool proximity_derive_key(const unsigned char their_pub[crypto_box_PUBLICKEYBYTES],
                          const unsigned char our_priv[crypto_box_SECRETKEYBYTES],
                          unsigned char out_key[crypto_box_BEFORENMBYTES])
{
    if (their_pub == NULL || our_priv == NULL || out_key == NULL)
        return false;
    /* Symmetric shared secret: beforenm(pk_peer, sk_self) on both sides yields
     * the same key (X25519). Returns 0 on success. */
    return crypto_box_beforenm(out_key, their_pub, our_priv) == 0;
}

/* Project (lat, lon) in degrees to local metres via an equirectangular
 * projection with a cos(lat) east-west correction. Both nearby peers use the
 * same formula at nearly the same latitude, so their cell boundaries align to
 * within the offset-grid tolerance; far-apart peers resolve to "far" regardless.
 */
static void _project(double lat_deg, double lon_deg, double *x_m, double *y_m)
{
    const double lat_rad = lat_deg * (M_PI / 180.0);
    const double lon_rad = lon_deg * (M_PI / 180.0);
    *x_m = AT_PROX_EARTH_R * lon_rad * cos(lat_rad);
    *y_m = AT_PROX_EARTH_R * lat_rad;
}

/* Little-endian encode a signed 64-bit cell coordinate into buf[8]. */
static void _put_i64le(uint8_t buf[8], int64_t v)
{
    uint64_t u = (uint64_t)v;
    for (int i = 0; i < 8; i++)
        buf[i] = (uint8_t)((u >> (8 * i)) & 0xff);
}

bool proximity_compute_tags(double lat_deg, double lon_deg,
                            const unsigned char key[crypto_box_BEFORENMBYTES],
                            const unsigned char salt[AT_PROX_SALT_LEN],
                            uint8_t tags_out[AT_PROX_NTAGS][AT_PROX_TAG_LEN])
{
    if (key == NULL || salt == NULL || tags_out == NULL)
        return false;
    if (!(lat_deg >= -90.0 && lat_deg <= 90.0))
        return false;
    if (!(lon_deg >= -180.0 && lon_deg <= 180.0))
        return false;

    double x, y;
    _project(lat_deg, lon_deg, &x, &y);

    for (int r = 0; r < AT_PROX_NRES; r++) {
        const double cell = AT_PROX_CELL_M[r];
        for (int g = 0; g < AT_PROX_NGRID; g++) {
            /* Offset this grid by g/NGRID of a cell in both axes so a boundary-
             * straddling pair still shares a cell in at least one grid. */
            const double off = (cell * (double)g) / (double)AT_PROX_NGRID;
            const int64_t cx = (int64_t)floor((x + off) / cell);
            const int64_t cy = (int64_t)floor((y + off) / cell);

            /* Keyed BLAKE2b over: domain || salt || res || grid || cx || cy. */
            uint8_t msg[sizeof(AT_PROX_DOMAIN) + AT_PROX_SALT_LEN + 2 + 8 + 8];
            size_t o = 0;
            memcpy(msg + o, AT_PROX_DOMAIN, sizeof(AT_PROX_DOMAIN));
            o += sizeof(AT_PROX_DOMAIN);
            memcpy(msg + o, salt, AT_PROX_SALT_LEN);
            o += AT_PROX_SALT_LEN;
            msg[o++] = (uint8_t)r;
            msg[o++] = (uint8_t)g;
            _put_i64le(msg + o, cx);
            o += 8;
            _put_i64le(msg + o, cy);
            o += 8;

            if (crypto_generichash(tags_out[r * AT_PROX_NGRID + g],
                                   AT_PROX_TAG_LEN, msg, o, key,
                                   crypto_box_BEFORENMBYTES) != 0)
                return false;
        }
    }
    return true;
}

at_prox_band_t proximity_band(
    const uint8_t mine[AT_PROX_NTAGS][AT_PROX_TAG_LEN],
    const uint8_t theirs[AT_PROX_NTAGS][AT_PROX_TAG_LEN])
{
    if (mine == NULL || theirs == NULL)
        return AT_PROX_UNKNOWN;
    /* Finest resolution first: a match there is the closest band. Compare only
     * matching (res, grid) slots — a shared cell yields identical tags. */
    for (int r = 0; r < AT_PROX_NRES; r++) {
        for (int g = 0; g < AT_PROX_NGRID; g++) {
            const int i = r * AT_PROX_NGRID + g;
            if (sodium_memcmp(mine[i], theirs[i], AT_PROX_TAG_LEN) == 0)
                return (r == 0) ? AT_PROX_NEAR : AT_PROX_MID;
        }
    }
    return AT_PROX_FAR;
}

json_t *proximity_tags_to_json(const uint8_t tags[AT_PROX_NTAGS][AT_PROX_TAG_LEN])
{
    if (tags == NULL)
        return NULL;
    json_t *arr = json_array();
    if (arr == NULL)
        return NULL;
    for (int i = 0; i < AT_PROX_NTAGS; i++) {
        char hex[AT_PROX_TAG_LEN * 2 + 1];
        sodium_bin2hex(hex, sizeof(hex), tags[i], AT_PROX_TAG_LEN);
        if (json_array_append_new(arr, json_string(hex)) != 0) {
            json_decref(arr);
            return NULL;
        }
    }
    return arr;
}

bool proximity_tags_from_json(const json_t *arr,
                              uint8_t tags_out[AT_PROX_NTAGS][AT_PROX_TAG_LEN])
{
    if (arr == NULL || tags_out == NULL || !json_is_array(arr))
        return false;
    if (json_array_size(arr) != AT_PROX_NTAGS)
        return false;
    for (int i = 0; i < AT_PROX_NTAGS; i++) {
        json_t *s = json_array_get(arr, i);
        if (!json_is_string(s))
            return false;
        const char *hex = json_string_value(s);
        size_t bin_len = 0;
        if (sodium_hex2bin(tags_out[i], AT_PROX_TAG_LEN, hex, strlen(hex), NULL,
                           &bin_len, NULL) != 0 || bin_len != AT_PROX_TAG_LEN)
            return false;
    }
    return true;
}

#endif /* AT_SOCIAL_ENABLED */
