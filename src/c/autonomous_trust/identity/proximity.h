/* Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors. Apache-2.0.
 *
 * Private-proximity testing (Phase 2, SOCIAL_APP_PLAN.md §3, §7 Q3). Two
 * CONNECTED peers learn a coarse distance BAND (near / mid / far) about each
 * other WITHOUT either revealing its exact coordinates and without any third
 * party learning anything.
 *
 * Construction — multi-resolution keyed grid tags (a Narayanan-style private
 * equality test at several resolutions, yielding a band):
 *   - Each side quantizes its exact position to grid CELLS at two resolutions
 *     (~1 km and ~5 km), each with several OVERLAPPING offset grids so a pair
 *     that straddles a cell boundary still matches in some grid.
 *   - For each (resolution, grid) it derives a TAG = keyed BLAKE2b over the cell
 *     id, keyed by the PAIRWISE box secret the two peers already share
 *     (crypto_box_beforenm over their X25519 keys) plus a per-probe salt.
 *   - The two sides exchange their tag sets and intersect them. The FINEST
 *     resolution at which any tag matches is the band; no match ⇒ far.
 *
 * Privacy: only the two connected peers hold the pairwise key, so a third party
 * sees opaque tags; the counterpart learns only which resolution matched (the
 * band), never the cell or the coordinates; the exact position never leaves the
 * node. The salt rotates per probe to bound cross-probe correlation.
 *
 * This header is the PURE core (grid math + tag derivation + band decision +
 * JSON (de)serialization of a tag set); the wire exchange and app emit live in
 * id_proc.c. Guarded by AT_SOCIAL_ENABLED like the rest of the social layer.
 */
#ifndef AT_IDENTITY_PROXIMITY_H
#define AT_IDENTITY_PROXIMITY_H

#ifdef AT_SOCIAL_ENABLED

#include <stdbool.h>
#include <stdint.h>

#include <jansson.h>
#include <sodium.h>

/** Resolutions (coarse distance bands), finest first. */
#define AT_PROX_NRES 2
/** Overlapping offset grids per resolution (boundary robustness). */
#define AT_PROX_NGRID 3
/** Total tags exchanged = NRES * NGRID. */
#define AT_PROX_NTAGS (AT_PROX_NRES * AT_PROX_NGRID)
/** Truncated BLAKE2b tag length (bytes). 16 bytes = 128-bit collision safety. */
#define AT_PROX_TAG_LEN 16
/** Per-probe salt length (bytes). */
#define AT_PROX_SALT_LEN 16

/** Coarse distance band learned by a probe. Ordered by closeness. */
typedef enum {
    AT_PROX_UNKNOWN = 0, /* one side had no exact position / no key */
    AT_PROX_NEAR    = 1, /* same ~1 km cell */
    AT_PROX_MID     = 2, /* same ~5 km cell (but not ~1 km) */
    AT_PROX_FAR     = 3  /* no cell match at any resolution */
} at_prox_band_t;

/** Cell edge length (metres) per resolution, finest first: ~1 km, ~5 km. */
extern const double AT_PROX_CELL_M[AT_PROX_NRES];

/**
 * Derive the pairwise proximity key from our X25519 secret and the peer's
 * public key (crypto_box_beforenm). Symmetric: both peers derive the same key.
 * @return true on success.
 */
bool proximity_derive_key(const unsigned char their_pub[crypto_box_PUBLICKEYBYTES],
                          const unsigned char our_priv[crypto_box_SECRETKEYBYTES],
                          unsigned char out_key[crypto_box_BEFORENMBYTES]);

/**
 * Compute this node's tag set for (@p lat_deg, @p lon_deg) under @p key and
 * @p salt. Writes AT_PROX_NTAGS tags, indexed tag[res * NGRID + grid].
 * @return true on success, false if the coordinates are out of range.
 */
bool proximity_compute_tags(double lat_deg, double lon_deg,
                            const unsigned char key[crypto_box_BEFORENMBYTES],
                            const unsigned char salt[AT_PROX_SALT_LEN],
                            uint8_t tags_out[AT_PROX_NTAGS][AT_PROX_TAG_LEN]);

/**
 * Decide the band by intersecting @p mine with @p theirs. A match at a
 * (resolution, grid) means the two nodes shared that cell. Returns the band of
 * the FINEST resolution with any match, or AT_PROX_FAR if none.
 */
at_prox_band_t proximity_band(
    const uint8_t mine[AT_PROX_NTAGS][AT_PROX_TAG_LEN],
    const uint8_t theirs[AT_PROX_NTAGS][AT_PROX_TAG_LEN]);

/** Serialize a tag set to a JSON array of AT_PROX_NTAGS lowercase-hex strings
 *  (new reference; caller decrefs), or NULL on failure. */
json_t *proximity_tags_to_json(
    const uint8_t tags[AT_PROX_NTAGS][AT_PROX_TAG_LEN]);

/** Parse a tag set from a JSON array produced by proximity_tags_to_json.
 *  @return true iff @p arr is an array of exactly AT_PROX_NTAGS valid hex tags. */
bool proximity_tags_from_json(const json_t *arr,
                              uint8_t tags_out[AT_PROX_NTAGS][AT_PROX_TAG_LEN]);

#endif /* AT_SOCIAL_ENABLED */
#endif /* AT_IDENTITY_PROXIMITY_H */
