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

#include <string.h>
#include <sodium.h>

#include "identity/connection.h"

size_t at_connection_canonical(const uuid_t requester_uuid,
                               const uuid_t accepter_uuid,
                               uint8_t decision, uint64_t seq,
                               uint8_t *out, size_t outcap)
{
    if (out == NULL || outcap < AT_CONNECTION_CANON_LEN) return (size_t)-1;
    size_t off = 0;
    memcpy(out + off, requester_uuid, sizeof(uuid_t)); off += sizeof(uuid_t);
    memcpy(out + off, accepter_uuid, sizeof(uuid_t));  off += sizeof(uuid_t);
    out[off++] = (uint8_t)(decision ? 1 : 0);
    for (int i = 0; i < 8; i++)
        out[off++] = (uint8_t)((seq >> (8 * i)) & 0xFF);   /* u64 little-endian */
    return off;
}

int at_connection_sign(const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                       const uuid_t requester_uuid, const uuid_t accepter_uuid,
                       uint8_t decision, uint64_t seq, char *sig_hex_out)
{
    if (sk == NULL || sig_hex_out == NULL) return -1;
    uint8_t canon[AT_CONNECTION_CANON_LEN];
    size_t clen = at_connection_canonical(requester_uuid, accepter_uuid,
                                          decision, seq, canon, sizeof(canon));
    if (clen == (size_t)-1) return -1;
    unsigned char sig[crypto_sign_BYTES];
    if (crypto_sign_detached(sig, NULL, canon, clen, sk) != 0)
        return -1;
    sodium_bin2hex(sig_hex_out, AT_CONNECTION_SIG_HEX_LEN + 1, sig, sizeof(sig));
    return 0;
}

bool at_connection_verify(const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                          const uuid_t requester_uuid, const uuid_t accepter_uuid,
                          uint8_t decision, uint64_t seq, const char *sig_hex)
{
    if (pk == NULL || sig_hex == NULL) return false;
    if (strlen(sig_hex) != AT_CONNECTION_SIG_HEX_LEN) return false;
    unsigned char sig[crypto_sign_BYTES];
    size_t bin_len = 0;
    if (sodium_hex2bin(sig, sizeof(sig), sig_hex, strlen(sig_hex),
                       NULL, &bin_len, NULL) != 0 || bin_len != sizeof(sig))
        return false;
    uint8_t canon[AT_CONNECTION_CANON_LEN];
    size_t clen = at_connection_canonical(requester_uuid, accepter_uuid,
                                          decision, seq, canon, sizeof(canon));
    if (clen == (size_t)-1) return false;
    return crypto_sign_verify_detached(sig, canon, clen, pk) == 0;
}
