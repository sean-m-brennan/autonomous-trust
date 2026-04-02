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

#ifndef UPDATE_PROC_H
#define UPDATE_PROC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "autonomous_trust/processes/processes.h"
#include "fleet/update_proposal.h"  /* UPDATE_HASH_LEN, UPDATE_VERSION_LEN */

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol message function name for broadcasting update status */
#define UPDATE_PROTO_STATUS  "update status"

/* Default timeout for peer handshake self-test (seconds) */
#define UPDATE_HANDSHAKE_TIMEOUT_SEC 15

/* Maximum number of peers to try during handshake self-test */
#define UPDATE_HANDSHAKE_MAX_PEERS 5

/* --- Update state (persisted across restart) --- */

typedef struct {
    char state[32];                             /* IDLE, STAGING, APPLYING, ROLLBACK, COMPLETE */
    char version[UPDATE_VERSION_LEN + 1];
    char hash_hex[UPDATE_HASH_LEN * 2 + 1];
    char backup_path[256];
    char binary_path[256];
    long timestamp;
    int attempt;
    char type[16];                              /* "binary" or "config" */
} update_state_t;

/* --- State file helpers (pure, no process deps) --- */

int update_state_write(const char *data_dir, const update_state_t *state);
int update_state_read(const char *data_dir, update_state_t *state);
int update_state_delete(const char *data_dir);
bool update_state_exists(const char *data_dir);

/* Returns true if attempt > 1 (previous rollback already ran) */
bool update_should_abort(const update_state_t *state);

/* --- Path helpers (pure, no process deps) --- */

/* Build path to update staging directory: <data_dir>/update/ */
int update_staging_dir(const char *data_dir, char *buf, size_t buflen);

/* Build path to staged new binary: <data_dir>/update/at_demo.new */
int update_staging_path(const char *data_dir, char *buf, size_t buflen);

/* Build path to backup binary: <data_dir>/update/at_demo.backup */
int update_backup_path(const char *data_dir, char *buf, size_t buflen);

/* Get path of current running binary via /proc/self/exe */
int update_current_binary_path(char *buf, size_t buflen);

/* --- Self-test (pure functions, except peer handshake) --- */

typedef struct {
    bool identity_ok;
    bool crypto_ok;
    bool config_ok;
    bool peer_handshake_ok;
    bool overall;
} selftest_result_t;

/* Individual self-tests */
bool selftest_identity(const char *cfg_dir);
bool selftest_crypto(void);
bool selftest_config(const char *cfg_dir);

/* --- Process entry point --- */

int update_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

#ifdef __cplusplus
}
#endif

#endif /* UPDATE_PROC_H */
