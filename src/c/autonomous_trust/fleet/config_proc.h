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

#ifndef CONFIG_PROC_H
#define CONFIG_PROC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

#include "autonomous_trust/processes/processes.h"
#include "fleet/update_proposal.h"
#include "config/configuration.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CONFIG_PROTO_PROPOSE    "config proposal"
#define CONFIG_PROTO_VOTE_REQ   "config vote request"
#define CONFIG_PROTO_VOTE_GRANT "config vote grant"
#define CONFIG_PROTO_VOTE_NACK  "config vote nack"
#define CONFIG_PROTO_ACCEPTED   "config accepted"
#define CONFIG_PROTO_READY      "config ready"

#define CONFIG_IDENTITY_PENALTY -1.0

typedef struct {
    char config_name[CFG_NAME_SIZE + 1];
    uint8_t content_hash[UPDATE_HASH_LEN];
    char version[UPDATE_VERSION_LEN + 1];
    uuid_t proposer_uuid;
    double min_proposer_reputation;
    uuid_t proposal_uuid;
    uint8_t signature[UPDATE_SIG_LEN];
} config_proposal_t;

json_t *config_proposal_to_json(const config_proposal_t *prop);
int config_proposal_from_json(const json_t *json, config_proposal_t *prop);

int config_proposal_sign(config_proposal_t *prop, const uint8_t *sk);
int config_proposal_verify(const config_proposal_t *prop, const uint8_t *pk);

bool config_is_identity(const char *config_name);

bool config_validate_json(const uint8_t *data, size_t len);

int config_backup_dir(const char *data_dir, char *buf, size_t buflen);
int config_backup_all(const char *cfg_dir, const char *data_dir);
int config_restore_all(const char *cfg_dir, const char *data_dir);
int config_backup_delete(const char *data_dir);

int config_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_PROC_H */
