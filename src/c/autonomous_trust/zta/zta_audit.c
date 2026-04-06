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

#include <string.h>
#include <time.h>

#include <jansson.h>

#include "zta_audit.h"

/* ---------- helpers ---------- */

static void timeval_to_iso8601(const struct timeval *tv, char *buf, size_t len)
{
    struct tm tm;
    gmtime_r(&tv->tv_sec, &tm);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
    size_t used = strlen(buf);
    snprintf(buf + used, len - used, ".%06ldZ", (long)tv->tv_usec);
}

static void uuid_to_str(const uuid_t uuid, char *buf)
{
    uuid_unparse_lower(uuid, buf);
}

static void hash_to_hex(const uint8_t *hash, size_t hash_len, char *buf, size_t buf_len)
{
    size_t i;
    for (i = 0; i < hash_len && (i * 2 + 2) < buf_len; i++)
        snprintf(buf + i * 2, 3, "%02x", hash[i]);
    buf[i * 2] = '\0';
}

/**
 * @brief Write an audit entry as a single JSON line to the log file
 */
static int write_entry_jsonl(FILE *fp, const zta_audit_entry_t *entry)
{
    char ts_buf[64], uuid_buf[37], hash_buf[ZTA_HASH_LEN * 2 + 1];

    timeval_to_iso8601(&entry->timestamp, ts_buf, sizeof(ts_buf));
    uuid_to_str(entry->peer_uuid, uuid_buf);
    hash_to_hex(entry->result.credential_hash, ZTA_HASH_LEN, hash_buf, sizeof(hash_buf));

    json_t *obj = json_object();
    json_object_set_new(obj, "timestamp", json_string(ts_buf));
    json_object_set_new(obj, "peer_uuid", json_string(uuid_buf));
    json_object_set_new(obj, "action", json_string(entry->action));
    json_object_set_new(obj, "status", json_string(zta_status_str(entry->result.status)));
    json_object_set_new(obj, "reason", json_string(entry->result.reason));
    json_object_set_new(obj, "credential_hash", json_string(hash_buf));
    json_object_set_new(obj, "deferred", json_boolean(entry->deferred));

    if (entry->resolved) {
        char resolved_ts[64];
        timeval_to_iso8601(&entry->resolved_at, resolved_ts, sizeof(resolved_ts));
        json_object_set_new(obj, "resolved_at", json_string(resolved_ts));
        json_object_set_new(obj, "resolution_status",
                            json_string(zta_status_str(entry->resolution_result.status)));
        json_object_set_new(obj, "resolution_reason",
                            json_string(entry->resolution_result.reason));
    }

    char *line = json_dumps(obj, JSON_COMPACT);
    json_decref(obj);
    if (!line)
        return -1;

    fprintf(fp, "%s\n", line);
    fflush(fp);
    free(line);
    return 0;
}

/* ---------- public API ---------- */

int zta_audit_init(zta_audit_log_t *log, const char *path)
{
    if (!log || !path)
        return -1;

    memset(log, 0, sizeof(*log));
    pthread_mutex_init(&log->lock, NULL);

    log->log_file = fopen(path, "a");
    if (!log->log_file)
        return -1;

    log->initialized = true;
    return 0;
}

int zta_audit_record(zta_audit_log_t *log, const zta_audit_entry_t *entry)
{
    if (!log || !log->initialized || !entry)
        return -1;

    pthread_mutex_lock(&log->lock);

    /* Write to log file */
    int rc = write_entry_jsonl(log->log_file, entry);

    /* Track deferred entries in memory */
    if (entry->deferred && !entry->resolved &&
            log->deferred_count < ZTA_AUDIT_MAX_DEFERRED) {
        memcpy(&log->deferred[log->deferred_count], entry, sizeof(zta_audit_entry_t));
        log->deferred_count++;
    }

    pthread_mutex_unlock(&log->lock);
    return rc;
}

int zta_audit_deferred_count(const zta_audit_log_t *log)
{
    if (!log)
        return 0;
    return log->deferred_count;
}

int zta_audit_get_deferred(const zta_audit_log_t *log, int index,
                           zta_audit_entry_t *out)
{
    if (!log || !out || index < 0 || index >= log->deferred_count)
        return -1;
    memcpy(out, &log->deferred[index], sizeof(zta_audit_entry_t));
    return 0;
}

int zta_audit_resolve(zta_audit_log_t *log, const uuid_t peer_uuid,
                      const zta_result_t *resolution)
{
    if (!log || !log->initialized || !resolution)
        return -1;

    pthread_mutex_lock(&log->lock);

    int found = -1;
    for (int i = 0; i < log->deferred_count; i++) {
        if (uuid_compare(log->deferred[i].peer_uuid, peer_uuid) == 0 &&
                !log->deferred[i].resolved) {
            log->deferred[i].resolved = true;
            gettimeofday(&log->deferred[i].resolved_at, NULL);
            memcpy(&log->deferred[i].resolution_result, resolution, sizeof(zta_result_t));

            /* Write resolution to log */
            write_entry_jsonl(log->log_file, &log->deferred[i]);

            /* Remove from deferred list by swapping with last */
            if (i < log->deferred_count - 1) {
                memcpy(&log->deferred[i],
                       &log->deferred[log->deferred_count - 1],
                       sizeof(zta_audit_entry_t));
            }
            log->deferred_count--;
            found = 0;
            break;
        }
    }

    pthread_mutex_unlock(&log->lock);
    return found;
}

void zta_audit_close(zta_audit_log_t *log)
{
    if (!log || !log->initialized)
        return;

    pthread_mutex_lock(&log->lock);
    if (log->log_file) {
        fclose(log->log_file);
        log->log_file = NULL;
    }
    log->initialized = false;
    pthread_mutex_unlock(&log->lock);
    pthread_mutex_destroy(&log->lock);
}
