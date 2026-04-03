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

#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <getopt.h>

#include <sodium.h>
#include <jansson.h>

#include "autonomous_trust.h"
#include "autonomous_trust/config/generate.h"

#include "autonomous_trust/fleet/update_proposal.h"
#include "autonomous_trust/fleet/artifact_store.h"
#include "autonomous_trust/fleet/artifact_proc.h"
#include "autonomous_trust/fleet/fleet_proc.h"
#include "autonomous_trust/utilities/msg_types.h"
#include "autonomous_trust/utilities/msg_types_priv.h"
#include "autonomous_trust/utilities/message.h"

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [--generate-config] [--log-level LEVEL] [--test] [--inject-update]\n", prog);
    fprintf(stderr, "  --generate-config   Generate identity, network, and subsystems configs\n");
    fprintf(stderr, "  --log-level LEVEL   Set log level: debug, info, warning, error, critical\n");
    fprintf(stderr, "  --test              Run in test mode (limited iterations)\n");
    fprintf(stderr, "  --inject-update     Inject a self-referencing update proposal after peer discovery\n");
}

static log_level_t parse_log_level(const char *str)
{
    if (strcasecmp(str, "debug") == 0) return DEBUG;
    if (strcasecmp(str, "info") == 0) return INFO;
    if (strcasecmp(str, "warning") == 0) return WARNING;
    if (strcasecmp(str, "error") == 0) return ERROR;
    if (strcasecmp(str, "critical") == 0) return CRITICAL;
    fprintf(stderr, "Unknown log level '%s', defaulting to INFO\n", str);
    return INFO;
}

static int mkdirs(const char *path)
{
    char tmp[CFG_PATH_LEN + 1];
    strncpy(tmp, path, CFG_PATH_LEN);
    for (char *p = tmp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

#define TEST_ITERATIONS 800
#define INJECT_ITERATIONS 1200    /* ~600s at 500ms cadence */
#define INJECT_DELAY_ITERATIONS 60 /* ~30s delay for peer discovery */

int main(int argc, char *argv[])
{
    log_level_t log_level = INFO;
    bool gen_config = false;
    bool test_mode = false;
    bool inject_update = false;

    static struct option long_options[] = {
        {"generate-config", no_argument, NULL, 'g'},
        {"log-level", required_argument, NULL, 'l'},
        {"test", no_argument, NULL, 't'},
        {"inject-update", no_argument, NULL, 'i'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "gl:tih", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'g':
            gen_config = true;
            break;
        case 'l':
            log_level = parse_log_level(optarg);
            break;
        case 't':
            test_mode = true;
            break;
        case 'i':
            inject_update = true;
            test_mode = true;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    logger_t log = {0};
    logger_init(&log, log_level, NULL);

    /* Create required directories */
    char cfg_dir[CFG_PATH_LEN + 1];
    char data_dir[CFG_PATH_LEN + 1];
    get_cfg_dir(cfg_dir);
    get_data_dir(data_dir);

    if (mkdirs(cfg_dir) != 0)
    {
        log_error(&log, "Failed to create config dir %s: %s\n", cfg_dir, strerror(errno));
        return 1;
    }
    if (mkdirs(data_dir) != 0)
    {
        log_error(&log, "Failed to create data dir %s: %s\n", data_dir, strerror(errno));
        return 1;
    }

    /* Generate configs if requested */
    if (gen_config)
    {
        log_info(&log, "Generating configs in %s\n", cfg_dir);
        int err = random_config(cfg_dir);
        if (err != 0)
        {
            log_error(&log, "Config generation failed: %s\n", strerror(errno));
            log_exception(&log);
            return 1;
        }
        log_info(&log, "Configs generated successfully\n");
    }

    /* Launch autonomous trust daemon */
    char *q_out = (char *)"demo_to_at";
    char *q_in = (char *)"at_to_demo";

    int at_pid = run_autonomous_trust(q_out, q_in, NULL, 0, log_level, NULL);
    if (at_pid <= 0)
    {
        log_error(&log, "Autonomous Trust (%d) failed to start: %s\n", at_pid, strerror(errno));
        return at_pid;
    }

    init_sig_handling(NULL);

    /* Initialize IPC so we can send messages to AT sub-processes */
    queue_t demo_q = {0};
    if (messaging_init("at_demo", &demo_q) != 0)
        log_exception(&log);
    messaging_assign(&demo_q);

    log_info(&log, "AT demo running (AT daemon at PID %d)\n", at_pid);

    /* Monitor loop */
    bool at_alive = true;
    size_t loop = 0;
    size_t max_iters = inject_update ? INJECT_ITERATIONS : TEST_ITERATIONS;
    while (!stop_process && (!test_mode || loop < max_iters))
    {
        loop++;

        if (inject_update && loop == INJECT_DELAY_ITERATIONS)
        {
            log_info(&log, "Inject-update: starting self-referencing update proposal\n");

            if (sodium_init() < 0)
            {
                log_error(&log, "Inject-update: sodium_init failed\n");
            }
            else
            {
                /* Initialize artifact store */
                artifact_store_init(data_dir);

                /* Read our own binary */
                char self_path[256];
                ssize_t self_len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
                if (self_len > 0)
                {
                    self_path[self_len] = '\0';
                    FILE *f = fopen(self_path, "rb");
                    if (f)
                    {
                        fseek(f, 0, SEEK_END);
                        long fsize = ftell(f);
                        fseek(f, 0, SEEK_SET);

                        uint8_t *binary_data = malloc(fsize);
                        if (binary_data && fread(binary_data, 1, fsize, f) == (size_t)fsize)
                        {
                            /* Hash the binary */
                            uint8_t hash[UPDATE_HASH_LEN];
                            crypto_generichash_blake2b(hash, UPDATE_HASH_LEN,
                                                       binary_data, fsize, NULL, 0);
                            char hash_hex[UPDATE_HASH_LEN * 2 + 1];
                            sodium_bin2hex(hash_hex, sizeof(hash_hex), hash, UPDATE_HASH_LEN);

                            log_info(&log, "Inject-update: binary hash = %s (%ld bytes)\n",
                                     hash_hex, fsize);

                            /* Store as artifact chunks */
                            artifact_manifest_t manifest;
                            memset(&manifest, 0, sizeof(manifest));
                            strncpy(manifest.hash_hex, hash_hex, sizeof(manifest.hash_hex) - 1);
                            manifest.total_size = fsize;
                            manifest.chunk_size = ARTIFACT_CHUNK_SIZE;
                            manifest.total_chunks = (int)((fsize + ARTIFACT_CHUNK_SIZE - 1) / ARTIFACT_CHUNK_SIZE);
                            strncpy(manifest.version, "test-1.0.0", sizeof(manifest.version) - 1);
                            artifact_store_save_manifest(&manifest);

                            for (int i = 0; i < manifest.total_chunks; i++)
                            {
                                size_t offset = (size_t)i * ARTIFACT_CHUNK_SIZE;
                                size_t chunk_len = ARTIFACT_CHUNK_SIZE;
                                if (offset + chunk_len > (size_t)fsize)
                                    chunk_len = (size_t)fsize - offset;
                                artifact_store_save_chunk(hash_hex, i, binary_data + offset, chunk_len);
                            }
                            artifact_store_verify(hash_hex, hash);

                            log_info(&log, "Inject-update: stored %d chunks in artifact store\n",
                                     manifest.total_chunks);

                            /* Build update proposal */
                            update_proposal_t prop;
                            memset(&prop, 0, sizeof(prop));
                            strncpy(prop.version, "test-1.0.0", UPDATE_VERSION_LEN);
                            memcpy(prop.artifact_hash, hash, UPDATE_HASH_LEN);
                            strncpy(prop.target_arch, "test", UPDATE_ARCH_LEN);
                            prop.min_proposer_reputation = 0.0;
                            uuid_generate(prop.proposal_uuid);

                            /* Sign with throwaway keypair */
                            uint8_t pk[crypto_sign_PUBLICKEYBYTES];
                            uint8_t sk[crypto_sign_SECRETKEYBYTES];
                            crypto_sign_keypair(pk, sk);
                            memcpy(prop.signer_uuid, prop.proposal_uuid, sizeof(uuid_t));
                            update_proposal_sign(&prop, sk);

                            /* Send to fleet process */
                            json_t *prop_json = update_proposal_to_json(&prop);
                            if (prop_json)
                            {
                                generic_msg_t msg = {0};
                                msg.type = NET_MESSAGE;
                                net_msg_t *nmsg = &msg.info.net_msg;
                                strncpy(nmsg->process, "fleet", 64);
                                nmsg->function = (char *)FLEET_PROTO_PROPOSE;
                                strncpy(nmsg->return_to, "fleet", 64);
                                /* Set sender's signing public key so fleet can verify */
                                memcpy(nmsg->from_whom.signature.public, pk,
                                       crypto_sign_PUBLICKEYBYTES);
                                sodium_bin2hex((char *)nmsg->from_whom.signature.public_hex,
                                              crypto_sign_PUBLICKEYBYTES * 2 + 1,
                                              pk, crypto_sign_PUBLICKEYBYTES);
                                net_msg_pack_json(nmsg, prop_json);
                                json_decref(prop_json);
                                messaging_send("fleet", NET_MESSAGE, &msg, false);
                                log_info(&log, "Inject-update: proposal submitted to fleet process\n");
                            }
                        }
                        free(binary_data);
                        fclose(f);
                    }
                }
                else
                {
                    log_error(&log, "Inject-update: could not read /proc/self/exe\n");
                }
            }
        }

        int err = kill(at_pid, 0);
        if (err == -1)
        {
            if (errno == ESRCH)
            {
                log_info(&log, "AT daemon exited\n");
                stop_process = true;
                at_alive = false;
            }
            else
            {
                SYS_EXCEPTION();
                log_exception(&log);
            }
        }
        usleep(cadence);
    }

    if (at_alive)
    {
        log_info(&log, "Sending SIGINT to AT daemon (PID %d)\n", at_pid);
        kill(at_pid, SIGINT);
        int status;
        waitpid(at_pid, &status, 0);
    }

    log_info(&log, "AT demo exiting\n");
    return 0;
}
