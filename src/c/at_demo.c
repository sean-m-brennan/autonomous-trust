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

#include "autonomous_trust.h"
#include "autonomous_trust/config/generate.h"

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [--generate-config] [--log-level LEVEL] [--test]\n", prog);
    fprintf(stderr, "  --generate-config   Generate identity, network, and subsystems configs\n");
    fprintf(stderr, "  --log-level LEVEL   Set log level: debug, info, warning, error, critical\n");
    fprintf(stderr, "  --test              Run in test mode (limited iterations)\n");
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

#define TEST_ITERATIONS 200

int main(int argc, char *argv[])
{
    const long cadence = 500000L; /* microseconds */

    log_level_t log_level = INFO;
    bool gen_config = false;
    bool test_mode = false;

    static struct option long_options[] = {
        {"generate-config", no_argument, NULL, 'g'},
        {"log-level", required_argument, NULL, 'l'},
        {"test", no_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "gl:th", long_options, NULL)) != -1)
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

    log_info(&log, "AT demo running (AT daemon at PID %d)\n", at_pid);

    /* Monitor loop */
    bool at_alive = true;
    size_t loop = 0;
    while (!stop_process && (!test_mode || loop < TEST_ITERATIONS))
    {
        loop++;
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
