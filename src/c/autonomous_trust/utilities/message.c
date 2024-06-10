/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#include "config/configuration.h"
#include "util.h"
#include "structures/data.h"
#include "structures/map.h"
#include "message.h"

size_t message_size(message_t msg) {
    return sizeof(message_t);
}

msgq_key_t get_msgq_key(const char *subdir, const char *filename, const int id)
{
    char cfg_path[CFG_PATH_LEN] = {0};
    get_cfg_dir(cfg_path);
    strncat(cfg_path, subdir, CFG_PATH_LEN - strlen(cfg_path));

    struct stat st = {0};
    if (stat(cfg_path, &st) == -1)
        makedirs(cfg_path, 0700);
    strncat(cfg_path, filename, CFG_PATH_LEN - strlen(cfg_path));

    int r_id = id;
    if (id == 0) {
        srand(time(0));
        unsigned int min = (INT_MAX / 2);  // do not interfere with
        r_id = (random() % (INT_MAX - min)) + min;
    }

    return ftok(cfg_path, r_id);
}

queue_id_t fetch_msgq(map_t *map, const char *key)
{
    data_t *mk_dat;
    int err = map_get(map, (char*)key, &mk_dat);
    if (err != 0)
        return err;
    int mk = 0;
    err = data_integer(mk_dat, &mk);
    if (err != 0)
        return err;
    return mk;
}
