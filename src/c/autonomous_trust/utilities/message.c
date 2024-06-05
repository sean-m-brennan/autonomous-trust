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

queue_id_t fetch_msgq(map_t *map, map_key_t key)
{
    data_t mk_dat = {0};
    int err = map_get(map, key, &mk_dat);
    if (err != 0)
        return -err;
    return mk_dat.intgr;
}
