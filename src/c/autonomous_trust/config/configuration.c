#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "configuration.h"

const char ROOT_ENV_VAR[] = "AUTONOMOUS_TRUST_ROOT";

const char CFG_PATH[] = "etc/at";

const char DATA_PATH[] = "var/at";

char *rootDir()
{
    char *root = getenv(ROOT_ENV_VAR);
    if (root == NULL)
        root = "/";
    return root;
}

int get_cfg_dir(char path[])
{
    return snprintf(path, 255, "%s/%s", rootDir(), CFG_PATH);
}

int get_data_dir(char path[])
{
    return snprintf(path, 255, "%s/%s", rootDir(), DATA_PATH);
}
