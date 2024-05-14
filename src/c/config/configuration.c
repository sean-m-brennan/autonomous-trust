#include <stdlib.h>
#include <yaml.h>

#include "configuration.h"

const char ROOT_ENV_VAR[] = "AUTONOMOUS_TRUST_ROOT";

const char CFG_PATH[] = "etc/at";

const char DATA_PATH[] = "var/at";

const char YAML_PREFIX[] = "!Cfg";

const char YML_FILE_EXT[] = ".cfg.yaml";

char *rootDir()
{
    char *root = getenv(ROOT_ENV_VAR);
    if (root == NULL)
        root = "/";
    return root;
}

const char *get_cfg_dir()
{
    const char path[256];
    snprintf(path, 255, "%s/%s", rootDIR(), CFG_PATH);
    return path;
}

const char *get_data_dir()
{
    const char path[256];
    snprintf(path, 255, "%s/%s", rootDIR(), DATA_PATH);
    return path;
}

// FIXME representers and constructors
// datetime
// timedelta
// uuid
// signedmessage
// decimal
