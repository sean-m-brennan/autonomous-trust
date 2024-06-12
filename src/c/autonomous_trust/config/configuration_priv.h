#ifndef CONFIGURATION_PRIV_H
#define CONFIGURATION_PRIV_H

#include "structures/array.h"
#include "configuration.h"

/**
 * @brief Configuration names cannot exceed this many characters
 *
 */
#define CFG_NAME_SIZE 128

/**
 * @brief
 *
 * @param path_in
 * @param path_out
 * @return int
 */
int config_absolute_path(const char *path_in, char *path_out);

/**
 * @brief
 *
 * @param path
 * @return int
 */
int num_config_files(char path[]);

/**
 * @brief
 *
 * @param dir
 * @param paths
 * @return int
 */
int all_config_files(char dir[], array_t *paths);

/**
 * @brief
 *
 * @param name
 * @return config_t*
 */
config_t *find_configuration(const char *name) __attribute__((used));

#endif  // CONFIGURATION_PRIV_H
