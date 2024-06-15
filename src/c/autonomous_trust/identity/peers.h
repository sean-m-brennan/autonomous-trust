#ifndef PEERS_H
#define PEERS_H

#include "structures/map_priv.h"

#define LEVELS 3

#define VALUES 10

typedef struct {
    map_t hierarchy[LEVELS];
    map_t valuations[VALUES];
} peers_t;

#endif  // PEERS_H
