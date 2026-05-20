/* Frama-C stub wrapper: redirect <sodium.h> to ACSL-annotated stubs.
   Since -I stubs/ precedes -I $CONDA_PREFIX/include, this file is
   found first, preventing Frama-C from parsing the real libsodium. */
#ifndef SODIUM_H
#define SODIUM_H
#include "sodium_stubs.h"
#endif /* SODIUM_H */
