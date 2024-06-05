#ifndef UTIL_H
#define UTIL_H

#include <sys/types.h>

#define TERM_RESET "\x1B[0m"
#define TERM_RED "\x1B[31m"
#define TERM_GREEN "\x1B[32m"
#define TERM_YELLOW "\x1B[33m"
#define TERM_BLUE "\x1B[34m"
#define TERM_PURPLE "\x1B[35m"

int min(int a, int b);
int max(int a, int b);

char *strremove(char *str, const char *sub);

int makedirs(char *path, mode_t mode);

#endif // UTIL_H
