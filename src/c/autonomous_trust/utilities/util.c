#include <string.h>
#include <stddef.h>

#include "util.h"

inline int min(int a, int b) { return ((a) < (b) ? a : b); }

inline int max(int a, int b) { return ((a) > (b) ? a : b); }

char *strremove(char *str, const char *sub) {
    char *p, *q, *r;
    if (*sub && (q = r = strstr(str, sub)) != NULL) {
        size_t len = strlen(sub);
        while ((r = strstr(p = r + len, sub)) != NULL) {
            memmove(q, p, r - p);
            q += r - p;
        }
        memmove(q, p, strlen(p) + 1);
    }
    return str;
}