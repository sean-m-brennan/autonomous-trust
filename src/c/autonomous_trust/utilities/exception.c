#include <string.h>
#include "exception.h"

#define EXCEPTION_IMPL

exception_t _exception = {0};

int _set_exception(int err, size_t line, const char *file)
{
    _exception.errnum = err;
    _exception.line = line;
    strncpy(_exception.file, file, 255);
    return -1;
}
