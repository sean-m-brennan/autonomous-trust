#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <stddef.h>
#include <errno.h>

typedef struct
{
    int errnum;
    const char *description;
} exception_info_t;

typedef struct
{
    int errnum;
    size_t line;
    char file[256];
} exception_t;

#ifndef EXCEPTION_IMPL
extern exception_t _exception;

extern exception_info_t error_table[];
extern size_t error_table_size;
#endif

int _set_exception(int err, size_t line, const char *file);

#define SYS_EXCEPTION() _set_exception(errno, __LINE__, __FILE__)

#define EXCEPTION(err) _set_exception(err, __LINE__, __FILE__)

#define DECLARE_ERROR(num, descr)

#define DEFINE_ERROR(num, descr)                                                                                                \
    void __attribute__((constructor)) register_err_##num()                                                                      \
    {                                                                                                                           \
        error_table[error_table_size].errnum = num;                                                                             \
        error_table[error_table_size].description = descr;                                                                      \
        error_table_size++;                                                                                                     \
    }

#endif  // EXCEPTION_H
