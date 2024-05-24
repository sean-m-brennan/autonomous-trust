#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "serialization.h"


ssize_t read_stream_to_buffer(FILE *stream, size_t max_len, uint8_t *out)
{
    size_t len = 0;
    size_t nread;
    while ((nread = fread(out + len, 1, max_len- len, stream)) != 0) {
        len += nread;
        if (len == max_len)
            return EMSGSIZE;
    }
    size_t err = ferror(stream);
    if (err != 0)
        return err;
    return len;
}

ssize_t read_file_to_buffer(const char *filename, size_t max_len, uint8_t *out)
{
    FILE *stream = fopen(filename, "rb");
    if (stream == NULL)
        return errno;

    return read_stream_to_buffer(stream, max_len, out);
}

ssize_t readable_file_mapping(const char *filename, file_mapping_t *mapping)
{
    mapping->fd = open(filename, O_RDONLY);
    if (mapping->fd == -1)
        return errno;

    struct stat s;
    int err = fstat(mapping->fd, &s);
    if (err == -1) {
        close(mapping->fd);
        return errno;
    }
    mapping->data_len = s.st_size;

    mapping->data = mmap(0, mapping->data_len, PROT_READ, MAP_PRIVATE, mapping->fd, 0);
    if (mapping->data == MAP_FAILED) {
        close(mapping->fd);
        return errno;
    }
    return mapping->data_len;
}

int writeable_file_mapping(const char *filename, file_mapping_t *mapping)
{
    if (mapping->data_len == 0)
        return EINVAL;
    mapping->fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0x0777);
    if (mapping->fd == -1)
        return errno;

    mapping->data = mmap(0, mapping->data_len, PROT_READ, MAP_PRIVATE, mapping->fd, 0);
    if (mapping->data == MAP_FAILED) {
        close(mapping->fd);
        return errno;
    }
    return 0;
}

int demap_file(file_mapping_t *mapping)
{
    int err = munmap(mapping->data, mapping->data_len);
    close(mapping->fd);
    return err;
}