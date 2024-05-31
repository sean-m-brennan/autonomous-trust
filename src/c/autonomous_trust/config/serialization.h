#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * @brief 
 * 
 * @param stream 
 * @param max_length 
 * @param out 
 * @return ssize_t 
 */
ssize_t read_stream_to_buffer(FILE *stream, size_t max_length, uint8_t *out);

/**
 * @brief 
 * 
 * @param filename 
 * @param max_length 
 * @param out 
 * @return ssize_t 
 */
ssize_t read_file_to_buffer(const char *filename, size_t max_length, uint8_t *out);

/**
 * @brief 
 * 
 * @param filename 
 * @param max_len 
 * @param out 
 * @return ssize_t 
 */
ssize_t read_text_file_to_buffer(const char *filename, size_t max_len, uint8_t *out);

typedef struct {
    int fd;
    uint8_t *data;
    size_t data_len;
} file_mapping_t;

/**
 * @brief 
 * 
 * @param filename 
 * @param mapping 
 * @return ssize_t 
 */
ssize_t readable_file_mapping(const char *filename, file_mapping_t *mapping);

/**
 * @brief 
 * 
 * @param filename 
 * @param mapping 
 * @return int 
 */
int writeable_file_mapping(const char *filename, file_mapping_t *mapping);

/**
 * @brief 
 * 
 * @param mapping 
 * @return int 
 */
int demap_file(file_mapping_t *mapping);


/**
 * @brief Serialization unpacking error
 * 
 */
#define ESER_UNPK 160


#endif // SERIALIZATION_H