#ifndef HASHTABLE_H
#define HASHTABLE_H

typedef void* hashtable_data_ptr_t;

typedef struct hashtable_s hashtable_t;

/**
 * @brief 
 * 
 * @param ht 
 * @return int 
 */
int hashtable_create(hashtable_t **ht);

/**
 * @brief 
 * 
 * @param ht 
 * @param key 
 * @return hashtable_data_ptr_t
 */
hashtable_data_ptr_t hashtable_get(hashtable_t *ht, const char *key);

/**
 * @brief 
 * 
 * @param ht 
 * @param key 
 * @param value 
 * @return int 
 */
int hashtable_set(hashtable_t *ht, const char *key, hashtable_data_ptr_t value);

/**
 * @brief 
 * 
 * @param ht 
 */
void hashtable_free(hashtable_t *ht);


#endif // HASHTABLE_H