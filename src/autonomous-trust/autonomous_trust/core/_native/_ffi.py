# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

"""
CFFI ABI-mode bindings for libautonomous_trust.

This module provides the singleton ``ffi`` and ``lib`` objects used by all
native wrapper classes.  The C library is loaded once at import time via
``ffi.dlopen()``.
"""

import ctypes
import ctypes.util
import os

from cffi import FFI

ffi = FFI()

# ---------------------------------------------------------------------------
# CFFI cdef declarations — must match the public C API exactly.
# Opaque structs are declared as ``typedef struct <tag> <name>;``.
# ---------------------------------------------------------------------------

ffi.cdef("""

    /* ---- utilities/allocation.h ---- */
    typedef struct { bool alloc; size_t refs; } smrt_ptr_t;

    void *smrt_create(size_t size);
    void *smrt_recreate(void *orig, size_t size);
    void smrt_ref(void *ptr);
    void smrt_deref(void *ptr);

    /* ---- utilities/exception.h ---- */
    typedef struct {
        int errnum;
        const char *errstr;
        const char *description;
    } exception_info_t;

    typedef struct {
        int errnum;
        size_t line;
        char file[257];
    } exception_t;

    extern exception_t _exception;
    extern exception_info_t error_table[];
    extern size_t error_table_size;

    int  _set_exception(int err, size_t line, const char *file);
    const char *_get_err_str(int err);

    /* ---- utilities/logger.h ---- */
    typedef enum { DEBUG = 1, INFO, WARNING, ERROR, CRITICAL } log_level_t;

    typedef struct {
        log_level_t max_level;
        char file_name[257];
        FILE *file;
        bool term;
        bool local_time;
        int resolution;    /* time_resolution_t */
    } logger_t;

    int  logger_init(logger_t *logger, log_level_t max_level, const char *log_file);
    void logger_close(logger_t *logger);

    /* ---- structures/data.h ---- */
    typedef enum {
        NONE, INT, UINT, FLOAT, BOOL, STRING, BYTES, OBJECT
    } data_type_t;

    typedef struct data_s data_t;

    /* POD → data_t* constructors */
    data_t *integer_data(int i);
    data_t *l_integer_data(long i);
    data_t *u_integer_data(unsigned int u);
    data_t *ul_integer_data(unsigned long u);
    data_t *floating_pt_data(float f);
    data_t *floating_pt_dbl_data(double f);
    data_t *boolean_data(bool b);
    data_t *string_data(char *s, size_t len);
    data_t *bytes_data(unsigned char *b, size_t len);
    data_t *object_ptr_data(void *o, size_t len);

    /* data_t* → POD accessors */
    int data_integer(data_t *d, int *i_ptr);
    int data_l_integer(data_t *d, long *i_ptr);
    int data_u_integer(data_t *d, unsigned int *u_ptr);
    int data_ul_integer(data_t *d, unsigned long *u_ptr);
    int data_floating_pt(data_t *d, float *f_ptr);
    int data_floating_pt_dbl(data_t *d, double *f_ptr);
    int data_boolean(data_t *d, bool *b_ptr);
    int data_string(data_t *d, char *s, size_t max_len);
    int data_string_ptr(data_t *d, char **s_ptr);
    int data_bytes(data_t *d, unsigned char *b, size_t max_len);
    int data_bytes_ptr(data_t *d, unsigned char **b_ptr);
    int data_object(data_t *d, void *o, size_t max_len);
    int data_object_ptr(data_t *d, void **o_ptr);
    bool data_equal(data_t *a, data_t *b);

    /* ---- structures/array.h ---- */
    typedef struct array_s array_t;

    int    array_init(array_t *a);
    int    array_create(array_t **a_ptr);
    int    array_copy(array_t *a, array_t *cpy);
    int    array_append(array_t *a, data_t *element);
    int    array_find(array_t *a, data_t *element);
    int    array_filter(array_t *a, bool (*filter)(data_t *));
    bool   array_contains(array_t *a, data_t *element);
    size_t array_size(array_t *a);
    int    array_get(array_t *a, int index, data_t **element);
    int    array_set(array_t *a, int index, data_t *element);
    int    array_remove(array_t *a, data_t *element);
    void   array_free(array_t *a);

    /* ---- structures/map.h ---- */
    typedef struct map_s map_t;

    int      map_init(map_t *map);
    int      map_create(map_t **map_ptr);
    size_t   map_size(map_t *map);
    array_t *map_keys(map_t *map);
    int      map_get(map_t *map, const char *key, data_t **value);
    int      map_set(map_t *map, const char *key, data_t *value);
    int      map_remove(map_t *map, char *key);
    void     map_free(map_t *map);

    /* ---- structures/datetime.h ---- */
    typedef enum {
        MILLISECONDS = 1,
        MICROSECONDS,
        NANOSECONDS
    } time_resolution_t;

    typedef struct {
        /* Flattened struct tm fields (CFFI can't handle anonymous struct) */
        int tm_sec;
        int tm_min;
        int tm_hour;
        int tm_mday;
        int tm_mon;
        int tm_year;
        int tm_wday;
        int tm_yday;
        int tm_isdst;
        long tm_gmtoff;         /* glibc extension */
        const char *tm_zone;    /* glibc extension */
        /* datetime_t extensions */
        unsigned long tm_nsec;
        float tm_tz_offset;
        bool tm_utc;
    } datetime_t;

    typedef struct {
        long days;
        unsigned int seconds;
        unsigned int nsecs;
    } timedelta_t;

    int datetime_strftime_res(const datetime_t *dt, const char *format,
                              int tr, char *s, size_t max);
    int datetime_strftime(const datetime_t *dt, const char *format,
                          char *s, size_t max);
    int datetime_to_isoformat(const datetime_t *dt, char *s, size_t max);
    int datetime_strptime(const char *s, const char *format, datetime_t *dt);
    int datetime_from_isostring(const char *s, datetime_t *dt);
    int datetime_from_time(long time, long nsec, bool local, datetime_t *dt);
    int datetime_now(bool local, datetime_t *dt);
    int timedelta_from_string(const char *s, timedelta_t *td);
    int timedelta_to_string(const timedelta_t *td, char *s, size_t max);

    /* ---- utilities/util.h ---- */
    char *strremove(char *str, const char *sub);
    int   makedirs(char *path, int mode);

    /* ---- config/configuration.h ---- */
    typedef struct {
        const char *name;
        int (*to_json)(const void *data_struct, void **obj_ptr);
        int (*from_json)(const void *obj, void *data_struct);
        size_t data_len;
        void *data_struct;
    } config_t;

    extern config_t configuration_table[];
    extern size_t configuration_table_size;

    int  get_cfg_dir(char path[]);
    int  get_data_dir(char path[]);
    int  read_config_file(const char *filename, void *data_struct);
    int  write_config_file(const config_t *cfg_obj, const void *data_struct,
                           const char *filename);
    int  load_config(char *filepath, config_t **config_ptr, char *cfg_name,
                     logger_t *logger);
    int  load_all_configs(char *cfg_dir, map_t *configs, logger_t *logger);

    /* ---- identity/identity.h ---- */
    typedef struct {
        bool alloc; size_t refs;  /* smrt_ptr_t */
        unsigned char private_key[64];  /* crypto_sign_SECRETKEYBYTES */
        unsigned char public_key[32];   /* crypto_sign_PUBLICKEYBYTES */
        unsigned char public_hex[65];   /* hex + NUL */
    } signature_t;

    typedef struct {
        bool alloc; size_t refs;  /* smrt_ptr_t */
        unsigned char private_key[32];  /* crypto_box_SECRETKEYBYTES */
        unsigned char public_key[32];   /* crypto_box_PUBLICKEYBYTES */
        unsigned char public_hex[65];   /* hex + NUL */
    } encryptor_t;

    typedef struct {
        bool alloc; size_t refs;  /* smrt_ptr_t */
        unsigned char uuid[16];
        char address[33];
        char fullname[129];
        signature_t signature;
        encryptor_t encryptor;
    } public_identity_t;

    typedef struct identity_s identity_t;  /* opaque - contains private keys */

    typedef struct {
        unsigned char *msg;
        unsigned long long len;
    } msg_str_t;

    int  identity_create(unsigned char *uuid, char *address, char *fullname,
                         identity_t **ident);
    int  identiry_init(unsigned char *uuid, char *address, char *fullname,
                       identity_t *identity);
    int  identity_publish(const identity_t *ident, public_identity_t **pub_copy);
    int  identity_sign(const identity_t *ident, const msg_str_t *in,
                       msg_str_t *out);
    int  identity_verify(const public_identity_t *ident, const msg_str_t *in,
                         msg_str_t *out);
    int  identity_encrypt(const identity_t *ident, const msg_str_t *in,
                          const public_identity_t *whom,
                          const unsigned char *nonce, unsigned char *cipher);
    int  identity_decrypt(const identity_t *ident, const msg_str_t *cipher,
                          const public_identity_t *whom,
                          const unsigned char *nonce, unsigned char *out);
    int  peer_to_proto(public_identity_t *msg, void **data_ptr,
                       size_t *data_len_ptr);
    int  proto_to_peer(uint8_t *data, size_t len, public_identity_t *peer);
    void identity_free(identity_t *ident);

    /* ---- processes/process_tracker.h (partial) ---- */
    typedef struct {
        bool alloc; size_t refs;  /* smrt_ptr_t */
        map_t *registry;
        logger_t *logger;
    } tracker_t;

    int  tracker_init(tracker_t *tracker, logger_t *logger);
    int  tracker_create(tracker_t **tracker_ptr, logger_t *logger);
    void tracker_free(tracker_t *tracker);

    /* ---- autonomous_trust.h ---- */
    int run_autonomous_trust(char *q_in, char *q_out,
                             void *capabilities, size_t cap_len,
                             log_level_t log_level, char log_file[]);

""")


# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------

def _find_library() -> str:
    """Locate libautonomous_trust.so, searching common paths."""
    # 1. Explicit env var
    path = os.environ.get('AUTONOMOUS_TRUST_LIB')
    if path and os.path.isfile(path):
        return path

    # 2. Relative to this source tree  (src/c/build/)
    src_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(src_dir, '..', '..', '..', '..', '..', 'c', 'build',
                     'libautonomous_trust.so'),
    ]

    # 3. Conda prefix
    conda_prefix = os.environ.get('CONDA_PREFIX')
    if conda_prefix:
        candidates.append(os.path.join(conda_prefix, 'lib',
                                       'libautonomous_trust.so'))

    for p in candidates:
        p = os.path.normpath(p)
        if os.path.isfile(p):
            return p

    # 4. System search
    found = ctypes.util.find_library('autonomous_trust')
    if found:
        return found

    raise OSError(
        "Cannot find libautonomous_trust.so. Set AUTONOMOUS_TRUST_LIB "
        "env var or build the C library (build_clib.sh)."
    )


def _preload_deps():
    """Pre-load shared library dependencies so dlopen() can resolve symbols."""
    dep_names = ['sodium', 'jansson', 'protobuf-c', 'protobuf', 'uuid']
    for name in dep_names:
        path = ctypes.util.find_library(name)
        if path:
            try:
                ctypes.CDLL(path, mode=ctypes.RTLD_GLOBAL)
            except OSError:
                pass


_preload_deps()
lib = ffi.dlopen(_find_library())
