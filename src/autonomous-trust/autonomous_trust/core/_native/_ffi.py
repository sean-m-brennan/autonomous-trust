# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
    int smrt_recreate(void **pptr, size_t size);
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
    typedef array_t directory_t;   /* processes.h: typedef array_t directory_t */
    typedef ... pthread_mutex_t;    /* opaque; only ever passed as a pointer */

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
        /* Added 2026-08-12 (doc/architecture/native-ffi-dual-implementation.md): the proto
         * hooks were missing, so the
           mirror was 40 bytes against C's 56. Optional in C (NULL = no proto
           serializer, JSON fallback), but a NULL field still occupies its slot. */
        int (*to_proto)(const void *data_struct, void **buf_out, size_t *len_out);
        int (*from_proto)(const void *buf, size_t len, void *data_struct);
    } config_t;

    extern config_t configuration_table[];
    extern size_t configuration_table_size;

    /* Both gained an explicit `destlen` on 2026-08-04 (the path-length overflow: they
       used to hardcode 255 as path_join's bound while taking an unsized
       `char path[]`, which overflowed a 108-byte caller). Keep the arity in step
       with the C header — `ffi.dlopen` is ABI mode, so CFFI validates nothing
       and a stale arity means the C side reads `destlen` off a garbage register
       and writes that far. `scripts/audit-ffi-drift.py` catches this one. */
    int  get_cfg_dir(char path[], size_t destlen);
    int  get_data_dir(char path[], size_t destlen);
    int  read_config_file(const char *filename, void *data_struct);
    int  write_config_file(const config_t *cfg_obj, const void *data_struct,
                           const char *filename);
    int  load_config(char *filepath, config_t **config_ptr, char *cfg_name,
                     logger_t *logger);
    int  load_all_configs(char *cfg_dir, map_t *configs, logger_t *logger);

    /* ---- identity/identity.h ---- */
    /* One ZTA credential (identity.h:129-136). Declared unconditionally there,
       so it is declared unconditionally here too. */
    typedef struct {
        uint8_t *der;
        size_t der_len;
        uint8_t *binding;
        size_t binding_len;
        char issuer[64];
    } zta_credential_t;

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
        char address[46];     /* ADDR_LEN(45) + 1 == IPV6_ADDR_LEN; was 33 */
        char nickname[129];   /* NAME_LEN+1; Zooko ONLINE name (was fullname) */
        char petname[129];    /* NAME_LEN+1; local-only Zooko name -- never */
                              /* serialized (see identity.c sync_out/sync_in). */
        signature_t signature;
        encryptor_t encryptor;
        /* Operator-attended signal (identity.h:83-84). Kept OUTSIDE the AT_ZTA
           guard in C, so these fields are always present regardless of build
           flags and must appear here in the same position (between encryptor
           and the ZTA fields) or the struct layout — and every trailing field
           offset — is wrong. */
        bool operator_bound;
        double operator_attested_at;
        /* Operator KEY binding (identity.h:130-132), the operator-key slice's
           three fields. Also outside the AT_ZTA guard in C, for the same reason.
           `crypto_sign_PUBLICKEYBYTES` is 32; spelled literally because the cdef
           has no libsodium macros.

           These were MISSING here until 2026-08-04, and the comment above
           already said what that costs: the struct was 48 bytes short and every
           ZTA offset below it was wrong. `PublicIdentity.from_proto_bytes` does
           `ffi.new('public_identity_t *')` and hands that to `proto_to_peer`,
           which writes the full C-sized struct into the undersized CFFI
           allocation — a heap overflow that surfaced later as
           `free(): invalid pointer` and aborted pytest. Struct drift is invisible
           to `scripts/audit-ffi-drift.py`, which compares function ARG COUNTS
           only. */
        uint8_t operator_pubkey[32];
        uint8_t *operator_key_binding;
        size_t operator_key_binding_len;
        /* ZTA credential binding (identity.h, #ifdef AT_ZTA_ENABLED). The
           native lib is built AT_ZTA=ON (build-native.sh -DAT_ZTA=ON), so these
           are part of the ABI layout and must be present here to match. */
        uint8_t zta_credential_hash[32];
        char zta_issuer[64];
        uint8_t *zta_credential;
        size_t zta_credential_len;
        /* Multi-credential set + proved anchors (identity.h, same AT_ZTA block;
           landed with doc/architecture/zta-integration.md on 2026-08-06). MISSING here until 2026-08-10, and
           the cost was exactly what the comment above describes for the
           operator-key fields: the mirror ended at zta_credential_len, 840
           bytes against the C struct's 1752, so `proto_to_peer` wrote 912 bytes
           past the `ffi.new('public_identity_t *')` allocation and corrupted the
           heap (`free(): corrupted unsorted chunks`, aborting pytest in
           tests/d_comparison/test_identity_parity.py::test_proto_roundtrip).

           Sizes are spelled literally because the cdef has no C macros:
           ZTA_MAX_CREDENTIALS 4, ZTA_MAX_ANCHORS 8, ZTA_ANCHOR_NAME_LEN 64.
           Verify a change here against the C ABI rather than by eye -- compile
           a probe that prints sizeof/offsetof from identity.h (with
           -DAT_ZTA_ENABLED -fms-extensions) and compare to ffi.sizeof /
           ffi.offsetof. `scripts/audit-ffi-drift.py` compares function ARG
           COUNTS only and cannot see any of this
           (doc/architecture/native-ffi-dual-implementation.md). */
        zta_credential_t zta_credentials[4];
        size_t num_zta_credentials;
        char zta_anchors[8][64];
        size_t num_zta_anchors;
    } public_identity_t;

    typedef struct identity_s identity_t;  /* opaque - contains private keys */

    typedef struct {
        unsigned char *msg;
        unsigned long long len;
    } msg_str_t;

    int  identity_create(unsigned char *uuid, char *address, char *nickname,
                         char *petname, identity_t **ident);
    int  identity_init(unsigned char *uuid, char *address, char *nickname,
                       char *petname, identity_t *identity);
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

    /* ---- network/network.h ---- */
    typedef struct {
        bool alloc; size_t refs;  /* smrt_ptr_t */
        int port;
        char mac_address[18];    /* MAC_ADDR_LEN(17) + 1 */
        char ip4_cidr[20];       /* CIDR4_LEN(19) + 1 */
        char mcast4_addr[17];    /* IPV4_ADDR_LEN(16) + 1 */
        char ip6_cidr[51];       /* CIDR6_LEN(50) + 1 */
        char mcast6_addr[47];    /* IPV6_ADDR_LEN(46) + 1 */
    } network_config_t;

    int network_to_json(const void *data_struct, void **obj_ptr);
    int network_from_json(const void *obj, void *data_struct);

    /* ---- network/net_message.h ---- */
    typedef enum {
        RECIPIENT_PEER = 0,
        RECIPIENT_BROADCAST = 1
    } recipient_type_t;

    typedef struct {
        recipient_type_t type;
        union {
            public_identity_t peer;
        } target;
    } net_recipient_t;

    /* Field order is the ABI. `trace_id` and `from_rank` sit MID-STRUCT, so
       omitting them (as this did until 2026-08-04) did not merely truncate the
       struct — it put `to_whom`, `from_whom` and `encrypt` at wrong offsets, so
       every one of them was read from the wrong bytes. Total was 1792 against
       C's 1896, and `ffi.new('net_wire_msg_t *')` in _native/network/message.py
       handed C a buffer 104 bytes short. Verified by measurement against the
       header: cdef sizeof == C sizeof == 1896. */
    typedef struct {
        char process[65];        /* PROC_NAME_LEN(64) + 1 */
        char *function;
        uint8_t *data;
        size_t data_len;
        char trace_id[33];       /* NET_TRACE_ID_LEN(32) + 1 */
        net_recipient_t to_whom;
        public_identity_t from_whom;
        int from_rank;
        bool encrypt;
        uint8_t signature[64];   /* crypto_sign_BYTES */
        bool has_signature;
        bool verified;
    } net_wire_msg_t;

    int  net_message_to_wire(const net_wire_msg_t *msg,
                             const identity_t *signer,
                             uint8_t **wire_out, size_t *wire_len);
    int  net_message_from_wire(const uint8_t *data, size_t len,
                               const public_identity_t *peer,
                               net_wire_msg_t *msg_out);
    void net_wire_msg_free(net_wire_msg_t *msg);

    /* Envelope format (doc/architecture/network-wire-format.md). The enum is spelled `int`
     * here because
     * the cdef needs its WIDTH, not its identity; NET_WIRE_JSON = 0,
     * NET_WIRE_PROTO = 1 (network/net_wire_format.h). The `_fmt` pair is what a
     * caller with a group in hand uses; the two above stay the JSON-fixed entry
     * points, which is what every caller outside a group wants. */
    int  net_message_to_wire_fmt(const net_wire_msg_t *msg,
                                 const identity_t *signer,
                                 int fmt,
                                 uint8_t **wire_out, size_t *wire_len);
    int  net_message_from_wire_fmt(const uint8_t *data, size_t len,
                                   const public_identity_t *peer,
                                   int fmt, net_wire_msg_t *msg_out);
    const char *net_wire_format_name(int fmt);

    /* ---- network/network.h ---- */
    /* Base-port resolution: config -> AT_COMM_PORT -> COMM_PORT. Declared so
       the Python side can assert it agrees with C for a given base instead of
       hand-copying the constants (which is how the old port table drifted). */
    typedef enum { PORT_SRC_CONFIG, PORT_SRC_ENV, PORT_SRC_DEFAULT } net_port_source_t;
    int net_port_resolve(int cfg_port, net_port_source_t *src, void *logger);
    const char *net_port_source_name(net_port_source_t src);
    void net_port_resolve_reset(void);

    /* ping.h is deliberately absent: C does not implement ping. There was a
       ping_stats_t + ping()/ping_server_start()/ping_server_stop() block here,
       bound by _ping_native.py. Both are gone -- Python's ping is the only
       implementation, and the C network process answers the `ping` selector
       with {"error": "unsupported"}. Do NOT re-add these declarations without
       the C functions. `ffi.dlopen` resolves symbols LAZILY, per attribute
       (measured): a stale declaration does NOT fail at import -- it raises
       AttributeError the first time something touches `lib.<name>`, so the
       breakage surfaces wherever that call site is, possibly long after the
       mismatch was introduced. Delete declarations together with the functions
       they describe rather than leaving harmless-looking prototypes. */

    /* ---- processes/capabilities.h ---- */
    /* thread_args_t and capability_t contain embedded opaque structs
       (array_t, map_t), so we treat them as opaque and use pointers only. */
    typedef struct thread_args_s thread_args_t;
    typedef struct capability_s capability_t;

    capability_t *find_capability(const char *name);
    /* Result-producing invocation. `capability_function_t` returns void, so a
       capability's answer could not be collected until this existed and a C
       worker had nothing to report; see processes/capabilities.h. */
    int capability_execute_result(const capability_t *cap,
                                 const char *kwargs_json,
                                 char *result_out, size_t result_len);

    /* ---- utilities/msg_types.h ---- */
    typedef enum {
        SIGNAL = 1,
        GROUP_MSG,
        PEER_MSG,
        PEER_CAPABILITIES_MSG,
        TASK_MSG,
        NET_MESSAGE_MSG,
        TASK_STATUS_MSG,
        TASK_RESULT_MSG,
        TRANSACTION_SCORE_MSG
    } message_type_t;

    typedef struct {
        char descr[33];          /* SIGNAL_LEN(32) + 1 */
        int sig;
    } signal_t;

    typedef struct {
        char process[65];        /* PROC_NAME_LEN(64) + 1 */
        char *function;
        uint8_t *obj;
        size_t len;
        public_identity_t to_whom;
        public_identity_t from_whom;
        /* from_rank / trace_id / verified / has_signature were MISSING here
           until 2026-08-12 (doc/architecture/native-ffi-dual-implementation.md): the
           mirror was 1848 bytes against
           C's 1888. Note where each one goes — `from_rank` sits between
           `from_whom` and `encrypt`, and `trace_id` after `return_to`, exactly as
           in msg_types.h. Order IS layout, so appending them at the end would
           have left every field from `encrypt` onward reading at the wrong
           offset, which is the same defect with a tidier diff. */
        int from_rank;
        bool encrypt;
        char return_to[65];
        char trace_id[33];      /* 32-char hex + NUL; NET_TRACE_ID_LEN */
        bool verified;
        bool has_signature;
    } net_msg_t;

    typedef enum {
        TASK_STATUS_RUNNING = 1,
        TASK_STATUS_SLEEPING,
        TASK_STATUS_ZOMBIE,
        TASK_STATUS_STOPPED,
        TASK_STATUS_DEAD,
        TASK_STATUS_PENDING,
        TASK_STATUS_UNKNOWN
    } task_status_val_t;

    typedef struct {
        unsigned char task_uuid[16];
        unsigned char requestor_uuid[16];
        task_status_val_t status;
    } task_status_msg_t;

    typedef struct {
        unsigned char task_uuid[16];
        unsigned char requestor_uuid[16];
        uint8_t *result_data;
        size_t result_len;
    } task_result_msg_t;

    typedef struct {
        unsigned char task_uuid[16];
        unsigned char peer_uuid[16];
        double score;
        /* Added 2026-08-12 (doc/architecture/native-ffi-dual-implementation.md): the
         * mirror was 40 bytes against C's
           112. CAP_NAMELEN is PROC_NAME_LEN(64), + NUL. Carried verbatim by the
           whole-struct memcpy in msg_types.c, so a short mirror truncates the
           capability name that resolves the transaction weight. */
        char capability_name[65];
        /* Evidence channel (R+D.md §12.8). TX_CHANNEL_NAMELEN is 31, + NUL.
           Carried verbatim by the same whole-struct memcpy, so a short or
           missing mirror truncates the channel into an unknown spelling --
           which the far end then refuses rather than grades, an obscure way to
           learn the mirror drifted. Mirrors reputation/tx_channel.h. */
        char channel[32];
        /* Learned EMA weight multiplier (R+D.md §12.5). Same whole-struct
           memcpy, so an absent mirror shifts nothing but loses the field and
           silently weights every peer at the authored number. Non-positive
           (a zeroed struct) means 1.0, which is what pre-field producers
           meant. Local-only: this struct never crosses the wire. Mirrors
           Python TransactionScore.competence. */
        double competence;
    } tx_score_msg_t;

    size_t message_size(message_type_t type);

    /* ---- utilities/message.h ---- */
    typedef struct {
        int fd;
        char key[65];            /* MSG_KEY_LEN(64) + 1 */
    } queue_t;

    int  messaging_init(const char *id, queue_t *queue);
    void messaging_assign(queue_t *queue);
    int  messaging_send(const char *key, const message_type_t type,
                        void *msg, bool blocking);
    void messaging_qclose(queue_t *queue);
    void messaging_close(void);

    /* ---- processes/process_tracker.h ---- */
    typedef struct {
        bool alloc; size_t refs;  /* smrt_ptr_t */
        map_t *registry;
        logger_t *logger;
    } tracker_t;

    int  tracker_init(tracker_t *tracker, logger_t *logger);
    int  tracker_create(tracker_t **tracker_ptr, logger_t *logger);
    void tracker_free(tracker_t *tracker);

    /* ---- processes/processes.h (partial) ---- */
    typedef struct process_s process_t;  /* opaque */

    typedef int (*handler_ptr_t)(process_t *, array_t *, char *, logger_t *);

    /* The four trailing collaborators became a `proc_context_t` in the
       2026-07-01 refactor (doc/architecture/process-architecture.md,
       autonomous_trust.c:283); this cdef
       kept the old 8-arg form until 2026-08-04. Nothing calls it from Python,
       so it was LATENT rather than a live segfault — `audit-ffi-drift.py`
       classifies it exactly that way. */
    typedef struct {
        map_t *procs;
        pthread_mutex_t *procs_lock;
        directory_t *queues;
        logger_t *logger;
    } proc_context_t;

    int  start_process(char *pname, handler_ptr_t runner,
                       map_t *configs, tracker_t *tracker,
                       proc_context_t *ctx);
    void process_free(process_t *proc);

    /* ---- negotiation/task.h ---- */
    /* task_t contains embedded capability_t (opaque), so treat as opaque */
    typedef struct task_s task_t;

    typedef struct {
        /* `task_t *task_ptr` used to lead this struct and does NOT exist in C
           (negotiation.h: uuid_t task_uuid; int flood_count). Removed 2026-08-12
           (doc/architecture/native-ffi-dual-implementation.md) — this is the one mirror
           that was BIGGER than C, 32
           bytes against 20, so it did not overflow; it read `task_uuid` out of
           C's `flood_count` and past the end. */
        unsigned char task_uuid[16];
        int flood_count;
    } task_counter_t;

    /* task_tracker_t contains embedded map_t (opaque) — treat as opaque */
    typedef struct task_tracker_s task_tracker_t;

    int  task_tracker_create(task_tracker_t **tracker,
                             const unsigned char *task_uuid, int expected);
    int  task_tracker_init(task_tracker_t *tracker,
                           const unsigned char *task_uuid, int expected);
    void task_tracker_destroy(task_tracker_t *tracker);
    int  task_tracker_set_result(task_tracker_t *tracker,
                                const unsigned char *peer_uuid,
                                const uint8_t *data, size_t len);
    int  task_tracker_result_count(const task_tracker_t *tracker);
    /* What the requestor asked for, retained so the reply can be judged
       against it (R+D.md §12.7). Python's TaskTracker subclasses Task and
       keeps `parameters` for free. */
    int  task_tracker_set_request(task_tracker_t *tracker,
                                  const char *capability_name,
                                  const char *kwargs_json);
    void task_tracker_free(task_tracker_t *tracker);

    /* ---- negotiation/negotiation.h ---- */
    /* job_queue_t contains embedded task_t with opaque fields */
    typedef struct job_queue_s job_queue_t;

    int  job_queue_create(job_queue_t **q);
    int  job_queue_init(job_queue_t *q);
    void job_queue_destroy(job_queue_t *q);
    int  job_queue_count(const job_queue_t *q);
    void job_queue_clear(job_queue_t *q);

    /* ---- reputation/reputation.h ---- */
    typedef struct {
        unsigned char task_uuid[16];
        unsigned char p1_uuid[16];
        double p1_score;
        bool p1_set;
        unsigned char p2_uuid[16];
        double p2_score;
        bool p2_set;
        int index;
        /* Added 2026-08-12 (doc/architecture/native-ffi-dual-implementation.md):
         * hash-linking's prev_hash was missing,
           so the mirror was 80 bytes against C's 152. TX_HASH_HEX_LEN(64) + NUL. */
        char prev_hash[65];
        /* Added 2026-09-02 (R+D.md §12.8): the evidence channel of each side's
         * score is part of the committed fact, so it is part of this struct.
         * TX_CHANNEL_NAMELEN(31) + NUL, appended after prev_hash exactly as C
         * appends it. */
        char p1_channel[32];
        char p2_channel[32];
    } transaction_t;

    /* tx_history_t/reputations_t contain embedded maps/arrays — opaque */
    typedef struct tx_history_s tx_history_t;
    typedef struct reputations_s reputations_t;

    int  tx_history_create(tx_history_t **hist);
    int  tx_history_init(tx_history_t *hist);
    void tx_history_destroy(tx_history_t *hist);
    int  tx_history_update(tx_history_t *hist, const unsigned char *task_uuid,
                           const unsigned char *peer_uuid, double score,
                           const char *channel);
    int  tx_history_len(const tx_history_t *hist);
    void tx_history_free(tx_history_t *hist);

    int  reputations_create(reputations_t **reps);
    int  reputations_init(reputations_t *reps);
    void reputations_destroy(reputations_t *reps);
    int  reputations_update(reputations_t *reps,
                            const unsigned char *peer_uuid, double score);
    int  reputations_get(const reputations_t *reps,
                         const unsigned char *peer_uuid, double *score);
    bool reputations_contains(const reputations_t *reps,
                              const unsigned char *peer_uuid);
    void reputations_free(reputations_t *reps);

    double reputation_compute(const tx_history_t *hist,
                              const reputations_t *reps,
                              const unsigned char *self_uuid,
                              const unsigned char *peer_uuid,
                              const map_t *task_weights);

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

    # 2. Relative to this source tree
    src_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        # Distributed alongside _ffi.py in core/_native/
        os.path.join(src_dir, 'libautonomous_trust.so'),
        # Development build tree (src/c/build/)
        os.path.join(src_dir, '..', '..', '..', '..', 'c', 'build',
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
        "env var or build the C library (build.sh)."
    )


def _preload_deps():
    """Pre-load shared library dependencies so dlopen() can resolve symbols."""
    # crypto/ssl are needed because the lib is built AT_ZTA=ON (OpenSSL). They
    # usually resolve via RPATH/LD_LIBRARY_PATH; preloading is belt-and-braces.
    dep_names = ['sodium', 'jansson', 'protobuf-c', 'protobuf', 'uuid', 'crypto', 'ssl']
    for name in dep_names:
        path = ctypes.util.find_library(name)
        if path:
            try:
                ctypes.CDLL(path, mode=ctypes.RTLD_GLOBAL)
            except OSError:
                pass


_preload_deps()
lib = ffi.dlopen(_find_library())
