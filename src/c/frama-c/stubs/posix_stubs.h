/**
 * @file posix_stubs.h
 * @brief ACSL-annotated stub declarations for POSIX functions used by
 *        AutonomousTrust.  Covers pthreads (mutex, create/join/detach)
 *        and the subset of POSIX APIs the codebase relies on.
 *
 * Note: mq_* (POSIX message queues) are NOT used in the current codebase,
 * so they are omitted.  The project uses sockets (UDP/TCP) for IPC instead.
 *
 * Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef POSIX_STUBS_H
#define POSIX_STUBS_H

#include <stddef.h>

/* ================================================================
 * Opaque types — just enough for Frama-C to track validity.
 * We do NOT redefine these if the real headers are already included.
 * ================================================================ */

#ifndef _BITS_PTHREADTYPES_COMMON_H
#ifndef __FRAMA_C_POSIX_PTHREAD_TYPES
#define __FRAMA_C_POSIX_PTHREAD_TYPES

typedef unsigned long int pthread_t;

typedef union {
    char __size[40];
    long int __align;
} pthread_attr_t;

typedef union {
    char __size[40];
    long int __align;
} pthread_mutex_t;

typedef union {
    char __size[4];
    int __align;
} pthread_mutexattr_t;

#define PTHREAD_MUTEX_INITIALIZER { { 0 } }

#endif /* __FRAMA_C_POSIX_PTHREAD_TYPES */
#endif /* _BITS_PTHREADTYPES_COMMON_H */

/* ================================================================
 * pthread_mutex — Mutual Exclusion
 * ================================================================ */

/*@
  requires \valid(mutex);
  requires attr == \null || \valid_read(attr);
  assigns *mutex;
  ensures \result == 0 || \result > 0;
  // 0 = success; positive = errno on failure
*/
int pthread_mutex_init(pthread_mutex_t *mutex,
                       const pthread_mutexattr_t *attr);

/*@
  requires \valid(mutex);
  assigns *mutex;
  ensures \result == 0 || \result > 0;
  // Blocks until the lock is acquired.
  // 0 = success; EINVAL/EDEADLK on error
*/
int pthread_mutex_lock(pthread_mutex_t *mutex);

/*@
  requires \valid(mutex);
  assigns *mutex;
  ensures \result == 0 || \result > 0;
  // 0 = success; EBUSY = already locked by another thread
*/
int pthread_mutex_trylock(pthread_mutex_t *mutex);

/*@
  requires \valid(mutex);
  assigns *mutex;
  ensures \result == 0 || \result > 0;
  // 0 = success
*/
int pthread_mutex_unlock(pthread_mutex_t *mutex);

/*@
  requires \valid(mutex);
  assigns *mutex;
  ensures \result == 0 || \result > 0;
  // 0 = success; EBUSY = mutex is locked
*/
int pthread_mutex_destroy(pthread_mutex_t *mutex);

/* ================================================================
 * pthread — Thread creation / lifecycle
 * ================================================================ */

/*@
  requires \valid(thread);
  requires attr == \null || \valid_read(attr);
  requires \valid_read((void *)start_routine);
  assigns *thread;
  ensures \result == 0 || \result > 0;
  // 0 = success, thread is created and start_routine will be called.
*/
int pthread_create(pthread_t *thread,
                   const pthread_attr_t *attr,
                   void *(*start_routine)(void *),
                   void *arg);

/*@
  requires thread != 0;
  requires retval == \null || \valid(retval);
  assigns *retval \from thread;
  ensures \result == 0 || \result > 0;
  // Blocks until the target thread terminates.
*/
int pthread_join(pthread_t thread, void **retval);

/*@
  requires thread != 0;
  assigns \nothing;
  ensures \result == 0 || \result > 0;
  // Marks the thread as detached; its resources will be reclaimed
  // automatically on termination.
*/
int pthread_detach(pthread_t thread);

/*@
  assigns \nothing;
  ensures \result != 0;
  // Returns the thread ID of the calling thread.
*/
pthread_t pthread_self(void);

/*@
  requires \valid_read(name);
  assigns \nothing;
  ensures \result == 0 || \result > 0;
  // Sets the name of the calling thread (for debugging).
  // name must be <= 16 chars including NUL.
*/
int pthread_setname_np(pthread_t thread, const char *name);

/* ================================================================
 * Standard I/O stubs — minimal set used indirectly
 * ================================================================ */

/*@
  requires \valid_read(pathname);
  assigns \nothing;
  ensures \result >= -1;
  // Opens a file; returns fd >= 0 on success, -1 on error.
*/
int open(const char *pathname, int flags, ...);

/*@
  requires fd >= 0;
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int close(int fd);

/*@
  requires fd >= 0;
  requires \valid(buf + (0 .. count - 1));
  assigns buf[0 .. count - 1];
  ensures -1 <= \result <= (long long)count;
*/
long long read(int fd, void *buf, size_t count);

/*@
  requires fd >= 0;
  requires \valid_read((const char *)buf + (0 .. count - 1));
  assigns \nothing;
  ensures -1 <= \result <= (long long)count;
*/
long long write(int fd, const void *buf, size_t count);

/* ================================================================
 * Socket stubs — minimal for UDP/TCP
 * ================================================================ */

/*@
  assigns \nothing;
  ensures \result >= -1;
*/
int socket(int domain, int type, int protocol);

/*@
  requires sockfd >= 0;
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int bind(int sockfd, const void *addr, unsigned int addrlen);

/*@
  requires sockfd >= 0;
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int listen(int sockfd, int backlog);

/*@
  requires sockfd >= 0;
  assigns \nothing;
  ensures \result >= -1;
*/
int accept(int sockfd, void *addr, unsigned int *addrlen);

/*@
  requires sockfd >= 0;
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int connect(int sockfd, const void *addr, unsigned int addrlen);

/*@
  requires sockfd >= 0;
  requires \valid_read((const char *)buf + (0 .. len - 1));
  assigns \nothing;
  ensures -1 <= \result <= (long long)len;
*/
long long send(int sockfd, const void *buf, size_t len, int flags);

/*@
  requires sockfd >= 0;
  requires \valid((char *)buf + (0 .. len - 1));
  assigns ((char *)buf)[0 .. len - 1];
  ensures -1 <= \result <= (long long)len;
*/
long long recv(int sockfd, void *buf, size_t len, int flags);

/*@
  requires sockfd >= 0;
  requires \valid_read((const char *)buf + (0 .. len - 1));
  assigns \nothing;
  ensures -1 <= \result <= (long long)len;
*/
long long sendto(int sockfd, const void *buf, size_t len, int flags,
                 const void *dest_addr, unsigned int addrlen);

/*@
  requires sockfd >= 0;
  requires \valid((char *)buf + (0 .. len - 1));
  assigns ((char *)buf)[0 .. len - 1];
  ensures -1 <= \result <= (long long)len;
*/
long long recvfrom(int sockfd, void *buf, size_t len, int flags,
                   void *src_addr, unsigned int *addrlen);

/*@
  requires sockfd >= 0;
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int setsockopt(int sockfd, int level, int optname,
               const void *optval, unsigned int optlen);

#endif /* POSIX_STUBS_H */
