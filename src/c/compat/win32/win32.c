/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

/* The rest of at_win32.h: Winsock start-up and file mode, rename-over,
 * dladdr, strptime, mkdtemp. */

#include <at_win32.h>
#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>

/* Winsock must be started before the first socket call; libautonomous_trust
 * starts it as it loads, before any constructor of its own could open one. */
__attribute__((constructor(101))) static void _at_wsa_start(void)
{
    WSADATA data;
    (void)WSAStartup(MAKEWORD(2, 2), &data);
    /* Files are bytes, as on POSIX: the CRT's default text mode would write
     * every \n as \r\n, and AT's stores are pinned byte for byte against the
     * Python runtime's (social_store_test, the JCS hashes). One UCRT is shared
     * by every DLL in the process, jansson's fopen included. */
    (void)_set_fmode(_O_BINARY);
}

#undef rename
int at_w32_rename(const char *from, const char *to)
{
    if (MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        return 0;
    DWORD err = GetLastError();
    errno = err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND ? ENOENT
          : err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION ? EACCES
          : EIO;
    return -1;
}

int dladdr(const void *addr, Dl_info *info)
{
    static __thread char path[MAX_PATH * 2];
    HMODULE mod = NULL;
    if (info == NULL
        || !GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                               | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)addr, &mod))
        return 0;
    DWORD n = GetModuleFileNameA(mod, path, sizeof(path));
    if (n == 0 || n >= sizeof(path))
        return 0;
    info->dli_fname = path;
    info->dli_fbase = (void *)mod;
    info->dli_sname = NULL;
    info->dli_saddr = NULL;
    return 1;
}

/* The strptime conversions AT parses with (ISO-8601: structures/datetime.c):
 * %Y %m %d %H %M %S, %F (= %Y-%m-%d), %T (= %H:%M:%S), %%, and literal
 * characters; whitespace in the format matches any run of it. */
static const char *_num(const char *s, int digits, int lo, int hi, int *out)
{
    int v = 0, n = 0;
    while (n < digits && isdigit((unsigned char)*s))
    {
        v = v * 10 + (*s++ - '0');
        n++;
    }
    if (n == 0 || v < lo || v > hi)
        return NULL;
    *out = v;
    return s;
}

char *strptime(const char *s, const char *f, struct tm *tm)
{
    int v;
    while (*f != '\0' && s != NULL)
    {
        if (isspace((unsigned char)*f))
        {
            while (isspace((unsigned char)*s))
                s++;
            f++;
            continue;
        }
        if (*f != '%')
        {
            if (*s != *f)
                return NULL;
            s++;
            f++;
            continue;
        }
        f++;
        switch (*f++)
        {
        case 'Y': if ((s = _num(s, 4, 0, 9999, &v))) tm->tm_year = v - 1900; break;
        case 'm': if ((s = _num(s, 2, 1, 12, &v)))   tm->tm_mon = v - 1;     break;
        case 'd': if ((s = _num(s, 2, 1, 31, &v)))   tm->tm_mday = v;        break;
        case 'H': if ((s = _num(s, 2, 0, 23, &v)))   tm->tm_hour = v;        break;
        case 'M': if ((s = _num(s, 2, 0, 59, &v)))   tm->tm_min = v;         break;
        case 'S': if ((s = _num(s, 2, 0, 61, &v)))   tm->tm_sec = v;         break;
        case 'F': s = strptime(s, "%Y-%m-%d", tm); break;
        case 'T': s = strptime(s, "%H:%M:%S", tm); break;
        case '%': if (*s++ != '%') return NULL; break;
        default:  return NULL;   /* a conversion AT does not use */
        }
    }
    return (char *)s;
}

/* Not _mktemp_s: it varies one letter, so a process gets at most 26 names per
 * template. Random characters instead, retried on a collision. */
char *mkdtemp(char *tmpl)
{
    static const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    size_t len = tmpl != NULL ? strlen(tmpl) : 0;
    if (len < 6 || strcmp(tmpl + len - 6, "XXXXXX") != 0)
    {
        errno = EINVAL;
        return NULL;
    }
    for (int attempt = 0; attempt < 100; attempt++)
    {
        for (size_t i = len - 6; i < len; i++)
        {
            unsigned int r = 0;
            (void)rand_s(&r);
            tmpl[i] = chars[r % (sizeof(chars) - 1)];
        }
        if (_mkdir(tmpl) == 0)
            return tmpl;
        if (errno != EEXIST)
            return NULL;
    }
    errno = EEXIST;
    return NULL;
}
