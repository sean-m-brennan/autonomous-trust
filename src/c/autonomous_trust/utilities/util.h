/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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

#ifndef UTIL_H
#define UTIL_H

#include <sys/types.h>

#include "exception.h"

#define TERM_RESET "\x1B[0m"
#define TERM_RED "\x1B[31m"
#define TERM_GREEN "\x1B[32m"
#define TERM_YELLOW "\x1B[33m"
#define TERM_BLUE "\x1B[34m"
#define TERM_PURPLE "\x1B[35m"

int min(int a, int b);
int max(int a, int b);

char *strremove(char *str, const char *sub);

int makedirs(char *path, mode_t mode);

int compare_float_precision(float f1, float f2, float, float epsilon);

#define compare_float(f1, f2) \
    compare_float_precision(f1, f2, 0.00001)

int compare_double_precision(double f1, double f2, double epsilon);

#define compare_double(f1, f2) \
    compare_double_precision(f1, f2, 0.00001)

/********************/
// json errors

#define EJSN_OBJ_SET 201
DECLARE_ERROR(EJSN_OBJ_SET, "JSON error when adding an element to an object");

#define EJSN_ARR_APP 202
DECLARE_ERROR(EJSN_ARR_APP, "JSON error when appending to an array");

#define EJSN_DUMP 203
DECLARE_ERROR(EJSN_DUMP, "JSON error dumping to string/file/etc.");

#endif // UTIL_H
