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

#ifndef COMPILER_H
#define COMPILER_H

#define QUOTE(x) #x

#if defined __GNUC__

#if __GNUC__ >= 20
#define GCC_20 true
#else
#define GCC_20 false
#endif
#if __GNUC__ >= 19
#define GCC_19 true
#else
#define GCC_19 false
#endif
#if __GNUC__ >= 18
#define GCC_18 true
#else
#define GCC_18 false
#endif
#if __GNUC__ >= 17
#define GCC_17 true
#else
#define GCC_17 false
#endif
#if __GNUC__ >= 16
#define GCC_16 true
#else
#define GCC_16 false
#endif
#if __GNUC__ >= 15
#define GCC_15 true
#else
#define GCC_15 false
#endif
#if __GNUC__ >= 14
#define GCC_14 true
#else
#define GCC_14 false
#endif
#if __GNUC__ >= 13
#define GCC_13 true
#else
#define GCC_13 false
#endif
#if __GNUC__ >= 12
#define GCC_12 true
#else
#define GCC_12 false
#endif
#if __GNUC__ >= 11
#define GCC_11 true
#else
#define GCC_11 false
#endif
#if __GNUC__ >= 10
#define GCC_10 true
#else
#define GCC_10 false
#endif
#if __GNUC__ >= 9
#define GCC_9 true
#else
#define GCC_9 false
#endif
#if __GNUC__ >= 8
#define GCC_8 true
#else
#define GCC_8 false
#endif
#if __GNUC__ >= 7
#define GCC_7 true
#else
#define GCC_7 false
#endif
#if __GNUC__ >= 6
#define GCC_6 true
#else
#define GCC_6 false
#endif
#if __GNUC__ >= 5
#define GCC_5 true
#else
#define GCC_5 false
#endif
#if __GNUC__ >= 4
#define GCC_4 true
#else
#define GCC_4 false
#endif

#define _GCC_V2(x) GCC_##x
#define _GCC_V(x) _GCC_V2(x)

#define _GCC_VER_COND3(a, b) a##b
#define _GCC_VER_COND2(a, b) _GCC_VER_COND3(a, b)
#define _GCC_VER_COND(f, v) _GCC_VER_COND2(f, _GCC_V(v))

#define _GCC_DIAGNOSTIC(which) QUOTE(GCC diagnostic ignored #which)

#endif // __GNUC__

#endif // COMPILER_H
