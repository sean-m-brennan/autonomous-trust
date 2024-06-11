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

#ifndef REDBLACK_PRIV_H
#define REDBLACK_PRIV_H

#include "redblack.h"

enum Direction
{
    LEFT,
    RIGHT
};

enum Direction opposite_direction(enum Direction dir);

struct rbNode
{
    int key;
    bool red;
    tree_data_ptr_t data;
    struct rbNode *parent, *left, *right;
};

struct rbTree_s {
    struct rbNode *root;
    int size;
};

#endif  // REDBLACK_PRIV_H
