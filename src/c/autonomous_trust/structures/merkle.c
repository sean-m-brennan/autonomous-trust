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

#include "merkle.h"
#include "array.h"
#include "redblack.h"

struct merkleNode
{
    int digest; // FIXME hash
    void *blob;
    char *uuid;
};

struct merkleTree
{
    tree_t *tree;
    int superHash;
    array_t *blobs;
    array_t *unique;
    array_t *nonUnique;
};

