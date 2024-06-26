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

#include <stdlib.h>
#include "autonomous_trust/structures/redblack.h"

#define DEBUG_TESTS 0

#include "test_setup.h"

DEFINE_TEST(test_red_black_tree)
{
    
    /*int ch, data;
    while (1) {
        printf("1. Insertion\t2. Deletion\n");
        printf("\nEnter your choice:");
      scanf("%d", &ch);
      switch (ch) {
        case 1:
          printf("Enter the element to insert:");
          scanf("%d", &data);
          insertion(data);
          break;
        case 2:
          printf("Enter the element to delete:");
          scanf("%d", &data);
          deletion(data);
          break;
        default:
          printf("Not available\n");
          break;
      }
      printf("\n");
    }*/
}
END_TEST_DEFINITION()

RUN_TESTS(Red/Black Tree, test_red_black_tree)
