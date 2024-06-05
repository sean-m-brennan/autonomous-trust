#include <stdio.h>
#include "autonomous_trust/structures/array_priv.h"

void testArray()
{
    int errors = 0;
    array_t arr;
    array_init(&arr);

    data_t data = {0};
    data.intgr = 1;
    array_append(&arr, &data);
    data.str = "two";
    array_append(&arr, &data);
    data.bl = true;
    array_append(&arr, &data);
    data.flt_pt = 4.0;
    array_append(&arr, &data);
    data.uintr = 5UL;
    array_append(&arr, &data);
    data.byt = (unsigned char*)"six";
    array_append(&arr, &data);
    int size = array_size(&arr);
    if (size != 6) {
        printf("Incorrect array size: expected 6, actual %d\n", size);
        errors++;
    }

    array_get(&arr, 5, &data);
    unsigned char *bytes = data.byt;
    if (bytes != (unsigned char*)"six") {
        printf("Incorrect array entry: expected 'six', actual '%s'\n", bytes);
        errors++;
    }

    array_get(&arr, 4, &data);
    unsigned long l = data.uintr;
    if (l != 5UL) {
        printf("Incorrect array entry: expected %lu, actual %lu\n", 5UL, l);
        errors++;
    }
    
    array_get(&arr, 3, &data);
    double d = data.flt_pt;
    if (d != 4.0) {
        printf("Incorrect array entry: expected %f, actual %f\n", 4.0, d);
        errors++;
    }
    
    array_get(&arr, 2, &data);
    bool b = data.bl;
    if (d != 4.0) {
        printf("Incorrect array entry: expected 1, actual %d\n", b);
        errors++;
    }
    
    array_get(&arr, 1, &data);
    char *str = data.str;
    if (strcmp(str, "two") != 0) {
        printf("Incorrect array entry: expected 'two', actual '%s'\n", str);
        errors++;
    }
    
    array_get(&arr, 0, &data);
    int one = data.intgr;
    if (one != 1) {
        printf("Incorrect array entry: expected 1, actual %d\n", one);
        errors++;
    }

    printf("%d errors\n", errors);
}

int main(void)
{
    testArray();
    return 0;
}
