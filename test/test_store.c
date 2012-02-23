#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "hstore.h"

int main(int argc, char** argv)
{
    HStore *store = hs_open("testdb", 2);
    assert(store);
    hs_set(store, "hello", "hello", 5, 1);
    return 0;
    int n;
    printf("%s\n", hs_get(store, "@", &n));
    char *r = hs_get(store, "hello", &n);
    printf("%d %d\n", n, 0);
    return 0;
    hs_close(store);
    return 0;
}
