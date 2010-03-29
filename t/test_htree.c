#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../htree.h"

int main(int argc, char** argv)
{
    HTree *t = ht_open("*", 0);
    printf("hash %d\n", ht_get_hash(t, "@", NULL));
    printf("%s\n", ht_list(t,""));
    ht_clear(t);
    //printf("hash %d\n", ht_get_hash(t, "@", NULL));
    //printf("%s\n", ht_list(t,""));

    int i=0;
    char buf[100];
    for (int k=0;k<1;k++){
        for (i=0;i<200000;i++){
            sprintf(buf, "/photo/photo/%d.jpg", i);
            //printf(buf);
            ht_add(t, buf, 1, 3, 0);
        }
        printf("add complete\n");
        for (i=0;i<1000;i++){
            sprintf(buf, "/photo/photo/%d.jpg", i);
            /*sprintf(buf, "/photo/photo/xxxxxxxxxxxxxxxxxxxxxxfile%d", i);*/
            //ht_remove(t, buf, 0);
        }
        printf("remove complete\n");
    }
    //remove_from_htree(buf);
    printf("update complete\n");
    // print_tree(&tree);
   
    printf("hash %d\n", ht_get_hash(t, "@", NULL));
    printf("%s\n", ht_list(t,""));

    ht_close(t);
    return 0;
}
