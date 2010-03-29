#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <tchdb.h>
#include "../fnv1a.h"
#include "../htree.c"
#include "../hstore.c"

typedef struct t_old_meta {
    int32_t version;
    uint32_t flags;
    int32_t length;
} OldMeta;

static TCHDB *my_open(const char *path, int mode)
{
    TCHDB *db = tchdbnew();
    if (!db){
        printf("create %s failed\n", path);
        exit(1);
    }
    tchdbtune(db, 1000000, 6, -1, HDBTDEFLATE);
    if(!tchdbopen(db, path, mode)){
        printf("open %s failed %d\n", path, tchdbecode(db));
   //     exit(1);
    }
    return db;
}

int main(int argc, char** argv)
{
    int i ;
    char buf[255];
    char *src = argv[1];
    char *dst = argv[2];
    printf("from %s to %s\n", src, dst);
    /*HStore *store = hs_open(dst, true, 2, 0, -1);
    if (!store){
        exit(1);
    }*/
    TCHDB **out = (TCHDB**) malloc(sizeof(TCHDB*) * 256);
    memset(out, 0, sizeof(TCHDB*) * 256);
    for (i=0; i<256; i++) {
        sprintf(buf, "%s/%02x.tch", dst, i);
        printf("open %s\n", buf);
        out[i] = my_open(buf, HDBOCREAT | HDBOREADER | HDBOWRITER| HDBONOLCK);
	if(!out[i]) {
	   exit(1);
	}
    }

    for (i=63; i<64; i++) {
        sprintf(buf, "%s/%02x.tch", src, i);
        printf("start to scan %s\n", buf);
        TCHDB* db = my_open(buf, HDBOREADER);
        if(!db) continue;
        sprintf(buf, "%s/.%02x.tch", src, i);
        TCHDB* index = my_open(buf, HDBOREADER);
        if(!index) continue;
        tchdbiterinit(db);
        TCXSTR *xkey = tcxstrnew(), *xvalue = tcxstrnew();
	int c = 0;
	time_t now = time(0);
        while (tchdbiternext3(db, xkey, xvalue)){
            void *key = (void*)tcxstrptr(xkey);
            void *value = (void*)tcxstrptr(xvalue);
            int nkey = tcxstrsize(xkey);
            int nvalue = tcxstrsize(xvalue);
            int ver = 1, flag = 0, vlen;

            OldMeta *old = (OldMeta*)tchdbget2(index, key);
            if (old){
                ver = old->version;
                flag = old->flags;
                free(old);
            }else{
                printf("no index: %s\n", key);
            }
            //hs_set(store, key, value, nvalue, ver, flag);
            char *v = malloc(nvalue + sizeof(Meta));
            memcpy(v, value, nvalue);
            Meta *meta = (Meta*)(v + nvalue);
            meta->version = ver;
            meta->flag = flag;
            meta->hash = gen_hash(v, nvalue);
	    meta->modified = now;

            unsigned int h = fnv1a(key, nkey);
            h = (h >> 24) & 0xff;
	    if (out[h])
	            tchdbput(out[h], key, nkey, v, nvalue + sizeof(Meta));
            free(v);

            tcxstrclear(xkey);
            tcxstrclear(xvalue);

	    c ++;
	    if (c % 10000 == 0){
	    	//hs_flush(store, 100);
		printf("%d\n", c);
	    }
        }
        tcxstrdel(xkey);
        tcxstrdel(xvalue);
        tchdbclose(index);
        tchdbclose(db);
    }
    for (i=0; i<256; i++){
    	if(out[i])
        tchdbclose(out[i]);
    }
    //hs_close(store);

    return 0;
}

