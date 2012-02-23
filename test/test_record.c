#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../../htree.c"
#include "../../codec.c"
#include "../../quicklz.c"
#include "../../record.c"

int c = 0;
int size = 0;
int comp = 0;
bool count(DataRecord *r, void *args, void *arg2)
{
    c += 1;
    size += r->vsz;
    return true;
}

void compress_with_lzo(DataRecord *r, void *args)
{
}

bool compress_with_quicklz(DataRecord *r, void *args, void *arg2)
{
    if (r->vsz <= 200) {
        size += r->vsz;
        return true;
    }
    char *v =(char*) malloc(r->vsz + 400);
    char *buf =(char*) malloc(QLZ_SCRATCH_COMPRESS);
    int n = qlz_compress(r->value, v, r->vsz, buf);
    if (n > 0) {
     c ++;
     size += qlz_size_compressed(v);
    }else {
     size += r->vsz;
     printf("error %d\n", n);
    }
    free(v);
    free(buf);
    return true;
}

#include <bzlib.h>
bool compress_with_bzip2(DataRecord *r, void *args, void *arg2)
{
    if (r->vsz <= 200) {
        size += r->vsz;
        return true;
    }
    char *v =(char*) malloc(r->vsz + 600 + r->vsz * 0.01);
    unsigned int n = r->vsz + 600 + r->vsz * 0.01;
    int ok = BZ2_bzBuffToBuffCompress(v, &n, r->value, r->vsz, 9, 0, 0);
    if (ok == BZ_OK) {
     c ++;
     size += n;
    }else{
      size += r->vsz;
    }
    free(v);
    return true;
}
/*
#include <zlib.h>
bool compress_with_zlib(DataRecord *r, void *args)
{
    if (r->vsz <= 200) {
        size += r->vsz;
        return true;
    }
    uLongf n = compressBound(r->vsz);
    char *v =(char*) malloc(n);
    int ok = compress2((Bytef*)v, &n, (Bytef*)r->value, r->vsz, 9);
    if (ok == Z_OK) {
     c ++;
     size += n;
    }else{
      size += r->vsz;
    }
    free(v);
    return true;
}

#include <libbsc.h>
bool compress_with_bsc(DataRecord *r, void *args)
{
    if (r->vsz <= 2000) {
        size += r->vsz;
        return true;
    }
    printf("bsc %d %d\n", c, r->vsz);
    char *v =(char*) malloc(r->vsz + LIBBSC_HEADER_SIZE);
    int n = bsc_compress((unsigned char *)r->value, (unsigned char *)v, r->vsz, 16, 128, LIBBSC_BLOCKSORTER_BWT, LIBBSC_FEATURE_NONE); 
    if (n > 0){
       c ++;
     size += n;
    }else {
     size += r->vsz;
     printf("error %d\n", n);
    }
    free(v);
    return true;
}
*/
void test(RecordVisitor v)
{
    c = 0; size = 0;
    time_t t = time(NULL);
    visit_record("051.data", true, v, NULL, NULL);
    printf("total: %d, size: %d, used: %d\n", c, size, time(NULL)-t);
}

int main(int argc, char** argv)
{
    test(count);
    test(compress_with_quicklz);
//    test(compress_with_zlib);
//    test(compress_with_bzip2);
//    test(compress_with_bsc);
    return 0;
}

