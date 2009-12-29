#!/bin/bash

gcc -std=c99 -O2 ../htree.c test_htree.c -ltokyocabinet -pg && time ./a.out
#gcc -std=c99 htree.c hstore.c test_store.c -ltokyocabinet && ./a.out
#gcc -std=c99 htree.c hstore.c test_store.c -ltokyocabinet && ./a.out
