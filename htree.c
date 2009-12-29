/*
 *  Beansdb - A high available distributed key-value storage system:
 *
 *      http://beansdb.googlecode.com
 *
 *  Copyright 2009 Douban Inc.  All rights reserved.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      Davies Liu <davies.liu@gmail.com>
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include <tcutil.h>
#include <tchdb.h>
#include <stdbool.h>
#include <stdint.h>

#include "fnv1a.h"
#include "htree.h"

const int BUCKET_SIZE = 16;
const int SPLIT_LIMIT = 128; // (1 << (BUCKET_WIDTH+2)) // *1.5
const int MAX_DEPTH = 6;
static const int g_index[] = {0, 1, 17, 289, 4913, 83521, 1419857, 24137569, 410338673};
const char KEY_PATTERN[] = "%03d";

typedef struct t_item Item;
struct t_item {
    uint32_t keyhash;
    uint32_t hash;
    short    ver;
    unsigned char length;
    char     name[1];
};

#define HASH(it) ((it)->hash)

typedef struct t_data Data;
struct t_data {
    int size;
    int count;
    Item head[0];
};

typedef struct t_node Node;
struct t_node {
    uint16_t is_node:1;
    uint16_t valid:1;
    uint16_t modified:1;
    uint16_t depth:4;
    uint16_t flag:9;
    uint16_t hash;
    uint32_t count;
};

struct t_hash_tree {
    int depth;
    int height;
    TCHDB *db;
    Node *root;
    Data **data;
    int pool_size;
    pthread_mutex_t lock;
    char keybuf[30];
    char buf[512];
};

#define max(a,b) ((a)>(b)?(a):(b))

// forward dec
static void add_item(HTree *tree, Node *node, Item *it, 
        bool autosave, bool enlarge);
static void remove_item(HTree *tree, Node *node, Item *it, bool autosave);
static void split_node(HTree *tree, Node *node);
static void merge_node(HTree *tree, Node *node);
static void update_node(HTree *tree, Node *node);

inline uint32_t get_pos(HTree *tree, Node *node)
{
    return (node - tree->root) - g_index[(int)node->depth];
}

inline Node *get_child(HTree *tree, Node *node, int b)
{
    assert(0 <= b && b <= 0x0f);
    assert(node->depth < tree->height - 1);

    int i = g_index[node->depth + 1] + (get_pos(tree, node) << 4) + b;
    
    assert( i < tree->pool_size );
    if (i >= tree->pool_size){
        printf("get_child out of bound: %dth %d >= %d\n", b, i, tree->pool_size);
        return NULL;
    }
    return tree->root + i;
}

inline char* get_key(HTree *tree, Node *node)
{
    sprintf(tree->keybuf, KEY_PATTERN, node - tree->root);
    return tree->keybuf; 
}

inline Data* get_data(HTree *tree, Node *node)
{
    return tree->data[node - tree->root];
}

inline void set_data(HTree *tree, Node *node, Data *data)
{
    tree->data[node - tree->root] = data;
}

static int get_max_pos(TCHDB *db)
{
    tchdbiterinit(db);
    char *key;
    int max_pos = 0;
    while(key = tchdbiternext2(db)){
        int pos = atoi(key);
        if (pos > max_pos) max_pos = pos;
        free(key);
    }
    return max_pos;
}


// TODO: may be failed
//
static void enlarge_pool(HTree *tree)
{
    int i;
    int old_size = tree->pool_size;
    int new_size = g_index[tree->height + 1];
    
    tree->root = realloc(tree->root, sizeof(Node) * new_size);
    assert(tree->root);
    memset(tree->root + old_size, 0, sizeof(Node) * (new_size - old_size));
    for (i=old_size; i<new_size; i++){
        tree->root[i].depth = tree->height;
    }

    tree->data = realloc(tree->data, sizeof(Data*) * new_size);
    assert(tree->data);
    memset(tree->data + old_size, 0, sizeof(Data*) * (new_size - old_size));
   
    tree->height ++;
    tree->pool_size = new_size;
}

static void *load_node(HTree *tree, Node *node)
{
    assert(node);
    assert(tree->db);

    if (node->is_node) return NULL;

    Data *data = get_data(tree, node);
    if (data) return data;

    char *key = get_key(tree, node);
    int nsize = 0;
    data = tchdbget(tree->db, key, strlen(key), &nsize);
    
    // check
    if (data){
        if (data->size != nsize){
            fprintf(stderr, "broken data: size %d not match data->size %d\n",
                    nsize, data->size);
            free(data);
            data = NULL;
        }else{
            int i;
            Item *it = data->head;
            void *end = (void*)data + data->size;
            int64_t mask = (1L << ((8 - tree->depth) * 4)) - 1;
            int64_t pos = get_pos(tree, node);
            int64_t _min = pos << ((8 - tree->depth - node->depth) * 4);
            int64_t _max = (pos + 1) << ((8 - tree->depth - node->depth) * 4); 
            for (i=0; i<data->count; i++){
                if ((void*)it + it->length >= end){
                    fprintf(stderr, "broken data: item %d out of bound %d\n",
                        i, data->size);
                    data->count = i;
                    node->valid = 0;
                    node->modified = 1;
                    break;
                }else if (0 != *((char*)it + it->length - 1)){
                    fprintf(stderr, "broken data: item not ends with 0\n");
                    *((char*)it + it->length - 1) = 0;
                    data->count = i;
                    node->valid = 0;
                    node->modified = 1;
                    break;
                }else if (it->keyhash != fnv1a(it->name, strlen(it->name))){
                    fprintf(stderr, "invalid item: keyhash %x not match %x",
                            it->keyhash, fnv1a(it->name, strlen(it->name)));
                    data->count = i;
                    node->valid = 0;
                    node->modified = 1;
                }else if (node->depth > 0 && ((it->keyhash & mask) < _min 
                        || (it->keyhash & mask) >= _max)){
                    fprintf(stderr, "invalid item: %x & %x at %x (%x-%x)\n", it->keyhash, mask, pos, 
                            _min, _max);
                    data->count = i;
                    node->valid = 0;
                    node->modified = 1;
                    break;
                }
            }
        }
    }
    
    if (data){
        if (data->count < 0){
            if (node->depth < tree->height - 1){
                node->is_node = 1;
                free(data);
                data = NULL;
            }else{
                fprintf(stderr, "broken data: should not be node\n");
                data->count = 0;
                node->valid = 0;
                node->modified = 1;
            }
        }
    }else{
        data = (Data*) malloc(64);
        assert(data);
        data->count = 0;
        data->size = 64;
    }
    //assert(node->modified == 0);
    node->valid == 0;

    set_data(tree, node, data);
    return data;
}

static void save_node(HTree *tree, Node *node)
{
    assert(node);
    Data *data = get_data(tree, node);
    if (data){
        if (node->modified){
            char *key = get_key(tree, node);
            if(tchdbput(tree->db, key, strlen(key), data, data->size)){
                update_node(tree, node);
                free(data);
                set_data(tree, node, NULL);
                node->modified = 0;
            }else{
                fprintf(stderr, "put %s into db %s failed\n", key, tchdbpath(tree->db));
            }
        }else{
            free(data);
            set_data(tree, node, NULL);
        }
    }
    if (node->is_node){
        int i;
        for (i=0; i<BUCKET_SIZE; i++) {
            save_node(tree, get_child(tree, node, i));
        }
    }
}

static void clear(HTree *tree, Node *node)
{
    assert(node);

    tchdbout2(tree->db, get_key(tree, node));
    Data *data = get_data(tree, node);
    if (data) free(data);

    /*data = (Data*) malloc(64);
    assert(data);
    data->count = 0;
    data->size = 64;
    set_data(tree, node, data);*/
    set_data(tree, node, NULL);
    
    node->is_node = 0;
    node->valid = 0;
    node->modified = 0;
}

static Item* create_item(HTree *tree, const char *name, int ver, uint32_t hash)
{
    size_t n = strlen(name);
    Item *it = (Item*)tree->buf;
    strncpy(it->name, name, n);
    it->name[n] = 0;
    it->ver = ver;
    it->hash = hash;
    it->keyhash = fnv1a(name, n);
    it->length = sizeof(Item) + n;

    return it;
}

#define INDEX(it) (0x0f & ((it)->keyhash >> ((7 - node->depth - tree->depth) * 4)))

static void add_item(HTree *tree, Node *node, Item *it, 
        bool autosave, bool enlarge)
{
    assert(tree);
    assert(it);

    Data *data = load_node(tree, node);

    if (node->is_node) {
        node->valid = 0;
        add_item(tree, get_child(tree, node, INDEX(it)), it, autosave, enlarge);
        return ;
    }

    Item *p = data->head;
    int i;
    for (i=0; i<data->count; i++){
        assert(p);
        if (it->keyhash == p->keyhash && strcmp(it->name, p->name) == 0){
            if (it->ver > p->ver){
                if(node->valid){
                    node->hash += (HASH(it) - HASH(p)) * it->keyhash;
                }
                p->ver = it->ver;
                p->hash = it->hash;
                
                node->modified = 1;
                if (autosave){
                    save_node(tree, node);
                }
            }
            return;
        }
        p = (Item*)((char*)p + p->length);
    }

    if (data->size < (void*)p - (void*)data + it->length){
        int size = data->size + max(64, it->length);
        int pos = (void*)p-(void*)data;
        data = realloc(data, size);
        assert(data);
        data->size = size;
        set_data(tree, node, data);
        p = (Item *)((void*)data + pos);
    }
    
    assert(p);
    memcpy(p, it, it->length);
    data->count ++;
    if (node->valid){
        node->count = data->count;
        node->hash += it->keyhash * HASH(it);
    }
    
    if (data->count > SPLIT_LIMIT){
        if (node->depth == tree->height - 1){
            if (enlarge){
                int pos = node - tree->root;
                enlarge_pool(tree);
                node = tree->root + pos; // reload
                split_node(tree, node);
            }
        }else{
            split_node(tree, node);
        }
    }
   
    node->modified = 1;
    if (autosave){
        save_node(tree, node);
    }
}

static void split_node(HTree *tree, Node *node)
{
    assert(tree && node);
    assert(!node->is_node);

    Node *child = get_child(tree, node, 0);
    assert (child);
    int i;
    for (i=0; i<BUCKET_SIZE; i++){
        clear(tree, child+i);
    }
    
    Data *data = load_node(tree, node);
    Item *it = data->head;
    for (i=0; i<data->count; i++) {
        add_item(tree, child + INDEX(it), it, false, false);
        it = (Item*)((void*)it + it->length);
    }
   
    free(data);
    data = (Data*) malloc(sizeof(Data));
    data->size = sizeof(Data);
    data->count = -1;
    set_data(tree, node, data);
    
    node->is_node = 1;
    node->valid = 0;
}


void remove_item(HTree *tree, Node *node, Item *it, bool autosave)
{
    assert(tree && node && it);

    // load data, then know the type
    Data *data = load_node(tree, node);

    if (node->is_node) {
        node->valid = 0;
        remove_item(tree, get_child(tree, node, INDEX(it)), it, autosave);
        update_node(tree, node);
        if (node->count <= SPLIT_LIMIT && node->is_node){
            merge_node(tree, node);
            if (autosave){
                save_node(tree, node);
            }
        }
        return ;
    }

    if (data->count == 0) return ;
    Item *p = data->head;
    int i;
    for (i=0; i<data->count; i++){
        if (it->keyhash == p->keyhash && strcmp(it->name, p->name) == 0){
            if(node->valid){
                node->count --;
                node->hash -= p->keyhash * HASH(p);
            }
            data->count --;
            memcpy(p, (void*)p + p->length, 
                    data->size - ((void*)p - (void*)data) - p->length);
            node->modified = 1;
            if (autosave){
                save_node(tree, node);
            }
            return;
        }
        p = (Item*)((void*)p + p->length);
    }
}

static void merge_node(HTree *tree, Node *node)
{
    assert(tree);
    assert(node->count <= SPLIT_LIMIT);

    clear(tree, node);

    Node* child = get_child(tree, node, 0);
    int i, j;
    for (i=0; i<BUCKET_SIZE; i++){
        assert(!child[i].is_node);
        Data *data = load_node(tree, child+i); 
        Item *it = data->head;
        for (j=0; j<data->count; j++){
            add_item(tree, node, it, false, false);
            it = (Item*)((void*)it + it->length);
        }
        clear(tree, child + i);
    }
}

void update_node(HTree *tree, Node *node)
{
    if (node->valid) return ;
    
    int i;
    Data *data = load_node(tree, node);
    node->hash = 0;
    if (node->is_node){
        Node *child = get_child(tree, node, 0);
        node->count = 0;
        for (i=0; i<BUCKET_SIZE; i++){
            update_node(tree, child+i);
            node->hash = node->hash * 97 + child[i].hash;
            node->count += child[i].count;
        }
        if (node->count <= SPLIT_LIMIT){
            merge_node(tree, node);
            update_node(tree, node);
            save_node(tree, node);
        }
    }else{
        node->count = data->count;
        Item* it = data->head;
        for (i=0; i<data->count; i++){
            node->hash += it->keyhash * HASH(it);
            it = (Item*)((void*)it + it->length);
        }
    }
    node->valid = 1;
}

// call note_update before call it
static uint32_t get_item_hash(HTree* tree, Node* node, Item* it, int* ver)
{
    assert(node->valid);
    if (node->is_node){
        return get_item_hash(tree, get_child(tree, node, INDEX(it)), it, ver);
    }
    
    Data *data = load_node(tree, node);
    Item *p = data->head;
    int i;
    for (i=0; i<data->count; i++){
        if (it->keyhash == p->keyhash && strcmp(it->name, p->name) == 0){
            if (ver) *ver = p->ver;
            return p->hash;
        }
        p = (Item*)((char*)p + p->length);
    }
    if (ver) *ver = 0;
    return 0;
}

inline int hex2int(char b)
{
    if (('0'<=b && b<='9') || ('a'<=b && b<='f')) {
        return (b>='a') ?  (b-'a'+10) : (b-'0');
    }else{
        return -1;
    }
}

// call note_update before call it
static uint16_t get_node_hash(HTree* tree, Node* node, const char* dir, 
    int *count)
{
    assert(node->valid);
    if (node->is_node && strlen(dir) > 0){
        char i = hex2int(dir[0]);
        if (i >= 0) {
            return get_node_hash(tree, get_child(tree, node, i), dir+1, count);
        }else{
            if(count) *count = 0;
            return 0;
        }
    }
    
    if (count) *count = node->count;
    return node->hash;
}

static char* list_dir(HTree *tree, Node* node, const char* dir)
{
    Data *data = load_node(tree, node); 

    /*if (!node->is_node && data->count > SPLIT_LIMIT){
        if (node->depth == tree->height - 1){
            int pos = node - tree->root;
            enlarge_pool(tree);
            node = tree->root + pos; // reload
            data = load_node(tree, node); 
            split_node(tree, node);
        }else{
            split_node(tree, node);
        }
	update_node(tree, node);
    }*/
    
    if (node->is_node && strlen(dir) > 0){
        int b = hex2int(dir[0]);
        if (b >=0 ) {
            return list_dir(tree, get_child(tree, node, b), dir+1);
        }else{
            return NULL;
        }
    }
    /*node->valid = 0;
    update_node(tree, node);*/
    
    int bsize = 4096;
    char *buf = (char*) malloc(bsize);
    memset(buf, 0, bsize);
    int n = 0, i, j;
    if (node->is_node) {
        Node *child = get_child(tree, node, 0);
        for (i=0; i<BUCKET_SIZE; i++) {
            Node *t = child + i;
            update_node(tree, t);
            n += snprintf(buf + n, bsize - n, "%x/ %u %u\n", 
                        i, t->hash, t->count);
        }
    }else{
        Item *it = data->head;
        for (i=0; i<data->count; i++){
            n += snprintf(buf+n, bsize-n, "%s %u %u\n", 
                        it->name, it->hash, it->ver);
            if (bsize - n < 200) {
                buf = (char*)realloc(buf, bsize * 2);
                bsize *= 2;
            }
            it = (Item*)((char*)it + it->length);
        }
    }
    return buf;
}

/*
 * API
 */

HTree* ht_open(char* path, int depth)
{
    HTree *tree = (HTree*)malloc(sizeof(HTree));
    assert(tree);
    if (!tree) return NULL;
    tree->depth = depth;
    
    TCHDB *db = tchdbnew();
    assert(db);
    tchdbtune(db, 1024 * 64, 6, -1, HDBTDEFLATE);
    tchdbsetxmsiz(db, 128 * 4 * 1024);
    if (!tchdbopen(db, path, HDBOCREAT | HDBOREADER | HDBOWRITER)){
        printf("HTree: open %s failed. %s\n", path, 
                tchdberrmsg(tchdbecode(db)));
        tchdbdel(db);
        free(tree);
        return NULL;
    }
    tree->db = db;

    char *sync = tchdbget2(db, "__sync__");
    Node *root = NULL;
    int pool_size = 0, i;
    if (sync && *sync == '1') {
        root = tchdbget(db, "__pool__", 8, &pool_size);
        if (root){
            pool_size /= sizeof(Node);
            tree->height = 0;
            while (g_index[tree->height] < pool_size){
                tree->height ++;
            }
            assert(g_index[tree->height] == pool_size);
            if (g_index[tree->height] != pool_size){
                printf("invalid pool length: %d\n", pool_size);
                root = NULL;
                pool_size = 0;
                tree->height = 0;
            }
            tchdbout2(db, "__pool__");
        }else{
            fprintf(stderr, "__pool__ not found in %s\n", path);
        }

        tchdbout2(db, "__sync__");
        free(sync);
    }
    
    if (!root) {
        tree->height = 1;

        int max_pos = get_max_pos(db);
        if (max_pos >= g_index[MAX_DEPTH]){
            printf("too deep tree: max_pos=%d\n", max_pos);
            tchdbvanish(db);
        }else{
            while(g_index[tree->height] <= max_pos) tree->height ++;
        }
        if (tree->height > 1){
            printf("rebuild htree %s : height=%d\n", path, tree->height);
        }

        pool_size = g_index[tree->height];
        root = (Node*)malloc(sizeof(Node) * pool_size);
        assert(root);
        if (!root){
            tchdbclose(db);
            tchdbdel(db);
            free(tree);
            return NULL;
        }
        memset(root, 0, sizeof(Node) * pool_size);

        // init depth
        int i,j;
        for (i=0; i<tree->height; i++){
            for (j=g_index[i]; j<g_index[i+1]; j++){
                root[j].depth = i;
            }
        }
    }

    tree->root = root;
    tree->pool_size = pool_size;

    tree->data = (Data**) malloc(sizeof(Data*) * pool_size);
    assert(tree->data);
    memset(tree->data, 0, sizeof(Data*) * pool_size);

    update_node(tree, root); //try to restore
    save_node(tree, root); // free data
    
    pthread_mutex_init(&tree->lock, NULL);
    return tree;
}

void ht_flush(HTree *tree)
{
    assert(tree);
    assert(tree->pool_size > 0);
    if (!tree) return ;
    
    pthread_mutex_lock(&tree->lock);
    
    update_node(tree, tree->root);
    save_node(tree, tree->root);
    //tchdbsync(tree->db);
    
    pthread_mutex_unlock(&tree->lock);
}

void ht_close(HTree *tree)
{
    assert(tree);
    assert(tree->pool_size > 0);
    if (!tree) return ;
   
    ht_flush(tree);

    pthread_mutex_lock(&tree->lock);

    if(tchdbput(tree->db, "__pool__", 8, tree->root, 
                    sizeof(Node) * tree->pool_size)){
        if(!tchdbput2(tree->db, "__sync__", "1"))
            fprintf(stderr, "put __sync__ in %s failed\n", 
                tchdbpath(tree->db));
    }else{
        fprintf(stderr, "put __pool__ in %s failed\n", 
            tchdbpath(tree->db));
    }
    tchdbclose(tree->db);
    tchdbdel(tree->db);
    tree->db = NULL;

    free(tree->root);
    free(tree->data);
    free(tree);

    pthread_mutex_unlock(&tree->lock);
}

void ht_clear(HTree *tree)
{
    assert(tree);
    if (!tree) return;

    pthread_mutex_lock(&tree->lock);

    tchdbvanish(tree->db);
    clear(tree, tree->root);
    /*memset(tree->root, 0, sizeof(Node)*tree->pool_size);
    int i,j;
    for (i=0; i<tree->height; i++){
        for (j=g_index[i]; j<g_index[i+1]; j++){
            tree->root[j].depth = i;
        }
    }*/
    int i;
    for(i=0; i<tree->pool_size; i++){
        if (tree->data[i]) free(tree->data[i]);
    }
    memset(tree->data, 0, sizeof(Data*) * tree->pool_size);

    pthread_mutex_unlock(&tree->lock);
}

void ht_add(HTree *tree, char *name, int ver, uint32_t hash, bool autosave)
{
    if (!tree || !name) return;

    pthread_mutex_lock(&tree->lock);

    Item *it = create_item(tree, name, ver, hash);
    add_item(tree, tree->root, it, autosave, true);

    pthread_mutex_unlock(&tree->lock);
}


void ht_remove(HTree* tree, char *name, bool autosave)
{
    if (!tree || !name) return;

    pthread_mutex_lock(&tree->lock);

    Item *it = create_item(tree, name, 0, 0);
    remove_item(tree, tree->root, it, autosave);
    
    pthread_mutex_unlock(&tree->lock);
}

uint32_t ht_get_hash(HTree* tree, char* key, int* count)
{
    if (!tree || !key) {
        if(count) *count = 0;
        return 0;
    }
    
    uint32_t hash = 0;
    pthread_mutex_lock(&tree->lock);

    update_node(tree, tree->root);

    if (key[0] == '@'){
        hash = get_node_hash(tree, tree->root, key+1, count);
    }else{
        Item *it = create_item(tree, key, 0, 0);
        hash = get_item_hash(tree, tree->root, it, count);
    }
    pthread_mutex_unlock(&tree->lock);
    return hash;
}

char* ht_list(HTree* tree, char* dir)
{
    if (!tree || !dir) return NULL;

    pthread_mutex_lock(&tree->lock);
    char* r = list_dir(tree, tree->root, dir);
    pthread_mutex_unlock(&tree->lock);

    return r;
}
