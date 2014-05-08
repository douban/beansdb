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
 *      Hurricane Lee <hurricane1026@gmail.com>
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <fcntl.h>
#include <ctype.h>

#include "fnv1a.h"
#include "htree.h"
#include "codec.h"
#include "const.h"

const int MAX_KEY_LENGTH = 200;
const int BUCKET_SIZE = 16;
const int SPLIT_LIMIT = 64;
const int MAX_DEPTH = 8;
static const long long g_index[] = {0, 1, 17, 273, 4369, 69905, 1118481, 17895697, 286331153, 4581298449L};

const char VERSION[] = "HTREE001";

#define max(a,b) ((a)>(b)?(a):(b))
#define INDEX(it) (0x0f & (keyhash >> ((7 - node->depth - tree->depth) * 4)))
#define KEYLENGTH(it) ((it)->length-sizeof(Item)+ITEM_PADDING)
#define HASH(it) ((it)->hash * ((it)->ver>0))

typedef struct t_data Data;
struct t_data
{
    int size;
    int used;
    int count;
    Item head[0];
};

typedef struct t_node Node;
struct t_node
{
    uint16_t is_node:1;
    uint16_t valid:1;
    uint16_t depth:4;
    uint16_t flag:9;
    uint16_t hash;
    uint32_t count;
    Data *data;
};

struct t_hash_tree
{
    int depth;
    int pos;
    int height;
    Node *root;
    Codec *dc;
    pthread_mutex_t lock;
    char buf[512];
};


// forward dec
static void add_item(HTree *tree, Node *node, Item *it, uint32_t keyhash, bool enlarge);
static void remove_item(HTree *tree, Node *node, Item *it, uint32_t keyhash);
static void split_node(HTree *tree, Node *node);
static void merge_node(HTree *tree, Node *node);
static void update_node(HTree *tree, Node *node);

static inline uint32_t get_pos(HTree *tree, Node *node)
{
    return (node - tree->root) - g_index[(int)node->depth];
}

static inline Node *get_child(HTree *tree, Node *node, int b)
{
    int i = g_index[node->depth + 1] + (get_pos(tree, node) << 4) + b;
    return tree->root + i;
}

static inline Data* get_data(Node *node)
{
    return node->data;
}

static inline void set_data(Node *node, Data *data)
{
    if (data != node->data)
    {
        if (node->data) free(node->data);
        node->data = data;
    }
}

static inline uint32_t key_hash(HTree *tree, Item* it)
{
    char buf[MAX_KEY_LENGTH];
    int n = dc_decode(tree->dc, buf, MAX_KEY_LENGTH, it->key, KEYLENGTH(it));
    return fnv1a(buf, n);
}

static Item* create_item(HTree *tree, const char* key, int len, uint32_t pos, uint16_t hash, int32_t ver)
{
    Item *it = (Item*)tree->buf;
    it->pos = pos;
    it->ver = ver;
    it->hash = hash;
    int n = dc_encode(tree->dc, it->key, 512 - (sizeof(Item) - ITEM_PADDING) , key, len);
    it->length = sizeof(Item) + n - ITEM_PADDING;
    return it;
}

static void enlarge_pool(HTree *tree)
{
    int i;
    int old_size = g_index[tree->height];
    int new_size = g_index[tree->height + 1];

    tree->root = (Node*)safe_realloc(tree->root, sizeof(Node) * new_size);
    memset(tree->root + old_size, 0, sizeof(Node) * (new_size - old_size));
    for (i=old_size; i<new_size; i++)
    {
        tree->root[i].depth = tree->height;
    }

    tree->height ++;
}

static void clear(Node *node)
{
    Data* data = (Data*)safe_malloc(64);
    data->size = 64;
    data->used = sizeof(Data);
    data->count = 0;
    set_data(node, data);

    node->is_node = 0;
    node->valid = 1;
    node->count = 0;
    node->hash = 0;
}

static void add_item(HTree *tree, Node *node, Item *it, uint32_t keyhash, bool enlarge)
{
    while (node->is_node)
    {
        node->valid = 0;
        node = get_child(tree, node, INDEX(it));
    }

    Data *data = get_data(node);
    Item *p = data->head;
    int i;
    for (i=0; i<data->count; ++i)
    {
        if (it->length == p->length &&
                memcmp(it->key, p->key, KEYLENGTH(it)) == 0)
        {
            node->hash += (HASH(it) - HASH(p)) * keyhash;
            node->count += (it->ver > 0);
            node->count -= (p->ver > 0);
            memcpy(p, it, sizeof(Item)); // safe
            return;
        }
        p = (Item*)((char*)p + p->length);
    }

    if (data->size < data->used + it->length)
    {
        int size = max(data->used + it->length, data->size + 64);
        int pos = (char*)p - (char*)data;
        Data *new_data = (Data*)safe_malloc(size);
        safe_memcpy(new_data, size, data, data->used);
        data = new_data;
        set_data(node, data);
        data->size = size;
        p = (Item *)((char*)data + pos);
    }

    safe_memcpy(p, data->size - data->used, it, it->length);
    data->count++;
    data->used += it->length;
    node->count += (it->ver > 0);
    node->hash += keyhash * HASH(it);

    if (node->count > SPLIT_LIMIT)
    {
        if (node->depth == tree->height - 1)
        {
            if (enlarge && node->count > SPLIT_LIMIT * 4)
            {
                int pos = node - tree->root;
                enlarge_pool(tree);
                node = tree->root + pos; // reload
                split_node(tree, node);
            }
        }
        else
        {
            split_node(tree, node);
        }
    }
}

static void split_node(HTree *tree, Node *node)
{
    Node *child = get_child(tree, node, 0);
    int i;
    for (i=0; i<BUCKET_SIZE; ++i)
    {
        clear(child + i);
    }

    Data *data = get_data(node);
    Item *it = data->head;
    for (i=0; i < data->count; ++i)
    {
        int32_t keyhash = key_hash(tree, it);
        add_item(tree, child + INDEX(it), it, keyhash, false);
        it = (Item*)((char*)it + it->length);
    }

    set_data(node, NULL);

    node->is_node = 1;
    node->valid = 0;
}

static void remove_item(HTree *tree, Node *node, Item *it, uint32_t keyhash)
{
    while (node->is_node)
    {
        node->valid = 0;
        node = get_child(tree, node, INDEX(it));
    }

    Data *data = get_data(node);
    if (data->count == 0) return ;
    Item *p = data->head;
    int i;
    for (i=0; i < data->count; ++i)
    {
        if (it->length == p->length &&
                memcmp(it->key, p->key, KEYLENGTH(it)) == 0)
        {
            data->count--;
            data->used -= p->length;
            node->count -= p->ver > 0;
            node->hash -= keyhash * HASH(p);
            memmove(p, (char*)p + p->length,
                    data->size - ((char*)p - (char*)data) - p->length);
            set_data(node, data);
            return;
        }
        p = (Item*)((char*)p + p->length);
    }
}

static void merge_node(HTree *tree, Node *node)
{
    clear(node);

    Node* child = get_child(tree, node, 0);
    int i, j;
    for (i=0; i<BUCKET_SIZE; i++)
    {
        Data *data = get_data(child+i);
        Item *it = data->head;
        int count = (child+i)->count;
        for (j=0; j < count; j++)
        {
            if (it->ver > 0)
            {
                add_item(tree, node, it, key_hash(tree, it), false);
            } // drop deleted items, ver < 0
            it = (Item*)((char*)it + it->length);
        }
        clear(child + i);
    }
}

static void update_node(HTree *tree, Node *node)
{
    if (node->valid) return ;

    int i;
    node->hash = 0;
    if (node->is_node)
    {
        Node *child = get_child(tree, node, 0);
        node->count = 0;
        for (i=0; i<BUCKET_SIZE; i++)
        {
            update_node(tree, child+i);
            node->count += child[i].count;
        }
        for (i=0; i<BUCKET_SIZE; i++)
        {
            if (node->count > SPLIT_LIMIT * 4)
            {
                node->hash *= 97;
            }
            node->hash += child[i].hash;
        }
    }
    node->valid = 1;

    // merge nodes
    if (node->count <= SPLIT_LIMIT)
    {
        merge_node(tree, node);
    }
}

static Item* get_item_hash(HTree* tree, Node* node, Item* it, uint32_t keyhash)
{
    while (node->is_node)
    {
        node = get_child(tree, node, INDEX(it));
    }

    Data *data = get_data(node);
    Item *p = data->head, *r = NULL;
    int i;
    for (i=0; i<data->count; i++)
    {
        if (it->length == p->length &&
                memcmp(it->key, p->key, KEYLENGTH(it)) == 0)
        {
            r = p;
            break;
        }
        p = (Item*)((char*)p + p->length);
    }
    return r;
}

static inline int hex2int(char b)
{
    if (('0'<=b && b<='9') || ('a'<=b && b<='f'))
    {
        return (b>='a') ?  (b-'a'+10) : (b-'0');
    }
    else
    {
        return -1;
    }
}

static uint16_t get_node_hash(HTree* tree, Node* node, const char* dir,
                              unsigned int *count)
{
    if (node->is_node && strlen(dir) > 0)
    {
        char i = hex2int(dir[0]);
        if (i >= 0)
        {
            return get_node_hash(tree, get_child(tree, node, i), dir+1, count);
        }
        else
        {
            if(count) *count = 0;
            return 0;
        }
    }
    update_node(tree, node);
    if (count) *count = node->count;
    return node->hash;
}

static char* list_dir(HTree *tree, Node* node, const char* dir, const char* prefix)
{
    int dlen = strlen(dir);
    while (node->is_node && dlen > 0)
    {
        int b = hex2int(dir[0]);
        if (b >= 0 && b < BUCKET_SIZE)
        {
            node = get_child(tree, node, b);
            ++dir;
            --dlen;
        }
        else
        {
            return NULL;
        }
    }

    int bsize = 4096;
    char *buf = (char*)safe_malloc(bsize);
    memset(buf, 0, bsize);
    int n = 0, i;
    if (node->is_node)
    {
        update_node(tree, node);

        Node *child = get_child(tree, node, 0);
        if (node->count > 100000 || (prefix == NULL && node->count > SPLIT_LIMIT * 4))
        {
            for (i=0; i<BUCKET_SIZE; i++)
            {
                Node *t = child + i;
                n += safe_snprintf(buf + n, bsize - n, "%x/ %u %u\n",
                              i, t->hash, t->count);
            }
        }
        else
        {
            for (i=0; i<BUCKET_SIZE; i++)
            {
                char *r = list_dir(tree, child + i, "", prefix);
                int rl = strlen(r) + 1;
                if (bsize - n < rl)
                {
                    bsize += rl;
                    buf = (char*)safe_realloc(buf, bsize);
                }
                n += safe_snprintf(buf + n, bsize - n, "%s", r);
                free(r);
            }
        }
    }
    else
    {
        Data *data = get_data(node);
        Item *it = data->head;
        char pbuf[20], key[255];
        int prefix_len = 0;
        if (prefix != NULL) prefix_len = strlen(prefix);
        for (i=0; i<data->count; i++, it = (Item*)((char*)it + it->length))
        {
            if (dlen > 0)
            {
                safe_snprintf(pbuf, 20, "%08x", key_hash(tree, it));
                if (memcmp(pbuf + tree->depth + node->depth, dir, dlen) != 0)
                {
                    continue;
                }
            }
            int l = dc_decode(tree->dc, key, 255, it->key, KEYLENGTH(it));
            if (prefix == NULL || (l >= prefix_len && strncmp(key, prefix, prefix_len) == 0))
            {
                n += safe_snprintf(buf + n, bsize - n, "%s %u %d\n", key, it->hash, it->ver);
                if (bsize - n < 200)
                {
                    bsize *= 2;
                    buf = (char*)safe_realloc(buf, bsize);
                }
            }
        }
    }
    return buf;
}

static void visit_node(HTree *tree, Node* node, fun_visitor visitor, void* param)
{
    int i;
    if (node->is_node)
    {
        Node *child = get_child(tree, node, 0);
        for (i=0; i<BUCKET_SIZE; i++)
        {
            visit_node(tree, child+i, visitor, param);
        }
    }
    else
    {
        Data *data = get_data(node);
        Item *p = data->head;
        Item *it = (Item*)tree->buf;
        int buf_size = 512;
        int decode_len;
        for (i=0; i<data->count; i++)
        {
            safe_memcpy(it, buf_size, p, sizeof(Item));
            buf_size -= (sizeof(Item) - ITEM_PADDING);
            decode_len = dc_decode(tree->dc, it->key, buf_size, p->key, KEYLENGTH(p));
            buf_size -= decode_len;
            it->length = sizeof(Item) + strlen(it->key) - ITEM_PADDING;
            visitor(it, param);
            p = (Item*)((char*)p + p->length);
        }
    }
}

/*
 * API
 */

HTree* ht_new(int depth, int pos)
{
    HTree *tree = (HTree*)safe_malloc(sizeof(HTree));
    /*if (!tree) return NULL;*/
    memset(tree, 0, sizeof(HTree));
    tree->depth = depth;
    tree->pos = pos;
    tree->height = 1;

    int pool_size = g_index[tree->height];
    Node *root = (Node*)safe_malloc(sizeof(Node) * pool_size);
/*
 *
 *    if (!root)
 *    {
 *        free(tree);
 *        return NULL;
 *    }
 *
 */
    memset(root, 0, sizeof(Node) * pool_size);

    // init depth
    int i,j;
    for (i=0; i<tree->height; i++)
    {
        for (j=g_index[i]; j<g_index[i+1]; j++)
        {
            root[j].depth = i;
        }
    }

    tree->root = root;
    clear(tree->root);

    tree->dc = dc_new();
    pthread_mutex_init(&tree->lock, NULL);

    return tree;
}

HTree* ht_open(int depth, int pos, const char *path)
{
    char version[sizeof(VERSION)+1] = {0};
    HTree *tree = NULL;
    Node *root = NULL;
    int pool_used = 0;
    char *buf = NULL;

    FILE *f = fopen(path, "rb");
    if (f == NULL)
    {
        fprintf(stderr, "open %s failed\n", path);
        return NULL;
    }

    if (fread(version, sizeof(VERSION), 1, f) != 1
            || memcmp(version, VERSION, sizeof(VERSION)) != 0)
    {
        fprintf(stderr, "the version %s is not expected\n", version);
        fclose(f);
        return NULL;
    }

    off_t fsize = 0;
    if (fread(&fsize, sizeof(fsize), 1, f) != 1 ||
            fseeko(f, 0, 2) != 0 || ftello(f) != fsize)
    {
        fprintf(stderr, "the size %lld is not expected\n", fsize);
        fclose(f);
        return NULL;
    }
    fseeko(f, sizeof(VERSION) + sizeof(off_t), 0);
#if _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
    if (posix_fadvise(fileno(f), 0, fsize, POSIX_FADV_SEQUENTIAL) != 0)
    {
        fprintf(stderr, "posix_favise() failed\n");
    }
#endif

    tree = (HTree*)safe_malloc(sizeof(HTree));
/*
 *
 *    if (!tree)
 *    {
 *        fclose(f);
 *        return NULL;
 *    }
 *
 */
    memset(tree, 0, sizeof(HTree));
    tree->depth = depth;
    tree->pos = pos;

    if (fread(&tree->height, sizeof(int), 1, f) != 1 ||
            tree->height + depth < 0 || tree->height + depth > 9)
    {
        fprintf(stderr, "invalid height: %d\n", tree->height);
        goto FAIL;
    }

    int pool_size = g_index[tree->height];
    int psize = sizeof(Node) * pool_size;
    root = (Node*)safe_malloc(psize);
/*
 *
 *    if (!root)
 *    {
 *        goto FAIL;
 *    }
 *
 */
    if (fread(root, psize, 1, f) != 1)
    {
        goto FAIL;
    }
    tree->root = root;

    // load Data
    int i,size = 0;
    Data *data;
    for (i=0; i<pool_size; i++)
    {
        if(fread(&size, sizeof(int), 1, f) != 1)
        {
            goto FAIL;
        }
        if (size > 0)
        {
            data = (Data*)safe_malloc(size);
            if (fread(data, size, 1, f) != 1)
            {
                goto FAIL;
            }
            if (data->used != size)
            {
                fprintf(stderr, "broken data: %d != %d\n", data->used, size);
                goto FAIL;
            }
            data->size = size;
        }
        else if (size == 0)
        {
            data = NULL;
        }
        else
        {
            fprintf(stderr, "unexpected size: %d\n", size);
            goto FAIL;
        }
        tree->root[i].data = data;
        pool_used ++;
    }

    // load Codec
    if (fread(&size, sizeof(int), 1, f) != 1
            || size < 0 || size > (10<<20))
    {
        fprintf(stderr, "bad codec size: %d\n", size);
        goto FAIL;
    }
    buf = (char*)safe_malloc(size);
    if (fread(buf, size, 1, f) != 1)
    {
        fprintf(stderr, "read codec failed\n");
        goto FAIL;
    }
    tree->dc = dc_new();
    if (dc_load(tree->dc, buf, size) != 0)
    {
        fprintf(stderr, "load codec failed\n");
        goto FAIL;
    }
    free(buf);
    fclose(f);

    pthread_mutex_init(&tree->lock, NULL);

    return tree;

FAIL:
    if (tree->dc) dc_destroy(tree->dc);
    if (buf) free(buf);
    if (root)
    {
        for (i=0; i<pool_used; i++)
        {
            if (root[i].data) free(root[i].data);
        }
        free(root);
    }
    free(tree);
    fclose(f);
    return NULL;
}

int ht_save(HTree *tree, const char *path)
{
    if (!tree || !path) return -1;

    char tmp[MAX_PATH_LEN];
    safe_snprintf(tmp, MAX_PATH_LEN, "%s.tmp", path);

    FILE *f = fopen(tmp, "wb");
    if (f == NULL)
    {
        fprintf(stderr, "open %s failed\n", tmp);
        return -1;
    }

    off_t pos = 0;
    if (fwrite(VERSION, sizeof(VERSION), 1, f) != 1 ||
            fwrite(&pos, sizeof(off_t), 1, f) != 1)
    {
        fprintf(stderr, "write version failed\n");
        fclose(f);
        return -1;
    }

    pthread_mutex_lock(&tree->lock);

    int pool_size = g_index[tree->height];
    if (fwrite(&tree->height, sizeof(int), 1, f) != 1 ||
            fwrite(tree->root, sizeof(Node) * pool_size, 1, f) != 1 )
    {
        fprintf(stderr, "write nodes failed\n");
        fclose(f);
        return -1;
    }

    int i, zero = 0;
    for (i=0; i<pool_size; i++)
    {
        Data *data= tree->root[i].data;
        if (data)
        {
            if (fwrite(&data->used, sizeof(int), 1, f) != 1
                    || fwrite(data, data->used, 1, f) != 1)
            {
                fclose(f);
                return -1;
            }
        }
        else
        {
            if (fwrite(&zero, sizeof(int), 1, f) != 1)
            {
                fclose(f);
                return -1;
            }
        }
    }

    int s = dc_size(tree->dc);
    char *buf = (char*)safe_malloc(s + sizeof(int));
    *(int*)buf = s;
    if (dc_dump(tree->dc, buf + sizeof(int), s) != s)
    {
        fprintf(stderr, "dump Codec failed\n");
        free(buf);
        fclose(f);
        return -1;
    }
    if (fwrite(buf, s + sizeof(int), 1, f) != 1)
    {
        fprintf(stderr, "write Codec failed\n");
        free(buf);
        fclose(f);
        return -1;
    }
    free(buf);

    pos = ftello(f);
    fseeko(f, sizeof(VERSION), 0);
    if (fwrite(&pos, sizeof(off_t), 1, f) != 1)
    {
        fprintf(stderr, "write size failed\n");
        fclose(f);
        return -1;
    }

    pthread_mutex_unlock(&tree->lock);

    fclose(f);
    rename(tmp, path);

    return 0;
}

void ht_destroy(HTree *tree)
{
    if (!tree) return;

    pthread_mutex_lock(&tree->lock);

    dc_destroy(tree->dc);

    int i;
    int pool_size = g_index[tree->height];
    for(i=0; i<pool_size; i++)
    {
        if (tree->root[i].data) free(tree->root[i].data);
    }
    free(tree->root);
    free(tree);
}

static inline uint32_t keyhash(const char *s, int len)
{
    return fnv1a(s, len);
}

bool check_key(HTree *tree, const char* key, int len)
{
    if (!tree || !key) return false;
    if (len == 0 || len > MAX_KEY_LENGTH)
    {
        fprintf(stderr, "bad key len=%d\n", len);
        return false;
    }
    if (key[0]<=' ')
    {
        fprintf(stderr, "bad key len=%d %x\n", len, key[0]);
        return false;
    }
    int k;
    for (k=0; k<len; k++)
    {
        if (isspace(key[k]) || iscntrl(key[k]))
        {
            fprintf(stderr, "bad key len=%d %s\n", len, key);
            return false;
        }
    }

    uint32_t h = keyhash(key, len);
    if (tree->depth > 0 && h >> ((8-tree->depth)*4) != (unsigned int)(tree->pos))
    {
        fprintf(stderr, "key %s (#%x) should not in this tree (%d:%0x)\n", key, h >> ((8-tree->depth)*4), tree->depth, tree->pos);
        return false;
    }

    return true;
}

void ht_add2(HTree *tree, const char* key, int len, uint32_t pos, uint16_t hash, int32_t ver)
{
    if (!check_key(tree, key, len)) return;
    Item *it = create_item(tree, key, len, pos, hash, ver);
    add_item(tree, tree->root, it, keyhash(key, len), true);
}

void ht_add(HTree *tree, const char* key, uint32_t pos, uint16_t hash, int32_t ver)
{
    pthread_mutex_lock(&tree->lock);
    ht_add2(tree, key, strlen(key), pos, hash, ver);
    pthread_mutex_unlock(&tree->lock);
}

void ht_remove2(HTree* tree, const char *key, int len)
{
    if (!check_key(tree, key, len)) return;
    Item *it = create_item(tree, key, len, 0, 0, 0);
    remove_item(tree, tree->root, it, keyhash(key, len));
}

void ht_remove(HTree* tree, const char *key)
{
    pthread_mutex_lock(&tree->lock);
    ht_remove2(tree, key, strlen(key));
    pthread_mutex_unlock(&tree->lock);
}

Item* ht_get2(HTree* tree, const char* key, int len)
{
    if (!check_key(tree, key, len)) return NULL;

    pthread_mutex_lock(&tree->lock);
    Item *it = create_item(tree, key, len, 0, 0, 0);
    Item *r = get_item_hash(tree, tree->root, it, keyhash(key, len));
    if (r != NULL)
    {
        Item *rr = (Item*)safe_malloc(sizeof(Item) + len);
        memcpy(rr, r, sizeof(Item)); // safe
        memcpy(rr->key, key, len);  // safe
        rr->key[len] = 0; // c-str
        r = rr; // r is in node->Data block
    }
    pthread_mutex_unlock(&tree->lock);
    return r;
}

Item* ht_get(HTree* tree, const char* key)
{
    return ht_get2(tree, key, strlen(key));
}

uint32_t ht_get_hash(HTree* tree, const char* key, unsigned int* count)
{
    if (!tree || !key || key[0] != '@')
    {
        if(count) *count = 0;
        return 0;
    }

    uint32_t hash = 0;
    pthread_mutex_lock(&tree->lock);
    update_node(tree, tree->root);
    hash = get_node_hash(tree, tree->root, key+1, count);
    pthread_mutex_unlock(&tree->lock);
    return hash;
}

char* ht_list(HTree* tree, const char* dir, const char* prefix)
{
    if (!tree || !dir || strlen(dir) > 8) return NULL;
    if (prefix != NULL && strlen(prefix) == 0) prefix = NULL;

    pthread_mutex_lock(&tree->lock);
    char* r = list_dir(tree, tree->root, dir, prefix);
    pthread_mutex_unlock(&tree->lock);

    return r;
}

void ht_visit(HTree *tree, fun_visitor visitor, void *param)
{
    pthread_mutex_lock(&tree->lock);
    visit_node(tree, tree->root, visitor, param);
    pthread_mutex_unlock(&tree->lock);
}
