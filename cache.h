#ifndef CACHE_H
#define CACHE_H 1

#include <stdint.h>
#include <sys/types.h>

/*
 * 31 ..... 16 15 ..... 0
 *   cache nr     obj nr
 */
#define CACHE_SIZE 4096
#define CACHE_MAX_NAME 32

#define CACHE_DEC_FREE(c) --((c)->nr_free)
#define CACHE_INC_FREE(c) ++((c)->nr_free)

typedef int (*cache_ctor_t)(void *);
typedef void (*cache_dtor_t)(void *);

struct active_ptr_ctx
{
	void *ptr_addr;
	int in_cache;
	void *obj_addr;
	off_t obj_offset;
	off_t ptr_offset;
};

typedef struct cache_t
{
	void *cache;
	int capacity;
	int nr_free;
	unsigned char *free_bitmap;
	uint16_t bitmap_size;
	struct active_ptr_ctx *active_ptrs;
	int nr_active_ptrs;
	size_t objsize;
	size_t cache_size;
	char *name;
	cache_ctor_t ctor;
	cache_dtor_t dtor;
} cache_t;

cache_t *cache_create(char *, size_t, int, cache_ctor_t, cache_dtor_t);
void cache_destroy(cache_t *) __nonnull((1));
void *cache_alloc(cache_t *, void *) __nonnull((1,2)) __wur;
void cache_dealloc(cache_t *, void *, void *) __nonnull((1,2,3));
int cache_obj_used(cache_t *, void *) __nonnull((1,2)) __wur;
int cache_nr_used(cache_t *) __nonnull((1)) __wur;
int cache_capacity(cache_t *) __nonnull((1)) __wur;
void cache_clear_all(cache_t *) __nonnull((1));

#endif /* CACHE_H */
