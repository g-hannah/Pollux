#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cache.h"

#define BITS_PER_CHAR (sizeof(char) * 8)
#define clear_struct(s) memset((s), 0, sizeof((*s)))

static inline void *
__cache_object(cache_t *cachep, int index)
{
	return (void *)((char *)cachep->cache + (index * cachep->objsize));
}

static inline off_t
__cache_object_offset(cache_t *cachep, void *object)
{
	return (off_t)((char *)object - (char *)cachep->cache);
}

static inline int
__cache_object_index(cache_t *cachep, void *object)
{
	return (int)(__cache_object_offset(cachep, object) / cachep->objsize);
}

static inline int
__addr_in_cache(cache_t *cachep, void *addr)
{
	int __in_cache = ((unsigned long)addr >= (unsigned long)cachep->cache && (unsigned long)addr < (unsigned long)((char *)cachep->cache + (cachep->capacity * cachep->objsize)));

	return __in_cache;
}

#define CACHE_SAVE_ACTIVE_PTR(c, o, p)\
do {\
	int ___i_c = __addr_in_cache((c), (p));\
	int __nr_active = (c)->nr_active_ptrs;\
	assert(__nr_active < (c)->capacity);\
	struct active_ptr_ctx *__ap_ctx;\
	__ap_ctx = &((c)->active_ptrs[__nr_active]);\
	__ap_ctx->obj_offset = __cache_object_offset((c), (o));\
	__ap_ctx->obj_addr = (void *)(o);\
	if (___i_c)\
		__ap_ctx->ptr_offset = (off_t)((char *)(p) - (char *)cachep->cache);\
	__ap_ctx->ptr_addr = (p);\
	++((c)->nr_active_ptrs);\
} while (0)

#define CACHE_REMOVE_ACTIVE_PTR(c, o, p)\
do {\
	int __nr_active = (c)->nr_active_ptrs;\
	int __i;\
	int __k;\
	struct active_ptr_ctx *__ap_ctx;\
	assert(__nr_active < (c)->capacity);\
	__ap_ctx = &((c)->active_ptrs[0]);\
	for (__i = 0; __i < __nr_active; ++__i)\
	{\
		if (__ap_ctx->ptr_addr == (p)\
		&& *((unsigned long *)__ap_ctx->ptr_addr) == (unsigned long)(o))\
		{\
			for (__k = __i; __k < (__nr_active - 1); ++__k)\
			{\
				memcpy(&(c)->active_ptrs[__k], &(c)->active_ptrs[__k+1], sizeof(struct active_ptr_ctx));\
			}\
			memset(&(c)->active_ptrs[__k], 0, sizeof(struct active_ptr_ctx));\
			--((c)->nr_active_ptrs);\
		}\
		++__ap_ctx;\
	}\
} while (0)

#define CACHE_ADJUST_ACTIVE_PTRS(c)\
do {\
	int __nr_active = (c)->nr_active_ptrs;\
	int __i;\
	struct active_ptr_ctx *__ap_ctx;\
	assert(__nr_active < (c)->capacity);\
	__ap_ctx = &((c)->active_ptrs[0]);\
	for (__i = 0; __i < __nr_active; ++__i)\
	{\
		if (__ap_ctx->in_cache)\
			__ap_ctx->ptr_addr = (void *)((char *)(c)->cache + __ap_ctx->ptr_offset);\
		*((unsigned long *)__ap_ctx->ptr_addr) = (unsigned long)((char *)(c)->cache + __ap_ctx->obj_offset);\
		++__ap_ctx;\
	}\
} while (0)

/**
 * __cache_next_free_idx - get index of next free object
 * @cachep: pointer to the metadata cache structure
 */
static inline int __cache_next_free_idx(cache_t *cachep)
{
	unsigned char *bm = cachep->free_bitmap;
	unsigned char bit = 1;
	int idx = 0;
	int capacity = cachep->capacity;

	while (1)
	{
		while (*bm & bit)
		{
			bit <<= 1;
			++idx;
		}

		if (idx >= capacity)
			return -1;

		if (!bit)
		{
			bit = 1;
			++bm;
		}
		else
		if (!(*bm & bit))
		{
			assert(idx < capacity);
			return idx;
		}
	}

	return -1;
}

/**
 * __cache_mark_used - mark an object as used
 * @c: pointer to the metadata cache structure
 * @i: the index of the object in the cache
 */
#define __cache_mark_used(c, i)	\
do {\
	unsigned char *bm = ((c)->free_bitmap + ((i) >> 3));	\
	(*bm |= (unsigned char)(1 << ((i) & 7)));							\
} while(0)

/**
 * __cache_mark_unused - mark an object as unused
 * @c: pointer to the metadata cache structure
 * @i: the index of the object in the cache
 */
#define __cache_mark_unused(c, i)	\
do {\
	unsigned char *bm = ((c)->free_bitmap + ((i) >> 3));	\
	(*bm &= (unsigned char) ~(1 << ((i) & 7)));						\
} while(0)

/**
 * cache_nr_used - return the number of objects used
 * @cachep: pointer to the metadata cache structure
 */
inline int cache_nr_used(cache_t *cachep)
{
	return (cachep->capacity - cachep->nr_free);
}

/**
 * cache_capacity - return capacity of the cache
 * @cachep: pointer to the metadata cache structure
 */
inline int cache_capacity(cache_t *cachep)
{
	return cachep->capacity;
}

/**
 * cache_obj_used - determine if an object is active or not.
 * @cachep: pointer to the metadata cache structure
 * @obj pointer to the queried cache object
 */
inline int
cache_obj_used(cache_t *cachep, void *obj)
{
	int idx;
	int capacity;
	unsigned char *bm = cachep->free_bitmap;

	capacity = cachep->capacity;
	idx = __cache_object_index(cachep, obj);
	assert(idx < capacity);

	bm += (idx >> 3);

	return (*bm & (1 << (idx & 7))) ? 1 : 0;
}

/**
 * cache_create - create a new cache
 * @name: name of the cache for statistics
 * @size: size of the type of object that will be stored in the cache
 * @alignment: minimum alignment of the cache objects
 * @ctor: pointer to a constructor function called on each object
 * @dtor: pointer to a destructor function called on each dealloc()
 */
cache_t *
cache_create(char *name,
		size_t size,
		int alignment,
		cache_ctor_t ctor,
		cache_dtor_t dtor)
{
	cache_t	*cachep = malloc(sizeof(cache_t));
	int capacity = (CACHE_SIZE / size);
	int	i;
	uint16_t bitmap_size;

	assert(cachep);

	clear_struct(cachep);

	cachep->objsize = size;
	bitmap_size = (uint16_t)(capacity / BITS_PER_CHAR);

	if (capacity & (BITS_PER_CHAR - 1))
		++bitmap_size;

	if (!(cachep->name = calloc(CACHE_MAX_NAME, 1)))
		goto fail_release_mem;

	assert(strlen(name) < CACHE_MAX_NAME);
	strcpy(cachep->name, name);

	if (!(cachep->cache = calloc(CACHE_SIZE, 1)))
		goto fail_release_mem;

	assert(cachep->cache);

	if (!(cachep->free_bitmap = calloc(bitmap_size, 1)))
		goto fail_release_mem;

	assert(cachep->free_bitmap);

	for (i = 0; (uint16_t)i < bitmap_size; ++i)
		cachep->free_bitmap[i] = 0;

	if (!(cachep->active_ptrs = calloc(capacity, sizeof(struct active_ptr_ctx))))
		goto fail_release_mem;

	assert(cachep->active_ptrs);

	if (ctor)
	{
		for (i = 0; i < capacity; ++i)
			ctor(__cache_object(cachep, i));
	}

	cachep->capacity = capacity;
	cachep->nr_free = capacity;
	cachep->nr_active_ptrs = 0;
	cachep->cache_size = CACHE_SIZE;
	cachep->bitmap_size = bitmap_size;
	cachep->ctor = ctor;
	cachep->dtor = dtor;

#ifdef DEBUG
	fprintf(stderr,
			"Created cache \"%s\"\n"
			"Size of each object=%lu bytes\n"
			"Capacity of cache=%d objects\n"
			"Bitmap size=%hu bytes\n"
			"Bitmap can represent %hu objects\n"
			"%s\n"
			"%s\n",
			name,
			size,
			capacity,
			bitmap_size,
			bitmap_size * 8,
			ctor ? "constructor provided" : "constructor not provided",
			dtor ? "destructor provided" : "destructor not provided");
#endif

	return cachep;

	fail_release_mem:

	if (cachep)
	{
		if (cachep->name)
			free(cachep->name);

		if (cachep->cache)
			free(cachep->cache);

		if (cachep->free_bitmap)
			free(cachep->free_bitmap);

		if (cachep->active_ptrs)
			free(cachep->active_ptrs);

		free(cachep);
		cachep = NULL;
	}

	return NULL;
}

/**
 * cache_destroy - destroy a cache
 * @cachep: pointer to the metadata cache structure
 */
void
cache_destroy(cache_t *cachep)
{
	assert(cachep);

	int	i;
	int capacity = cache_capacity(cachep);

	if (cachep->dtor)
	{
		for (i = 0; i < capacity; ++i)
			cachep->dtor(__cache_object(cachep, i));
	}

	free(cachep->cache);
	free(cachep->free_bitmap);
	free(cachep->active_ptrs);
	free(cachep->name);
	free(cachep);

	return;
}

/**
 * cache_alloc - allocate an object from a cache
 * @cachep: pointer to the metadata cache structure
 */
void *
cache_alloc(cache_t *cachep, void *ptr_addr)
{
	assert(cachep);

	void *slot = NULL;
	int idx = __cache_next_free_idx(cachep);
	uint16_t old_bitmap_size = cachep->bitmap_size;
	uint16_t new_bitmap_size;
	int old_capacity = cachep->capacity;
	int new_capacity = 0;
	int i;
	void *old_cache;
	void *active_ptr_addr = ptr_addr;
	off_t active_ptr_offset;
	int in_cache;
	unsigned char *byteptr;

	if (idx != -1 && idx < old_capacity && cache_nr_used(cachep) < old_capacity)
	{
		slot = __cache_object(cachep, idx);

		__cache_mark_used(cachep, idx);
		CACHE_DEC_FREE(cachep);
		CACHE_SAVE_ACTIVE_PTR(cachep, slot, active_ptr_addr);

		return slot;
	}
	else
	{
		new_capacity = (old_capacity * 2);
		new_bitmap_size = (old_bitmap_size * 2);

		old_cache = cachep->cache;

		in_cache = __addr_in_cache(cachep, active_ptr_addr);

		if (in_cache)
			active_ptr_offset = (off_t)((char *)active_ptr_addr - (char *)cachep->cache);

		if (!(cachep->cache = realloc(cachep->cache, (new_capacity * cachep->objsize))))
		{
			fprintf(stderr, "cache_alloc: failed to reallocate memory for cache objects\n");
			goto fail_release_mem;
		}

		void *__slot1 = cachep->cache;

		cachep->capacity = new_capacity;
		cachep->nr_free += (new_capacity - old_capacity);
		cachep->cache_size = (new_capacity * cachep->objsize);

		if (old_cache != cachep->cache)
		{
			if (in_cache)
			{
				active_ptr_addr = (void *)((char *)cachep->cache + active_ptr_offset);
			}

			CACHE_ADJUST_ACTIVE_PTRS(cachep);
		}

		if (!(cachep->free_bitmap = realloc(cachep->free_bitmap, new_bitmap_size)))
		{
			fprintf(stderr, "cache_alloc: failed to reallocate memory for cache objects bitmap\n");
			goto fail_release_mem;
		}

		cachep->bitmap_size = new_bitmap_size;

		byteptr = cachep->free_bitmap;
		for (i = old_bitmap_size; i < new_bitmap_size; ++i)
			byteptr[i] = 0;

		if (cachep->ctor)
		{
			for (i = old_capacity; i < new_capacity; ++i)
			{
				assert((unsigned long)__cache_object(cachep, i) != (unsigned long)__slot1);
				cachep->ctor(__cache_object(cachep, i));
			}
		}

		if (!(cachep->active_ptrs = realloc(cachep->active_ptrs, (new_capacity * sizeof(struct active_ptr_ctx)))))
		{
			fprintf(stderr, "cache_alloc: failed to reallocate memory for list of cache object owners\n");
			goto fail_release_mem;
		}

		idx = __cache_next_free_idx(cachep);
		assert(idx >= old_capacity);
		assert(idx < new_capacity);

		slot = __cache_object(cachep, idx);
		__cache_mark_used(cachep, idx);
		CACHE_DEC_FREE(cachep);
		CACHE_SAVE_ACTIVE_PTR(cachep, slot, active_ptr_addr);

		return slot;
	}

	fail_release_mem:

	if (cachep)
	{
		if (cachep->cache)
			free(cachep->cache);

		if (cachep->free_bitmap)
			free(cachep->free_bitmap);

		if (cachep->active_ptrs)
			free(cachep->active_ptrs);

		free(cachep);
		cachep = NULL;
	}

	return NULL;
}

/**
 * cache_dealloc - return an object to the cache
 * @cachep: pointer to the metadata cache structure
 * @slot: the object to be returned
 */
void
cache_dealloc(cache_t *cachep, void *slot, void *ptr_addr)
{
	assert(cachep);
	assert(slot);

	__cache_mark_unused(cachep, __cache_object_index(cachep, slot));

	if (ptr_addr)
		CACHE_REMOVE_ACTIVE_PTR(cachep, slot, ptr_addr);

	CACHE_INC_FREE(cachep);

	return;
}

static void *
__cache_get_object_owner(cache_t *cachep, void *obj)
{
	int i;
	int nr_active = cachep->nr_active_ptrs;
	struct active_ptr_ctx *ap_ctx;

	ap_ctx = &(cachep->active_ptrs[0]);
	for (i = 0; i < nr_active; ++i)
	{
		if (*((unsigned long *)ap_ctx->ptr_addr) == (unsigned long)obj)
			return (void *)ap_ctx->ptr_addr;
	}

	return NULL;
}

void
cache_clear_all(cache_t *cachep)
{
	void *obj = NULL;
	int i;
	int capacity = cachep->capacity;

	for (i = 0; i < capacity; ++i)
	{
		obj = __cache_object(cachep, i);
		if (cache_obj_used(cachep, obj))
			cache_dealloc(cachep, obj, __cache_get_object_owner(cachep, obj));
	}

	return;
}
