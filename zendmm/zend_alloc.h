/*
 * zend_alloc.h
 *
 *  Created on: Sep 15, 2012
 *      Author: hujin
 */

#ifndef ZEND_ALLOC_H_
#define ZEND_ALLOC_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/signal.h>
#include "zend.h"


/*form php_config.h*/
#define ZEND_MM_ALIGNMENT 8
#define ZEND_MM_ALIGNMENT_LOG2 3
/* virtual machine dispatch method */
#define ZEND_VM_KIND ZEND_VM_KIND_CALL
/*end form php_config.h*/



#define ZEND_MM_ALIGNMENT_MASK ~(ZEND_MM_ALIGNMENT-1)
#define ZEND_MM_ALIGNED_SIZE(size)	(((size) + ZEND_MM_ALIGNMENT - 1) & ZEND_MM_ALIGNMENT_MASK)




/* Heaps with user defined storage */
typedef struct _zend_mm_storage zend_mm_storage;

typedef struct _zend_mm_segment {
	size_t	size;
	struct _zend_mm_segment *next_segment;
} zend_mm_segment;

typedef struct _zend_mm_mem_handlers {
	const char *name;
	zend_mm_storage* (*init)(void *params);
	void (*dtor)(zend_mm_storage *storage);
	void (*compact)(zend_mm_storage *storage);
	zend_mm_segment* (*_alloc)(zend_mm_storage *storage, size_t size);
	zend_mm_segment* (*_realloc)(zend_mm_storage *storage, zend_mm_segment *ptr, size_t size);
	void (*_free)(zend_mm_storage *storage, zend_mm_segment *ptr);
} zend_mm_mem_handlers;

struct _zend_mm_storage {
	const zend_mm_mem_handlers *handlers;
	void *data;
};




/* mm block type */
typedef struct _zend_mm_block_info {
	size_t _cookie;/*for debug*/ // ZEND_MM_COOKIES
	size_t _size;
	size_t _prev;
} zend_mm_block_info;


/* only for debug */
typedef struct _zend_mm_debug_info {
	const char *filename;
	uint lineno;
	const char *orig_filename;
	uint orig_lineno;
	size_t size;
	unsigned int start_magic;
} zend_mm_debug_info;



typedef struct _zend_mm_block {
	zend_mm_block_info info;
	unsigned int magic;
	zend_mm_debug_info debug;
} zend_mm_block;


typedef struct _zend_mm_small_free_block {
	zend_mm_block_info info;
	unsigned int magic;
	struct _zend_mm_free_block *prev_free_block;
	struct _zend_mm_free_block *next_free_block;
} zend_mm_small_free_block;


typedef struct _zend_mm_free_block {
	zend_mm_block_info info;
	unsigned int magic;
	struct _zend_mm_free_block *prev_free_block;
	struct _zend_mm_free_block *next_free_block;
	struct _zend_mm_free_block **parent;
	struct _zend_mm_free_block *child[2];
} zend_mm_free_block;

/* ZendMM buckets number*/
#define ZEND_MM_NUM_BUCKETS 		(sizeof(size_t) << 3)

#define ZEND_MM_CACHE 				1
#define ZEND_MM_CACHE_SIZE 			(ZEND_MM_NUM_BUCKETS * 4 * 1024)


typedef struct _zend_mm_heap {
	int                 use_zend_alloc;
	void               *(*_malloc)(size_t);
	void                (*_free)(void*);
	void               *(*_realloc)(void*, size_t);
	size_t              free_bitmap;
	size_t              large_free_bitmap;
	size_t              block_size;
	size_t              compact_size;
	zend_mm_segment    *segments_list;
	zend_mm_storage    *storage;
	size_t              real_size;
	size_t              real_peak;
	size_t              limit;
	size_t              size;
	size_t              peak;
	size_t              reserve_size;
	void               *reserve;
	int                 overflow;
	int                 internal;

	unsigned int        cached;
	zend_mm_free_block *cache[ZEND_MM_NUM_BUCKETS];

	zend_mm_free_block *free_buckets[ZEND_MM_NUM_BUCKETS*2];
	zend_mm_free_block *large_free_buckets[ZEND_MM_NUM_BUCKETS];
	zend_mm_free_block *rest_buckets[2];
	int                 rest_count;
}zend_mm_heap;





static zend_mm_storage* zend_mm_mem_dummy_init(void *params)
{
	return malloc(sizeof(zend_mm_storage));
}

static void zend_mm_mem_dummy_dtor(zend_mm_storage *storage)
{
	free(storage);
}

static void zend_mm_mem_dummy_compact(zend_mm_storage *storage)
{
}

static zend_mm_segment* zend_mm_mem_malloc_alloc(zend_mm_storage *storage, size_t size)
{
	return (zend_mm_segment*)malloc(size);
}

static zend_mm_segment* zend_mm_mem_malloc_realloc(zend_mm_storage *storage, zend_mm_segment *ptr, size_t size)
{
	return (zend_mm_segment*)realloc(ptr, size);
}

static void zend_mm_mem_malloc_free(zend_mm_storage *storage, zend_mm_segment *ptr)
{
	free(ptr);
}

# define ZEND_MM_MEM_MALLOC_DSC {"malloc", zend_mm_mem_dummy_init, zend_mm_mem_dummy_dtor, zend_mm_mem_dummy_compact, zend_mm_mem_malloc_alloc, zend_mm_mem_malloc_realloc, zend_mm_mem_malloc_free}


static const zend_mm_mem_handlers mem_handlers[] = {
	ZEND_MM_MEM_MALLOC_DSC,
	//ZEND_MM_MEM_MMAP_ANON_DSC,
	//ZEND_MM_MEM_MMAP_ZERO_DSC,
	{NULL, NULL, NULL, NULL, NULL, NULL}
};

# define ZEND_MM_STORAGE_DTOR()						heap->storage->handlers->dtor(heap->storage)
# define ZEND_MM_STORAGE_ALLOC(size)				heap->storage->handlers->_alloc(heap->storage, size)
# define ZEND_MM_STORAGE_REALLOC(ptr, size)			heap->storage->handlers->_realloc(heap->storage, ptr, size)
# define ZEND_MM_STORAGE_FREE(ptr)					heap->storage->handlers->_free(heap->storage, ptr)



#define MEM_BLOCK_VALID  0x7312F8DC
#define	MEM_BLOCK_FREED  0x99954317
#define	MEM_BLOCK_CACHED 0xFB8277DC
#define	MEM_BLOCK_GUARD  0x2A8FCC84
#define	MEM_BLOCK_LEAK   0x6C5E8F2D







#define ZEND_MM_LONG_CONST(x)	(x##L)


#define ZEND_MM_SMALL_FREE_BUCKET(heap, index) 								\
		(zend_mm_free_block*) ((char*)&heap->free_buckets[index * 2] + 		\
		sizeof(zend_mm_free_block*) * 2 - 									\
		sizeof(zend_mm_small_free_block))


#define ZEND_MM_REST_BUCKET(heap) 											\
		(zend_mm_free_block*)((char*)&heap->rest_buckets[0] + 				\
		sizeof(zend_mm_free_block*) * 2 - 									\
		sizeof(zend_mm_small_free_block))


#define ZEND_MM_REST_BLOCK ((zend_mm_free_block**)(zend_uintptr_t)(1))

#define ZEND_MM_MAX_REST_BLOCKS 16


static unsigned int _zend_mm_cookie = 0;

# define ZEND_MM_COOKIE(block) \
	(((size_t)(block)) ^ _zend_mm_cookie)
# define ZEND_MM_SET_COOKIE(block) \
	(block)->info._cookie = ZEND_MM_COOKIE(block)
# define ZEND_MM_CHECK_COOKIE(block) \
	if (UNEXPECTED((block)->info._cookie != ZEND_MM_COOKIE(block))) { \
		zend_mm_panic("zend_mm_heap corrupted"); \
	}

/* Default memory segment size */
#define ZEND_MM_SEG_SIZE   (256 * 1024)

/* Reserved space for error reporting in case of memory overflow */
#define ZEND_MM_RESERVE_SIZE            (8*1024)

#define ZEND_MM_LONG_CONST(x)	(x##L)

#define ZEND_MM_TYPE_MASK		ZEND_MM_LONG_CONST(0x3)

#define ZEND_MM_FREE_BLOCK		ZEND_MM_LONG_CONST(0x0)
#define ZEND_MM_USED_BLOCK		ZEND_MM_LONG_CONST(0x1)
#define ZEND_MM_GUARD_BLOCK		ZEND_MM_LONG_CONST(0x3)

#define ZEND_MM_BLOCK(b, type, size)	do { \
											size_t _size = (size); \
											(b)->info._size = (type) | _size; \
											ZEND_MM_BLOCK_AT(b, _size)->info._prev = (type) | _size; \
											ZEND_MM_SET_COOKIE(b); \
										} while (0);
#define ZEND_MM_LAST_BLOCK(b)			do { \
		(b)->info._size = ZEND_MM_GUARD_BLOCK | ZEND_MM_ALIGNED_HEADER_SIZE; \
		ZEND_MM_SET_MAGIC(b, MEM_BLOCK_GUARD); \
 	} while (0);
#define ZEND_MM_BLOCK_SIZE(b)			((b)->info._size & ~ZEND_MM_TYPE_MASK)
#define ZEND_MM_IS_FREE_BLOCK(b)		(!((b)->info._size & ZEND_MM_USED_BLOCK))
#define ZEND_MM_IS_USED_BLOCK(b)		((b)->info._size & ZEND_MM_USED_BLOCK)
#define ZEND_MM_IS_GUARD_BLOCK(b)		(((b)->info._size & ZEND_MM_TYPE_MASK) == ZEND_MM_GUARD_BLOCK)

#define ZEND_MM_NEXT_BLOCK(b)			ZEND_MM_BLOCK_AT(b, ZEND_MM_BLOCK_SIZE(b))
#define ZEND_MM_PREV_BLOCK(b)			ZEND_MM_BLOCK_AT(b, -(ssize_t)((b)->info._prev & ~ZEND_MM_TYPE_MASK))

#define ZEND_MM_PREV_BLOCK_IS_FREE(b)	(!((b)->info._prev & ZEND_MM_USED_BLOCK))

#define ZEND_MM_MARK_FIRST_BLOCK(b)		((b)->info._prev = ZEND_MM_GUARD_BLOCK)
#define ZEND_MM_IS_FIRST_BLOCK(b)		((b)->info._prev == ZEND_MM_GUARD_BLOCK)

/* optimized access */
#define ZEND_MM_FREE_BLOCK_SIZE(b)		(b)->info._size

/* Aligned header size */
#define ZEND_MM_ALIGNED_HEADER_SIZE			ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_block))
#define ZEND_MM_ALIGNED_FREE_HEADER_SIZE	ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_small_free_block))
#define ZEND_MM_MIN_ALLOC_BLOCK_SIZE		ZEND_MM_ALIGNED_SIZE(ZEND_MM_ALIGNED_HEADER_SIZE + END_MAGIC_SIZE)
#define ZEND_MM_ALIGNED_MIN_HEADER_SIZE		(ZEND_MM_MIN_ALLOC_BLOCK_SIZE>ZEND_MM_ALIGNED_FREE_HEADER_SIZE?ZEND_MM_MIN_ALLOC_BLOCK_SIZE:ZEND_MM_ALIGNED_FREE_HEADER_SIZE)
#define ZEND_MM_ALIGNED_SEGMENT_SIZE		ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_segment))

#define ZEND_MM_MIN_SIZE					((ZEND_MM_ALIGNED_MIN_HEADER_SIZE>(ZEND_MM_ALIGNED_HEADER_SIZE+END_MAGIC_SIZE))?(ZEND_MM_ALIGNED_MIN_HEADER_SIZE-(ZEND_MM_ALIGNED_HEADER_SIZE+END_MAGIC_SIZE)):0)

#define ZEND_MM_MAX_SMALL_SIZE				((ZEND_MM_NUM_BUCKETS<<ZEND_MM_ALIGNMENT_LOG2)+ZEND_MM_ALIGNED_MIN_HEADER_SIZE)

#define ZEND_MM_TRUE_SIZE(size)				((size<ZEND_MM_MIN_SIZE)?(ZEND_MM_ALIGNED_MIN_HEADER_SIZE):(ZEND_MM_ALIGNED_SIZE(size+ZEND_MM_ALIGNED_HEADER_SIZE+END_MAGIC_SIZE)))

#define ZEND_MM_BUCKET_INDEX(true_size)		((true_size>>ZEND_MM_ALIGNMENT_LOG2)-(ZEND_MM_ALIGNED_MIN_HEADER_SIZE>>ZEND_MM_ALIGNMENT_LOG2))

#define ZEND_MM_SMALL_SIZE(true_size)		(true_size < ZEND_MM_MAX_SMALL_SIZE)


/* Memory calculations */
#define ZEND_MM_BLOCK_AT(blk, offset)	((zend_mm_block *) (((char *) (blk))+(offset)))
#define ZEND_MM_DATA_OF(p)				((void *) (((char *) (p))+ZEND_MM_ALIGNED_HEADER_SIZE))
#define ZEND_MM_HEADER_OF(blk)			ZEND_MM_BLOCK_AT(blk, -(int)ZEND_MM_ALIGNED_HEADER_SIZE)


/* Debug output */

#define ZEND_MM_SET_THREAD_ID(block)
#define ZEND_MM_BAD_THREAD_ID(block) 0

#define ZEND_MM_VALID_PTR(block) \
	zend_mm_check_ptr(heap, block, 1 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC)

#define ZEND_MM_SET_MAGIC(block, val) do { \
		(block)->magic = (val); \
	} while (0)

#define ZEND_MM_CHECK_MAGIC(block, val) do { \
		if ((block)->magic != (val)) { \
			zend_mm_panic("zend_mm_heap corrupted"); \
		} \
	} while (0)

# define ZEND_MM_SET_DEBUG_INFO(block, __size, set_valid, set_thread) do { \
		((zend_mm_block*)(block))->debug.filename = __zend_filename; \
		((zend_mm_block*)(block))->debug.lineno = __zend_lineno; \
		((zend_mm_block*)(block))->debug.orig_filename = __zend_orig_filename; \
		((zend_mm_block*)(block))->debug.orig_lineno = __zend_orig_lineno; \
		ZEND_MM_SET_BLOCK_SIZE(block, __size); \
		if (set_valid) { \
			ZEND_MM_SET_MAGIC(block, MEM_BLOCK_VALID); \
		} \
		if (set_thread) { \
			ZEND_MM_SET_THREAD_ID(block); \
		} \
	} while (0)




# define ZEND_MM_CHECK_PROTECTION(block) \
	do { \
		if ((block)->debug.start_magic != _mem_block_start_magic || \
		    memcmp(ZEND_MM_END_MAGIC_PTR(block), &_mem_block_end_magic, END_MAGIC_SIZE) != 0) { \
		    zend_mm_panic("zend_mm_heap corrupted"); \
		} \
	} while (0)

# define ZEND_MM_END_MAGIC_PTR(block) \
	(((char*)(ZEND_MM_DATA_OF(block))) + ((zend_mm_block*)(block))->debug.size)

# define END_MAGIC_SIZE sizeof(unsigned int)

# define ZEND_MM_SET_BLOCK_SIZE(block, __size) do { \
		char *p; \
		((zend_mm_block*)(block))->debug.size = (__size); \
		p = ZEND_MM_END_MAGIC_PTR(block); \
		((zend_mm_block*)(block))->debug.start_magic = _mem_block_start_magic; \
		memcpy(p, &_mem_block_end_magic, END_MAGIC_SIZE); \
	} while (0)

static unsigned int _mem_block_start_magic = 0;
static unsigned int _mem_block_end_magic   = 0;


# define ZEND_MM_CHECK_BLOCK_LINKAGE(block) \
	if (UNEXPECTED((block)->info._size != ZEND_MM_BLOCK_AT(block, ZEND_MM_FREE_BLOCK_SIZE(block))->info._prev) || \
		UNEXPECTED(!UNEXPECTED(ZEND_MM_IS_FIRST_BLOCK(block)) && \
	    UNEXPECTED(ZEND_MM_PREV_BLOCK(block)->info._size != (block)->info._prev))) { \
	    zend_mm_panic("zend_mm_heap corrupted"); \
	}
#define ZEND_MM_CHECK_TREE(block) \
	if (UNEXPECTED(*((block)->parent) != (block))) { \
		zend_mm_panic("zend_mm_heap corrupted"); \
	}

#define ZEND_MM_LARGE_BUCKET_INDEX(S) zend_mm_high_bit(S)





/*swappers*/

void start_memory_manager(TSRMLS_D);


void *_emalloc(size_t size ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC);
void _efree(void *ptr ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC);
void *_erealloc(void *ptr, size_t size, int allow_failure ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC);

/* Standard wrapper macros */
#define emalloc(size)						_emalloc((size) ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC)
#define safe_emalloc(nmemb, size, offset)	_safe_emalloc((nmemb), (size), (offset) ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC)
#define efree(ptr)							_efree((ptr) ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC)
#define ecalloc(nmemb, size)				_ecalloc((nmemb), (size) ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC)
#define erealloc(ptr, size)					_erealloc((ptr), (size), 0 ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC)
#define safe_erealloc(ptr, nmemb, size, offset)	_safe_erealloc((ptr), (nmemb), (size), (offset) ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC)
#define erealloc_recoverable(ptr, size)		_erealloc((ptr), (size), 1 ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC)
#define estrdup(s)							_estrdup((s) ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC)
#define estrndup(s, length)					_estrndup((s), (length) ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC)
#define zend_mem_block_size(ptr)			_zend_mem_block_size((ptr) TSRMLS_CC ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC)


#endif /* ZEND_ALLOC_H_ */
