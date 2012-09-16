/*
 * zend_alloc.c
 *
 *  Created on: Sep 15, 2012
 *      Author: hujin
 */

#include <stdarg.h>
#include "zend_alloc.h"

#define PTR_FMT "0x%0.8lx"

static inline void zend_mm_remove_from_free_list(zend_mm_heap *heap, zend_mm_free_block *mm_block);
static inline void zend_mm_add_to_rest_list(zend_mm_heap *heap, zend_mm_free_block *mm_block);
static void zend_mm_free_cache(zend_mm_heap *heap);


int zend_atoi(const char *str, int str_len) /* {{{ */
{
	int retval;

	if (!str_len) {
		str_len = strlen(str);
	}
	retval = strtol(str, NULL, 0);
	if (str_len>0) {
		switch (str[str_len-1]) {
			case 'g':
			case 'G':
				retval *= 1024;
				/* break intentionally missing */
			case 'm':
			case 'M':
				retval *= 1024;
				/* break intentionally missing */
			case 'k':
			case 'K':
				retval *= 1024;
				break;
		}
	}
	return retval;
}


static void zend_mm_random(unsigned char *buf, size_t size) /* {{{ */
{
	size_t i = 0;
	unsigned char t;

	int fd = open("/dev/urandom", 0);

	if (fd >= 0) {
		if (read(fd, buf, size) == size) {
			while (i < size && buf[i] != 0) {
				i++;
			}
			if (i == size) {
				close(fd);
			    return;
			}
		}
		close(fd);
	}

	t = (unsigned char)getpid();
	while (i < size) {
		do {
			buf[i] = ((unsigned char)rand()) ^ t;
		} while (buf[i] == 0);
		t = buf[i++] << 1;
    }
}


static inline unsigned int zend_mm_high_bit(size_t _size)
{
	unsigned int n = 0;
	while (_size != 0) {
		_size = _size >> 1;
		n++;
	}
	return n-1;
}


static inline unsigned int zend_mm_low_bit(size_t _size)
{
	static const int offset[16] = {4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0};
	unsigned int n;
	unsigned int index = 0;

	n = offset[_size & 15];
	while (n == 4) {
		_size >>= 4;
		index += n;
		n = offset[_size & 15];
	}

	return index + n;
}


static void zend_mm_panic(const char *message)
{
	fprintf(stderr, "%s\n", message);
	kill(getpid(), SIGSEGV);//only debug mode
	exit(1);
}



static void zend_mm_safe_error(zend_mm_heap *heap,
	const char *format,
	size_t limit,
	const char *filename,
	uint lineno,
	size_t size)
{
	/*
	if (heap->reserve) {
		_zend_mm_free_int(heap, heap->reserve ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC);
		heap->reserve = NULL;
	}
	if (heap->overflow == 0) {
		const char *error_filename;
		uint error_lineno;
		TSRMLS_FETCH();
		if (zend_is_compiling(TSRMLS_C)) {
			error_filename = zend_get_compiled_filename(TSRMLS_C);
			error_lineno = zend_get_compiled_lineno(TSRMLS_C);
		} else if (EG(in_execution)) {
			error_filename = EG(active_op_array)?EG(active_op_array)->filename:NULL;
			error_lineno = EG(opline_ptr)?(*EG(opline_ptr))->lineno:0;
		} else {
			error_filename = NULL;
			error_lineno = 0;
		}
		if (!error_filename) {
			error_filename = "Unknown";
		}
		heap->overflow = 1;
		zend_try {
			zend_error_noreturn(E_ERROR,
				format,
				limit,
				filename,
				lineno,
				size);
		} zend_catch {
			if (heap->overflow == 2) {
				fprintf(stderr, "\nFatal error: ");
				fprintf(stderr,
					format,
					limit,
					filename,
					lineno,
					size);
				fprintf(stderr, " in %s on line %d\n", error_filename, error_lineno);
			}
		} zend_end_try();
	} else {
		heap->overflow = 2;
	}
	zend_bailout();
	*/
}


static inline void zend_mm_add_to_free_list(zend_mm_heap *heap, zend_mm_free_block *mm_block)
{
	size_t size;
	size_t index;

	ZEND_MM_SET_MAGIC(mm_block, MEM_BLOCK_FREED);

	size = ZEND_MM_FREE_BLOCK_SIZE(mm_block);
	if (EXPECTED(!ZEND_MM_SMALL_SIZE(size))) {
		zend_mm_free_block **p;

		index = ZEND_MM_LARGE_BUCKET_INDEX(size);
		p = &heap->large_free_buckets[index];
		mm_block->child[0] = mm_block->child[1] = NULL;
		if (!*p) {
			*p = mm_block;
			mm_block->parent = p;
			mm_block->prev_free_block = mm_block->next_free_block = mm_block;
			heap->large_free_bitmap |= (ZEND_MM_LONG_CONST(1) << index);
		} else {
			size_t m;

			for (m = size << (ZEND_MM_NUM_BUCKETS - index); ; m <<= 1) {
				zend_mm_free_block *prev = *p;

				if (ZEND_MM_FREE_BLOCK_SIZE(prev) != size) {
					p = &prev->child[(m >> (ZEND_MM_NUM_BUCKETS-1)) & 1];
					if (!*p) {
						*p = mm_block;
						mm_block->parent = p;
						mm_block->prev_free_block = mm_block->next_free_block = mm_block;
						break;
					}
				} else {
					zend_mm_free_block *next = prev->next_free_block;

					prev->next_free_block = next->prev_free_block = mm_block;
					mm_block->next_free_block = next;
					mm_block->prev_free_block = prev;
					mm_block->parent = NULL;
					break;
				}
			}
		}
	} else {
		zend_mm_free_block *prev, *next;

		index = ZEND_MM_BUCKET_INDEX(size);

		prev = ZEND_MM_SMALL_FREE_BUCKET(heap, index);
		if (prev->prev_free_block == prev) {
			heap->free_bitmap |= (ZEND_MM_LONG_CONST(1) << index);
		}
		next = prev->next_free_block;

		mm_block->prev_free_block = prev;
		mm_block->next_free_block = next;
		prev->next_free_block = next->prev_free_block = mm_block;
	}
}


static void zend_mm_del_segment(zend_mm_heap *heap, zend_mm_segment *segment)
{
	zend_mm_segment **p = &heap->segments_list;

	while (*p != segment) {
		p = &(*p)->next_segment;
	}
	*p = segment->next_segment;
	heap->real_size -= segment->size;
	ZEND_MM_STORAGE_FREE(segment);
}


static void zend_mm_free_cache(zend_mm_heap *heap)
{
	int i;

	for (i = 0; i < ZEND_MM_NUM_BUCKETS; i++) {
		if (heap->cache[i]) {
			zend_mm_free_block *mm_block = heap->cache[i];

			while (mm_block) {
				size_t size = ZEND_MM_BLOCK_SIZE(mm_block);
				zend_mm_free_block *q = mm_block->prev_free_block;
				zend_mm_block *next_block = ZEND_MM_NEXT_BLOCK(mm_block);

				heap->cached -= size;

				if (ZEND_MM_PREV_BLOCK_IS_FREE(mm_block)) {
					mm_block = (zend_mm_free_block*)ZEND_MM_PREV_BLOCK(mm_block);
					size += ZEND_MM_FREE_BLOCK_SIZE(mm_block);
					zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) mm_block);
				}
				if (ZEND_MM_IS_FREE_BLOCK(next_block)) {
					size += ZEND_MM_FREE_BLOCK_SIZE(next_block);
					zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) next_block);
				}
				ZEND_MM_BLOCK(mm_block, ZEND_MM_FREE_BLOCK, size);

				if (ZEND_MM_IS_FIRST_BLOCK(mm_block) &&
				    ZEND_MM_IS_GUARD_BLOCK(ZEND_MM_NEXT_BLOCK(mm_block))) {
					zend_mm_del_segment(heap, (zend_mm_segment *) ((char *)mm_block - ZEND_MM_ALIGNED_SEGMENT_SIZE));
				} else {
					zend_mm_add_to_free_list(heap, (zend_mm_free_block *) mm_block);
				}

				mm_block = q;
			}
			heap->cache[i] = NULL;
		}
	}
}


void zend_debug_alloc_output(char *format, ...)
{
	char output_buf[256];
	va_list args;

	va_start(args, format);
	vsprintf(output_buf, format, args);
	va_end(args);

	fprintf(stderr, "%s", output_buf);
}


static int zend_mm_check_ptr(zend_mm_heap *heap, void *ptr, int silent ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	zend_mm_block *p;
	int no_cache_notice = 0;
	int had_problems = 0;
	int valid_beginning = 1;

	if (silent==2) {
		silent = 1;
		no_cache_notice = 1;
	} else if (silent==3) {
		silent = 0;
		no_cache_notice = 1;
	}
	if (!silent) {
		TSRMLS_FETCH();

		//zend_message_dispatcher(ZMSG_LOG_SCRIPT_NAME, NULL TSRMLS_CC);
		zend_debug_alloc_output("---------------------------------------\n");
		zend_debug_alloc_output("%s(%d) : Block "PTR_FMT" status:\n" ZEND_FILE_LINE_RELAY_CC, ptr);
		if (__zend_orig_filename) {
			zend_debug_alloc_output("%s(%d) : Actual location (location was relayed)\n" ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
		if (!ptr) {
			zend_debug_alloc_output("NULL\n");
			zend_debug_alloc_output("---------------------------------------\n");
			return 0;
		}
	}

	if (!ptr) {
		if (silent) {
			return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
	}

	p = ZEND_MM_HEADER_OF(ptr);


	if (p->info._size != ZEND_MM_NEXT_BLOCK(p)->info._prev) {
		if (!silent) {
			zend_debug_alloc_output("Invalid pointer: ((size="PTR_FMT") != (next.prev="PTR_FMT"))\n", p->info._size, ZEND_MM_NEXT_BLOCK(p)->info._prev);
			had_problems = 1;
		} else {
			return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
	}
	if (p->info._prev != ZEND_MM_GUARD_BLOCK &&
	    ZEND_MM_PREV_BLOCK(p)->info._size != p->info._prev) {
		if (!silent) {
			zend_debug_alloc_output("Invalid pointer: ((prev="PTR_FMT") != (prev.size="PTR_FMT"))\n", p->info._prev, ZEND_MM_PREV_BLOCK(p)->info._size);
			had_problems = 1;
		} else {
			return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
	}

	if (had_problems) {
		zend_debug_alloc_output("---------------------------------------\n");
		return 0;
	}

	if (!silent) {
		zend_debug_alloc_output("%10s\t","Beginning:  ");
	}

	if (!ZEND_MM_IS_USED_BLOCK(p)) {
		if (!silent) {
			if (p->magic != MEM_BLOCK_FREED) {
				zend_debug_alloc_output("Freed (magic=0x%0.8X, expected=0x%0.8X)\n", p->magic, MEM_BLOCK_FREED);
			} else {
				zend_debug_alloc_output("Freed\n");
			}
			had_problems = 1;
		} else {
			return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
	} else if (ZEND_MM_IS_GUARD_BLOCK(p)) {
		if (!silent) {
			if (p->magic != MEM_BLOCK_FREED) {
				zend_debug_alloc_output("Guard (magic=0x%0.8X, expected=0x%0.8X)\n", p->magic, MEM_BLOCK_FREED);
			} else {
				zend_debug_alloc_output("Guard\n");
			}
			had_problems = 1;
		} else {
			return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
	} else {
		switch (p->magic) {
			case MEM_BLOCK_VALID:
			case MEM_BLOCK_LEAK:
				if (!silent) {
					zend_debug_alloc_output("OK (allocated on %s:%d, %d bytes)\n", p->debug.filename, p->debug.lineno, (int)p->debug.size);
				}
				break; /* ok */
			case MEM_BLOCK_CACHED:
				if (!no_cache_notice) {
					if (!silent) {
						zend_debug_alloc_output("Cached\n");
						had_problems = 1;
					} else {
						return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
					}
				}
			case MEM_BLOCK_FREED:
				if (!silent) {
					zend_debug_alloc_output("Freed (invalid)\n");
					had_problems = 1;
				} else {
					return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
				}
				break;
			case MEM_BLOCK_GUARD:
				if (!silent) {
					zend_debug_alloc_output("Guard (invalid)\n");
					had_problems = 1;
				} else {
					return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
				}
				break;
			default:
				if (!silent) {
					zend_debug_alloc_output("Unknown (magic=0x%0.8X, expected=0x%0.8X)\n", p->magic, MEM_BLOCK_VALID);
					had_problems = 1;
					valid_beginning = 0;
				} else {
					return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
				}
				break;
		}
	}

	if (!valid_beginning) {
		if (!silent) {
			zend_debug_alloc_output("%10s\t", "Start:");
			zend_debug_alloc_output("Unknown\n");
			zend_debug_alloc_output("%10s\t", "End:");
			zend_debug_alloc_output("Unknown\n");
		}
	} else {
		char *end_magic = ZEND_MM_END_MAGIC_PTR(p);

		if (p->debug.start_magic == _mem_block_start_magic) {
			if (!silent) {
				zend_debug_alloc_output("%10s\t", "Start:");
				zend_debug_alloc_output("OK\n");
			}
		} else {
			char *overflow_ptr, *magic_ptr=(char *) &_mem_block_start_magic;
			int overflows=0;
			int i;

			if (silent) {
				return _mem_block_check(ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
			}
			had_problems = 1;
			overflow_ptr = (char *) &p->debug.start_magic;
			i = END_MAGIC_SIZE;
			while (--i >= 0) {
				if (overflow_ptr[i]!=magic_ptr[i]) {
					overflows++;
				}
			}
			zend_debug_alloc_output("%10s\t", "Start:");
			zend_debug_alloc_output("Overflown (magic=0x%0.8X instead of 0x%0.8X)\n", p->debug.start_magic, _mem_block_start_magic);
			zend_debug_alloc_output("%10s\t","");
			if (overflows >= END_MAGIC_SIZE) {
				zend_debug_alloc_output("At least %d bytes overflown\n", END_MAGIC_SIZE);
			} else {
				zend_debug_alloc_output("%d byte(s) overflown\n", overflows);
			}
		}
		if (memcmp(end_magic, &_mem_block_end_magic, END_MAGIC_SIZE)==0) {
			if (!silent) {
				zend_debug_alloc_output("%10s\t", "End:");
				zend_debug_alloc_output("OK\n");
			}
		} else {
			char *overflow_ptr, *magic_ptr=(char *) &_mem_block_end_magic;
			int overflows=0;
			int i;

			if (silent) {
				return _mem_block_check(ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
			}
			had_problems = 1;
			overflow_ptr = (char *) end_magic;

			for (i=0; i < END_MAGIC_SIZE; i++) {
				if (overflow_ptr[i]!=magic_ptr[i]) {
					overflows++;
				}
			}

			zend_debug_alloc_output("%10s\t", "End:");
			zend_debug_alloc_output("Overflown (magic=0x%0.8X instead of 0x%0.8X)\n", *end_magic, _mem_block_end_magic);
			zend_debug_alloc_output("%10s\t","");
			if (overflows >= END_MAGIC_SIZE) {
				zend_debug_alloc_output("At least %d bytes overflown\n", END_MAGIC_SIZE);
			} else {
				zend_debug_alloc_output("%d byte(s) overflown\n", overflows);
			}
		}
	}

	if (!silent) {
		zend_debug_alloc_output("---------------------------------------\n");
	}
	return ((!had_problems) ? 1 : 0);
}


static zend_mm_free_block *zend_mm_search_large_block(zend_mm_heap *heap, size_t true_size)
{
	zend_mm_free_block *best_fit;
	size_t index = ZEND_MM_LARGE_BUCKET_INDEX(true_size);
	size_t bitmap = heap->large_free_bitmap >> index;
	zend_mm_free_block *p;

	if (bitmap == 0) {
		return NULL;
	}

	if (UNEXPECTED((bitmap & 1) != 0)) {
		/* Search for best "large" free block */
		zend_mm_free_block *rst = NULL;
		size_t m;
		size_t best_size = -1;

		best_fit = NULL;
		p = heap->large_free_buckets[index];
		for (m = true_size << (ZEND_MM_NUM_BUCKETS - index); ; m <<= 1) {
			if (UNEXPECTED(ZEND_MM_FREE_BLOCK_SIZE(p) == true_size)) {
				return p->next_free_block;
			} else if (ZEND_MM_FREE_BLOCK_SIZE(p) >= true_size &&
			           ZEND_MM_FREE_BLOCK_SIZE(p) < best_size) {
				best_size = ZEND_MM_FREE_BLOCK_SIZE(p);
				best_fit = p;
			}
			if ((m & (ZEND_MM_LONG_CONST(1) << (ZEND_MM_NUM_BUCKETS-1))) == 0) {
				if (p->child[1]) {
					rst = p->child[1];
				}
				if (p->child[0]) {
					p = p->child[0];
				} else {
					break;
				}
			} else if (p->child[1]) {
				p = p->child[1];
			} else {
				break;
			}
		}

		for (p = rst; p; p = p->child[p->child[0] != NULL]) {
			if (UNEXPECTED(ZEND_MM_FREE_BLOCK_SIZE(p) == true_size)) {
				return p->next_free_block;
			} else if (ZEND_MM_FREE_BLOCK_SIZE(p) > true_size &&
			           ZEND_MM_FREE_BLOCK_SIZE(p) < best_size) {
				best_size = ZEND_MM_FREE_BLOCK_SIZE(p);
				best_fit = p;
			}
		}

		if (best_fit) {
			return best_fit->next_free_block;
		}
		bitmap = bitmap >> 1;
		if (!bitmap) {
			return NULL;
		}
		index++;
	}

	/* Search for smallest "large" free block */
	best_fit = p = heap->large_free_buckets[index + zend_mm_low_bit(bitmap)];
	while ((p = p->child[p->child[0] != NULL])) {
		if (ZEND_MM_FREE_BLOCK_SIZE(p) < ZEND_MM_FREE_BLOCK_SIZE(best_fit)) {
			best_fit = p;
		}
	}
	return best_fit->next_free_block;
}


static void *_zend_mm_alloc_int(zend_mm_heap *heap, size_t size ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	zend_mm_free_block *best_fit;
	size_t true_size = ZEND_MM_TRUE_SIZE(size);
	size_t block_size;
	size_t remaining_size;
	size_t segment_size;
	zend_mm_segment *segment;
	int keep_rest = 0;

	//HANDLE_BLOCK_INTERRUPTIONS();

	if (EXPECTED(ZEND_MM_SMALL_SIZE(true_size))) {
		size_t index = ZEND_MM_BUCKET_INDEX(true_size);
		size_t bitmap;

		if (UNEXPECTED(true_size < size)) {
			goto out_of_memory;
		}

		/* find form cache */
		if (EXPECTED(heap->cache[index] != NULL)) {
			/* Get block from cache */
			best_fit = heap->cache[index];
			heap->cache[index] = best_fit->prev_free_block;
			heap->cached -= true_size;
			ZEND_MM_CHECK_MAGIC(best_fit, MEM_BLOCK_CACHED);
			ZEND_MM_SET_DEBUG_INFO(best_fit, size, 1, 0);
			//HANDLE_UNBLOCK_INTERRUPTIONS();
			return ZEND_MM_DATA_OF(best_fit);
 		}

		bitmap = heap->free_bitmap >> index;
		if (bitmap) {
			/* Found some "small" free block that can be used */
			index += zend_mm_low_bit(bitmap);
			best_fit = heap->free_buckets[index*2];
			goto zend_mm_finished_searching_for_block;
		}
	}


	best_fit = zend_mm_search_large_block(heap, true_size);

	if (!best_fit && heap->real_size >= heap->limit - heap->block_size) {
		zend_mm_free_block *p = heap->rest_buckets[0];
		size_t best_size = -1;

		while (p != ZEND_MM_REST_BUCKET(heap)) {
			if (UNEXPECTED(ZEND_MM_FREE_BLOCK_SIZE(p) == true_size)) {
				best_fit = p;
				goto zend_mm_finished_searching_for_block;
			} else if (ZEND_MM_FREE_BLOCK_SIZE(p) > true_size &&
			           ZEND_MM_FREE_BLOCK_SIZE(p) < best_size) {
				best_size = ZEND_MM_FREE_BLOCK_SIZE(p);
				best_fit = p;
			}
			p = p->prev_free_block;
		}
	}

	if (!best_fit) {
		if (true_size > heap->block_size - (ZEND_MM_ALIGNED_SEGMENT_SIZE + ZEND_MM_ALIGNED_HEADER_SIZE)) {
			/* Make sure we add a memory block which is big enough,
			   segment must have header "size" and trailer "guard" block */
			segment_size = true_size + ZEND_MM_ALIGNED_SEGMENT_SIZE + ZEND_MM_ALIGNED_HEADER_SIZE;
			segment_size = (segment_size + (heap->block_size-1)) & ~(heap->block_size-1);
			keep_rest = 1;
		} else {
			segment_size = heap->block_size;
		}

		if (segment_size < true_size ||
		    heap->real_size + segment_size > heap->limit) {
			/* Memory limit overflow */
			zend_mm_free_cache(heap);

			//HANDLE_UNBLOCK_INTERRUPTIONS();
			zend_mm_safe_error(heap, "Allowed memory size of %ld bytes exhausted at %s:%d (tried to allocate %lu bytes)", heap->limit, __zend_filename, __zend_lineno, size);
		}

		/*分配段存储空间*/
		segment = (zend_mm_segment *) ZEND_MM_STORAGE_ALLOC(segment_size);

		if (!segment) {
			/* Storage manager cannot allocate memory */
			zend_mm_free_cache(heap);

out_of_memory:
			//HANDLE_UNBLOCK_INTERRUPTIONS();
			zend_mm_safe_error(heap, "Out of memory (allocated %ld) at %s:%d (tried to allocate %lu bytes)", heap->real_size, __zend_filename, __zend_lineno, size);
			return NULL;
		}

		heap->real_size += segment_size;

		// 设置内存使用峰值，为最大的 real_size
		if (heap->real_size > heap->real_peak) {
			heap->real_peak = heap->real_size;
		}

		segment->size = segment_size;
		segment->next_segment = heap->segments_list;
		heap->segments_list = segment;

		best_fit = (zend_mm_free_block *) ((char *) segment + ZEND_MM_ALIGNED_SEGMENT_SIZE);
		ZEND_MM_MARK_FIRST_BLOCK(best_fit);

		block_size = segment_size - ZEND_MM_ALIGNED_SEGMENT_SIZE - ZEND_MM_ALIGNED_HEADER_SIZE;

		ZEND_MM_LAST_BLOCK(ZEND_MM_BLOCK_AT(best_fit, block_size));

	} else {
zend_mm_finished_searching_for_block:
		/* remove from free list */
		ZEND_MM_CHECK_MAGIC(best_fit, MEM_BLOCK_FREED);
		ZEND_MM_CHECK_COOKIE(best_fit);
		ZEND_MM_CHECK_BLOCK_LINKAGE(best_fit);
		zend_mm_remove_from_free_list(heap, best_fit);

		block_size = ZEND_MM_FREE_BLOCK_SIZE(best_fit);
	}

	remaining_size = block_size - true_size;

	if (remaining_size < ZEND_MM_ALIGNED_MIN_HEADER_SIZE) {
		true_size = block_size;
		ZEND_MM_BLOCK(best_fit, ZEND_MM_USED_BLOCK, true_size);
	} else {
		zend_mm_free_block *new_free_block;

		/* prepare new free block */
		ZEND_MM_BLOCK(best_fit, ZEND_MM_USED_BLOCK, true_size);
		new_free_block = (zend_mm_free_block *) ZEND_MM_BLOCK_AT(best_fit, true_size);
		ZEND_MM_BLOCK(new_free_block, ZEND_MM_FREE_BLOCK, remaining_size);

		/* add the new free block to the free list */
		if (EXPECTED(!keep_rest)) {
			zend_mm_add_to_free_list(heap, new_free_block);
		} else {
			zend_mm_add_to_rest_list(heap, new_free_block);
		}
	}

	ZEND_MM_SET_DEBUG_INFO(best_fit, size, 1, 1);

	heap->size += true_size;
	if (heap->peak < heap->size) {
		heap->peak = heap->size;
	}

	//HANDLE_UNBLOCK_INTERRUPTIONS();

	return ZEND_MM_DATA_OF(best_fit);
}


static void _zend_mm_free_int(zend_mm_heap *heap, void *p ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	zend_mm_block *mm_block;
	zend_mm_block *next_block;
	size_t size;

	if (!ZEND_MM_VALID_PTR(p)) {
		return;
	}

	//HANDLE_BLOCK_INTERRUPTIONS();

	mm_block = ZEND_MM_HEADER_OF(p);
	size = ZEND_MM_BLOCK_SIZE(mm_block);
	ZEND_MM_CHECK_PROTECTION(mm_block);


	memset(ZEND_MM_DATA_OF(mm_block), 0x5a, mm_block->debug.size);


	// 如果所释放的内存是小块内存，且当前缓存大小没有操作 ZEND_MM_CACHE_SIZE（sizeof(size_t) << 3 * 4 * 1024）64*4K 时，将释放的内存插入缓存列表。
	if (EXPECTED(ZEND_MM_SMALL_SIZE(size)) && EXPECTED(heap->cached < ZEND_MM_CACHE_SIZE)) {
		size_t index = ZEND_MM_BUCKET_INDEX(size);
		zend_mm_free_block **cache = &heap->cache[index];

		((zend_mm_free_block*)mm_block)->prev_free_block = *cache;
		*cache = (zend_mm_free_block*)mm_block;
		heap->cached += size;
		ZEND_MM_SET_MAGIC(mm_block, MEM_BLOCK_CACHED);

		//HANDLE_UNBLOCK_INTERRUPTIONS();
		return;
	}


	heap->size -= size;

	next_block = ZEND_MM_BLOCK_AT(mm_block, size);
	if (ZEND_MM_IS_FREE_BLOCK(next_block)) {
		zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) next_block);
		size += ZEND_MM_FREE_BLOCK_SIZE(next_block);
	}
	if (ZEND_MM_PREV_BLOCK_IS_FREE(mm_block)) {
		mm_block = ZEND_MM_PREV_BLOCK(mm_block);
		zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) mm_block);
		size += ZEND_MM_FREE_BLOCK_SIZE(mm_block);
	}
	if (ZEND_MM_IS_FIRST_BLOCK(mm_block) &&
	    ZEND_MM_IS_GUARD_BLOCK(ZEND_MM_BLOCK_AT(mm_block, size))) {
		zend_mm_del_segment(heap, (zend_mm_segment *) ((char *)mm_block - ZEND_MM_ALIGNED_SEGMENT_SIZE));
	} else {
		ZEND_MM_BLOCK(mm_block, ZEND_MM_FREE_BLOCK, size);
		zend_mm_add_to_free_list(heap, (zend_mm_free_block *) mm_block);
	}
	//HANDLE_UNBLOCK_INTERRUPTIONS();
}



static void *_zend_mm_realloc_int(zend_mm_heap *heap, void *p, size_t size ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	zend_mm_block *mm_block = ZEND_MM_HEADER_OF(p);
	zend_mm_block *next_block;
	size_t true_size;
	size_t orig_size;
	void *ptr;

	if (UNEXPECTED(!p) || !ZEND_MM_VALID_PTR(p)) {
		return _zend_mm_alloc_int(heap, size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
	}

	//HANDLE_BLOCK_INTERRUPTIONS();

	mm_block = ZEND_MM_HEADER_OF(p);
	true_size = ZEND_MM_TRUE_SIZE(size);
	orig_size = ZEND_MM_BLOCK_SIZE(mm_block);
	ZEND_MM_CHECK_PROTECTION(mm_block);

	if (UNEXPECTED(true_size < size)) {
		goto out_of_memory;
	}

	if (true_size <= orig_size) {
		size_t remaining_size = orig_size - true_size;

		if (remaining_size >= ZEND_MM_ALIGNED_MIN_HEADER_SIZE) {
			zend_mm_free_block *new_free_block;

			next_block = ZEND_MM_BLOCK_AT(mm_block, orig_size);
			if (ZEND_MM_IS_FREE_BLOCK(next_block)) {
				remaining_size += ZEND_MM_FREE_BLOCK_SIZE(next_block);
				zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) next_block);
			}

			/* prepare new free block */
			ZEND_MM_BLOCK(mm_block, ZEND_MM_USED_BLOCK, true_size);
			new_free_block = (zend_mm_free_block *) ZEND_MM_BLOCK_AT(mm_block, true_size);

			ZEND_MM_BLOCK(new_free_block, ZEND_MM_FREE_BLOCK, remaining_size);

			/* add the new free block to the free list */
			zend_mm_add_to_free_list(heap, new_free_block);
			heap->size += (true_size - orig_size);
		}
		ZEND_MM_SET_DEBUG_INFO(mm_block, size, 0, 0);
		//HANDLE_UNBLOCK_INTERRUPTIONS();
		return p;
	}


	if (ZEND_MM_SMALL_SIZE(true_size)) {
		size_t index = ZEND_MM_BUCKET_INDEX(true_size);

		if (heap->cache[index] != NULL) {
			zend_mm_free_block *best_fit;
			zend_mm_free_block **cache;


			best_fit = heap->cache[index];
			heap->cache[index] = best_fit->prev_free_block;
			ZEND_MM_CHECK_MAGIC(best_fit, MEM_BLOCK_CACHED);
			ZEND_MM_SET_DEBUG_INFO(best_fit, size, 1, 0);

			ptr = ZEND_MM_DATA_OF(best_fit);


			memcpy(ptr, p, mm_block->debug.size);



			heap->cached -= true_size - orig_size;

			index = ZEND_MM_BUCKET_INDEX(orig_size);
			cache = &heap->cache[index];

			((zend_mm_free_block*)mm_block)->prev_free_block = *cache;
			*cache = (zend_mm_free_block*)mm_block;
			ZEND_MM_SET_MAGIC(mm_block, MEM_BLOCK_CACHED);

			//HANDLE_UNBLOCK_INTERRUPTIONS();
			return ptr;
		}
	}


	next_block = ZEND_MM_BLOCK_AT(mm_block, orig_size);

	if (ZEND_MM_IS_FREE_BLOCK(next_block)) {
		ZEND_MM_CHECK_COOKIE(next_block);
		ZEND_MM_CHECK_BLOCK_LINKAGE(next_block);
		if (orig_size + ZEND_MM_FREE_BLOCK_SIZE(next_block) >= true_size) {
			size_t block_size = orig_size + ZEND_MM_FREE_BLOCK_SIZE(next_block);
			size_t remaining_size = block_size - true_size;

			zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) next_block);

			if (remaining_size < ZEND_MM_ALIGNED_MIN_HEADER_SIZE) {
				true_size = block_size;
				ZEND_MM_BLOCK(mm_block, ZEND_MM_USED_BLOCK, true_size);
			} else {
				zend_mm_free_block *new_free_block;

				/* prepare new free block */
				ZEND_MM_BLOCK(mm_block, ZEND_MM_USED_BLOCK, true_size);
				new_free_block = (zend_mm_free_block *) ZEND_MM_BLOCK_AT(mm_block, true_size);
				ZEND_MM_BLOCK(new_free_block, ZEND_MM_FREE_BLOCK, remaining_size);

				/* add the new free block to the free list */
				if (ZEND_MM_IS_FIRST_BLOCK(mm_block) &&
				    ZEND_MM_IS_GUARD_BLOCK(ZEND_MM_BLOCK_AT(new_free_block, remaining_size))) {
					zend_mm_add_to_rest_list(heap, new_free_block);
				} else {
					zend_mm_add_to_free_list(heap, new_free_block);
				}
			}
			ZEND_MM_SET_DEBUG_INFO(mm_block, size, 0, 0);
			heap->size = heap->size + true_size - orig_size;
			if (heap->peak < heap->size) {
				heap->peak = heap->size;
			}
			//HANDLE_UNBLOCK_INTERRUPTIONS();
			return p;
		} else if (ZEND_MM_IS_FIRST_BLOCK(mm_block) &&
				   ZEND_MM_IS_GUARD_BLOCK(ZEND_MM_BLOCK_AT(next_block, ZEND_MM_FREE_BLOCK_SIZE(next_block)))) {
			zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) next_block);
			goto realloc_segment;
		}
	} else if (ZEND_MM_IS_FIRST_BLOCK(mm_block) && ZEND_MM_IS_GUARD_BLOCK(next_block)) {
		zend_mm_segment *segment;
		zend_mm_segment *segment_copy;
		size_t segment_size;
		size_t block_size;
		size_t remaining_size;

realloc_segment:
		/* segment size, size of block and size of guard block */
		if (true_size > heap->block_size - (ZEND_MM_ALIGNED_SEGMENT_SIZE + ZEND_MM_ALIGNED_HEADER_SIZE)) {
			segment_size = true_size+ZEND_MM_ALIGNED_SEGMENT_SIZE+ZEND_MM_ALIGNED_HEADER_SIZE;
			segment_size = (segment_size + (heap->block_size-1)) & ~(heap->block_size-1);
		} else {
			segment_size = heap->block_size;
		}

		segment_copy = (zend_mm_segment *) ((char *)mm_block - ZEND_MM_ALIGNED_SEGMENT_SIZE);
		if (segment_size < true_size ||
		    heap->real_size + segment_size - segment_copy->size > heap->limit) {
			if (ZEND_MM_IS_FREE_BLOCK(next_block)) {
				zend_mm_add_to_free_list(heap, (zend_mm_free_block *) next_block);
			}

			zend_mm_free_cache(heap);

			//HANDLE_UNBLOCK_INTERRUPTIONS();

			zend_mm_safe_error(heap, "Allowed memory size of %ld bytes exhausted at %s:%d (tried to allocate %ld bytes)", heap->limit, __zend_filename, __zend_lineno, size);

			return NULL;
		}

		segment = ZEND_MM_STORAGE_REALLOC(segment_copy, segment_size);
		if (!segment) {
			zend_mm_free_cache(heap);
out_of_memory:
			//HANDLE_UNBLOCK_INTERRUPTIONS();

			zend_mm_safe_error(heap, "Out of memory (allocated %ld) at %s:%d (tried to allocate %ld bytes)", heap->real_size, __zend_filename, __zend_lineno, size);

			return NULL;
		}
		heap->real_size += segment_size - segment->size;
		if (heap->real_size > heap->real_peak) {
			heap->real_peak = heap->real_size;
		}

		segment->size = segment_size;

		if (segment != segment_copy) {
			zend_mm_segment **seg = &heap->segments_list;
			while (*seg != segment_copy) {
				seg = &(*seg)->next_segment;
			}
			*seg = segment;
			mm_block = (zend_mm_block *) ((char *) segment + ZEND_MM_ALIGNED_SEGMENT_SIZE);
			ZEND_MM_MARK_FIRST_BLOCK(mm_block);
		}

		block_size = segment_size - ZEND_MM_ALIGNED_SEGMENT_SIZE - ZEND_MM_ALIGNED_HEADER_SIZE;
		remaining_size = block_size - true_size;

		/* setup guard block */
		ZEND_MM_LAST_BLOCK(ZEND_MM_BLOCK_AT(mm_block, block_size));

		if (remaining_size < ZEND_MM_ALIGNED_MIN_HEADER_SIZE) {
			true_size = block_size;
			ZEND_MM_BLOCK(mm_block, ZEND_MM_USED_BLOCK, true_size);
		} else {
			zend_mm_free_block *new_free_block;

			/* prepare new free block */
			ZEND_MM_BLOCK(mm_block, ZEND_MM_USED_BLOCK, true_size);
			new_free_block = (zend_mm_free_block *) ZEND_MM_BLOCK_AT(mm_block, true_size);
			ZEND_MM_BLOCK(new_free_block, ZEND_MM_FREE_BLOCK, remaining_size);

			/* add the new free block to the free list */
			zend_mm_add_to_rest_list(heap, new_free_block);
		}

		ZEND_MM_SET_DEBUG_INFO(mm_block, size, 1, 1);

		heap->size = heap->size + true_size - orig_size;
		if (heap->peak < heap->size) {
			heap->peak = heap->size;
		}

		//HANDLE_UNBLOCK_INTERRUPTIONS();
		return ZEND_MM_DATA_OF(mm_block);
	}

	ptr = _zend_mm_alloc_int(heap, size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);

	memcpy(ptr, p, mm_block->debug.size);

	_zend_mm_free_int(heap, p ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
	//HANDLE_UNBLOCK_INTERRUPTIONS();
	return ptr;
}



static inline void zend_mm_remove_from_free_list(zend_mm_heap *heap, zend_mm_free_block *mm_block)
{
	zend_mm_free_block *prev = mm_block->prev_free_block;
	zend_mm_free_block *next = mm_block->next_free_block;

	ZEND_MM_CHECK_MAGIC(mm_block, MEM_BLOCK_FREED);

	if (EXPECTED(prev == mm_block)) {
		zend_mm_free_block **rp, **cp;

		if (UNEXPECTED(next != mm_block)) {
			zend_mm_panic("zend_mm_heap corrupted");
		}

		rp = &mm_block->child[mm_block->child[1] != NULL];
		prev = *rp;
		if (EXPECTED(prev == NULL)) {
			size_t index = ZEND_MM_LARGE_BUCKET_INDEX(ZEND_MM_FREE_BLOCK_SIZE(mm_block));

			ZEND_MM_CHECK_TREE(mm_block);
			*mm_block->parent = NULL;
			if (mm_block->parent == &heap->large_free_buckets[index]) {
				heap->large_free_bitmap &= ~(ZEND_MM_LONG_CONST(1) << index);
		    }
		} else {
			while (*(cp = &(prev->child[prev->child[1] != NULL])) != NULL) {
				prev = *cp;
				rp = cp;
			}
			*rp = NULL;

subst_block:
			ZEND_MM_CHECK_TREE(mm_block);
			*mm_block->parent = prev;
			prev->parent = mm_block->parent;
			if ((prev->child[0] = mm_block->child[0])) {
				ZEND_MM_CHECK_TREE(prev->child[0]);
				prev->child[0]->parent = &prev->child[0];
			}
			if ((prev->child[1] = mm_block->child[1])) {
				ZEND_MM_CHECK_TREE(prev->child[1]);
				prev->child[1]->parent = &prev->child[1];
			}
		}
	} else {

		if (UNEXPECTED(prev->next_free_block != mm_block) || UNEXPECTED(next->prev_free_block != mm_block)) {
			zend_mm_panic("zend_mm_heap corrupted");
		}

		prev->next_free_block = next;
		next->prev_free_block = prev;

		if (EXPECTED(ZEND_MM_SMALL_SIZE(ZEND_MM_FREE_BLOCK_SIZE(mm_block)))) {
			if (EXPECTED(prev == next)) {
				size_t index = ZEND_MM_BUCKET_INDEX(ZEND_MM_FREE_BLOCK_SIZE(mm_block));

				if (EXPECTED(heap->free_buckets[index*2] == heap->free_buckets[index*2+1])) {
					heap->free_bitmap &= ~(ZEND_MM_LONG_CONST(1) << index);
				}
			}
		} else if (UNEXPECTED(mm_block->parent == ZEND_MM_REST_BLOCK)) {
			heap->rest_count--;
		} else if (UNEXPECTED(mm_block->parent != NULL)) {
			goto subst_block;
		}
	}
}


static inline void zend_mm_add_to_rest_list(zend_mm_heap *heap, zend_mm_free_block *mm_block)
{
	zend_mm_free_block *prev, *next;

	while (heap->rest_count >= ZEND_MM_MAX_REST_BLOCKS) {
		zend_mm_free_block *p = heap->rest_buckets[1];

		if (!ZEND_MM_SMALL_SIZE(ZEND_MM_FREE_BLOCK_SIZE(p))) {
			heap->rest_count--;
		}
		prev = p->prev_free_block;
		next = p->next_free_block;
		prev->next_free_block = next;
		next->prev_free_block = prev;
		zend_mm_add_to_free_list(heap, p);
	}

	if (!ZEND_MM_SMALL_SIZE(ZEND_MM_FREE_BLOCK_SIZE(mm_block))) {
		mm_block->parent = ZEND_MM_REST_BLOCK;
		heap->rest_count++;
	}

	ZEND_MM_SET_MAGIC(mm_block, MEM_BLOCK_FREED);

	prev = heap->rest_buckets[0];
	next = prev->next_free_block;
	mm_block->prev_free_block = prev;
	mm_block->next_free_block = next;
	prev->next_free_block = next->prev_free_block = mm_block;
}


static inline void zend_mm_init(zend_mm_heap *heap)
{
	zend_mm_free_block* p;
	int i;

	heap->free_bitmap = 0;
	heap->large_free_bitmap = 0;
	/* for cache */
	heap->cached = 0;
	memset(heap->cache, 0, sizeof(heap->cache));

	p = ZEND_MM_SMALL_FREE_BUCKET(heap, 0);
	for (i = 0; i < ZEND_MM_NUM_BUCKETS; i++) {
		p->next_free_block = p;
		p->prev_free_block = p;
		p = (zend_mm_free_block*)((char*)p + sizeof(zend_mm_free_block*) * 2);
		heap->large_free_buckets[i] = NULL;
	}
	heap->rest_buckets[0] = heap->rest_buckets[1] = ZEND_MM_REST_BUCKET(heap);
	heap->rest_count = 0;
}


zend_mm_heap *zend_mm_startup_ex(const zend_mm_mem_handlers *handlers, size_t block_size, size_t reserve_size, int internal, void *params)
{
	zend_mm_storage *storage;
	zend_mm_heap    *heap;

#if 0
	int i;

	printf("ZEND_MM_ALIGNMENT=%d\n", ZEND_MM_ALIGNMENT);
	printf("ZEND_MM_ALIGNMENT_LOG2=%d\n", ZEND_MM_ALIGNMENT_LOG2);
	printf("ZEND_MM_MIN_SIZE=%d\n", ZEND_MM_MIN_SIZE);
	printf("ZEND_MM_MAX_SMALL_SIZE=%d\n", ZEND_MM_MAX_SMALL_SIZE);
	printf("ZEND_MM_ALIGNED_HEADER_SIZE=%d\n", ZEND_MM_ALIGNED_HEADER_SIZE);
	printf("ZEND_MM_ALIGNED_FREE_HEADER_SIZE=%d\n", ZEND_MM_ALIGNED_FREE_HEADER_SIZE);
	printf("ZEND_MM_MIN_ALLOC_BLOCK_SIZE=%d\n", ZEND_MM_MIN_ALLOC_BLOCK_SIZE);
	printf("ZEND_MM_ALIGNED_MIN_HEADER_SIZE=%d\n", ZEND_MM_ALIGNED_MIN_HEADER_SIZE);
	printf("ZEND_MM_ALIGNED_SEGMENT_SIZE=%d\n", ZEND_MM_ALIGNED_SEGMENT_SIZE);
	for (i = 0; i < ZEND_MM_MAX_SMALL_SIZE; i++) {
		printf("%3d%c: %3ld %d %2ld\n", i, (i == ZEND_MM_MIN_SIZE?'*':' '), (long)ZEND_MM_TRUE_SIZE(i), ZEND_MM_SMALL_SIZE(ZEND_MM_TRUE_SIZE(i)), (long)ZEND_MM_BUCKET_INDEX(ZEND_MM_TRUE_SIZE(i)));
	}
	exit(0);
#endif

	if (_mem_block_start_magic == 0) {
		zend_mm_random((unsigned char*)&_mem_block_start_magic, sizeof(_mem_block_start_magic));
	}
	if (_mem_block_end_magic == 0) {
		zend_mm_random((unsigned char*)&_mem_block_end_magic, sizeof(_mem_block_end_magic));
	}

	if (_zend_mm_cookie == 0) {
		zend_mm_random((unsigned char*)&_zend_mm_cookie, sizeof(_zend_mm_cookie));
	}

	if (zend_mm_low_bit(block_size) != zend_mm_high_bit(block_size)) {
		fprintf(stderr, "'block_size' must be a power of two\n");
		exit(255);
	}
	storage = handlers->init(params);//使用 malloc 分配 zend_mm_storage 内存。
	if (!storage) {
		fprintf(stderr, "Cannot initialize zend_mm storage [%s]\n", handlers->name);
		exit(255);
	}
	storage->handlers = handlers;

	heap = malloc(sizeof(struct _zend_mm_heap));
	if (heap == NULL) {
		fprintf(stderr, "Cannot allocate heap for zend_mm storage [%s]\n", handlers->name);
		exit(255);
	}
	heap->storage = storage;
	heap->block_size = block_size;//由 ZEND_MM_SEG_SIZE 环境变量设置，默认 256K。
	heap->compact_size = 0;
	heap->segments_list = NULL;
	zend_mm_init(heap);

	heap->use_zend_alloc = 1;
	heap->real_size = 0;
	heap->overflow = 0;
	heap->real_peak = 0;
	heap->limit = ZEND_MM_LONG_CONST(1)<<(ZEND_MM_NUM_BUCKETS-2);
	heap->size = 0;
	heap->peak = 0;
	heap->internal = internal;
	heap->reserve = NULL;
	heap->reserve_size = reserve_size; // 设为 ZEND_MM_RESERVE_SIZE 宏所指定大小

	if (reserve_size > 0) {
		heap->reserve = _zend_mm_alloc_int(heap, reserve_size ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC);
	}
	if (internal) {
		int i;
		zend_mm_free_block *p, *q, *orig;
		zend_mm_heap *mm_heap = _zend_mm_alloc_int(heap, sizeof(zend_mm_heap)  ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC);

		*mm_heap = *heap;

		p = ZEND_MM_SMALL_FREE_BUCKET(mm_heap, 0);
		orig = ZEND_MM_SMALL_FREE_BUCKET(heap, 0);
		for (i = 0; i < ZEND_MM_NUM_BUCKETS; i++) {
			q = p;
			while (q->prev_free_block != orig) {
				q = q->prev_free_block;
			}
			q->prev_free_block = p;
			q = p;
			while (q->next_free_block != orig) {
				q = q->next_free_block;
			}
			q->next_free_block = p;
			p = (zend_mm_free_block*)((char*)p + sizeof(zend_mm_free_block*) * 2);
			orig = (zend_mm_free_block*)((char*)orig + sizeof(zend_mm_free_block*) * 2);
			if (mm_heap->large_free_buckets[i]) {
				mm_heap->large_free_buckets[i]->parent = &mm_heap->large_free_buckets[i];
			}
		}
		mm_heap->rest_buckets[0] = mm_heap->rest_buckets[1] = ZEND_MM_REST_BUCKET(mm_heap);
		mm_heap->rest_count = 0;

		free(heap);
		heap = mm_heap;
	}
	return heap;
}



zend_mm_heap *zend_mm_startup(void)
{
	int i;
	size_t seg_size;
	char *mem_type = getenv("ZEND_MM_MEM_TYPE");

	char *tmp;
	const zend_mm_mem_handlers *handlers;
	zend_mm_heap *heap;

	if (mem_type == NULL) {
		i = 0;
	} else {
		for (i = 0; mem_handlers[i].name; i++) {
			if (strcmp(mem_handlers[i].name, mem_type) == 0) {
				break;
			}
		}
		if (!mem_handlers[i].name) {
			fprintf(stderr, "Wrong or unsupported zend_mm storage type '%s'\n", mem_type);
			fprintf(stderr, "  supported types:\n");
			for (i = 0; mem_handlers[i].name; i++) {
				fprintf(stderr, "    '%s'\n", mem_handlers[i].name);
			}
			exit(255);
		}
	}

	/*
	 * 跟据环境变量 ZEND_MM_MEM_TYPE 查找适合的 mem_handlers。
	 * 如果未设置环境变量，Linux 使用命名 malloc 的 mem_handlers。
	 */
	handlers = &mem_handlers[i];
	//printf("using hanlders:%s\n", handlers->name);
	tmp = getenv("ZEND_MM_SEG_SIZE");
	if (tmp) {
		seg_size = zend_atoi(tmp, 0);
		if (zend_mm_low_bit(seg_size) != zend_mm_high_bit(seg_size)) {
			fprintf(stderr, "ZEND_MM_SEG_SIZE must be a power of two\n");
			exit(255);
		} else if (seg_size < ZEND_MM_ALIGNED_SEGMENT_SIZE + ZEND_MM_ALIGNED_HEADER_SIZE) {
			fprintf(stderr, "ZEND_MM_SEG_SIZE is too small\n");
			exit(255);
		}
	} else {
		seg_size = ZEND_MM_SEG_SIZE;
	}

	heap = zend_mm_startup_ex(handlers, seg_size, ZEND_MM_RESERVE_SIZE, 0, NULL);
	if (heap) {
		tmp = getenv("ZEND_MM_COMPACT");
		if (tmp) {
			heap->compact_size = zend_atoi(tmp, 0);
		} else {
			heap->compact_size = 2 * 1024 * 1024;
		}
	}
	return heap;
}





/**********************/
/* Allocation Manager */
/**********************/

typedef struct _zend_alloc_globals {
	zend_mm_heap *mm_heap;
} zend_alloc_globals;

#define AG(v) (alloc_globals.v)
static zend_alloc_globals alloc_globals;






static void alloc_globals_ctor(zend_alloc_globals *alloc_globals TSRMLS_DC)
{
	char *tmp = getenv("USE_ZEND_ALLOC");

	if (tmp && !zend_atoi(tmp, 0)) {
		alloc_globals->mm_heap = malloc(sizeof(struct _zend_mm_heap));
		memset(alloc_globals->mm_heap, 0, sizeof(struct _zend_mm_heap));
		alloc_globals->mm_heap->use_zend_alloc = 0;
		alloc_globals->mm_heap->_malloc = malloc;
		alloc_globals->mm_heap->_free = free;
		alloc_globals->mm_heap->_realloc = realloc;
	} else {
		alloc_globals->mm_heap = zend_mm_startup();
	}
}



void start_memory_manager(TSRMLS_D)
{
	alloc_globals_ctor(&alloc_globals);
}



int is_zend_mm(TSRMLS_D)
{
	return AG(mm_heap)->use_zend_alloc;
}


void *_emalloc(size_t size ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	TSRMLS_FETCH();

	if (UNEXPECTED(!AG(mm_heap)->use_zend_alloc)) {
		return AG(mm_heap)->_malloc(size);
	}
	return _zend_mm_alloc_int(AG(mm_heap), size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
}


void _efree(void *ptr ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	TSRMLS_FETCH();

	if (UNEXPECTED(!AG(mm_heap)->use_zend_alloc)) {
		AG(mm_heap)->_free(ptr);
		return;
	}
	_zend_mm_free_int(AG(mm_heap), ptr ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
}


void *_erealloc(void *ptr, size_t size, int allow_failure ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	TSRMLS_FETCH();

	if (UNEXPECTED(!AG(mm_heap)->use_zend_alloc)) {
		return AG(mm_heap)->_realloc(ptr, size);
	}
	return _zend_mm_realloc_int(AG(mm_heap), ptr, size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
}

int _mem_block_check(void *ptr, int silent ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	TSRMLS_FETCH();

	if (!AG(mm_heap)->use_zend_alloc) {
		return 1;
	}
	return zend_mm_check_ptr(AG(mm_heap), ptr, silent ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
}


size_t _zend_mm_block_size(zend_mm_heap *heap, void *p ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	zend_mm_block *mm_block;

	if (!ZEND_MM_VALID_PTR(p)) {
		return 0;
	}
	mm_block = ZEND_MM_HEADER_OF(p);
	ZEND_MM_CHECK_PROTECTION(mm_block);

	return mm_block->debug.size;

}


size_t _zend_mem_block_size(void *ptr TSRMLS_DC ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	if (UNEXPECTED(!AG(mm_heap)->use_zend_alloc)) {
		return 0;
	}
	return _zend_mm_block_size(AG(mm_heap), ptr ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
}




/******************************/
/* my functions for study use */
/******************************/


zend_mm_heap * zend_get_global_heap() {
	return alloc_globals.mm_heap;
}


void zend_mm_print_heap_info() {
	zend_mm_heap * heap = zend_get_global_heap();
	printf("heap reserve size  : %ld\n", heap->reserve_size);
	printf("heap block size    : %ld\n", heap->block_size);
	printf("heap compact size  : %ld\n", heap->compact_size);
	printf("use zend alloc     : %d\n", heap->use_zend_alloc);
	printf("heap real peak     : %ld\n", heap->real_peak);
	printf("heap real size     : %ld\n", heap->real_size);
	printf("heap size          : %ld\n", heap->size);
	printf("heap peak          : %ld\n", heap->peak);
	printf("heap cached        : %d\n", heap->cached);
	printf("heap limit         : %ld\n", heap->limit);
	printf("heap internal      : %ld\n", heap->internal);
}



void zend_mm_aligned_test(size_t size) {
	printf("ZEND_MM_ALIGNMENT       :%ld\n", ZEND_MM_ALIGNMENT);
	printf("ZEND_MM_ALIGNMENT_MASK  :%ld\n", ZEND_MM_ALIGNMENT_MASK);
	printf("ZEND_MM_ALIGNMENT_SIZE  :%ld\n", ZEND_MM_ALIGNED_SIZE(size));
	printf("ZEND_MM_TRUE_SIZE       :%ld\n", ZEND_MM_TRUE_SIZE(size));
}



