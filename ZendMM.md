# ZendMM 内存管理器

ZendMM 申请每次一大快内存供PHP使用，当申请内存使用完后再次向系统申请。


## 配置：
* USE_ZEND_ALLOC	是否使用 ZendMM 进行内存管理。
* ZEND_MM_SEG_SIZE 	指定分配段大小，默认 256K。
* ZEND_MM_MEM_TYPE 	指定内存分配的方案，默认 malloc。
* ZEND_MM_COMPACT	指定压缩边界值


## 启动过程内存分配：
1. 为 `struct zend_mm_storage` 分配内存
2. 为 `struct zend_mm_heap` 分配内存
3. 通过 `_zend_mm_alloc_int()` 一次性分配 `ZEND_MM_RESERVE_SIZE + ZEND_MM_SEG_SIZE` 大小的内存。


## 第一次 `_zend_mm_alloc_int()` 调用过程：

第一次调用 `_zend_mm_alloc_int()` 是为PHP的执行分配预留空间。其过程如下：

1. 使用 `ZEND_MM_SMALL_SIZE(size)` 判断是否小块内存（显然不是）。
2. 调用 `zend_mm_search_large_block()` 在大块内存列表中查找合适的。显然找不到，因为此时 ZendMM 尚未向操作系统申请任何内存。
3. 程序转入 Storage 逻辑，向操作系统申请大块内存。
4. 将剩余内存放入空闲列表。
5. 返回


## true size:

`ZEND_MM_ALIGNMENT_SIZE(size)` 取得大于等于size最小的一个是 ZEND_MM_ALIGNMENT 倍数的数。



## 常用宏说明
对 ZendMM 中常用和比较重要的宏予以说明，假设目标机器为64位操作系统。

* ZEND_MM_NUM_BUCKETS

		#define ZEND_MM_NUM_BUCKETS 		(sizeof(size_t) << 3)
	sizeof(size_t)在32位平台为4，64位平台下为8，所以 ZEND_MM_NUM_BUCKET 为32或64字节。

* ZEND_MM_ALIGNED_SIZE(size)

		#define ZEND_MM_ALIGNMENT 8 // form php_config.h
		#define ZEND_MM_ALIGNMENT_MASK ~(ZEND_MM_ALIGNMENT-1)
		#define ZEND_MM_ALIGNED_SIZE(size)	(((size) + ZEND_MM_ALIGNMENT - 1) & ZEND_MM_ALIGNMENT_MASK)
	ZEND_MM_ALIGNMENT 定义在 php_config.h，由系统配置自动生成。宏 ZEND_MM_ALIGNED_SIZE(size) 最终的作用是获取一个大于等于 size 且为 ZEND_MM_ALIGNMENT 倍数的最小的一个数。

	> **实现细节**
	> 
	> 

* ZEND_MM_ALIGNED_HEADER_SIZE 、 ZEND_MM_ALIGNED_FREE_HEADER_SIZE 和 ZEND_MM_ALIGNED_SEGMENT_SIZE

		#define ZEND_MM_ALIGNED_HEADER_SIZE			ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_block))
		#define ZEND_MM_ALIGNED_FREE_HEADER_SIZE	ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_small_free_block))
		#define ZEND_MM_ALIGNED_SEGMENT_SIZE		ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_segment))
	分别获取结构 zend_mm_block 和 zend_mm_small_free_block 的对齐大小（aligned size）。

* ZEND_MM_MIN_ALLOC_BLOCK_SIZE

		#define ZEND_MM_MIN_ALLOC_BLOCK_SIZE		ZEND_MM_ALIGNED_SIZE(ZEND_MM_ALIGNED_HEADER_SIZE + END_MAGIC_SIZE)
	最小分配内存块的大小，它的值为 ZEND_MM_ALIGNED_HEADER_SIZE 的大小加上 sizeof(int) 的对齐大小。

* ZEND_MM_ALIGNED_MIN_HEADER_SIZE

		#define ZEND_MM_ALIGNED_MIN_HEADER_SIZE		( ZEND_MM_MIN_ALLOC_BLOCK_SIZE > ZEND_MM_ALIGNED_FREE_HEADER_SIZE
															? ZEND_MM_MIN_ALLOC_BLOCK_SIZE : ZEND_MM_ALIGNED_FREE_HEADER_SIZE )
	最小分配 header size。为 ZEND_MM_ALIGNED_FREE_HEADER_SIZE 和 ZEND_MM_MIN_ALLOC_BLOCK_SIZE 的最大值。

<a name="zend_mm_min_size"/>
* ZEND_MM_MIN_SIZE

		#define ZEND_MM_MIN_SIZE	((ZEND_MM_ALIGNED_MIN_HEADER_SIZE > (ZEND_MM_ALIGNED_HEADER_SIZE + END_MAGIC_SIZE))
											? (ZEND_MM_ALIGNED_MIN_HEADER_SIZE - (ZEND_MM_ALIGNED_HEADER_SIZE + END_MAGIC_SIZE)) : 0)

<a name="zend_mm_small_size"/>
* ZEND_MM_SMALL_SIZE(true_size) 

		#define ZEND_MM_SMALL_SIZE(true_size)	(true_size < ZEND_MM_MAX_SMALL_SIZE)
		#define ZEND_MM_MAX_SMALL_SIZE			((ZEND_MM_NUM_BUCKETS << ZEND_MM_ALIGNMENT_LOG2) + ZEND_MM_ALIGNED_MIN_HEADER_SIZE)

	判断所给 true_size 大小的内存是否属于小块内存。ZendMM 将小于 [ZEND_MM_MAX_SMALL_SIZE](#zend_mm_small_size) 大小内存的视为小内存。以ZEND_MM_NUM_BUCKETS为64， ZEND_MM_ALIGNMENT_LOG2 为3为例：ZEND_MM_MAX_SMALL_SIZE 的大小为 64 * 2^3 + ZEND_MM_ALIGNED_MIN_HEADER_SIZE 。

* ZEND_MM_TRUE_SIZE(size)

		#define ZEND_MM_TRUE_SIZE(size)		((size < ZEND_MM_MIN_SIZE) 
					? (ZEND_MM_ALIGNED_MIN_HEADER_SIZE) : (ZEND_MM_ALIGNED_SIZE(size + ZEND_MM_ALIGNED_HEADER_SIZE + END_MAGIC_SIZE)))
	如果 size 比 [ZEND_MM_MIN_SIZE](#zend_mm_min_size) 小，取 ZEND_MM_ALIGNED_MIN_HEADER_SIZE 作为其 true_size，否者取 size 加 ZEND_MM_ALIGNED_HEADER_SIZE + END_MAGIC_SIZE 值的最小8的倍数作为值。

* ZEND_MM_BUCKET_INDEX(true_size)

	根据 true_size 计算小块内存落在的 index。

* ZEND_MM_LARGE_BUCKET_INDEX(true_size)

	计算大块内存 index。

>**NOTE**
>

## 调用流程
1. `main`
2. `php_[cli]_startup`
3. `php_module_startup`
4. `zend_startup`
5. `start_memory_manager`
6. `alloc_globals_ctor`
7. `zend_mm_startup`
8. `zend_mm_startup_ex`




		typedef struct _zend_mm_segment {
			size_t	size;
			struct _zend_mm_segment *next_segment;
		} zend_mm_segment;



		typedef struct _zend_mm_mem_handlers {
			const char *name;
			zend_mm_storage* (*init)(void *params); //zend_mm_mem_dummy_init
			void (*dtor)(zend_mm_storage *storage); //zend_mm_mem_dummy_dtor
			void (*compact)(zend_mm_storage *storage); //zend_mm_mem_dummy_compact 	
			zend_mm_segment* (*_alloc)(zend_mm_storage *storage, size_t size); //zend_mm_mem_malloc_alloc
			zend_mm_segment* (*_realloc)(zend_mm_storage *storage, zend_mm_segment *ptr, size_t size);  //zend_mm_mem_malloc_realloc
			void (*_free)(zend_mm_storage *storage, zend_mm_segment *ptr); zend_mm_mem_malloc_free
		} zend_mm_mem_handlers;


		typedef struct _zend_mm_storage zend_mm_storage;
		struct _zend_mm_storage {
			const zend_mm_mem_handlers *handlers;
			void *data;
		};




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


## zend_mm_block

zend_mm_block_info
zend_mm_block

zend_mm_block, zend_mm_small_free_block 和 zend_mm_free_block 三者都以 zend_mm_block_info 为第一成员，debug 模式下均有 magic 成员。

* zend_mm_small_free_block 与 zend_mm_free_block
zend_mm_small_free_block 为双向链表，zend_mm_free_block 为双向链表和键树的混合结构。他们都有共同的成员 zend_mm_block_info。在 debug 模式下 magic 成员。
* zend_mm_block
在debug模式下有 magic 和 debug 成员。




		/* mm block type */
		typedef struct _zend_mm_block_info {
			size_t _cookie;/*for debug*/ // ZEND_MM_COOKIES
			size_t _size;
			size_t _prev;
		} zend_mm_block_info;

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


		/* only for debug */
		typedef struct _zend_mm_debug_info {
			const char *filename;
			uint lineno;
			const char *orig_filename;
			uint orig_lineno;
			size_t size;
			unsigned int start_magic;
		} zend_mm_debug_info;


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

