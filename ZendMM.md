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

