/*
 * zend.h
 *
 *  Created on: Sep 15, 2012
 *      Author: hujin
 */

#ifndef ZEND_H_
#define ZEND_H_

#define ZEND_FILE_LINE_D				const char *__zend_filename, const uint __zend_lineno
#define ZEND_FILE_LINE_DC				, ZEND_FILE_LINE_D
#define ZEND_FILE_LINE_ORIG_D			const char *__zend_orig_filename, const uint __zend_orig_lineno
#define ZEND_FILE_LINE_ORIG_DC			, ZEND_FILE_LINE_ORIG_D
#define ZEND_FILE_LINE_RELAY_C			__zend_filename, __zend_lineno
#define ZEND_FILE_LINE_RELAY_CC			, ZEND_FILE_LINE_RELAY_C
#define ZEND_FILE_LINE_C				__FILE__, __LINE__
#define ZEND_FILE_LINE_CC				, ZEND_FILE_LINE_C
#define ZEND_FILE_LINE_EMPTY_C			NULL, 0
#define ZEND_FILE_LINE_EMPTY_CC			, ZEND_FILE_LINE_EMPTY_C
#define ZEND_FILE_LINE_ORIG_RELAY_C		__zend_orig_filename, __zend_orig_lineno
#define ZEND_FILE_LINE_ORIG_RELAY_CC	, ZEND_FILE_LINE_ORIG_RELAY_C


#define EXPECTED(condition)   (condition)
#define UNEXPECTED(condition) (condition)


#define zend_try												\
	{															\
		JMP_BUF *__orig_bailout = EG(bailout);					\
		JMP_BUF __bailout;										\
																\
		EG(bailout) = &__bailout;								\
		if (SETJMP(__bailout)==0) {
#define zend_catch												\
		} else {												\
			EG(bailout) = __orig_bailout;
#define zend_end_try()											\
		}														\
		EG(bailout) = __orig_bailout;							\
	}
#define zend_first_try		EG(bailout)=NULL;	zend_try


/* Messages for applications of Zend */
#define ZMSG_FAILED_INCLUDE_FOPEN		1L
#define ZMSG_FAILED_REQUIRE_FOPEN		2L
#define ZMSG_FAILED_HIGHLIGHT_FOPEN		3L
#define ZMSG_MEMORY_LEAK_DETECTED		4L
#define ZMSG_MEMORY_LEAK_REPEATED		5L
#define ZMSG_LOG_SCRIPT_NAME			6L
#define ZMSG_MEMORY_LEAKS_GRAND_TOTAL	7L


/*from zend_types.h*/

typedef long zend_intptr_t;
typedef unsigned long zend_uintptr_t;


/* from TSRM.h */

#define TSRMLS_FETCH()
#define TSRMLS_FETCH_FROM_CTX(ctx)
#define TSRMLS_SET_CTX(ctx)
#define TSRMLS_D	void
#define TSRMLS_DC
#define TSRMLS_C
#define TSRMLS_CC


#endif /* ZEND_H_ */
