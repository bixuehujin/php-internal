/*
 ============================================================================
 Name        : php.c
 Author      : 
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <clib.h>
#include "zend_alloc.h"


int main(void) {

	start_memory_manager();
	char * p = emalloc(56	 * 1027);
	efree(p);
	zend_mm_print_heap_info();
	zend_mm_aligned_test(2);
	return 0;
}
