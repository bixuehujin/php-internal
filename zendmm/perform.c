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
	char * a = emalloc(10);
	sprintf(a, "%s", "abc");

	char * p;
	ctimer_t timer, *ptimer;
	ptimer = ctimer_init(&timer);
	ctimer_start(ptimer);
	int i = 100000;
	while(i --) {
		p = malloc(i);
		free(p);
	}
	ctimer_stop(ptimer);
	printf("used %lu\n", ctimer_last_runtime(ptimer));

	ctimer_clean(ptimer);
	ctimer_start(ptimer);
	i = 100000;
	while(i --) {
		p = emalloc(i);
		efree(p);
	}
	ctimer_stop(ptimer);
	printf("used %lu\n", ctimer_last_runtime(ptimer));

	return 0;
}
