#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NR_THREADS 128

void *doit(void *arg)
{
	unsigned int tmp;
	unsigned long thread = (unsigned long)arg;
	unsigned int val;

	while (1) {
		unsigned long i;

		for (i = 0; i < 10000000; i++)
			asm volatile("1: lwarx %0,0,%2; stwcx. %0,0,%2; bne 1b": "=&r" (tmp), "+m" (val): "r" (&val));

		printf("thread %ld\n", thread);
	}
}

int main(void)
{
	unsigned long i;

	for (i = 0; i < NR_THREADS; i++) {
		pthread_t tid;

		if (pthread_create(&tid, NULL, doit, (void *)0)) {
			perror("pthread_create");
			exit(1);
		}
	}

	sleep(60);
}
