#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NR_THREADS 128

void *doit(void *arg)
{
	while (1)
		;
}

int main(void)
{
	unsigned long i;

	for (i = 0; i < NR_THREADS; i++) {
		pthread_t tid;

		if (pthread_create(&tid, NULL, doit, NULL)) {
			perror("pthread_create");
			exit(1);
		}
	}

	sleep(60);
}
