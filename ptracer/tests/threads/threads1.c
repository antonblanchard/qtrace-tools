#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define DEPTH 1024

void *doit(void *arg)
{
	unsigned long depth = (unsigned long)arg;

	depth--;

	if (depth == 0) {
		while (1)
			;
	} else {
		pthread_t tid;

		if (pthread_create(&tid, NULL, doit, (void *)depth)) {
			perror("pthread_create");
			exit(1);
		}

		sleep(60);
	}
}

int main(void)
{
	doit((void *)DEPTH);

	sleep(60);
}
