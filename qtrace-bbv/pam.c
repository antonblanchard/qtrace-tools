#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "matrix.h"
#include "pam.h"

static uint64_t manhattan_distance(uint64_t *a, uint64_t *b, uint64_t length)
{
	uint64_t distance = 0;
	uint64_t p;

	for (p = 0; p < length; p++)
		distance += llabs(a[p] - b[p]);

	return distance;
}

/*
 * Find the nearest medoid, and return the offset into the medoid array.
 * Update costptr if not NULL.
 */
static uint64_t find_medoid(struct pam *pam, uint64_t *point, uint64_t *costptr)
{
	uint64_t cost;
	uint64_t m;
	uint64_t i;
	uint64_t ret = -1;

	cost = UINT64_MAX;

	for (m = 0, i = 0; m < pam->nr_medoids; m++, i++) {
		uint64_t s;

		s = manhattan_distance(point, pam->medoids[m], pam->point_length);

		if (s < cost) {
			ret = i;
			cost = s;
		}
	}

	if (costptr)
		*costptr = cost;

	return ret;
}

static uint64_t calculate_total_cost(struct pam *pam)
{
	uint64_t p;
	uint64_t sum = 0;

	for (p = 0; p < pam->nr_points; p++) {
		uint64_t nearest_medoid_cost;

		find_medoid(pam, pam->points[p], &nearest_medoid_cost);

		sum += nearest_medoid_cost;
	}

	return sum;
}

static bool is_medoid(struct pam *pam, uint64_t *point)
{
	uint64_t m;

	for (m = 0; m < pam->nr_medoids; m++) {
		if (manhattan_distance(point, pam->medoids[m], pam->point_length) == 0)
			return true;
	}

	return false;
}

bool pam_iteration(struct pam *pam)
{
	uint64_t m, p;
	bool progress = false;

	for (m = 0; m < pam->nr_medoids; m++) {
		for (p = 0; p < pam->nr_points; p++) {
			uint64_t *old_medoid = pam->medoids[m];
			uint64_t cost;

			if (is_medoid(pam, pam->points[p]))
				continue;

			/* swap the medoid and the point */
			pam->medoids[m] = pam->points[p];
			cost = calculate_total_cost(pam);

			if (cost < pam->current_cost) {
				pam->current_cost = cost;
				progress = true;
			} else {
				/* If the cost increased, undo */
				pam->medoids[m] = old_medoid;
			}

			/* Perfect matching, we are done */
			if (pam->current_cost == 0)
				return false;
		}
	}

	return progress;
}

void pam_destroy(struct pam *pam)
{
	free(pam->points);
	free(pam->medoids);
	free(pam);
}

struct pam *pam_initialise(struct matrix *matrix, uint64_t nr_medoids_requested)
{
	uint64_t p, m;
	struct pam *pam;

	if (nr_medoids_requested == 0)
		return NULL;

	pam = malloc(sizeof(*pam));
	if (!pam) {
		perror("malloc");
		return NULL;
	}
	memset(pam, 0, sizeof(*pam));

	pam->point_length = matrix->cols;
	pam->nr_points = matrix->rows;

	pam->points = malloc(sizeof(uint64_t) * matrix->rows);
	if (!pam->points) {
		perror("malloc");
		free(pam);
		return NULL;
	}

	for (p = 0; p < matrix->rows; p++)
		pam->points[p] = matrix_entry(matrix, p, 0);

	pam->medoids = malloc(sizeof(uint64_t) * nr_medoids_requested);
	if (!pam->medoids) {
		perror("malloc");
		free(pam->points);
		free(pam);
		return NULL;
	}

	/* Initialise medoids to first n unique points */
	m = 0;
	pam->nr_medoids = 0;
	for (p = 0; p < pam->nr_points; p++) {
		if (!is_medoid(pam, pam->points[p])) {
			pam->medoids[m] = pam->points[p];
			m++;
			pam->nr_medoids++;

			if (pam->nr_medoids == nr_medoids_requested)
				break;
		}
	}

	if (nr_medoids_requested > pam->nr_medoids) {
		fprintf(stderr, "Not enough unique points to create %ld medoids\n", nr_medoids_requested);
		pam_destroy(pam);
		return NULL;
	}

	pam->current_cost = calculate_total_cost(pam);

	return pam;
}

static void print_point(uint64_t *point, uint64_t length)
{
	uint64_t p;

	for (p = 0; p < length; p++)
		printf("%ld ", point[p]);

	printf("\n");
}

void print_raw_medoids(struct pam *pam)
{
	uint64_t m;

	for (m = 0; m < pam->nr_medoids; m++)
		print_point(pam->medoids[m], pam->point_length);
}

struct matrix *random_projection(struct matrix *a, uint64_t dimensions)
{
	struct matrix *b, *c;

	b = matrix_create(a->cols, dimensions);
	c = matrix_create(a->rows, dimensions);

	/* random projection matrix */
	matrix_random_ones(b);

	matrix_multiply(c, a, b);

	matrix_destroy(b);

	return c;
}

/* print mediods and weights */
/* print medoid for each point */

struct medoid_data {
	bool found;
	uint64_t offset;
	uint64_t count;
};

bool print_medoids(struct pam *pam, uint64_t period)
{
	uint64_t p, m;
	struct medoid_data *tmp;

	printf("Medoids:\n");

	tmp = malloc(pam->nr_medoids * sizeof(*tmp));
	if (!tmp) {
		perror("malloc");
		return false;
	}

	memset(tmp, 0, pam->nr_medoids * sizeof(*tmp));

	for (p = 0; p < pam->nr_points; p++) {
		uint64_t cost;

		m = find_medoid(pam, pam->points[p], &cost);

		if ((cost == 0) && (tmp[m].found == false)) {
			tmp[m].found = true;
			tmp[m].offset = p;
		}

		tmp[m].count++;
	}

	for (m = 0; m < pam->nr_medoids; m++)
		printf("%ld-%ld\t%ld\n", tmp[m].offset*period, (tmp[m].offset+1)*period - 1, tmp[m].count);

	free(tmp);

	return true;
}

void dump_pam(struct pam *pam, uint64_t period)
{
	uint64_t p, m, i;

	for (p = 0; p < pam->nr_points; p++) {
		uint64_t nearest_medoid_cost = UINT64_MAX;
		uint64_t nearest_medoid = UINT64_MAX;

		/* Find the nearest medoid */
		for (m = 0, i = 0; m < pam->nr_medoids; m++, i++) {
			uint64_t s;

			s = manhattan_distance(pam->points[p], pam->medoids[m], pam->point_length);

			if (s < nearest_medoid_cost) {
				nearest_medoid_cost = s;
				nearest_medoid = i;
			}
		}

		printf("%ld ", nearest_medoid);
	}
}

#ifdef PAM_TEST

#define ROWA 128
#define COLA 16

#define COLB 8

#define MAX_K 10

static struct matrix *create_test_matrix(void)
{
	uint64_t row, col;
	struct matrix *a;

	a = matrix_create(ROWA, COLA);

	for (row = 0; row < ROWA; row++) {
		for (col = 0; col < COLA; col++) {
			*matrix_entry(a, row, col) = 1;	
		}
	}

	*matrix_entry(a, 5, 2) = 2;
	*matrix_entry(a, 6, 2) = 2;
	*matrix_entry(a, 7, 2) = 2;

	*matrix_entry(a, 10, 4) = 2;

	*matrix_entry(a, 14, 6) = 200;
	*matrix_entry(a, 15, 6) = 200;

	*matrix_entry(a, 16, 1) = 10;
	*matrix_entry(a, 19, 1) = 10;
	*matrix_entry(a, 20, 1) = 10;
	*matrix_entry(a, 21, 1) = 10;
	*matrix_entry(a, 23, 1) = 10;
	*matrix_entry(a, 25, 1) = 10;

	return a;
}

int main(void)
{
	struct matrix *a, *b;
	unsigned long k;

	a = create_test_matrix();
	matrix_print(a);
	printf("\n");

#if 1
	b = random_projection(a, COLB);

	matrix_print(b);
	printf("\n\n");
#else
	b = a;
#endif

	for (k = 1; k <= MAX_K; k++) {
		struct pam *pam;

		printf("Testing K=%ld\n", k);

		pam = pam_initialise(b, k);
		assert(pam);

		while (pam_iteration(pam) == true) {
			printf("%ld\n", calculate_total_cost(pam));
		}

		printf("Cost: %ld\n", calculate_total_cost(pam));

		print_medoids(pam);

		pam_destroy(pam);

		printf("\n\n");

		if (pam->current_cost == 0)
			break;
	}

	return 0;
}

#endif
