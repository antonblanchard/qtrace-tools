#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "matrix.h"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

uint64_t *matrix_entry(struct matrix *m, uint64_t row, uint64_t col)
{
	return &m->data[row * m->cols + col];
}

void matrix_resize(struct matrix *m, uint64_t rows, uint64_t cols)
{
	struct matrix n;
	uint64_t row;
	uint64_t col;

	/* Optimisation if we are only adding rows */
	if (cols == m->cols) {
		uint64_t old_size = m->rows*m->cols*sizeof(uint64_t);
		uint64_t new_size = rows*cols*sizeof(uint64_t);

		m->data = realloc(m->data, new_size);
		if (!m->data) {
			perror("realloc");
			exit(1);
		}

		/* zero any new memory */
		if (new_size > old_size) {
			uint64_t sz = new_size - old_size;

			memset((void *)m->data+old_size, 0, sz);
		}

		m->rows = rows;
		m->cols = cols;

		return;
	}

	n.data = malloc(rows*cols*sizeof(uint64_t));
	if (!n.data) {
		perror("malloc");
		exit(1);
	}

	memset(n.data, 0, rows*cols*sizeof(uint64_t));

	n.rows = rows;
	n.cols = cols;

	for (row = 0; row < min(m->rows, rows); row++) {
		for (col = 0; col < min(m->cols, cols); col++) {
			*matrix_entry(&n, row, col) = *matrix_entry(m, row, col);

		}
	}

	free(m->data);

	m->data = n.data;
	m->rows = rows;
	m->cols = cols;
}

struct matrix *matrix_create(uint64_t rows, uint64_t cols)
{
	struct matrix *m;

	m = malloc(sizeof(*m));
	if (!m) {
		perror("malloc");
		exit(1);
	}

	memset(m, 0, sizeof(*m));

	m->data = malloc(rows*cols*sizeof(uint64_t));
	if (!m->data) {
		perror("malloc");
		exit(1);
	}

	memset(m->data, 0, rows*cols*sizeof(uint64_t));

	m->rows = rows;
	m->cols = cols;

	return m;
}

bool matrix_compare(struct matrix *a, struct matrix *b)
{
	uint64_t row, col;

	if ((a->rows != b->rows) || (a->cols != b->cols))
		return false;

	for (row = 0; row < a->rows; row++) {
		for (col = 0; col < a->cols; col++) {
			if (*matrix_entry(a, row, col) != *matrix_entry(b, row, col))
				return false;
		}
	}

	return true;
}

bool matrix_copy(struct matrix *a, struct matrix *b)
{
	uint64_t row, col;

	if ((a->rows != b->rows) || (a->cols != b->cols))
		return false;

	for (row = 0; row < a->rows; row++) {
		for (col = 0; col < a->cols; col++)
			*matrix_entry(a, row, col) = *matrix_entry(b, row, col);
	}

	return true;
}

void matrix_destroy(struct matrix *m)
{
	free(m->data);
	free(m);
}

void matrix_print(struct matrix *m)
{
	uint64_t row, col;

	for (row = 0; row < m->rows; row++) {
		for (col = 0; col < m->cols; col++)
			printf("%ld\t", *matrix_entry(m, row, col));

		printf("\n");
	}
}

void matrix_random_ones(struct matrix *m)
{
	uint64_t row, col;
	unsigned int seedp = 0;	/* Use same seed */

	for (row = 0; row < m->rows; row++) {
		for (col = 0; col < m->cols; col++) {
			*matrix_entry(m, row, col) = 1;
			if (rand_r(&seedp) > RAND_MAX/2)
				*matrix_entry(m, row, col) = -1;
		}
	}
}

bool matrix_multiply(struct matrix *c, struct matrix *a, struct matrix *b)
{
	unsigned long row, col;

	if (a->cols != b->rows)
		return false;

	if (a->rows != c->rows)
		return false;

	if (b->cols != c->cols)
		return false;

	for (row = 0; row < a->rows; row++) {
		for (col = 0; col < b->cols; col++) {
			unsigned long x;

			*matrix_entry(c, row, col) = 0;

			for (x = 0; x < a->cols; x++) {
				*matrix_entry(c, row, col) +=
					*matrix_entry(a, row, x) *
					*matrix_entry(b, x, col);
			}
		}
	}

	return true;
}

#ifdef MATRIX_TEST

#define ROWA 128
#define COLA 32
#define COLB 8

int main(void)
{
	uint64_t row, col;
	struct matrix *a, *aa, *b, *c;

	a = matrix_create(ROWA, COLA);
	aa = matrix_create(ROWA, COLA);
	b = matrix_create(COLA, COLB);
	c = matrix_create(ROWA, COLB);

	for (row = 0; row < ROWA; row++) {
		for (col = 0; col < COLA; col++) {
			*matrix_entry(a, row, col) = (row << 16) + col;	
		}
	}

	assert(matrix_multiply(c, a, b) == true);
	assert(matrix_multiply(c, a, a) == false);

	assert(matrix_copy(aa, a) == true);

	matrix_resize(a, ROWA+1000, COLA+0);
	assert(a->rows == (ROWA+1000));
	assert(a->cols == (COLA+0));

	matrix_resize(a, ROWA+1000, COLA+1000);
	assert(a->rows == (ROWA+1000));
	assert(a->cols == (COLA+1000));

	matrix_resize(a, ROWA+2000, COLA+2000);
	assert(a->rows == (ROWA+2000));
	assert(a->cols == (COLA+2000));

	matrix_resize(a, ROWA, COLA);

	assert(matrix_compare(a, aa) == true);

	assert(matrix_copy(a, c) == false);

	matrix_destroy(a);
	matrix_destroy(aa);
	matrix_destroy(b);
	matrix_destroy(c);

	return 0;
}
#endif
