#ifndef __MATRIX_H__
#define __MATRIX_H__

#include <stdint.h>
#include <stdbool.h>

struct matrix {
	uint64_t rows;
	uint64_t cols;
	uint64_t *data;
};

uint64_t *matrix_entry(struct matrix *m, uint64_t row, uint64_t col);
void matrix_resize(struct matrix *m, uint64_t rows, uint64_t cols);
struct matrix *matrix_create(uint64_t rows, uint64_t cols);
bool matrix_compare(struct matrix *a, struct matrix *b);
bool matrix_copy(struct matrix *a, struct matrix *b);
void matrix_destroy(struct matrix *m);
void matrix_print(struct matrix *m);
void matrix_random_ones(struct matrix *m);
bool matrix_multiply(struct matrix *c, struct matrix *a, struct matrix *b);

#endif
