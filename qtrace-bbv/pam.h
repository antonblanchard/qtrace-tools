#ifndef __PAM_H__
#define __PAM_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "matrix.h"

struct pam
{
	uint64_t nr_points;
	uint64_t nr_medoids;
	uint64_t **points;
	uint64_t **medoids;
	uint64_t point_length;
	uint64_t current_cost;
};

struct matrix *random_projection(struct matrix *a, uint64_t dimensions);

struct pam *pam_initialise(struct matrix *matrix, uint64_t nr_medoids_requested);
bool pam_iteration(struct pam *pam);
void pam_destroy(struct pam *pam);

void print_raw_medoids(struct pam *pam);
bool print_medoids(struct pam *pam, uint64_t period);

void dump_pam(struct pam *pam, uint64_t period);

#endif
