/*
 * Copyright (C) 2022 Jordan Niethe <jniethe5@gmail.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>

#include "ccan/hash/hash.h"
#include "ccan/htable/htable_type.h"

#include "erat.h"
#include "xlate.h"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

/*
 * EARA to Qtrace Radix Record map
 */

struct eara_key {
	unsigned int page_shift;
	uint64_t address;
	uint64_t real_address;
};

struct eara_val {
	struct qtrace_radix rec;
	unsigned int host_page_shift;
	unsigned int guest_page_shift;
};

struct eara_obj {
	struct eara_key key;
	struct eara_val val;
};


static struct eara_obj *new_eara_obj(unsigned int page_shift,
				     uint64_t address,
				     uint64_t real_address,
				     struct qtrace_radix *rec,
				     unsigned int host_page_shift,
				     unsigned int guest_page_shift)
{
	struct eara_obj *obj;

	obj = calloc(1, sizeof(*obj));
	if (!obj) {
		perror("calloc");
		exit(1);
	}

	obj->key.page_shift = page_shift;
	obj->key.address = address;
	obj->key.real_address = real_address;
	obj->val.rec = *rec;
	obj->val.guest_page_shift = guest_page_shift;
	obj->val.host_page_shift = host_page_shift;

	return obj;
}

static const struct eara_key *eara_obj_key(const struct eara_obj *e)
{
	return &e->key;
}

static size_t eara_obj_hash(const struct eara_key *key)
{
	return hash64(key, 1, 0);
}

static bool eara_obj_cmp(const struct eara_obj *e,
			    const struct eara_key *key)
{
	return (e->key.address == key->address) &&
	       (e->key.real_address == key->real_address) &&
	       (e->key.page_shift == key->page_shift);
}

HTABLE_DEFINE_TYPE(struct eara_obj, eara_obj_key, eara_obj_hash,
		   eara_obj_cmp, htable_eara);


static struct htable_eara eara_cache;

bool erat_get(unsigned int page_shift, uint64_t address,
	      uint64_t real_address, struct qtrace_radix *rec,
	      unsigned int *host_page_shift,
	      unsigned int *guest_page_shift)
{
	struct eara_key key = { 0 };
	struct eara_obj *obj;

	switch (page_shift) {
	case 12:
		key.address = address_aligned_4k(address);
		key.real_address = address_aligned_4k(real_address);
		break;
	case 16:
		key.address = address_aligned_64k(address);
		key.real_address = address_aligned_64k(real_address);
		break;
	case 21:
		key.address = address_aligned_2m(address);
		key.real_address = address_aligned_2m(real_address);
		break;
	case 30:
		key.address = address_aligned_1g(address);
		key.real_address = address_aligned_1g(real_address);
		break;
	default:
		assert(0);
	}

	key.page_shift = page_shift;
	obj = htable_eara_get(&eara_cache, &key);

	if (obj) {
		*rec = obj->val.rec;
		*guest_page_shift = obj->val.guest_page_shift;
		*host_page_shift = obj->val.host_page_shift;
		return true;
	}

	return false;
}

void erat_insert(unsigned int host_page_shift, uint64_t address,
		 uint64_t real_address, struct qtrace_radix *rec,
		 uint32_t guest_page_shift)
{
	struct eara_obj *new_obj, *old_obj;
	unsigned int page_shift;

	page_shift = min(host_page_shift, guest_page_shift);
	switch (page_shift) {
	case 12:
		address = address_aligned_4k(address);
		real_address = address_aligned_4k(real_address);
		break;
	case 16:
		address = address_aligned_64k(address);
		real_address = address_aligned_64k(real_address);
		break;
	case 21:
		address = address_aligned_2m(address);
		real_address = address_aligned_2m(real_address);
		break;
	case 30:
		address = address_aligned_1g(address);
		real_address = address_aligned_1g(real_address);
		break;
	default:
		assert(0);
	}

	new_obj = new_eara_obj(page_shift, address, real_address, rec,
			       host_page_shift, guest_page_shift);

	old_obj = htable_eara_get(&eara_cache, &new_obj->key);
	if (old_obj) {
		old_obj->val.rec = new_obj->val.rec;
		old_obj->val.guest_page_shift = new_obj->val.guest_page_shift;
		free(new_obj);
	} else {
		htable_eara_add(&eara_cache, new_obj);
	}
}


void erat_init(void)
{
	assert(htable_eara_init_sized(&eara_cache, 10000000));
}
