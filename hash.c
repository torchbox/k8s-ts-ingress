/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<sys/types.h>

#include	<stdlib.h>
#include	<string.h>
#include	<stdint.h>
#include	<stdio.h>
#include	<errno.h>
#include	<assert.h>

#ifdef	TEST
# include	<assert.h>
#endif

#include	"hash.h"

struct hashbucket {
	char		*hb_key;
	void		*hb_value;
	struct hashbucket
			*hb_next;
};

struct hash {
	size_t			  hs_size;
	hash_free_fn		  hs_free_fn;
	struct hashbucket	**hs_buckets;
};

/*
 * 32-bit FNV-1a hash function by Phong Vo, Glenn Fowler and Landon Curt Noll.
 * Implementation by Landon Curt Noll.  This implementation is in the public
 * domain and not subject to copyright.  <http://isthe.com/chongo/tech/comp/fnv/>
 */

#define FNV_32_PRIME ((uint32_t)0x01000193)
#define FNV1_32_INIT ((uint32_t)0x811c9dc5)

static uint32_t
fnv32(const char *str)
{
uint32_t		 hval = FNV1_32_INIT;
unsigned const char	*s = (unsigned const char *)str;

    while (*s) {
	hval *= FNV_32_PRIME;
	hval ^= (uint32_t)*s++;
    }

    return hval;
}

hash_t
hash_new(size_t sz, hash_free_fn freefn)
{
hash_t	ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;

	ret->hs_free_fn = freefn;
	ret->hs_size = sz;

	if ((ret->hs_buckets = calloc(ret->hs_size,
				      sizeof(struct hashbucket *))) == NULL) {
		free(ret);
		return NULL;
	}

	return ret;
}

void
hash_free(hash_t hs)
{
size_t	i;

	if (!hs)
		return;

	for (i = 0; i < hs->hs_size; i++) {
	struct hashbucket	*b, *nb;
		for (b = hs->hs_buckets[i]; b; b = nb) {
			nb = b->hb_next;
			free(b->hb_key);
			if (hs->hs_free_fn)
				hs->hs_free_fn(b->hb_value);
			free(b);
		}
	}

	free(hs->hs_buckets);
	free(hs);
}

void
hash_foreach(hash_t hs, hash_foreach_fn fn, void *data)
{
size_t	i;

	assert(hs);

	for (i = 0; i < hs->hs_size; i++) {
	struct hashbucket	*b;
		for (b = hs->hs_buckets[i]; b; b = b->hb_next) {
			fn(hs, b->hb_key, b->hb_value, data);
		}
	}
}

int
hash_iterate(hash_t hs, struct hash_iter_state *state,
	     const char **key, void **value)
{
struct hashbucket	*b = state->p;

	assert(hs);

	if (state->i >= hs->hs_size)
		return 0;

	if (b) {
		if (b->hb_next) {
			state->p = b = b->hb_next;
			*key = b->hb_key;
			*value = b->hb_value;
			return 1;
		}

		state->i++;
		state->p = NULL;
	}

	for (; state->i < hs->hs_size; state->i++) {
		if (!hs->hs_buckets[state->i])
			continue;

		state->p = b = hs->hs_buckets[state->i];
		*key = b->hb_key;
		*value = b->hb_value;
		return 1;
	}

	return 0;
}

void *
hash_find(hash_t hs, hash_find_fn fn, void *data)
{
size_t	i;

	assert(hs);

	for (i = 0; i < hs->hs_size; i++) {
	struct hashbucket	*b;
		for (b = hs->hs_buckets[i]; b; b = b->hb_next) {
			if (fn(hs, b->hb_key, b->hb_value, data))
				return b->hb_value;
		}
	}

	return NULL;
}

int
hash_set(hash_t hs, const char *key, void *value)
{
struct hashbucket	*newb;
uint32_t		 bn;

	assert(hs);
	assert(key);
	bn = fnv32(key) % hs->hs_size;
	assert(bn < hs->hs_size);

	if ((newb = calloc(1, sizeof(*newb))) == NULL)
		return -1;

	if ((newb->hb_key = strdup(key)) == NULL) {
		free(newb);
		return -1;
	}

	newb->hb_value = value;
	newb->hb_next = hs->hs_buckets[bn];
	hs->hs_buckets[bn] = newb;
	return 0;
}

void *
hash_get(hash_t hs, const char *key)
{
uint32_t		 bn;
struct hashbucket	*hb = NULL;

	assert(hs);
	assert(key);

	bn = fnv32(key) % hs->hs_size;
	assert(bn < hs->hs_size);
	hb = hs->hs_buckets[bn];

	for (; hb; hb = hb->hb_next) {
		if (!strcmp(hb->hb_key, key))
			return hb->hb_value;
	}

	errno = ENOENT;
	return NULL;
}

void *
hash_del(hash_t hs, const char *key)
{
void			*ret;
uint32_t		 bn;
struct hashbucket	*hb, *prev = NULL;

	assert(hs);
	assert(key);

	bn = fnv32(key) % hs->hs_size;
	assert(bn < hs->hs_size);
	hb = hs->hs_buckets[bn];

	while (hb) {
		if (strcmp(hb->hb_key, key)) {
			prev = hb;
			hb = hb->hb_next;
			continue;
		}

		if (prev)
			prev->hb_next = hb->hb_next;
		else
			hs->hs_buckets[bn] = NULL;

		ret = hb->hb_value;

		free(hb->hb_key);
		free(hb);

		return ret;
	}

	errno = ENOENT;
	return NULL;
}

#ifdef TEST
void
foreach_print(hash_t hs, const char *key, void *value, void *data)
{
	printf("[%s]=[%s]\n", key, (const char *)value);
}

int
main(int argc, char **argv)
{
	{
	hash_t	hs;
	struct hash_iter_state iterstate;
	const char *k;
	char *v;

		hs = hash_new(1, NULL);

		hash_set(hs, "foo", "key foo");
		hash_set(hs, "bar", "bar key");
		hash_set(hs, "quux", "quux key");

		assert(strcmp(hash_get(hs, "foo"), "key foo") == 0);
		assert(strcmp(hash_get(hs, "bar"), "bar key") == 0);
		assert(strcmp(hash_get(hs, "quux"), "quux key") == 0);
		hash_foreach(hs, foreach_print, NULL);

		hash_del(hs, "bar");

		assert(strcmp(hash_get(hs, "foo"), "key foo") == 0);
		assert(hash_get(hs, "bar") == NULL);
		assert(strcmp(hash_get(hs, "quux"), "quux key") == 0);
		hash_foreach(hs, foreach_print, NULL);

		bzero(&iterstate, sizeof(iterstate));
		assert(hash_iterate(hs, &iterstate, &k, (void **)&v) == 1);
		assert(strcmp(k, "quux") == 0);
		assert(strcmp(v, "quux key") == 0);
		assert(hash_iterate(hs, &iterstate, &k, (void **)&v) == 1);
		assert(strcmp(k, "foo") == 0);
		assert(strcmp(v, "key foo") == 0);
		assert(hash_iterate(hs, &iterstate, &k, (void **)&v) == 0);
	}

	{
	hash_t	hs;
		hs = hash_new(1051, NULL);

		hash_set(hs, "foo", "key foo");
		hash_set(hs, "bar", "bar key");
		hash_set(hs, "quux", "quux key");

		assert(strcmp(hash_get(hs, "foo"), "key foo") == 0);
		assert(strcmp(hash_get(hs, "bar"), "bar key") == 0);
		assert(strcmp(hash_get(hs, "quux"), "quux key") == 0);

		hash_del(hs, "bar");
		assert(strcmp(hash_get(hs, "foo"), "key foo") == 0);
		assert(hash_get(hs, "bar") == NULL);
		assert(strcmp(hash_get(hs, "quux"), "quux key") == 0);
	}

	return 0;
}
#endif
