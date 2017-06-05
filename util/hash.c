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

#include	"hash.h"

#if HASH_USE_RAX
struct hash {
	hash_free_fn	 hs_free_fn;
	rax		*hs_rax;
};

hash_t
hash_new(size_t sz, hash_free_fn freefn)
{
hash_t	ret;

	(void)sz;
	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;

	ret->hs_free_fn = freefn;

	if ((ret->hs_rax = raxNew()) == NULL) {
		free(ret);
		return NULL;
	}

	return ret;
}

void
hash_free(hash_t hs)
{
raxIterator	iter;

	if (!hs)
		return;

	if (hs->hs_rax) {
		raxStart(&iter, hs->hs_rax);
		raxSeek(&iter, "^", NULL, 0);

		while (raxNext(&iter)) {
			if (iter.data && hs->hs_free_fn)
				hs->hs_free_fn(iter.data);
		}

		raxStop(&iter);
		raxFree(hs->hs_rax);
	}

	free(hs);
}

int
hash_iterate(hash_t hs, struct hash_iter_state *state,
	     const char **key, size_t *keylen, void **value)
{
	if (!state->init) {
		raxStart(&state->iter, hs->hs_rax);
		raxSeek(&state->iter, "^", NULL, 0);
		state->init = 1;
	}

	if (!raxNext(&state->iter))
		return 0;

	if (key) 
		*key = (const char *)state->iter.key;
	if (keylen)
		*keylen = state->iter.key_len;
	if (value)
		*value = state->iter.data;

	return 1;
}

void *
hash_find(const hash_t hs, hash_find_fn fn, void *data)
{
raxIterator	it;

	assert(hs);
	if (!hs->hs_rax)
		return NULL;

	raxStart(&it, hs->hs_rax);
	raxSeek(&it, "^", NULL, 0);

	while (raxNext(&it)) {
	char	*key = strndup((const char *)it.key, it.key_len);

		if (fn(hs, key, it.data, data)) {
			raxStop(&it);
			return it.data;
		}
	}

	raxStop(&it);
	return NULL;
}

int
hash_set(hash_t hs, const char *key, void *value)
{
	return hash_setn(hs, key, strlen(key), value);
}

int
hash_setn(hash_t hs, const char *key, size_t keylen, void *value)
{
void	*oldvalue = NULL;

	assert(hs);
	assert(hs->hs_rax);

	raxInsert(hs->hs_rax, (unsigned char *) key, keylen, value, &oldvalue);

	if (oldvalue && hs->hs_free_fn)
		hs->hs_free_fn(oldvalue);

	return 0;
}

void *
hash_get(const hash_t hs, const char *key)
{
	return hash_getn(hs, key, strlen(key));
}

void *
hash_getn(const hash_t hs, const char *key, size_t keylen)
{
void	*data;

	assert(hs);
	if (!hs->hs_rax)
		return NULL;

	data = raxFind(hs->hs_rax, (unsigned char *)key, keylen);
	if (data == raxNotFound)
		return NULL;
	return data;
}

void
hash_del(hash_t hs, const char *key)
{
	hash_deln(hs, key, strlen(key));
}

void
hash_deln(hash_t hs, const char *key, size_t keylen)
{
void	*data = NULL;

	assert(hs);
	assert(hs->hs_rax);

	if (raxRemove(hs->hs_rax, (unsigned char *)key, keylen, &data) == 1)
		if (hs->hs_free_fn)
			hs->hs_free_fn(data);
}

#else	/* HASH_USE_RAX */

struct hashbucket {
	char		*hb_key;
	size_t		 hb_keylen;
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
fnv32(const char *str, const char *end)
{
uint32_t		 hval = FNV1_32_INIT;
unsigned const char	*s = (unsigned const char *)str;

    while (s < (unsigned const char *)end) {
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

int
hash_iterate(hash_t hs, struct hash_iter_state *state,
	     const char **key, size_t *keylen, void **value)
{
struct hashbucket	*b = state->p;

	assert(hs);

	if (state->i >= hs->hs_size)
		return 0;

	if (b) {
		if (b->hb_next) {
			state->p = b = b->hb_next;
			if (key) *key = b->hb_key;
			if (keylen) *keylen = b->hb_keylen;
			if (value) *value = b->hb_value;
			return 1;
		}

		state->i++;
		state->p = NULL;
	}

	for (; state->i < hs->hs_size; state->i++) {
		if (!hs->hs_buckets[state->i])
			continue;

		state->p = b = hs->hs_buckets[state->i];
		if (key) *key = b->hb_key;
		if (keylen) *keylen = b->hb_keylen;
		if (value) *value = b->hb_value;
		return 1;
	}

	return 0;
}

void *
hash_find(const hash_t hs, hash_find_fn fn, void *data)
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
	return hash_setn(hs, key, strlen(key), value);
}

int
hash_setn(hash_t hs, const char *key, size_t keylen, void *value)
{
struct hashbucket	*newb;
uint32_t		 bn;

	assert(hs);
	assert(key);
	bn = fnv32(key, key + keylen) % hs->hs_size;
	assert(bn < hs->hs_size);

	if ((newb = calloc(1, sizeof(*newb))) == NULL)
		return -1;

	if ((newb->hb_key = strndup(key, keylen)) == NULL) {
		free(newb);
		return -1;
	}
	newb->hb_keylen = keylen;

	newb->hb_value = value;
	newb->hb_next = hs->hs_buckets[bn];
	hs->hs_buckets[bn] = newb;
	return 0;
}

void *
hash_get(const hash_t hs, const char *key)
{
	return hash_getn(hs, key, strlen(key));
}

void *
hash_getn(const hash_t hs, const char *key, size_t keylen)
{
uint32_t		 bn;
struct hashbucket	*hb = NULL;

	assert(hs);
	assert(key);

	bn = fnv32(key, key + keylen) % hs->hs_size;
	assert(bn < hs->hs_size);
	hb = hs->hs_buckets[bn];

	for (; hb; hb = hb->hb_next) {
		if (hb->hb_keylen == keylen &&
		    memcmp(hb->hb_key, key, keylen) == 0)
			return hb->hb_value;
	}

	errno = ENOENT;
	return NULL;
}

void
hash_del(hash_t hs, const char *key)
{
	hash_deln(hs, key, strlen(key));
}

void
hash_deln(hash_t hs, const char *key, size_t keylen)
{
void			*ret;
uint32_t		 bn;
struct hashbucket	*hb, *prev = NULL;

	assert(hs);
	assert(key);

	bn = fnv32(key, key + keylen) % hs->hs_size;
	assert(bn < hs->hs_size);
	hb = hs->hs_buckets[bn];

	while (hb) {
		if (hb->hb_keylen != keylen || memcmp(hb->hb_key, key, keylen)) {
			prev = hb;
			hb = hb->hb_next;
			continue;
		}

		if (prev)
			prev->hb_next = hb->hb_next;
		else
			hs->hs_buckets[bn] = hb->hb_next;

		ret = hb->hb_value;

		free(hb->hb_key);
		free(hb);
		return;
	}
}

#endif	/* !HASH_USE_RAX */
