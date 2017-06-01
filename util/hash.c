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

	if(hs->hs_rax) {
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

	raxRemove(hs->hs_rax, (unsigned char *)key, keylen, &data);

	if (data == raxNotFound)
		return;

	if (data && hs->hs_free_fn)
		hs->hs_free_fn(data);
}
