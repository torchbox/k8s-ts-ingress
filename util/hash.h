/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
*/
/*
 * hash.h: a simple hashed key-value data store.  well, it used to be; now it's
 * just a thin wrapper around the radix trie implementation, Rax.
 */
#ifndef HASH_H
#define HASH_H

#define	HASH_USE_RAX	0

#include   	<stdlib.h>

#if	HASH_USE_RAX
# include	"rax.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * An opaque type representing a hash.
 */
typedef struct hash *hash_t;

/*
 * If using a hash as a set, this can be used as the value.
 */
#define	HASH_PRESENT	((void *)(uintptr_t)-1)

/*
 * Create a new hash table with the specified number of buckets.  The number of
 * items which can be stored in the hash table is not limited by its size, but
 * performance will reduce as the number of items exceeds the size.
 *
 * For best performance, the size should be a prime number, but this is not a
 * requirement.
 */
typedef void (*hash_free_fn) (void *);
hash_t  hash_new(size_t size, hash_free_fn);

/*
 * Free the memory used by this hash.  Any items it contains are not freed.
 */
void     hash_free(hash_t);

/*
 * Add an item to the hash.  The specified key should not already exist; if it
 * does, undefined behaviour occurs.
 *
 * Returns 0 on success.  On errors, returns -1 and errno is set.
 */
int      hash_set(hash_t, const char *key, void *data);
int      hash_setn(hash_t, const char *key, size_t keylen, void *data);

/*
 * Retrieve an item from the hash.  Returns the item data, or NULL if the item
 * was not found.
 */
void    *hash_get(const hash_t, const char *key);
void    *hash_getn(const hash_t, const char *key, size_t keylen);

/*
 * Remove an item from the hash.  Returns the item value on success.  On error,
 * NULL is returned and errno is set to ENOENT.
 */
void     hash_del(hash_t, const char *key);
void     hash_deln(hash_t, const char *key, size_t keylen);

/*
 * Return the first entry in the hash where find_fn(value) returns true.
 */
typedef int (*hash_find_fn) (hash_t, const char *key, void *value, void *data);
void	*hash_find(const hash_t, hash_find_fn, void *data);

/*
 * Iterate through each element of the hash; iteration context is stored in
 * iterstate, which the caller must allocate and zero prior to calling hash_iter.
 *
 * hash_iter is not re-entrant, and the hash must not be modified while iterating.
 *
 * Returns 1 for each object; 0 indicates the end was reached and no object was
 * returned.
 */
struct hash_iter_state {
#if	HASH_USE_RAX
	int init;
	char *key;
	raxIterator iter;
#else
	size_t i;
	void *p;
#endif
};

int	hash_iterate(hash_t, struct hash_iter_state *iterstate,
		     const char **key, size_t *keylen, void **value);

#if	HASH_USE_RAX
# define hash_foreach(HASH, KEY, KEYLEN, VALUE)				\
	for (struct hash_iter_state __s = {0, NULL, {}};		\
	     hash_iterate(HASH, &__s, KEY, KEYLEN, (void **)VALUE);)
#else
# define hash_foreach(HASH, KEY, KEYLEN, VALUE)				\
	for (struct hash_iter_state __s = {0, NULL};			\
	     hash_iterate(HASH, &__s, KEY, KEYLEN, (void **)VALUE);)
#endif

#ifdef __cplusplus
}
#endif

#endif  /* !HASH_H */
