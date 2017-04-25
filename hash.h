/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef HASH_H
#define HASH_H

#include    <stdlib.h>

/*
 * An opaque type representing a hash.
 */
typedef struct hash *hash_t;

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

/*
 * Retrieve an item from the hash.  Returns the item data, or NULL if the item
 * was not found.
 */
void    *hash_get(hash_t, const char *key);

/*
 * Remove an item from the hash.  Returns the item value on success.  On error,
 * NULL is returned and errno is set to ENOENT.
 */
void    *hash_del(hash_t, const char *key);

/*
 * Call the provided function with the key, value and provided data argument
 * for every entry in the map.
 */
typedef void (*hash_foreach_fn) (hash_t, const char *key, void *value, void *data);
void	 hash_foreach(hash_t, hash_foreach_fn, void *data);

/*
 * Return the first entry in the hash where find_fn(value) returns true.
 */
typedef int (*hash_find_fn) (hash_t, const char *key, void *value, void *data);
void	*hash_find(hash_t, hash_find_fn, void *data);

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
	size_t i;
	void *p;
};

int	hash_iterate(hash_t, struct hash_iter_state *iterstate,
		     const char **key, void **value);

#endif  /* !HASH_H */
