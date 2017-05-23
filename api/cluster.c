/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	"api.h"

cluster_t *
cluster_make(void)
{
cluster_t	*ret;
	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;
	if ((ret->cs_namespaces = hash_new(127, (hash_free_fn) namespace_free)) == NULL) {
		free(ret);
		return NULL;
	}
	return ret;
}

namespace_t *
cluster_get_namespace(cluster_t *cs, const char *name)
{
namespace_t	*ret;

	if ((ret = hash_get(cs->cs_namespaces, name)) == NULL) {
		if ((ret = namespace_make(name)) == NULL)
			return NULL;
		hash_set(cs->cs_namespaces, name, ret);
	}

	return ret;
}

void
cluster_free(cluster_t *cs)
{
	hash_free(cs->cs_namespaces);
	free(cs);
}
