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
 * remap_host: represent one 'host' in an Ingress.  one or more of these is
 * associated with every Ingress, and contains one or more remap_paths.
 */

#include	<ts/ts.h>

#include	"remap.h"

static int
truefalse(const char *str)
{
	if (strcmp(str, "true") == 0)
		return 1;
	return 0;
}

/*
 * remap_host stores a single hostname for remapping.
 */

remap_host_t *
remap_host_new(void)
{
remap_host_t	*ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;

	/* Add the default path */
	remap_host_new_path(ret, NULL);

	ret->rh_http2 = 1;
	/* Consider changing this to 1.1 at some point */
	ret->rh_tls_version = REMAP_TLS_1_0;

	return ret;
}

void
remap_host_free(remap_host_t *host)
{
size_t	i;

	for (i = 0; i < host->rh_npaths; i++)
		remap_path_free(host->rh_paths[i]);
	free(host->rh_paths);

	if (host->rh_ctx)
		TSSslContextDestroy((TSSslContext) host->rh_ctx);

	free(host);
}

/*
 * Search the list of paths in a remap_host for one that matches (by regexp) the
 * provided URL path, and return it.  If pfxs is non-NULL, the length of the
 * portion of the request path that was matched by the remap_path will be stored.
 */
remap_path_t *
remap_host_find_path(const remap_host_t *rh, const char *path, size_t *pfxsz)
{
	/* No path in the request, so this can only match the default path */
	if (!path) {
		if (pfxsz)
			*pfxsz = 0;
		return rh->rh_paths[0];
	}

	/* skip 0, the default path */
	for (size_t i = 1; i < rh->rh_npaths; i++) {
	remap_path_t	*rp = rh->rh_paths[i];
	regmatch_t	 matches[1];

		if (regexec(&rp->rp_regex, path, 1, matches, 0) == 0) {
			if (pfxsz)
				*pfxsz = matches[0].rm_eo - matches[0].rm_so;
			return rp;
		}
	}

	if (pfxsz)
		*pfxsz = 0;

	return rh->rh_paths[0];
}

remap_path_t *
remap_host_new_path(remap_host_t *rh, const char *path)
{
remap_path_t	*rp;

	if ((rp = remap_path_new(path)) == NULL)
		return NULL;

	rh->rh_paths = realloc(rh->rh_paths, sizeof(remap_path_t *)
						* (rh->rh_npaths + 1));
	rh->rh_paths[rh->rh_npaths] = rp;
	++rh->rh_npaths;

	return rp;
}

remap_path_t *
remap_host_get_default_path(remap_host_t *rh)
{
	return rh->rh_paths[0];
}

/*
 * Configure a remap_host from the given Ingress annotations.
 */
void
remap_host_annotate(remap_host_t *rh, hash_t annotations)
{
const char	*key_ = NULL, *value = NULL;
size_t		 keylen;

	/*
	 * There are two ways we could do this: use hash_get for each annotation
	 * we support, or iterate over all annotations and compare them.  We use
	 * the second method, because assuming we understand all (or most of)
	 * the annotations on the Ingress, which should be the same, it saves
	 * running a complete hash lookup for every string.
	 *
	 * It also makes the code a bit easier to read.
	 */

	hash_foreach(annotations, &key_, &keylen, &value) {
	char	*key = strndup(key_, keylen);

		TSDebug("kubernetes", "remap_host_annotate: [%s]=[%s]",
			key, value);

		if (strcmp(key, IN_HSTS_MAX_AGE) == 0)
			rh->rh_hsts_max_age = atoi(value);

		/* http2-enable: enable or disable http/2 */
		else if (strcmp(key, IN_HTTP2_ENABLE) == 0)
			rh->rh_http2 = truefalse(value);

		else if (strcmp(key, IN_HSTS_INCLUDE_SUBDOMAINS) == 0 &&
			 strcmp(value, "true") == 0)
			rh->rh_hsts_subdomains = 1;

		else if (strcmp(key, IN_TLS_MINIMUM_VERSION) == 0) {
			TSDebug("kubernetes", "TLS version is %s", value);

			if (strcmp(value, IN_TLS_VERSION_1_0) == 0)
				rh->rh_tls_version = REMAP_TLS_1_0;
			else if (strcmp(value, IN_TLS_VERSION_1_1) == 0)
				rh->rh_tls_version = REMAP_TLS_1_1;
			else if (strcmp(value, IN_TLS_VERSION_1_2) == 0)
				rh->rh_tls_version = REMAP_TLS_1_2;
		}

		free(key);
	}
}

