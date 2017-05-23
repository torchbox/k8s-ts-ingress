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
 * remap_db: store the remap database used by the remapping plugin.
 */

#include	<stdlib.h>
#include	<errno.h>
#include	<string.h>

#include	<regex.h>

#include	<ts/ts.h>

#include	"remap.h"

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
 * remap_path: an individual path inside a remap_host
 */

remap_path_t *
remap_path_new(const char *path)
{
remap_path_t	*ret;
char		*pregex;
int		 rerr;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;

	if (!path)
		return ret;

	if (*path != '/') {
		errno = EINVAL;
		return NULL;
	}

	/*
	* Path is required to begin with '/'.  However, when TS provides us the
	* request path later to match against, the leading '/' is stripped.  Strip
	* it here as well to make matching the request easier, then prepend a ^
	* to anchor the path.
	*/

	if ((pregex = strdup(path)) == NULL) {
		remap_path_free(ret);
		return NULL;
	}
	
	pregex[0] = '^';
	rerr = regcomp(&ret->rp_regex, pregex, REG_EXTENDED);
	free(pregex);

	if (rerr != 0) {
		remap_path_free(ret);
		errno = EINVAL;
		return NULL;
	}

	return ret;
}

void
remap_path_free(remap_path_t *rp)
{
size_t			 i;
struct remap_auth_addr	*rip, *nrip;

	for (i = 0; i < rp->rp_naddrs; i++)
		free(rp->rp_addrs[i]);

	free(rp->rp_addrs);
	free(rp->rp_app_root);
	free(rp->rp_rewrite_target);
	free(rp->rp_auth_realm);
	hash_free(rp->rp_users);
	regfree(&rp->rp_regex);

	for (rip = rp->rp_auth_addr_list; rip; rip = nrip) {
		nrip = rip->ra_next;
		free(rip);
	}

	free(rp);
}

/*
 * The remap_db itself.
 */

remap_db_t *
remap_db_new(void)
{
remap_db_t	*ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;

	if ((ret->rd_hosts = hash_new(4093, (hash_free_fn) remap_host_free)) == NULL) {
		free(ret);
		return NULL;
	}

	return ret;
}

void
remap_db_free(remap_db_t *db)
{
	hash_free(db->rd_hosts);
	free(db);
}

remap_host_t *
remap_db_get_host(const remap_db_t *db, const char *hostname)
{
	return hash_get(db->rd_hosts, hostname);
}

remap_host_t *
remap_db_get_or_create_host(remap_db_t *db, const char *hostname)
{
remap_host_t	*ret;

	if ((ret = remap_db_get_host(db, hostname)) != NULL)
		return ret;

	ret = remap_host_new();
	hash_set(db->rd_hosts, hostname, ret);
	return ret;
}
