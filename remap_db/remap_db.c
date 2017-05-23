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

#include	<sys/types.h>
#include	<sys/socket.h>

#include	<netinet/in.h>
#include	<arpa/inet.h>

#include	<stdlib.h>
#include	<errno.h>
#include	<string.h>

#include	<regex.h>

#include	<ts/ts.h>

#include	"remap.h"
#include	"base64.h"

static void remap_path_add_users(remap_path_t *, secret_t *);

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
 * Configure a remap_host from the given Ingress annotations.
 */
void
remap_host_annotate(remap_host_t *rh, hash_t annotations)
{
const char	*key, *value;

	/*
	 * There are two ways we could do this: use hash_get for each annotation
	 * we support, or iterate over all annotations and compare them.  We use
	 * the second method, because assuming we understand all (or most of)
	 * the annotations on the Ingress, which should be the same, it saves
	 * running a complete hash lookup for every string.
	 *
	 * It also makes the code a bit easier to read.
	 */

	hash_foreach(annotations, &key, &value) {
		if (strcmp(key, IN_HSTS_MAX_AGE) == 0)
			rh->rh_hsts_max_age = atoi(value);
		else if (strcmp(key, IN_HSTS_INCLUDE_SUBDOMAINS) == 0 &&
			 strcmp(value, "true") == 0)
			rh->rh_hsts_subdomains = 1;
	}
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
		free(rp->rp_addrs[i].rt_host);
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

void
remap_path_add_address(remap_path_t *rp, const char *host, int port)
{
	rp->rp_addrs = realloc(rp->rp_addrs,
			       sizeof(remap_target_t) * (rp->rp_naddrs + 1));
	rp->rp_addrs[rp->rp_naddrs].rt_host = strdup(host);
	rp->rp_addrs[rp->rp_naddrs].rt_port = port;
	++rp->rp_naddrs;
}

/*
 * Convert a string containing whitespace-separated IP addresses into a
 * remap_auth_addr list.
 */
struct remap_auth_addr *
remap_path_get_addresses(const char *str)
{
struct remap_auth_addr	*list = NULL;
char			*mstr, *save, *saddr;

	if ((mstr = strdup(str)) == NULL)
		return NULL;

	for (saddr = strtok_r(mstr, " \t\n\r", &save); saddr != NULL;
	     saddr = strtok_r(NULL, " \t\n\r", &save)) {
	struct remap_auth_addr	*entry;
	char			*p = NULL;
	
		entry = calloc(1, sizeof(*entry));
		if ((p = strchr(saddr, '/')) != NULL) {
			*p++ = '\0';
			entry->ra_prefix_length = atoi(p);
		}

		if (inet_pton(AF_INET6, saddr,
			      entry->ra_addr_v6.s6_addr) == 1) {
			entry->ra_family = AF_INET6;
			if (p == NULL)
				entry->ra_prefix_length = 128;
		} else if (inet_pton(AF_INET, saddr, &entry->ra_addr_v4) == 1) {
			entry->ra_family = AF_INET;
			if (p == NULL)
				entry->ra_prefix_length = 32;
		} else {
			free(entry);
			continue;
		}

		entry->ra_next = list;
		list = entry;
	}
	     
	free(mstr);
	return list;
}

static int
truefalse(const char *str)
{
	if (strcmp(str, "true") == 0)
		return 1;
	return 0;
}

/*
 * Configure a remap_path from the given Ingress annotations.
 */
void
remap_path_annotate(namespace_t *ns, remap_path_t *rp, hash_t annotations)
{
const char	*key, *value;

	/*
	 * There are two ways we could do this: use hash_get for each annotation
	 * we support, or iterate over all annotations and compare them.  We use
	 * the second method, because assuming we understand all (or most of)
	 * the annotations on the Ingress, which should be the same, it saves
	 * running a complete hash lookup for every string.
	 *
	 * It also makes the code a bit easier to read.
	 */

	hash_foreach(annotations, &key, &value) {
		/* cache-enable: turn caching on or off */
		if (strcmp(key, IN_CACHE_ENABLE) == 0)
			rp->rp_cache = truefalse(value);

		/* cache-generation: set the TS cache generation id */
		else if (strcmp(key, IN_CACHE_GENERATION) == 0)
			rp->rp_cache_gen = atoi(value);

		/* follow-redirects: if set, TS will resolve 3xx responses itself */
		else if (strcmp(key, IN_FOLLOW_REDIRECTS) == 0)
			rp->rp_follow_redirects = truefalse(value);

		/* secure-backends: use TLS for backend connections */
		else if (strcmp(key, IN_SECURE_BACKENDS) == 0)
			rp->rp_secure_backends = truefalse(value);

		/* ssl-redirect: if false, disable http->https redirect */
		else if (strcmp(key, IN_SSL_REDIRECT) == 0)
			rp->rp_no_ssl_redirect = !truefalse(value);

		/*
		 * force-ssl-redirect: redirect http->https even if the
		 * Ingress doesn't have TLS configured.
		 */
		else if (strcmp(key, IN_FORCE_SSL_REDIRECT) == 0)
			rp->rp_force_ssl_redirect = truefalse(value);

		/* preserve-host: use origin request host header */
		else if (strcmp(key, IN_PRESERVE_HOST) == 0)
			rp->rp_preserve_host = truefalse(value);

		/* app-root: enforce url prefix */
		else if (strcmp(key, IN_APP_ROOT) == 0)
			rp->rp_app_root = strdup(value);

		/* rewrite-target: rewrite URL path */
		else if (strcmp(key, IN_REWRITE_TARGET) == 0 && *value == '/')
			rp->rp_rewrite_target = strdup(value + 1);

		/*
		 * Authentication.
		 */

		/* authentication type (basic/digest) */
		else if (strcmp(key, IN_AUTH_TYPE) == 0) {
			if (strcmp(value, IN_AUTH_TYPE_BASIC) == 0)
				rp->rp_auth_type = REMAP_AUTH_BASIC;
			else if (strcmp(value, IN_AUTH_TYPE_DIGEST) == 0)
				rp->rp_auth_type = REMAP_AUTH_DIGEST;
		}

		/* authentication realm */
		else if (strcmp(key, IN_AUTH_REALM) == 0)
			rp->rp_auth_realm = strdup(value);

		/* authentication user database */
		else if (strcmp(key, IN_AUTH_SECRET) == 0) {
		secret_t	*se;
			if ((se = namespace_get_secret(ns, value)) != NULL) {
				rp->rp_users = hash_new(127, free);
				remap_path_add_users(rp, se);
			}
		}

		/* authentication satisfy requirement (any, all) */
		else if (strcmp(key, IN_AUTH_SATISFY) == 0) {
			if (strcmp(value, IN_AUTH_SATISFY_ANY) == 0)
				rp->rp_auth_satisfy = REMAP_SATISFY_ANY;
			else
				rp->rp_auth_satisfy = REMAP_SATISFY_ALL;
		}

		else if (strcmp(key, IN_AUTH_ADDRESS_LIST) == 0)
			rp->rp_auth_addr_list = remap_path_get_addresses(value);

	}
}

/*
 * Add users from a secret to a remap_path.
 */
static void
remap_path_add_users(remap_path_t *rp, secret_t *secret)
{
char	*authdata = NULL;
char	*buf, *entry, *s;
size_t	 dlen;
ssize_t	 n;

	if ((authdata = hash_get(secret->se_data, "auth")) == NULL)
		return;

	dlen = strlen(authdata);
	s = buf = malloc(base64_decode_len(dlen) + 1);
	n = base64_decode(authdata, dlen, (unsigned char *)buf);

	if (n == -1) {
		free(buf);
		return;
	}

	buf[n] = '\0';

	while ((entry = strsep(&s, "\r\n")) != NULL) {
	char	*password, *rest;
		if ((password = strchr(entry, ':')) == NULL)
			continue;
		*password++ = '\0';

		if ((rest = strchr(password, ':')) != NULL)
			*rest = '\0';

		while (strchr("\r\n", password[strlen(password) - 1]))
			password[strlen(password) - 1] = '\0';

		TSDebug("kubernetes", "added user %s/%s", entry, password);
		hash_set(rp->rp_users, entry, strdup(password));
	}

	free(buf);
}

/*
 * Pick a random backend for this path.
 */
const remap_target_t *
remap_path_pick_target(const remap_path_t *rp)
{
int	n = rand() / (RAND_MAX / rp->rp_naddrs + 1);
	return &rp->rp_addrs[n];
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
