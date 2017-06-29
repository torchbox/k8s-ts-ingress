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
 * remap_path: represents one 'path' attribute on an Ingress.  remap_paths are
 * always associated with a parent remap_host.
 */

#include	<sys/types.h>
#include	<sys/socket.h>

#include	<netinet/in.h>
#include	<arpa/inet.h>

#include	<string.h>
#include	<errno.h>

#include	<ts/ts.h>

#include	"remap.h"
#include	"base64.h"

static void remap_path_add_users(remap_path_t *, secret_t *);

static int
truefalse(const char *str)
{
	if (strcmp(str, "true") == 0)
		return 1;
	return 0;
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

	if (*path != '/') {
		errno = EINVAL;
		return NULL;
	}

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;

	ret->rp_preserve_host = 1;
	ret->rp_server_push = 1;
	ret->rp_cors_origins = hash_new(127, NULL);
	hash_set(ret->rp_cors_origins, "*", HASH_PRESENT);

	/* Cache by default */
	ret->rp_cache = 1;
	ret->rp_ignore_cookies = hash_new(127, NULL);

	/* Enable compresstion by default */
	ret->rp_compress = 1;
	ret->rp_compress_types = hash_new(127, NULL);

	/*
	 * This list of types is from the nginx Ingress controller.  Note that
	 * text/html is deliberately excluded to avoid the TLS BREACH attack.
	 */
	hash_set(ret->rp_compress_types, "application/atom+xml", HASH_PRESENT);
	hash_set(ret->rp_compress_types, "application/javascript",
		 HASH_PRESENT);
	hash_set(ret->rp_compress_types, "aplication/x-javascript",
		 HASH_PRESENT);
	hash_set(ret->rp_compress_types, "application/json", HASH_PRESENT);
	hash_set(ret->rp_compress_types, "application/rss+xml", HASH_PRESENT);
	hash_set(ret->rp_compress_types, "application/vnd.ms-fontobject",
		 HASH_PRESENT);
	hash_set(ret->rp_compress_types, "application/x-font-ttf",
		 HASH_PRESENT);
	hash_set(ret->rp_compress_types, "application/x-web-app-manifest+json",
		 HASH_PRESENT);
	hash_set(ret->rp_compress_types, "application/xml", HASH_PRESENT);
	hash_set(ret->rp_compress_types, "font/opentype", HASH_PRESENT);
	hash_set(ret->rp_compress_types, "image/svg+xml", HASH_PRESENT);
	hash_set(ret->rp_compress_types, "image/x-icon", HASH_PRESENT);
	hash_set(ret->rp_compress_types, "text/css", HASH_PRESENT);
	hash_set(ret->rp_compress_types, "text/plain", HASH_PRESENT);
	hash_set(ret->rp_compress_types, "text/x-component", HASH_PRESENT);

	if (!path)
		return ret;

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
	free(rp->rp_cors_headers);
	free(rp->rp_cors_methods);
	hash_free(rp->rp_users);
	hash_free(rp->rp_whitelist_params);
	hash_free(rp->rp_ignore_params);
	hash_free(rp->rp_cors_origins);
	hash_free(rp->rp_compress_types);
	hash_free(rp->rp_ignore_cookies);
	hash_free(rp->rp_whitelist_cookies);
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
			       sizeof(remap_target_t) *
				(rp->rp_naddrs + 1));
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

	for (saddr = strtok_r(mstr, ",", &save); saddr != NULL;
	     saddr = strtok_r(NULL, ",", &save)) {
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

/*
 * Configure a remap_path from the given Ingress annotations.
 */
void
remap_path_annotate(namespace_t *ns, remap_path_t *rp, hash_t annotations)
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
	 * This is probably not true any more (many more annotations have been
	 * added), and this code should be refactored.
	 */

	hash_foreach(annotations, &key_, &keylen, &value) {
	char	*key = strndup(key_, keylen);

		TSDebug("kubernetes", "[%s] = [%s]", key, value);

		/* cache-enable: turn caching on or off */
		if (strcmp(key, IN_CACHE_ENABLE) == 0)
			rp->rp_cache = truefalse(value);

		/* cache-generation: set the TS cache generation id */
		else if (strcmp(key, IN_CACHE_GENERATION) == 0)
			rp->rp_cache_gen = atoi(value);

		/* cache-ignore-params: query parameters to ignore for cache */
		else if (strcmp(key, IN_CACHE_IGNORE_PARAMS) == 0) {
		char	*v = strdup(value);
		char	*r = NULL, *sr;

			hash_free(rp->rp_ignore_params);
			rp->rp_ignore_params = hash_new(127, NULL);

			for (r = strtok_r(v, " \t", &sr); r;
			     r = strtok_r(NULL, " \t", &sr))
				hash_set(rp->rp_ignore_params, r, HASH_PRESENT);

			free(v);
		}

		/* cache-whitelist-params: query parameters whitelist for cache */
		else if (strcmp(key, IN_CACHE_WHITELIST_PARAMS) == 0) {
		char	*v = strdup(value);
		char	*r, *sr = NULL;

			hash_free(rp->rp_whitelist_params);
			rp->rp_whitelist_params = hash_new(127, NULL);

			for (r = strtok_r(v, " \t", &sr); r;
			     r = strtok_r(NULL, " \t", &sr))
				hash_set(rp->rp_whitelist_params, r, HASH_PRESENT);

			free(v);
		}

		/* cache-ignore-cookies: cookie names to remove from the request */
		else if (strcmp(key, IN_CACHE_IGNORE_COOKIES) == 0) {
		char	*v = strdup(value);
		char	*r, *sr = NULL;

			hash_free(rp->rp_ignore_cookies);
			rp->rp_ignore_cookies = hash_new(127, NULL);

			for (r = strtok_r(v, " \t", &sr); r;
			     r = strtok_r(NULL, " \t", &sr))
				hash_set(rp->rp_ignore_cookies, r, HASH_PRESENT);

			free(v);
		}

		/* cache-whitelist-cookies: cookie names to whitelist in request */
		else if (strcmp(key, IN_CACHE_WHITELIST_COOKIES) == 0) {
		char	*v = strdup(value);
		char	*r, *sr = NULL;

			hash_free(rp->rp_whitelist_cookies);
			rp->rp_whitelist_cookies = hash_new(127, NULL);

			for (r = strtok_r(v, " \t", &sr); r;
			     r = strtok_r(NULL, " \t", &sr))
				hash_set(rp->rp_whitelist_cookies, r, HASH_PRESENT);

			free(v);
		}

		/* compress-types: set types to compress */
		else if (strcmp(key, IN_COMPRESS_TYPES) == 0) {
		char	*v = strdup(value);
		char	*r, *sr = NULL;

			hash_free(rp->rp_compress_types);
			rp->rp_compress_types = hash_new(127, NULL);

			for (r = strtok_r(v, " \t", &sr); r;
			     r = strtok_r(NULL, " \t", &sr))
				hash_set(rp->rp_compress_types, r, HASH_PRESENT);

			free(v);
		}

		else if (strcmp(key, IN_COMPRESS_ENABLE) == 0)
			rp->rp_compress = truefalse(value);

		/* follow-redirects: if set, TS will resolve 3xx responses itself */
		else if (strcmp(key, IN_FOLLOW_REDIRECTS) == 0)
			rp->rp_follow_redirects = truefalse(value);

		/* server-push: enable/disable http/2 server push processing */
		else if (strcmp(key, IN_SERVER_PUSH) == 0)
			rp->rp_server_push = truefalse(value);

		/* secure-backends: use TLS for backend connections */
		else if (strcmp(key, IN_SECURE_BACKENDS) == 0)
			rp->rp_secure_backends = truefalse(value);

		/* debug-log: log request/response */
		else if (strcmp(key, IN_DEBUG_LOG) == 0)
			rp->rp_debug_log = truefalse(value);

		/* ssl-redirect: if false, disable http->https redirect */
		else if (strcmp(key, IN_SSL_REDIRECT) == 0) {
			rp->rp_no_ssl_redirect = truefalse(value) ? 0 : 1;
			TSDebug("kubernetes", "rp_no_ssl_redirect=%d",
				rp->rp_no_ssl_redirect);
		}

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

		/* read-respone-timeout: first byte timeout */
		else if (strcmp(key, IN_READ_RESPONSE_TIMEOUT) == 0)
			rp->rp_read_timeout = atoi(value);

		/*
		 * CORS; either enable-cors can be specified, or a more
		 * specific configuration. 
		*/
		else if (strcmp(key, IN_ENABLE_CORS) == 0)
			rp->rp_enable_cors = truefalse(value);

		else if (strcmp(key, IN_CORS_ORIGINS) == 0) {
		char	*p, *q, *r;

			hash_free(rp->rp_cors_origins);
			rp->rp_cors_origins = hash_new(1, NULL);

			q = strdup(value);
			for (p = strtok_r(q, " \t\r\n", &r);
			     p; p = strtok_r(NULL, " \t\r\n", &r))
				hash_set(rp->rp_cors_origins, p, HASH_PRESENT);
			free(q);
			rp->rp_enable_cors = 1;
		}

		else if (strcmp(key, IN_CORS_MAX_AGE) == 0)
			rp->rp_cors_max_age = atoi(value);
		else if (strcmp(key, IN_CORS_HEADERS) == 0)
			rp->rp_cors_headers = strdup(value);
		else if (strcmp(key, IN_CORS_METHODS) == 0)
			rp->rp_cors_methods = strdup(value);
		else if (strcmp(key, IN_CORS_CREDENTIALS) == 0)
			rp->rp_cors_creds = truefalse(value);

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

		else if (strcmp(key, IN_WHITELIST_SOURCE_RANGE) == 0)
			rp->rp_auth_addr_list = remap_path_get_addresses(value);

		free(key);
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

