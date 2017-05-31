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
#include	"auth.h"
#include	"base64.h"
#include	"strmatch.h"

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
const char	*key = NULL, *value = NULL;

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

	ret->rp_preserve_host = 1;
	ret->rp_cors_origins = hash_new(127, NULL);

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
	free(rp->rp_cors_headers);
	free(rp->rp_cors_methods);
	hash_free(rp->rp_users);
	hash_free(rp->rp_whitelist_params);
	hash_free(rp->rp_ignore_params);
	hash_free(rp->rp_cors_origins);
	hash_free(rp->rp_compress_types);
	hash_free(rp->rp_ignore_cookies);
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
const char	*key = NULL, *value = NULL;

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

		/* secure-backends: use TLS for backend connections */
		else if (strcmp(key, IN_SECURE_BACKENDS) == 0)
			rp->rp_secure_backends = truefalse(value);

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
		else if (strcmp(key, IN_ENABLE_CORS) == 0) {
			/*
			 * Set a standard, wide-open CORS configuration.
			 */
			rp->rp_enable_cors = 1;
			hash_set(rp->rp_cors_origins, "*", HASH_PRESENT);
			rp->rp_cors_creds = 1;
			rp->rp_cors_methods = strdup("GET, PUT, POST, "
						     "DELETE, OPTIONS");
			rp->rp_cors_headers = strdup(
				"DNT, Keep-Alive, User-Agent, "
				"X-Requested-With, If-Modified-Since, "
				"Cache-Control, Content-Type, Authorization");
			rp->rp_cors_max_age = 1728000;
		}

		else if (strcmp(key, IN_ACCESS_CONTROL_ALLOW_ORIGIN) == 0) {
		char	*p, *q, *r;
			q = strdup(value);
			for (p = strtok_r(q, " \t\r\n", &r);
			     p; p = strtok_r(NULL, " \t\r\n", &r))
				hash_set(rp->rp_cors_origins, p, HASH_PRESENT);
			free(q);
			rp->rp_enable_cors = 1;
		}

		else if (strcmp(key, IN_ACCESS_CONTROL_MAX_AGE) == 0)
			rp->rp_cors_max_age = atoi(value);
		else if (strcmp(key, IN_ACCESS_CONTROL_ALLOW_HEADERS) == 0)
			rp->rp_cors_headers = strdup(value);
		else if (strcmp(key, IN_ACCESS_CONTROL_ALLOW_METHODS) == 0)
			rp->rp_cors_methods = strdup(value);
		else if (strcmp(key, IN_ACCESS_CONTROL_ALLOW_CREDENTIALS) == 0)
			rp->rp_cors_creds = strcmp(value, "true") ? 1 : 0;

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
remap_db_new(k8s_config_t *cfg)
{
remap_db_t	*ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;

	if ((ret->rd_hosts = hash_new(4093, (hash_free_fn) remap_host_free)) == NULL) {
		free(ret);
		return NULL;
	}

	ret->rd_config = cfg;
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

int
rr_check_proto(const remap_db_t *db, const remap_request_t *req,
	       remap_result_t *ret)
{
	if (!strcmp(req->rr_proto, "http") ||
	    !strcmp(req->rr_proto, "https")) {

		ret->rz_proto = ret->rz_path->rp_secure_backends ?
			"https" : "http";
		return RR_OK;
	}

	if (!strcmp(req->rr_proto, "ws") ||
	    !strcmp(req->rr_proto, "wss")) {

		ret->rz_proto = ret->rz_path->rp_secure_backends ?
			"wss" : "ws";
		return RR_OK;
	}

	return RR_ERR_INVALID_PROTOCOL;
}

/*
 * app-root: redirect a request for "/" to the given path.
 */
int
rr_check_app_root(const remap_db_t *db, const remap_request_t *req,
		  remap_result_t *ret)
{
	if (!ret->rz_path->rp_app_root)
		return RR_OK;

	if (req->rr_path)
		return RR_OK;

	hash_set(ret->rz_headers, "Location", strdup(ret->rz_path->rp_app_root));
	ret->rz_status = 301;
	ret->rz_status_text = "Moved";
	ret->rz_body = "This document has moved.\n";
	return RR_SYNTHETIC;
}

int
rr_check_tls(const remap_db_t *db, const remap_request_t *req,
	     remap_result_t *ret)
{
const char	*newp;
size_t		 blen;
char		*hdr;

	/* If already TLS, do nothing */
	if (!strcmp(req->rr_proto, "https") || !strcmp(req->rr_proto, "wss"))
		return RR_OK;

	/*
	 * Skip redirect if no_ssl_redirect is set, or if the rh_ctx is null
	 * and force_ssl_redirect is not set.
	 */
	TSDebug("kubernetes", "rp_no_ssl_redirect=%d",
		ret->rz_path->rp_no_ssl_redirect);
	if (ret->rz_path->rp_no_ssl_redirect)
		return RR_OK;
	if (!ret->rz_host->rh_ctx && !ret->rz_path->rp_force_ssl_redirect)
		return RR_OK;

	/* We will redirect */

	/* Decide on the new protocol */
	if (!strcmp(req->rr_proto, "ws"))
		newp = "wss";
	else
		newp = "https";

	/* Build new URL, replacing the protocol */
	blen = strlen(newp) + 3 + strlen(req->rr_host) + 1 + 1;
	if (req->rr_path)
		blen += strlen(req->rr_path);
	if (req->rr_query)
		blen += strlen(req->rr_query) + 1;

	hdr = malloc(blen);
	snprintf(hdr, blen, "%s://%s/%s%s%s",
		 newp, req->rr_host,
		 req->rr_path ? req->rr_path : "",
		 req->rr_query ? "?" : "",
		 req->rr_query ? req->rr_query : "");

	hash_set(ret->rz_headers, "Location", hdr);
	ret->rz_status = 301;
	ret->rz_status_text = "Moved";
	ret->rz_body = "This document has moved.\n";
	return RR_SYNTHETIC;
}

int
rr_check_cors(const remap_db_t *db, const remap_request_t *req,
	      remap_result_t *res)
{
const char		*origin;
remap_hdrfield_t	*hdr;
char			 s[32];

	if (!res->rz_path->rp_enable_cors)
		return RR_OK;

	if ((hdr = hash_get(req->rr_hdrfields, "origin")) == NULL)
		return RR_OK;
	if (hdr->rh_nvalues < 1)
		return RR_OK;
	origin = hdr->rh_values[0];

	/*
	 * Is this a recognised CORS origin?
	 */
	if (hash_get(res->rz_path->rp_cors_origins, "*")) {
		hash_set(res->rz_headers, "Access-Control-Allow-Origin",
			 strdup("*"));
	} else if (hash_get(res->rz_path->rp_cors_origins,  origin)) {
		hash_set(res->rz_headers, "Access-Control-Allow-Origin",
			 strdup(origin));
		hash_set(res->rz_headers, "Vary", strdup("Origin"));
	} else
		return RR_OK;


	/*
	 * If this is a preflight request, set some extra headers and return
	 * an empty body.
	 */
	if (strcmp(req->rr_method, "OPTIONS"))
		return RR_OK;

	if (res->rz_path->rp_cors_methods)
		hash_set(res->rz_headers, "Access-Control-Allow-Methods",
			 strdup(res->rz_path->rp_cors_methods));

	if (res->rz_path->rp_cors_headers)
		hash_set(res->rz_headers, "Access-Control-Allow-Headers",
			 strdup(res->rz_path->rp_cors_headers));

	if (res->rz_path->rp_cors_max_age) {
		snprintf(s, sizeof(s), "%d", res->rz_path->rp_cors_max_age);
		hash_set(res->rz_headers, "Access-Control-Max-Age", strdup(s));
	}

	hash_set(res->rz_headers, "Access-Control-Allow-Credentials",
		 strdup(res->rz_path->rp_cors_creds ? "true" : "false"));

	res->rz_status = 204;
	res->rz_status_text = "No content";
	return RR_SYNTHETIC;
}

int
rr_check_auth(const remap_db_t *db, const remap_request_t *req,
	      remap_result_t *res)
{
remap_hdrfield_t	*rr_auth_field;
const char		*rr_auth = NULL;

	/* No authentication? */
	if (res->rz_path->rp_auth_type == REMAP_AUTH_NONE &&
	    !res->rz_path->rp_auth_addr_list)
		return RR_OK;

	/* Only IP auth? */
	if (res->rz_path->rp_auth_type == REMAP_AUTH_NONE) {
		if (auth_check_address(req->rr_addr, res->rz_path))
			return RR_OK;
		return RR_ERR_FORBIDDEN;
	}

	/* fetch Authorization header; it should only ever have one value */
	/* XXX is this right?  e.g., should we handle
	 * 	Authorization: Bearer 1234, Basic abcd==
	 * ?
	 * in practice, it's extremely unlikely we would ever see such a
	 * header.
	 */
	rr_auth_field = hash_get(req->rr_hdrfields, "authorization");
	if (rr_auth_field && rr_auth_field->rh_nvalues == 1)
		rr_auth = rr_auth_field->rh_values[0];

	/* Only basic auth? */
	if (!res->rz_path->rp_auth_addr_list) {
		if (!rr_auth)
			return RR_ERR_UNAUTHORIZED;
		if (auth_check_basic(rr_auth, res->rz_path) == 1)
			return RR_OK;
		return RR_ERR_UNAUTHORIZED;
	}

	/* Both; behaviour depends on auth-satisfy */
	if (res->rz_path->rp_auth_satisfy == REMAP_SATISFY_ANY) {
		if (auth_check_address(req->rr_addr, res->rz_path))
			return RR_OK;
		if (!rr_auth)
			return RR_ERR_UNAUTHORIZED;
		if (auth_check_basic(rr_auth, res->rz_path) == 1)
			return RR_OK;
		return RR_ERR_UNAUTHORIZED;
	} else {
		if (!auth_check_address(req->rr_addr, res->rz_path))
			return RR_ERR_FORBIDDEN;
		if (!rr_auth)
			return RR_ERR_UNAUTHORIZED;
		if (auth_check_basic(rr_auth, res->rz_path) != 1)
			return RR_ERR_UNAUTHORIZED;
		return RR_OK;
	}
}

int
qstrcmp(const void *a, const void *b)
{
	return strcmp(*(char **)a, *(char **)b);
}

int
keep_parameter(const remap_path_t *path, const char *param)
{
const char	*pend;
	if ((pend = strchr(param, '=')) == NULL)
		pend = param + strlen(param);

	/* If there's an ignore list, discard anything on it */
	if (path->rp_ignore_params) {
	const char	*p = NULL;
		hash_foreach(path->rp_ignore_params, &p, NULL) {
			if (strmatch(param, pend, p, p + strlen(p)))
				return 0;
		}
	}

	/* If there's a whitelist, discard anything not on the whitelist */
	if (path->rp_whitelist_params) {
	const char	*p = NULL;
		hash_foreach(path->rp_whitelist_params, &p, NULL) {
			if (strmatch(param, pend, p, p + strlen(p)))
				return 1;
		}

		/* Not on whitelist */
		return 0;
	}

	/* Not on ignore list and not rejected by whitelist */
	return 1;
}

void
make_query(const remap_request_t *req, remap_result_t *res)
{
char		**params = NULL;
size_t		  nparams = 0;

char		*sr = NULL, *p, *q, *ret;
size_t		 len = 0;

	q = strdup(req->rr_query);

	/*
	 * Extract the query parameters we actually want into a hash.
	 */
	for (p = strtok_r(q, "&", &sr); p; p = strtok_r(NULL, "&", &sr)) {
		if (!keep_parameter(res->rz_path, p))
			continue;

		params = realloc(params, sizeof(char *) * (nparams + 1));
		params[nparams] = strdup(p);
		++nparams;

		len += strlen(p) + 1;
	}

	free(q);

	if (!len) {
		free(params);
		return;
	}

	qsort(params, nparams, sizeof(char *), qstrcmp);

	/* Join the hash back into a query string. */
	ret = malloc(len + 1);
	ret[0] = '\0';

	for (size_t i = 0; i < nparams; ++i) {
		strcat(ret, params[i]);
		strcat(ret, "&");
		free(params[i]);
	}

	if (len)
		ret[len - 1] = '\0';

	res->rz_query = ret;
	free(params);
}

/*
 * Remap a request.
 */
int
remap_run(const remap_db_t *db, const remap_request_t *req, remap_result_t *ret)
{
int	 r;
size_t	 pfxsz;

	memset(ret, 0, sizeof(*ret));
	ret->rz_headers = hash_new(127, free);

	/* CORS? */
	/* Check host header is present */
	if (!req->rr_host || !*req->rr_host) {
		TSDebug("kubernetes", "missing or empty host header");
		return RR_ERR_INVALID_HOST;
	}

	/* See if this host exists */
	ret->rz_host = remap_db_get_host(db, req->rr_host);
	if (ret->rz_host == NULL) {
		TSDebug("kubernetes", "[%s] host not found", req->rr_host);
		return RR_ERR_NO_HOST;
	}

	/* Find a matching path */
	ret->rz_path = remap_host_find_path(ret->rz_host, req->rr_path, &pfxsz);
	if (ret->rz_path == NULL) {
		TSDebug("kubernetes", "[%s] path %s not found", req->rr_host,
		        req->rr_path);
		return RR_ERR_NO_PATH;
	}

	/* Check for TLS redirect */
	if ((r = rr_check_tls(db, req, ret)) != RR_OK)
		return r;

	/* 
	 * Check authentication; do this after TLS, to avoid prompting the user
	 * to enter a password over insecure http.
	 */
	if ((r = rr_check_auth(db, req, ret)) != RR_OK)
		return r;

	/* CORS */
	if ((r = rr_check_cors(db, req, ret)) != RR_OK)
		return r;

	/* Check for app-root */
	if ((r = rr_check_app_root(db, req, ret)) != RR_OK)
		return r;

	/* Check for rewrite-target */
	if (ret->rz_path->rp_rewrite_target) {
	size_t	blen =	strlen(req->rr_path) - pfxsz
			+ strlen(ret->rz_path->rp_rewrite_target) + 1;

		ret->rz_urlpath = malloc(blen);
		snprintf(ret->rz_urlpath, blen, "%s%s",
			 ret->rz_path->rp_rewrite_target,
			 req->rr_path + pfxsz);
	} else {
		if (req->rr_path)
			ret->rz_urlpath = strdup(req->rr_path);
	}

	/* Set query string */
	if (req->rr_query)
		make_query(req, ret);

	/* Set backend protocol */
	if ((r = rr_check_proto(db, req, ret)) != RR_OK)
		return r;

	/* Does this path have any backends? */
	if (ret->rz_path->rp_naddrs == 0) {
		TSDebug("kubernetes", "[%s] no backends", req->rr_host);
		return RR_ERR_NO_BACKEND;
	}

	/* Pick and return a random backend */
	ret->rz_target = remap_path_pick_target(ret->rz_path);
	TSDebug("kubernetes", "[%s] rewrite -> %s:%d", req->rr_host,
		ret->rz_target->rt_host, ret->rz_target->rt_port);
	return RR_OK;
}

void
remap_request_free(remap_request_t *req)
{
	free(req->rr_method);
	free(req->rr_proto);
	free(req->rr_host);
	free(req->rr_path);
	free(req->rr_query);

	hash_free(req->rr_hdrfields);
}

void
remap_result_free(remap_result_t *rz)
{
	hash_free(rz->rz_headers);
	free(rz->rz_urlpath);
	free(rz->rz_query);
}

void
remap_make_cache_key(remap_request_t *req, remap_result_t *res,
		     char **key, size_t *keylen)
{	
uint8_t		 protolen, hostlen;
uint16_t	 pathlen = 0, querylen = 0;
char		*buf, *p;
size_t		 buflen;

	buflen = 0;

	protolen = (uint8_t) strlen(req->rr_proto);
	hostlen = (uint8_t) strlen(req->rr_host);

	buflen += 1 + protolen + 1 + hostlen;

	if (req->rr_path)
		pathlen = (uint16_t) strlen(req->rr_path);
	if (res->rz_query)
		querylen = (uint16_t) strlen(res->rz_query);

	buflen += 2 + pathlen + 2 + querylen;

	p = buf = malloc(buflen);

	*p++ = protolen;
	memcpy(p, req->rr_proto, protolen);
	p += protolen;

	*p++ = hostlen;
	memcpy(p, req->rr_host, hostlen);
	p += hostlen;

	*p++ = pathlen & 0xFF;
	*p++ = (pathlen >> 8) & 0xFF;
	if (req->rr_path)
		memcpy(p, req->rr_path, pathlen);
	p += pathlen;

	*p++ = querylen & 0xFF;
	*p++ = (querylen >> 8) & 0xFF;
	if (res->rz_query)
		memcpy(p, res->rz_query, querylen);
	p += querylen;

	*keylen = base64_encode_len(buflen) + 1;
	*key = malloc(*keylen);
	**key = '/';
	base64_encode((unsigned char*)buf, buflen, *key + 1);
	free(buf);
}

void
remap_hdrfield_free(remap_hdrfield_t *field)
{
	for (size_t i = 0; i < field->rh_nvalues; ++i)
		free(field->rh_values[i]);
	free(field->rh_values);
	free(field);
}
