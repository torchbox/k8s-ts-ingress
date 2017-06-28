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
	TSDebug("kubernetes", "remap_db_free: %p", db);
	if (!db)
		return;

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

	TSDebug("kubernetes", "rr_check_cors: rp_enable_cors=%d",
		res->rz_path->rp_enable_cors);
	/*
	 * If CORS is not enabled, do nothing.
	 */
	if (!res->rz_path->rp_enable_cors)
		return RR_OK;

	/*
	 * If the request has no Origin header, do nothing.
	 */
	if ((hdr = hash_get(req->rr_hdrfields, "origin")) == NULL) {
		TSDebug("kubernetes", "rr_check_cors: no Origin");
		return RR_OK;
	}

	if (hdr->rh_nvalues != 1) {
		TSDebug("kubernetes", "rr_check_cors: incorrect number of values"
			"for origin: %d", (int) hdr->rh_nvalues);
		return RR_OK;
	}

	origin = hdr->rh_values[0];
	TSDebug("kubernetes", "rr_check_cors: origin is %s", origin);

	/*
	 * If no Origin list has been specified, the origin is "*".  This is
	 * treated specially by the CORS specification, so do not use the
	 * request Origin header.
	 */
	if (hash_get(res->rz_path->rp_cors_origins, "*") == HASH_PRESENT) {
		TSDebug("kubernetes", "rr_check_cors: using wildcard origin");
		hash_set(res->rz_headers, "Access-Control-Allow-Origin",
			 strdup("*"));
	/*
	 * Otherwise, check if the origin is in the list of origins.  In that
	 * case, we have to Vary by origin as the response changes depending
	 * on the origin.
	 */
	} else if (hash_get(res->rz_path->rp_cors_origins,
			    origin) == HASH_PRESENT) {
		TSDebug("kubernetes", "rr_check_cors: using origin %s",
			origin);
		hash_set(res->rz_headers, "Access-Control-Allow-Origin",
			 strdup(origin));
		hash_set(res->rz_headers, "Vary", strdup("Origin"));
	/*
	 * Otherwise, we don't recognise this origin, so do nothing.
	 */
	} else {
		TSDebug("kubernetes", "rr_check_cors: origin did not match");
		return RR_OK;
	}

	/*
	 * If this is not a preflight request, there's nothing more to do.
	 */
	if (strcmp(req->rr_method, "OPTIONS")) {
		TSDebug("kubernetes", "rr_check_cors: not preflight");
		return RR_OK;
	}

	/*
	 * Add response headers based on the configuration.
	 */
	if (res->rz_path->rp_cors_methods)
		hash_set(res->rz_headers, "Access-Control-Allow-Methods",
			 strdup(res->rz_path->rp_cors_methods));

	if (res->rz_path->rp_cors_headers)
		hash_set(res->rz_headers, "Access-Control-Allow-Headers",
			 strdup(res->rz_path->rp_cors_headers));

	if (res->rz_path->rp_cors_max_age) {
	char	s[32];
		snprintf(s, sizeof(s), "%d", res->rz_path->rp_cors_max_age);
		hash_set(res->rz_headers, "Access-Control-Max-Age", strdup(s));
	}

	if (res->rz_path->rp_cors_creds)
		hash_set(res->rz_headers, "Access-Control-Allow-Credentials",
			 strdup("true"));

	res->rz_status = 204;
	res->rz_status_text = "No content";
	return RR_SYNTHETIC;
}

static void
set_wwwauth_header(remap_result_t *res)
{
char	*hdr;
size_t	 len;

	len = sizeof("Basic realm=\"\"") + strlen(res->rz_path->rp_auth_realm);
	hdr = malloc(len);
	snprintf(hdr, len, "Basic realm=\"%s\"", res->rz_path->rp_auth_realm);
	hash_set(res->rz_headers, "WWW-Authenticate", hdr);
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
		if (rr_auth && auth_check_basic(rr_auth, res->rz_path) == 1)
			return RR_OK;

		set_wwwauth_header(res);
		return RR_ERR_UNAUTHORIZED;
	}

	/* Both; behaviour depends on auth-satisfy */
	if (res->rz_path->rp_auth_satisfy == REMAP_SATISFY_ANY) {
		if (auth_check_address(req->rr_addr, res->rz_path))
			return RR_OK;

		if (!rr_auth || auth_check_basic(rr_auth, res->rz_path) != 1) {
			set_wwwauth_header(res);
			return RR_ERR_UNAUTHORIZED;
		}

		return RR_OK;
	} else {
		if (!auth_check_address(req->rr_addr, res->rz_path))
			return RR_ERR_FORBIDDEN;

		if (!rr_auth || auth_check_basic(rr_auth, res->rz_path) != 1) {
			set_wwwauth_header(res);
			return RR_ERR_UNAUTHORIZED;
		}

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
	size_t		 plen;

		TSDebug("kubernetes", "keep_parameter: checking ignore");

		hash_foreach(path->rp_ignore_params, &p, &plen, NULL) {
			TSDebug("kubernetes", "keep_parameter: check [%.*s]"
				" against [%.*s]", (int)(pend - param), param,
				(int) plen, p);
			if (strmatch(param, pend, p, p + plen))
				return 0;
			TSDebug("kubernetes", "keep_parameter: no match");
		}
	}

	/* If there's a whitelist, discard anything not on the whitelist */
	if (path->rp_whitelist_params) {
	const char	*p = NULL;
	size_t		 plen;

		hash_foreach(path->rp_whitelist_params, &p, &plen, NULL) {
			if (strmatch(param, pend, p, p + plen))
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
		TSDebug("kubernetes", "make_query: param is [%s]", p);

		if (!keep_parameter(res->rz_path, p))
			continue;

		TSDebug("kubernetes", "keeping this param");
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
