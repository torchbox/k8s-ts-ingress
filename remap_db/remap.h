/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef REMAP_H
#define REMAP_H

#include	<sys/types.h>
#include	<netinet/in.h>

#include	<regex.h>

#include	<openssl/ssl.h>

#include	"config.h"
#include	"hash.h"
#include	"api.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Header fields.
 */
#define	REMAP_MIME_FIELD_X_FORWARDED_PROTO	"X-Forwarded-Proto"
#define	REMAP_MIME_FIELD_X_FORWARDED_PROTO_LEN	\
	(sizeof(REMAP_MIME_FIELD_X_FORWARDED_PROTO) - 1)
#define	REMAP_MIME_FIELD_X_NEXT_HOP_CACHE_CONTROL	\
	"X-Next-Hop-Cache-Control"
#define	REMAP_MIME_FIELD_X_NEXT_HOP_CACHE_CONTROL_LEN	\
	(sizeof(REMAP_MIME_FIELD_X_NEXT_HOP_CACHE_CONTROL) - 1)

#define REMAP_AUTH_NONE		0x0
#define REMAP_AUTH_BASIC	0x1
#define	REMAP_AUTH_DIGEST	0x2

/*
 * An entry in the IP whitelist.
 */

struct remap_auth_addr {
	struct remap_auth_addr	*ra_next;
	int			 ra_family;
	union {
		in_addr_t	 ra_v4;
		struct in6_addr	 ra_v6;
	}			 ra_addr;
#define ra_addr_v4 ra_addr.ra_v4
#define ra_addr_v6 ra_addr.ra_v6
	int			 ra_prefix_length;
};

#define	REMAP_SATISFY_ALL	0
#define	REMAP_SATISFY_ANY	1

typedef struct remap_target {
	char	*rt_host;
	int	 rt_port;
} remap_target_t;

/*
 * remap_path: stores one path entry in an Ingress.
 */
typedef struct {
	regex_t		  rp_regex;
	remap_target_t	 *rp_addrs;
	size_t		  rp_naddrs;
	hash_t		  rp_users;

	/* Caching */
	unsigned  rp_cache:1;			/* Enable caching	     */
	int	  rp_cache_gen;			/* Set cache generation	     */
	hash_t	  rp_ignore_params;		/* Params to ignore in cache */
	hash_t	  rp_whitelist_params;		/* Cache param whitelist     */
	hash_t	  rp_ignore_cookies;		/* Cookie names to remove    */
	hash_t	  rp_whitelist_cookies;		/* Cookie name whitelist     */

	/* TLS */
	unsigned  rp_follow_redirects:1;	/* Follow 301/302 redirect   */
	unsigned  rp_secure_backends:1;		/* Use TLS to origin	     */
	unsigned  rp_no_ssl_redirect:1;		/* Never TLS redirect	     */
	unsigned  rp_force_ssl_redirect:1;	/* Always TLS redirect	     */

	/* Misc */
	unsigned  rp_preserve_host:1;		/* Use origin name as Host   */
	char	 *rp_app_root;			/* Redirect /		     */
	char	 *rp_rewrite_target;		/* Rewrite path		     */
	int	  rp_read_timeout;		/* Origin read timeout	     */
	unsigned  rp_compress:1;		/* Compress response	     */
	unsigned  rp_server_push:1;		/* Enable HTTP/1 server push */
	unsigned  rp_debug_log:1;		/* Log request/response      */
	hash_t	  rp_compress_types;		/* Content types to compress */

	/* Authn/authz */
	unsigned  rp_auth_type:2;		/* Authentication type	     */
	unsigned  rp_auth_satisfy:1;		/* Auth satisfy (all/any)    */
	char	 *rp_auth_realm;		/* Auth realm		     */

	/* CORS */
	unsigned  rp_enable_cors:1;		/* Do CORS processing	     */
	unsigned  rp_cors_creds:1;		/* Allow credentials	     */
	hash_t	  rp_cors_origins;		/* Permitted CORS origins    */
	char	 *rp_cors_methods;		/* CORS methods		     */
	char	 *rp_cors_headers;		/* CORS headersil	     */
	int	  rp_cors_max_age;		/* CORS max age		     */

	struct remap_auth_addr *rp_auth_addr_list;
} remap_path_t;

remap_path_t	*remap_path_new(const char *path);
void		 remap_path_free(remap_path_t *);
void		 remap_path_annotate(namespace_t *ns, remap_path_t *, hash_t);
void		 remap_path_add_address(remap_path_t *, const char *host,
					int port);
const remap_target_t
		*remap_path_pick_target(const remap_path_t *);

/*
 * Store configuration for a particular hostname.  This contains the TLS
 * context, zero or more paths, and maybe a default backend.
 */
typedef struct {
	remap_path_t	**rh_paths;
	size_t		 rh_npaths;
	SSL_CTX		*rh_ctx;
	int		 rh_hsts_subdomains:1;
	int		 rh_hsts_max_age;
} remap_host_t;

remap_host_t	*remap_host_new(void);
void		 remap_host_free(remap_host_t *host);
remap_path_t	*remap_host_find_path(const remap_host_t *,
				      const char *pathname,
				      size_t *pfxsz);
remap_path_t	*remap_host_new_path(remap_host_t *, const char *path);
remap_path_t	*remap_host_get_default_path(remap_host_t *);
void		 remap_host_annotate(remap_host_t *, hash_t);

/*
 * remap_db stores a built remap database, i.e. remap_host objects.
 */
typedef struct {
	k8s_config_t	*rd_config;
	hash_t		 rd_hosts;
} remap_db_t;

/* create and destroy remap_dbs */
remap_db_t	*remap_db_new(k8s_config_t *cfg);
remap_db_t	*remap_db_from_cluster(k8s_config_t *cfg, cluster_t *);
void		 remap_db_free(remap_db_t *);

/* fetch hosts from a remap_db */
remap_host_t	*remap_db_get_host(const remap_db_t *, const char *hostname);
remap_host_t	*remap_db_get_or_create_host(remap_db_t *, const char *hostname);

/*
 * Represent a single header field.
 */
typedef struct remap_hdrfield {
	size_t	  rh_nvalues;
	char	**rh_values;
} remap_hdrfield_t;

void	remap_hdrfield_free(remap_hdrfield_t *);

/*
 * Request data for remap_run();
 */
typedef struct remap_request {
	char		*rr_proto;	/* Request proto (http, https...) */
	char		*rr_method;	/* Request method (GET, POST, ...) */
	char		*rr_host;	/* Request Host: header */
	char		*rr_path;	/* Request URL path, with leading '/' */
	char		*rr_query;	/* Request URL query string, not
					   including leading '/' */
	hash_t		 rr_hdrfields;	/* Lowercased request header fields */
	const struct sockaddr
			*rr_addr;	/* Client network address */
} remap_request_t;

/*
 * Result of a remap_run().
 *
 * If the return code is RR_OK, then rz_target contains the backend host and
 * port to remap the request to, and rz_proto contains the backend protocol.
 * If rz_path is non-null, it contains the rewritten URL path that should be
 * used for the request.
 *
 * If RR_REDIRECT, then rz_location contains a URL that the client should be
 * redirected to and rz_status contains the HTTP status code.
 *
 * Otherwise, return will be equal to RR_ERR_* indicating that an error 
 * occurred, and none of the struct fields are valid.
 */
typedef struct remap_result {
	/* success */
	const remap_target_t	*rz_target;
	const char		*rz_proto;
	char			*rz_urlpath;
	char			*rz_query;

	/* headers to include in the response */
	hash_t		 rz_headers;

	/* synthetic response */
	int		 rz_status;
	const char	*rz_status_text;
	const char	*rz_body;

	/* the host and path that matched the request, if any */
	remap_host_t	*rz_host;
	remap_path_t	*rz_path;
} remap_result_t;

#define	RR_OK			0	/* Successful remap		     */
#define	RR_SYNTHETIC		1	/* Return a synthetic response, e.g.
					   a redirect.			     */
#define	RR_ERR_INVALID_HOST	(-1)	/* Host: header missing or invalid   */
#define	RR_ERR_INVALID_PROTOCOL	(-2)	/* Unrecognised protocol	     */
#define	RR_ERR_NO_HOST		(-3)	/* Host not found		     */
#define	RR_ERR_NO_PATH		(-4)	/* Path not found		     */
#define	RR_ERR_NO_BACKEND	(-5)	/* Path found, but has no functional
					   backends */
#define	RR_ERR_FORBIDDEN	(-6)	/* Request denied by IP address	     */
#define	RR_ERR_UNAUTHORIZED	(-7)	/* Request denied by authenticatio   */


int	remap_run(const remap_db_t *db, const remap_request_t *,
		  remap_result_t *);

void	remap_request_free(remap_request_t *);
void	remap_result_free(remap_result_t *);

/*
 * Create a Traffic Server cache key for the given request.
 */
void	remap_make_cache_key(remap_request_t *, remap_result_t *,
			     char **, size_t *);
#ifdef __cplusplus
}
#endif

#endif  /* !REMAP_H */
