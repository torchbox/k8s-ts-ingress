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

#include	"hash.h"
#include	"api.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stores one path entry in an Ingress.
 */
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

typedef struct {
	regex_t	  rp_regex;
	char	**rp_addrs;
	size_t	  rp_naddrs;
	hash_t	  rp_users;

	int	  rp_cache:1;
	int	  rp_follow_redirects:1;
	int	  rp_secure_backends:1;
	int	  rp_preserve_host:1;
	int	  rp_no_ssl_redirect:1;
	int	  rp_force_ssl_redirect:1;
	uint	  rp_auth_type:2;
	uint	  rp_auth_satisfy:1;
	int	  rp_cache_gen;
	char	 *rp_app_root;
	char	 *rp_rewrite_target;
	char	 *rp_auth_realm;
	struct remap_auth_addr *rp_auth_addr_list;
} remap_path_t;

remap_path_t	*remap_path_new(const char *path);
void		 remap_path_free(remap_path_t *);
void		 remap_path_annotate(namespace_t *ns, remap_path_t *, hash_t);
void		 remap_path_add_address(remap_path_t *, const char *host,
					int port);

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
	hash_t	rd_hosts;
} remap_db_t;

/* create and destroy remap_dbs */
remap_db_t	*remap_db_new(void);
remap_db_t	*remap_db_from_cluster(cluster_t *);
void		 remap_db_free(remap_db_t *);

/* fetch hosts from a remap_db */
remap_host_t	*remap_db_get_host(const remap_db_t *, const char *hostname);
remap_host_t	*remap_db_get_or_create_host(remap_db_t *, const char *hostname);

#ifdef __cplusplus
}
#endif

#endif  /* !REMAP_H */
