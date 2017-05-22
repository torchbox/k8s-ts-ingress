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

#ifdef __cplusplus
extern "C" {
#endif

#include    <sys/types.h>
#include    <netinet/in.h>

#include    <regex.h>

#include    <openssl/ssl.h>

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

struct remap_path {
	char	 *rp_prefix;
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
};

/*
 * Store configuration for a particular hostname.  This contains the TLS
 * context, zero or more paths, and maybe a default backend.
 */
struct remap_host {
	struct remap_path	*rh_paths;
	size_t			 rh_npaths;
	struct remap_path	 rh_default;
	SSL_CTX			*rh_ctx;
	int			 rh_hsts_subdomains:1;
	int			 rh_hsts_max_age;
};


#ifdef __cplusplus
}
#endif

#endif  /* !REMAP_H */
