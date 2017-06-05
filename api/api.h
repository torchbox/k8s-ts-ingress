/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#ifndef	K8SAPI_API_H
#define	K8SAPI_API_H

#include	<sys/types.h>
#include	<pthread.h>

#include	<openssl/ssl.h>
#include	<json.h>

#include	"hash.h"

#ifdef __cplusplus
extern "C" {
#endif

char	*_k8s_get_ssl_error(void);

/*
 * Annotation prefixes.  ingress.kubernetes.io is for standard annotations,
 * ingress.torchbox.com is for TS-specific ones.
 */
#define	A_KUBERNETES	"kubernetes.io/"
#define	A_INGRESS	"ingress.kubernetes.io/"
#define	A_TORCHBOX	"ingress.torchbox.com/"

/*
 * Endpointses
 */
typedef struct {
	char	*et_name;
	int	 et_port;
	char	*et_protocol;
} endpoints_port_t;

typedef struct {
	char	*ea_ip;
	char	*ea_nodename;
} endpoints_address_t;

typedef struct {
	endpoints_address_t	*es_addrs;
	size_t			 es_naddrs;
	hash_t			 es_ports;
} endpoints_subset_t;

typedef struct {
	char			*ep_name;
	char			*ep_namespace;
	endpoints_subset_t	*ep_subsets;
	size_t			 ep_nsubsets;
} endpoints_t;

void		 endpoints_free(endpoints_t *ing);
endpoints_t	*endpoints_make(json_object *obj);
int		 endpoints_equal(endpoints_t *, endpoints_t *);

/*
 * Services
 */

#define	SV_TYPE_EXTERNALNAME	"ExternalName"

typedef enum {
	SV_P_TCP,
	SV_P_UDP,
} service_proto_t;

typedef struct {
	char		*sp_name;
	int		 sp_port;
	int		 sp_target_port;
	service_proto_t	 sp_protocol;
} service_port_t;

typedef struct {
	char	*sv_name;
	char	*sv_namespace;
	char	*sv_type;
	char	*sv_cluster_ip;
	char	*sv_session_affinity;
	char	*sv_external_name;
	hash_t	 sv_selector;
	hash_t	 sv_ports;
} service_t;

void		 service_free(service_t *);
service_t	*service_make(json_object *);
service_port_t	*service_find_port(const service_t *, const char *name,
				   service_proto_t);

/*
 * Ingresses
 */

/* Ingress annotations - Kubernetes */
#define	IN_SECURE_BACKENDS		A_INGRESS "secure-backends"
#define	IN_SSL_REDIRECT			A_INGRESS "ssl-redirect"
#define	IN_FORCE_SSL_REDIRECT		A_INGRESS "force-ssl-redirect"
#define	IN_APP_ROOT			A_INGRESS "app-root"
#define	IN_REWRITE_TARGET		A_INGRESS "rewrite-target"
#define	IN_AUTH_TYPE			A_INGRESS "auth-type"
#define	IN_AUTH_TYPE_BASIC		"basic"
#define	IN_AUTH_TYPE_DIGEST		"digest"
#define	IN_AUTH_REALM			A_INGRESS "auth-realm"
#define	IN_AUTH_SECRET			A_INGRESS "auth-secret"
#define	IN_AUTH_SATISFY			A_INGRESS "auth-satisfy"
#define	IN_AUTH_SATISFY_ANY		"any"
#define	IN_AUTH_SATISFY_ALL		"all"
#define	IN_WHITELIST_SOURCE_RANGE	A_INGRESS "whitelist-source-range"
#define	IN_CACHE_ENABLE			A_INGRESS "cache-enable"
#define	IN_CACHE_GENERATION		A_INGRESS "cache-generation"
#define	IN_CACHE_IGNORE_PARAMS		A_INGRESS "cache-ignore-query-params"
#define	IN_CACHE_WHITELIST_PARAMS	A_INGRESS "cache-whitelist-query-params"
#define	IN_CACHE_IGNORE_COOKIES		A_INGRESS "cache-ignore-cookies"
#define	IN_CACHE_WHITELIST_COOKIES	A_INGRESS "cache-whitelist-cookies"
#define	IN_HSTS_INCLUDE_SUBDOMAINS	A_INGRESS "hsts-include-subdomains"
#define	IN_HSTS_MAX_AGE			A_INGRESS "hsts-max-age"
#define	IN_FOLLOW_REDIRECTS		A_INGRESS "follow-redirects"
#define	IN_PRESERVE_HOST		A_INGRESS "preserve-host"
#define	IN_READ_RESPONSE_TIMEOUT	A_INGRESS "read-response-timeout"
#define	IN_CLASS			A_KUBERNETES "ingress.class"
#define	IN_CLASS_TRAFFICSERVER		"trafficserver"
#define	IN_ENABLE_CORS			A_INGRESS "enable-cors"
#define	IN_CORS_ORIGINS			A_INGRESS "cors-origins"
#define	IN_CORS_MAX_AGE			A_INGRESS "cors-max-age"
#define	IN_CORS_CREDENTIALS		A_INGRESS "cors-credentials"
#define	IN_CORS_HEADERS			A_INGRESS "cors-headers"
#define	IN_CORS_METHODS			A_INGRESS "cors-methods"
#define	IN_COMPRESS_ENABLE		A_INGRESS "compress-enable"
#define	IN_COMPRESS_TYPES		A_INGRESS "compress-types"
#define	IN_SERVER_PUSH			A_INGRESS "server-push"

/* Ingress annotations - Torchbox */
/* currently none, as all our custom annotations have been standardised */

typedef struct {
	char	*it_secret_name;
	char	**it_hosts;
	size_t	  it_nhosts;
} ingress_tls_t;

typedef struct {
	char	*ip_path;
	char	*ip_service_name;
	char	*ip_service_port;
} ingress_path_t;

typedef struct {
	char		*ir_host;
	ingress_path_t	*ir_paths;
	size_t		 ir_npaths;
} ingress_rule_t;

typedef struct {
	char		*in_name;
	char		*in_namespace;
	ingress_tls_t	*in_tls;
	size_t		 in_ntls;
	ingress_rule_t	*in_rules;
	size_t		 in_nrules;
	hash_t		 in_annotations;
} ingress_t;

void		 ingress_free(ingress_t *ing);
ingress_t	*ingress_make(json_object *obj);

/*
 * Secrets
 */
typedef struct {
	char	*se_name;
	char	*se_namespace;
	char	*se_type;
	hash_t	 se_data;
} secret_t;

void		 secret_free(secret_t *sec);
secret_t	*secret_make(json_object *obj);
SSL_CTX		*secret_make_ssl_ctx(secret_t *);

/*
 * Namespaces
 */
typedef struct {
	char	*ns_name;
	hash_t	 ns_ingresses;
	hash_t	 ns_secrets;
	hash_t	 ns_services;
	hash_t	 ns_endpointses;
} namespace_t;

namespace_t	*namespace_make(const char *name);
void		 namespace_free(namespace_t *);

void		 namespace_put_ingress(namespace_t *, ingress_t *);
ingress_t	*namespace_get_ingress(namespace_t *, const char *);
void		 namespace_del_ingress(namespace_t *, const char *);

void		 namespace_put_secret(namespace_t *, secret_t *);
secret_t	*namespace_get_secret(namespace_t *, const char *);
void		 namespace_del_secret(namespace_t *, const char *);

void		 namespace_put_service(namespace_t *, service_t *);
service_t	*namespace_get_service(namespace_t *, const char *);
void		 namespace_del_service(namespace_t *, const char *);

void		 namespace_put_endpoints(namespace_t *, endpoints_t *);
endpoints_t	*namespace_get_endpoints(namespace_t *, const char *);
void		 namespace_del_endpoints(namespace_t *, const char *);

/*
 * Clusters.
 */

struct cluster;

typedef void (*cluster_callback_t) (struct cluster *cluster, void *);

typedef struct cluster {
	pthread_rwlock_t	 cs_lock;
	hash_t			 cs_namespaces;
	cluster_callback_t	 cs_callback;
	void			*cs_callbackdata;
} cluster_t;

cluster_t	*cluster_make(void);
void		 cluster_free(cluster_t *cluster);
namespace_t	*cluster_get_namespace(cluster_t *, const char *nsname);

#ifdef __cplusplus
}
#endif

#endif
