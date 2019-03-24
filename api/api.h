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
#include	"tsqueue.h"


#ifdef __cplusplus
extern "C" {
#endif

char	*_k8s_get_ssl_error(void);
int	 domain_match(const char *pat, const char *str);

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
#define	IN_SSL_PASSTHROUGH		A_INGRESS "ssl-passthrough"
#define	IN_TLS_MINIMUM_VERSION		A_INGRESS "tls-minimum-version"
#define	IN_TLS_VERSION_1_0		"1.0"
#define	IN_TLS_VERSION_1_0_VALUE	0x0100
#define	IN_TLS_VERSION_1_1		"1.1"
#define	IN_TLS_VERSION_1_1_VALUE	0x0101
#define	IN_TLS_VERSION_1_2		"1.2"
#define	IN_TLS_VERSION_1_2_VALUE	0x0102
#define	IN_TLS_VERSION_1_3		"1.3"
#define	IN_TLS_VERSION_1_3_VALUE	0x0103
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
#define	IN_HTTP2_ENABLE			A_INGRESS "http2-enable"

/* Ingress annotations - Torchbox */
#define	IN_DEBUG_LOG			A_TORCHBOX "debug-log"

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

secret_t	*secret_make(json_object *obj);
SSL_CTX		*secret_make_ssl_ctx(secret_t *);
void		 secret_free(secret_t *sec);

/*
 * ConfigMaps.  These are basically identical to Secrets but with less base64.
 */
typedef struct {
	char	*cm_name;
	char	*cm_namespace;
	hash_t	 cm_data;
} configmap_t;

configmap_t	*configmap_make(json_object *obj);
void		 configmap_free(configmap_t *sec);

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

/*
 * Default configuration, stored in the cluster.
 */

/* A default certificate entry */
typedef struct cluster_cert {
	TAILQ_ENTRY(cluster_cert) cr_entry;

	char	*cr_domain;
	char	*cr_namespace;
	char	*cr_name;
} cluster_cert_t;
typedef TAILQ_HEAD(cluster_cert_list, cluster_cert) cluster_cert_list_t;

/* A domain access list entry */
typedef struct cluster_domain {
	TAILQ_ENTRY(cluster_domain) da_entry;

	char	*da_domain;
	hash_t	 da_namespaces;
} cluster_domain_t;
typedef TAILQ_HEAD(cluster_domain_list, cluster_domain) cluster_domain_list_t;

typedef struct {
	int			 cc_tls_minimum_version;
	int			 cc_hsts_max_age;
	unsigned		 cc_hsts_subdomains:1;
	unsigned		 cc_http2:1;
	char			*cc_healthcheck;
	cluster_domain_list_t	 cc_domains;
	cluster_cert_list_t	 cc_certs;
} cluster_config_t;

cluster_config_t	*cluster_config_new(void);
void			 cluster_config_free(cluster_config_t *);

typedef struct cluster {
	pthread_rwlock_t	 cs_lock;
	hash_t			 cs_namespaces;
	cluster_callback_t	 cs_callback;
	void			*cs_callbackdata;
	cluster_config_t	*cs_config;
} cluster_t;

cluster_t	*cluster_make(void);
namespace_t	*cluster_get_namespace(cluster_t *, const char *nsname);
void		 cluster_set_configmap(cluster_t *, configmap_t *);
cluster_cert_t	*cluster_get_cert_for_hostname(cluster_t *, const char *);
int		 cluster_domain_for_ns(cluster_t *, const char *dom,
				       const char *ns);
void		 cluster_free(cluster_t *cluster);

#ifdef __cplusplus
}
#endif

#endif
