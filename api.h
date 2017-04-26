/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef	K8SAPI_API_H
#define	K8SAPI_API_H

#include	<sys/types.h>

#include	<openssl/ssl.h>
#include	<json.h>

#include	"hash.h"

char	*_k8s_get_ssl_error(void);

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

/*
 * Secrets
 */
typedef struct {
	const char	*ts_crt;
	const char	*ts_key;
} tls_secret_t;

/*
 * Services
 */
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

/*
 * Ingresses
 */
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
	hash_t	ns_ingresses;
	hash_t	ns_secrets;
	hash_t	ns_services;
	hash_t	ns_endpointses;
} namespace_t;

namespace_t	*namespace_make(void);
void		 namespace_free(namespace_t *);

void		 namespace_put_ingress(namespace_t *, ingress_t *);
ingress_t	*namespace_get_ingress(namespace_t *, const char *);
ingress_t	*namespace_del_ingress(namespace_t *, const char *);

void		 namespace_put_secret(namespace_t *, secret_t *);
secret_t	*namespace_get_secret(namespace_t *, const char *);
secret_t	*namespace_del_secret(namespace_t *, const char *);

void		 namespace_put_service(namespace_t *, service_t *);
service_t	*namespace_get_service(namespace_t *, const char *);
service_t	*namespace_del_service(namespace_t *, const char *);

void		 namespace_put_endpoints(namespace_t *, endpoints_t *);
endpoints_t	*namespace_get_endpoints(namespace_t *, const char *);
endpoints_t	*namespace_del_endpoints(namespace_t *, const char *);

/*
 * Clusters
 */
typedef struct {
	hash_t	cs_namespaces;
} cluster_t;

cluster_t	*cluster_make(void);
namespace_t	*cluster_get_namespace(cluster_t *, const char *nsname);

#endif
