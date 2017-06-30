/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely. This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include	<string.h>

#include	<ts/ts.h>

#include	"hash.h"
#include	"remap.h"

static void build_namespace(remap_db_t *, cluster_t *, namespace_t *);
static void build_ingress(remap_db_t *, cluster_t *, namespace_t *, ingress_t *);
static void build_ingress_tls(remap_db_t *, cluster_t *, namespace_t *,
			      ingress_t *, ingress_tls_t *);
static void build_ingress_rule(remap_db_t *, cluster_t *, namespace_t *,
			       ingress_t *, ingress_rule_t *);
static void build_add_endpoints(remap_db_t *db, cluster_t *, namespace_t *,
				remap_path_t *rp, service_t *svc,
				const char *port_name);

remap_db_t *
remap_db_from_cluster(k8s_config_t *cfg, cluster_t *cluster)
{
namespace_t		*namespace;
remap_db_t		*db;

	db = remap_db_new(cfg);
	hash_foreach(cluster->cs_namespaces, NULL, NULL, &namespace)
		build_namespace(db, cluster, namespace);

	if (cluster->cs_config->cc_healthcheck)
		db->rd_healthcheck = strdup(cluster->cs_config->cc_healthcheck);

	return db;
}

/*
 * Build a single namespace.
 */
static void
build_namespace(remap_db_t *db, cluster_t *cs, namespace_t *ns)
{
ingress_t		*ingress;

	TSDebug("kubernetes", "namespace %s:", ns->ns_name);

	hash_foreach(ns->ns_ingresses, NULL, NULL, &ingress)
		build_ingress(db, cs, ns, ingress);
}

/*
 * Build a single ingress.
 */
static void
build_ingress(remap_db_t *db, cluster_t *cs, namespace_t *ns, ingress_t *ing)
{
char	*cls;

	TSDebug("kubernetes", "  ingress %s:", ing->in_name);
	
	/*
	 * Check whether we should handle this class.
	 */
	if ((cls = hash_get(ing->in_annotations, IN_CLASS)) != NULL) {
		TSDebug("kubernetes", "    ingress class is [%s]", cls);

		if (hash_get(db->rd_config->co_classes, cls) != HASH_PRESENT)
			return;
	}

	/* Rebuild remap state */
	for (size_t i = 0; i < ing->in_nrules; i++)
		build_ingress_rule(db, cs, ns, ing, &ing->in_rules[i]);

	/* Rebuild TLS state */
	for (size_t i = 0; i < ing->in_ntls; i++)
		build_ingress_tls(db, cs, ns, ing, &ing->in_tls[i]);
}

static void
build_ingress_rule(remap_db_t *db, cluster_t *cs, namespace_t *ns,
		   ingress_t *ing, ingress_rule_t *rule)
{
remap_host_t	*rh;
size_t		 i;

	if (!cluster_domain_for_ns(cs, rule->ir_host, ns->ns_name)) {
		TSError("kubernetes: ignoring Ingress %s host %s since "
			"namespace %s does not have access to this domain",
			ing->in_name, rule->ir_host, ns->ns_name);
		return;
	}

	rh = remap_db_get_or_create_host(db, rule->ir_host);

	/*
	 * Attach default TLS contexts here.  The context will be replaced by
	 * build_ingress_tls if the TLS provides its own TLS configuration.
	 */
	remap_host_attach_default_tls(rh, cs, rule->ir_host);

	for (i = 0; i < rule->ir_npaths; i++) {
	ingress_path_t	*path = &rule->ir_paths[i];
	remap_path_t	*rp;
	service_t	*svc;

		svc = namespace_get_service(ns, path->ip_service_name);
		if (svc == NULL)
			continue;

		TSDebug("kubernetes", "      path <%s> -> service <%s/%s>",
			path->ip_path, svc->sv_namespace, svc->sv_name);

		if (path->ip_path)
			rp = remap_host_new_path(rh, path->ip_path);
		else {
			/*
			 * Do host annotations here, on the default path, so
			 * we don't pick up invalid host-specific annotations
			 * from subpaths.
			 */
			remap_host_annotate(rh, cs, ing->in_annotations);
			rp = remap_host_get_default_path(rh);
		}

		if (rp == NULL)
			continue;

		remap_path_annotate(ns, cs, rp, ing->in_annotations);
		build_add_endpoints(db, cs, ns, rp, svc, path->ip_service_port);
	}
}

/*
 * Rebuild the tls configuration of an ingress.
 */
static void
build_ingress_tls(remap_db_t *db, cluster_t *cs, namespace_t *ns,
		  ingress_t *ing, ingress_tls_t *itls)
{
secret_t		*secret;

	TSDebug("kubernetes", "    secret %s (%d hosts):",
		itls->it_secret_name, (int) itls->it_nhosts);

	secret = namespace_get_secret(ns, itls->it_secret_name);
	if (!secret) {
		TSDebug("kubernetes", "    warning: could not find secret [%s]",
			itls->it_secret_name);
		return;
	}

	for (size_t i = 0; i < itls->it_nhosts; i++) {
	const char	*hostname = itls->it_hosts[i];
	remap_host_t	*rh;

		if (!cluster_domain_for_ns(cs, hostname, ns->ns_name)) {
			TSError("kubernetes: ignoring Ingress %s TLS %s since "
				"namespace %s does not have access to this "
				"domain", ing->in_name, hostname, ns->ns_name);
			return;
		}

		rh = remap_db_get_or_create_host(db, hostname);

		if (rh->rh_ctx) {
			/*
			 * Might already have a context attached if the host
			 * matched the default certificates.
			 */
			SSL_CTX_free(rh->rh_ctx);
			rh->rh_ctx = NULL;
		}

		if ((rh->rh_ctx = secret_make_ssl_ctx(secret)) == NULL) {
			TSDebug("kubernetes", "      %s: can't make ctx",
				hostname);
			continue;
		}

		TSDebug("kubernetes", "      %s: added with CTX[%p]",
			hostname, rh->rh_ctx);
	}
}

/*
 * Attach a Service's endpoints to a remap_path.
 */
static void
build_add_endpoints(
	remap_db_t *db,
	cluster_t *cs,
	namespace_t *ns,
	remap_path_t *rp,
	service_t *svc,
	const char *port_name)
{
service_port_t	*port;
endpoints_t	*eps;
size_t		 i, j;

	/*
	 * If this is an ExternalName service, add the name directly; no need to
	 * do anything else.
	 */
	if (strcmp(svc->sv_type, SV_TYPE_EXTERNALNAME) == 0) {
		TSDebug("kubernetes", "        found an ExternalName: %s:%s",
			svc->sv_external_name, port_name);
		remap_path_add_address(rp, svc->sv_external_name,
				       atoi(port_name));
		return;
	}

	/* Find the service port from the name given in the Ingress */
	if ((port = service_find_port(svc, port_name, SV_P_TCP)) == NULL)
		return;

	/* Find the endpoint for the service */
	eps = namespace_get_endpoints(ns, svc->sv_name);
	if (eps == NULL)
		return;

	/*
	 * Each endpoint has a list of subsets, each of which has a list of
	 * addresses.  Add each address from each subset.
	 */
	for (i = 0; i < eps->ep_nsubsets; i++) {
	endpoints_subset_t	*es = &eps->ep_subsets[i];
	endpoints_port_t	*epp;

		/* Fetch the named port from the endpoint */
		epp = hash_get(es->es_ports, port->sp_name);
		if (epp == NULL)
			continue;

		/* Add each address for this subset */
		for (j = 0; j < es->es_naddrs; j++) {
		endpoints_address_t *addr = &es->es_addrs[j];
			TSDebug("kubernetes", "        add host %s:%d",
				addr->ea_ip, epp->et_port);
			remap_path_add_address(rp, addr->ea_ip, epp->et_port);
		}
	}
}
