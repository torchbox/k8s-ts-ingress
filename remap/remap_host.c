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
 * remap_host: represent one 'host' in an Ingress.  one or more of these is
 * associated with every Ingress, and contains one or more remap_paths.
 */

#include	<assert.h>

#include	<ts/ts.h>

#include	"remap.h"

static int
truefalse(const char *str)
{
	if (strcmp(str, "true") == 0)
		return 1;
	return 0;
}

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
	/* No path in the request, so this can only match the default path */
	if (!path) {
		if (pfxsz)
			*pfxsz = 0;
		return rh->rh_paths[0];
	}

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

void
remap_host_annotate(remap_host_t *rh, cluster_t *cs, hash_t annotations)
{
const char	*s;

	/* hsts-max-age */
	if ((s = hash_get(annotations, IN_HSTS_MAX_AGE)) != NULL)
		rh->rh_hsts_max_age = atoi(s);
	else
		rh->rh_hsts_max_age = cs->cs_config->cc_hsts_max_age;

	/* hsts-include-subdomains */
	if ((s = hash_get(annotations, IN_HSTS_INCLUDE_SUBDOMAINS)) != NULL)
		rh->rh_hsts_subdomains = truefalse(s);
	else
		rh->rh_hsts_subdomains = cs->cs_config->cc_hsts_subdomains;

	/* http2-enable */
	if ((s = hash_get(annotations, IN_HTTP2_ENABLE)) != NULL)
		rh->rh_http2 = truefalse(s);
	else
		rh->rh_http2 = cs->cs_config->cc_http2;

	/* tls-minimum-version */
	if ((s = hash_get(annotations, IN_TLS_MINIMUM_VERSION)) != NULL) {
		if (strcmp(s, IN_TLS_VERSION_1_0) == 0)
			rh->rh_tls_version = IN_TLS_VERSION_1_0_VALUE;
		else if (strcmp(s, IN_TLS_VERSION_1_1) == 0)
			rh->rh_tls_version = IN_TLS_VERSION_1_1_VALUE;
		else if (strcmp(s, IN_TLS_VERSION_1_2) == 0)
			rh->rh_tls_version = IN_TLS_VERSION_1_2_VALUE;
	} else
		rh->rh_tls_version = cs->cs_config->cc_tls_minimum_version;
}

/*
 * Attach default TLS certificates to this host.  These come from the cluster
 * global configuration.
 */
void
remap_host_attach_default_tls(remap_host_t *rh, cluster_t *cs, const char *host)
{
cluster_cert_t	*crt;
namespace_t	*ns;
secret_t	*srt;

	assert(rh);
	assert(cs);
	assert(host);

	if ((crt = cluster_get_cert_for_hostname(cs, host)) == NULL)
		return;

	if ((ns = cluster_get_namespace(cs, crt->cr_namespace)) == NULL) {
		TSError("kubernetes: warning: default tls certificate %s/%s"
			" was not found on the cluster", crt->cr_namespace,
			crt->cr_name);
		return;
	}

	if ((srt = namespace_get_secret(ns, crt->cr_name)) == NULL) {
		TSError("kubernetes: warning: default tls certificate %s/%s"
			" was not found on the cluster", crt->cr_namespace,
			crt->cr_name);
		return;
	}

	if ((rh->rh_ctx = secret_make_ssl_ctx(srt)) == NULL) {
		TSError("kubernetes: warning: default tls certificate %s/%s"
			" is invalid", crt->cr_namespace, crt->cr_name);
		return;
	}
}
