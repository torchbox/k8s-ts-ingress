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
#include	<stdlib.h>
#include	<pthread.h>

#include	<ts/ts.h>

#include	"api.h"
#include	"hash.h"

static int
truefalse(const char *str)
{
	if (strcmp(str, "true") == 0)
		return 1;
	return 0;
}

cluster_t *
cluster_make(void)
{
cluster_t	*ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;

	if ((ret->cs_namespaces = hash_new(127, (hash_free_fn) namespace_free)) == NULL) {
		free(ret);
		return NULL;
	}

	ret->cs_config = cluster_config_new();

	pthread_rwlock_init(&ret->cs_lock, NULL);

	return ret;
}

namespace_t *
cluster_get_namespace(cluster_t *cs, const char *name)
{
namespace_t	*ret;

	if ((ret = hash_get(cs->cs_namespaces, name)) == NULL) {
		if ((ret = namespace_make(name)) == NULL)
			return NULL;
		hash_set(cs->cs_namespaces, name, ret);
	}

	return ret;
}

cluster_config_t *
cluster_config_new(void)
{
cluster_config_t	*cc;

	if ((cc = calloc(1, sizeof(*cc))) == NULL) {
		TSError("kubernetes: out of memory");
		return NULL;
	}

	cc->cc_http2 = 1;
	/* Consider changing this to TLS 1.1 at some point */
	cc->cc_tls_minimum_version = IN_TLS_VERSION_1_0_VALUE;

	TAILQ_INIT(&cc->cc_certs);

	return cc;
}

void
cluster_config_free(cluster_config_t *cc)
{
cluster_cert_t	*crt, *tmp;

	if (!cc)
		return;

	TAILQ_FOREACH_SAFE(crt, &cc->cc_certs, cr_entry, tmp) {
		free(crt->cr_domain);
		free(crt->cr_namespace);
		free(crt->cr_name);
		free(crt);
	}

	free(cc);
}

/*
 * Parser the tls-certificate options, which is a whitespace-separated list of
 * [domain[,domain...]:namespace/certname.  We don't process the list at all
 * here because we might not have a copy of the necessary secrets; just store
 * the details so the remap rebuild can use it.
 */
void
cluster_config_add_certs(cluster_config_t *cc, const char *certs)
{
char	*s, *p;

	s = strdup(certs);
	while ((p = strsep(&s, " \t,")) != NULL) {
	char	*certns, *certname, *dom;

		if ((certns = index(p, ':')) == NULL) {
			TSError("kubernetes: invalid tls-certificates "
				"entry: %s", p);
			continue;
		}

		*certns++ = '\0';
		
		if ((certname = index(certns, '/')) == NULL) {
			TSError("kubernetes: invalid certificate name in "
				"tls-certificate: %s", certns);
			continue;
		}

		*certname++ = '\0';

		while ((dom = strsep(&p, ",")) != NULL) {
		cluster_cert_t	*crt;
			crt = calloc(1, sizeof(*crt));
			crt->cr_domain = strdup(dom);
			crt->cr_namespace = strdup(certns);
			crt->cr_name = strdup(certname);
			TAILQ_INSERT_TAIL(&cc->cc_certs, crt, cr_entry);
		}
	}

	free(s);
}

/*
 * Parse default configuration.
 */
void
cluster_set_configmap(cluster_t *cs, configmap_t *cm)
{
const char		*s;
cluster_config_t	*cc;

	if (cm == NULL) {
		cluster_config_free(cs->cs_config);
		cs->cs_config = cluster_config_new();
		return;
	}

	if ((cc = cluster_config_new()) == NULL) {
		TSError("kubernetes: out of memory");
		return;
	}

	/* hsts-max-age */
	if ((s = hash_get(cm->cm_data, "hsts-max-age")) != NULL)
		cc->cc_hsts_max_age = atoi(s);

	/* hsts-include-subdomains */
	if ((s = hash_get(cm->cm_data, "hsts-include-subdomains")) != NULL)
		cc->cc_hsts_subdomains = truefalse(s);

	/* http2-enable */
	if ((s = hash_get(cm->cm_data, "http2-enable")) != NULL)
		cc->cc_http2 = truefalse(s);

	/* tls-minimum-version */
	if ((s = hash_get(cm->cm_data, "tls-minimum-version")) != NULL) {
		if (strcmp(s, IN_TLS_VERSION_1_0) == 0)
			cc->cc_tls_minimum_version = IN_TLS_VERSION_1_0_VALUE;
		else if (strcmp(s, IN_TLS_VERSION_1_1) == 0)
			cc->cc_tls_minimum_version = IN_TLS_VERSION_1_1_VALUE;
		else if (strcmp(s, IN_TLS_VERSION_1_2) == 0)
			cc->cc_tls_minimum_version = IN_TLS_VERSION_1_2_VALUE;
		else
			TSError("kubernetes: invalid tls-minimum-version: %s "
				"in configmap", s);
	}

	/* tls-certificates */
	if ((s = hash_get(cm->cm_data, "tls-certificates")) != NULL)
		cluster_config_add_certs(cc, s);

	cluster_config_free(cs->cs_config);
	cs->cs_config = cc;
}

/*
 * Match a hostname against a TLS certificate's host.  This is not a normal
 * wildcard match.  
 *
 * If the pattern is exactly '*', then the result is true and the host is
 * ignored.
 *
 * If the pattern doesn't start with '*', then an exact match is performed.
 *
 * If the pattern starts with '*.', then the leading * is removed from the
 * pattern and the first domain component is removed from the host, and an
 * exact match is done on the result.
 *
 * If the pattern starts with '*' but the second character is not '.' (e.g.
 * '*mydomain.com'), then both comparisons are done.
 */
int
domain_match(const char *pat, const char *str)
{
	if (strcmp(pat, "*") == 0)
		return 1;

	/* A valid domain must have at least two components, "a.b". */
	if (strlen(str) < 3 || strlen(pat) < 3)
		return 0;

	/* exact.domain.com */
	if (*pat != '*')
		return strcmp(pat, str) == 0;

	/* *.domain.com */
	if (pat[0] == '*' && pat[1] == '.') {
	const char	*dc;
		if ((dc = index(str, '.')) == NULL)
			return 0;
		return strcmp(pat + 2, dc + 1) == 0;
	}

	/* *domain.com */
	if (pat[0] == '*' && pat[1] != '.') {
	const char	*dc;

		/* Check for exact domain match */
		if (strcmp(pat + 1, str) == 0)
			return 1;

		/* Check for wildcard match */
		if ((dc = index(str, '.')) == NULL)
			return 0;

		return strcmp(pat + 1, dc + 1) == 0;
	}

	return 0;
}

cluster_cert_t *
cluster_get_cert_for_hostname(cluster_t *cs, const char *host)
{
cluster_cert_t	*crt;

	TAILQ_FOREACH(crt, &cs->cs_config->cc_certs, cr_entry) {
		if (domain_match(crt->cr_domain, host))
			return crt;
	}

	return NULL;
}

void
cluster_free(cluster_t *cs)
{
	TSDebug("kubernetes", "cluster_free: %p", cs);
	hash_free(cs->cs_namespaces);
	cluster_config_free(cs->cs_config);
	pthread_rwlock_destroy(&cs->cs_lock);
	free(cs);
}
