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

	return cc;
}

void
cluster_config_free(cluster_config_t *cc)
{
	if (!cc)
		return;

	free(cc);
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

	cluster_config_free(cs->cs_config);
	cs->cs_config = cc;
}

void
cluster_free(cluster_t *cs)
{
	TSDebug("kubernetes", "cluster_free: %p", cs);
	hash_free(cs->cs_namespaces);
	pthread_rwlock_destroy(&cs->cs_lock);
	free(cs);
}
