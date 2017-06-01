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

#include	"api.h"

namespace_t *
namespace_make(const char *name)
{
namespace_t	*ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;

	if ((ret->ns_name = strdup(name)) == NULL) {
		namespace_free(ret);
		return NULL;
	}

	if ((ret->ns_ingresses = hash_new(127, (hash_free_fn) ingress_free)) == NULL) {
		namespace_free(ret);
		return NULL;
	}

	if ((ret->ns_secrets = hash_new(127, (hash_free_fn) secret_free)) == NULL) {
		namespace_free(ret);
		return NULL;
	}

	if ((ret->ns_services = hash_new(127, (hash_free_fn) service_free)) == NULL) {
		namespace_free(ret);
		return NULL;
	}

	if ((ret->ns_endpointses = hash_new(127, (hash_free_fn) endpoints_free)) == NULL) {
		namespace_free(ret);
		return NULL;
	}

	return ret;
}

void
namespace_free(namespace_t *ns)
{
	hash_free(ns->ns_ingresses);
	hash_free(ns->ns_secrets);
	hash_free(ns->ns_services);
	hash_free(ns->ns_endpointses);
	free(ns->ns_name);
	free(ns);
}

void
namespace_put_ingress(namespace_t *ns, ingress_t *ing)
{
	hash_del(ns->ns_ingresses, ing->in_name);
	hash_set(ns->ns_ingresses, ing->in_name, ing);
}

ingress_t *
namespace_get_ingress(namespace_t *ns, const char *name)
{
	return hash_get(ns->ns_ingresses, name);
}

void
namespace_del_ingress(namespace_t *ns, const char *name)
{
	hash_del(ns->ns_ingresses, name);
}

void
namespace_put_secret(namespace_t *ns, secret_t *sec)
{
	hash_del(ns->ns_secrets, sec->se_name);
	hash_set(ns->ns_secrets, sec->se_name, sec);
}

secret_t *
namespace_get_secret(namespace_t *ns, const char *name)
{
	return hash_get(ns->ns_secrets, name);
}

void
namespace_del_secret(namespace_t *ns, const char *name)
{
	hash_del(ns->ns_secrets, name);
}

void
namespace_put_service(namespace_t *ns, service_t *svc)
{
	hash_del(ns->ns_services, svc->sv_name);
	hash_set(ns->ns_services, svc->sv_name, svc);
}

service_t *
namespace_get_service(namespace_t *ns, const char *name)
{
	return hash_get(ns->ns_services, name);
}

void
namespace_del_service(namespace_t *ns, const char *name)
{
	hash_del(ns->ns_services, name);
}

void
namespace_put_endpoints(namespace_t *ns, endpoints_t *eps)
{
	hash_del(ns->ns_endpointses, eps->ep_name);
	hash_set(ns->ns_endpointses, eps->ep_name, eps);
}

endpoints_t *
namespace_get_endpoints(namespace_t *ns, const char *name)
{
	return hash_get(ns->ns_endpointses, name);
}

void
namespace_del_endpoints(namespace_t *ns, const char *name)
{
	hash_del(ns->ns_endpointses, name);
}
